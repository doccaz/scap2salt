#!/usr/bin/env python3
"""
scap2salt — Generate native Salt states from an OpenSCAP/SCAP datastream.

Reads a SCAP Security Guide datastream (e.g. ssg-sle15-ds.xml), selects a
profile (default: PCI-DSS v4 for SUSE), and emits a curated tree of *native*
Salt states (file/pkg/service/sysctl/...) plus an MLM top.sls, pillar toggles
and oscap/Salt verify scripts. Rules with no native handler are reported in
UNMAPPED.md (never silently wrapped in cmd.run).

Stdlib only — runs on any python3, including a Multi-Linux Manager server.
"""
import argparse
import hashlib
import io
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone

# ----------------------------------------------------------------------------
# Datastream acquisition
# ----------------------------------------------------------------------------

# Common locations the scap-security-guide RPM installs content to.
SSG_LOCAL_PATHS = [
    "/usr/share/xml/scap/ssg/content/ssg-{target}-ds.xml",
    "/usr/share/openscap/ssg-{target}-ds.xml",
]
CAC_RELEASE = "v0.1.81"
# Releases ship compiled datastreams only inside the zip archive.
CAC_ZIP_URL = (
    "https://github.com/ComplianceAsCode/content/releases/download/"
    "{rel}/scap-security-guide-{ver}.zip"
)

# Runtime config shared with mappers (set in main()).
CONFIG = {"mac": "apparmor"}

# XCCDF Value defaults populated once in main() via load_values(); used to
# resolve <sub idref="..."/> substitution placeholders in bash fix scripts.
XCCDF_VALUES: dict = {}

# Which MAC framework a target ships by default.
#   SLE 16 / Leap 16 / Tumbleweed / MicroOS 6  -> SELinux (enforcing)
#   SLE 15 / SLE 12 / Leap 15 / MicroOS 5       -> AppArmor
SELINUX_TARGETS = ("sle16", "slmicro6", "leap16", "tumbleweed", "microos", "opensuse")
APPARMOR_TARGETS = ("sle15", "sle12", "slmicro5", "leap15", "opensuse-leap-15")


def mac_for_target(target):
    t = target.lower()
    if any(t.startswith(x) or x in t for x in SELINUX_TARGETS):
        return "selinux"
    if any(t.startswith(x) or x in t for x in APPARMOR_TARGETS):
        return "apparmor"
    return "apparmor"


def acquire_datastream(target, explicit, cache_dir):
    """Return a path to the datastream. Order: explicit -> local RPM -> download."""
    if explicit:
        if not os.path.exists(explicit):
            sys.exit(f"[!] --datastream not found: {explicit}")
        return explicit
    for tmpl in SSG_LOCAL_PATHS:
        p = tmpl.format(target=target)
        if os.path.exists(p):
            print(f"[*] Using locally installed content: {p}")
            return p
    os.makedirs(cache_dir, exist_ok=True)
    dest = os.path.join(cache_dir, f"ssg-{target}-ds.xml")
    if os.path.exists(dest):
        print(f"[*] Using cached download: {dest}")
        return dest
    ver = CAC_RELEASE.lstrip("v")
    zip_url = CAC_ZIP_URL.format(rel=CAC_RELEASE, ver=ver)
    inner = f"scap-security-guide-{ver}/ssg-{target}-ds.xml"
    print(f"[*] Downloading {zip_url}")
    try:
        with urllib.request.urlopen(zip_url) as resp:  # noqa: S310
            data = resp.read()
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            if inner not in zf.namelist():
                sys.exit(
                    f"[!] {inner} not found in release archive.\n"
                    f"    Available entries: {[n for n in zf.namelist() if 'ds.xml' in n]}"
                )
            with zf.open(inner) as src, open(dest, "wb") as out:
                out.write(src.read())
    except SystemExit:
        raise
    except Exception as e:  # pragma: no cover - network dependent
        sys.exit(
            f"[!] Download failed ({e}).\n"
            f"    On the MLM server install content instead:  zypper in scap-security-guide\n"
            f"    or pass --datastream /path/to/ssg-{target}-ds.xml"
        )
    return dest


# ----------------------------------------------------------------------------
# XCCDF parsing (namespace-tolerant: match by local tag name)
# ----------------------------------------------------------------------------

def ln(el):
    """Local name of an element, stripping any {namespace}."""
    return el.tag.rsplit("}", 1)[-1] if isinstance(el.tag, str) else ""


def findall_local(root, name):
    return [e for e in root.iter() if ln(e) == name]


def load_benchmark(path):
    """Return the XCCDF <Benchmark> element, unwrapping an SCAP datastream if needed."""
    root = ET.parse(path).getroot()
    if ln(root) == "Benchmark":
        return root
    # Source datastream: find the embedded XCCDF Benchmark component.
    for el in root.iter():
        if ln(el) == "Benchmark":
            return el
    sys.exit("[!] No XCCDF <Benchmark> found in file.")


def resolve_profile(bench, profile_id):
    """Return the set of selected rule idrefs for a profile (resolving 'extends')."""
    profiles = {p.get("id"): p for p in bench if ln(p) == "Profile"}
    # Allow short id or fully-qualified id.
    pid = profile_id
    if pid not in profiles:
        matches = [k for k in profiles if k.endswith("_" + profile_id) or k == profile_id]
        if not matches:
            avail = "\n      ".join(sorted(profiles))
            sys.exit(f"[!] Profile '{profile_id}' not found. Available:\n      {avail}")
        pid = matches[0]

    selected = set()

    def apply(p):
        parent = p.get("extends")
        if parent and parent in profiles:
            apply(profiles[parent])
        for sel in p:
            if ln(sel) == "select":
                ref = sel.get("idref")
                if sel.get("selected", "false") == "true":
                    selected.add(ref)
                else:
                    selected.discard(ref)

    apply(profiles[pid])
    return pid, selected


def load_values(bench):
    """Return a dict of XCCDF Value id -> default value string (for <sub> resolution)."""
    out = {}
    for el in bench.iter():
        if ln(el) != "Value":
            continue
        vid = el.get("id")
        if not vid:
            continue
        for child in el:
            if ln(child) == "value" and not child.get("selector") and child.text:
                out[vid] = child.text.strip()
                break
    return out


def resolve_fix_bash(fix_el):
    """Render the <fix> element text, substituting <sub idref="..."/> with XCCDF values."""
    parts = []
    if fix_el.text:
        parts.append(fix_el.text)
    for child in fix_el:
        if ln(child) == "sub":
            idref = child.get("idref", "")
            parts.append(XCCDF_VALUES.get(idref, ""))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def shell_resolve(val, bash):
    """Replace $var / ${var} references in `val` with their assignment value in `bash`."""
    def repl(m):
        name = m.group(1)
        am = re.search(rf'\b{re.escape(name)}=[\'"]?([^\'"\n]*)', bash)
        return am.group(1) if am else m.group(0)
    return re.sub(r'\$\{?([A-Za-z_]\w*)\}?', repl, val)


def index_rules(bench):
    return {r.get("id"): r for r in findall_local(bench, "Rule")}


def text_of(el, child_name):
    for c in el:
        if ln(c) == child_name and c.text:
            return c.text.strip()
    return None


class RuleInfo:
    __slots__ = ("id", "short", "title", "severity", "refs", "bash", "desc")

    def __init__(self, rid, el):
        self.id = rid
        self.short = re.sub(r"^xccdf_org\.ssgproject\.content_rule_", "", rid)
        self.title = text_of(el, "title") or self.short
        self.severity = el.get("severity", "unknown")
        self.refs = []
        self.bash = None
        self.desc = text_of(el, "description") or ""
        for c in el:
            if ln(c) == "reference":
                href = c.get("href", "")
                txt = (c.text or "").strip()
                if "pci" in href.lower() or "pci" in txt.lower() or txt:
                    self.refs.append((txt, href))
            elif ln(c) == "fix" and c.get("system", "").endswith("script:sh"):
                self.bash = resolve_fix_bash(c)

    def pci_refs(self):
        out = [t for (t, h) in self.refs if "pci" in h.lower()]
        return out or [t for (t, _) in self.refs if t]


# ----------------------------------------------------------------------------
# Native Salt mappers — keyed on rule-id family, value pulled from resolved bash
# ----------------------------------------------------------------------------

class SaltState:
    """A single Salt state declaration."""

    def __init__(self, sid, fun, args, category, rule):
        self.id = sid          # state id (unique within file)
        self.fun = fun         # e.g. 'sysctl.present'
        self.args = args       # list of (key, value) ; value None => bare arg
        self.category = category
        self.rule = rule
        self.audit_fragment = False
        self.needs_grub_reload = False
        self.extra_states = []   # list of (sid, fun, [(k,v)]) rendered after the main block
        self.dconf_reload = False
        self.auditd_restart = False  # auditd.conf change -> restart auditd
        self.operational = False  # guarded cmd.run (no declarative primitive exists)

    def render(self):
        lines = [
            f"# {self.rule.id}",
            f"# {self.rule.title}  [severity: {self.rule.severity}]",
        ]
        if self.operational:
            lines.append("# (guarded operational state: imperative remediation, "
                         "kept idempotent via creates/onlyif/unless)")
        pci = self.rule.pci_refs()
        if pci:
            lines.append(f"# PCI-DSS: {', '.join(pci)}")
        lines.append(f"{salt_quote_id(self.id)}:")
        lines.append(f"  {self.fun}:")
        for k, v in self.args:
            if v is None:
                lines.append(f"    - {k}")
            elif isinstance(v, list):
                lines.append(f"    - {k}:")
                raw = k in REQUISITE_KEYS
                for item in v:
                    lines.append(f"        - {item if raw else yaml_scalar(item)}")
            else:
                lines.append(f"    - {k}: {yaml_scalar(v)}")
        for (sid, fun, args) in self.extra_states:
            lines.append("")
            lines.append(f"{salt_quote_id(sid)}:")
            lines.append(f"  {fun}:")
            for k, v in args:
                if v is None:
                    lines.append(f"    - {k}")
                elif isinstance(v, list):
                    lines.append(f"    - {k}:")
                    raw = k in REQUISITE_KEYS
                    for item in v:
                        lines.append(f"        - {item if raw else yaml_scalar(item)}")
                else:
                    lines.append(f"    - {k}: {yaml_scalar(v)}")
        return "\n".join(lines) + "\n"


def yaml_scalar(v):
    if isinstance(v, bool):
        return "True" if v else "False"
    s = str(v)
    if re.fullmatch(r"0[0-7]{3,4}", s):  # file mode -> always a quoted string
        return '"' + s + '"'
    if s == "" or re.search(r"[:#{}\[\],&*?|<>=!%@`\"']", s) or s != s.strip():
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def salt_quote_id(s):
    if re.search(r"[:#\s]", s):
        return "'" + s.replace("'", "''") + "'"
    return s


# Requisite args whose list items are YAML mappings (e.g. 'pkg: aide'),
# which must NOT be quoted as scalars.
REQUISITE_KEYS = {"require", "watch", "onchanges", "listen", "prereq",
                  "onfail", "require_in", "watch_in", "onchanges_in",
                  "listen_in", "prereq_in", "onfail_in"}


# Each mapper: (predicate(short) -> bool, fn(RuleInfo) -> SaltState|None)
MAPPERS = []


def mapper(fn):
    MAPPERS.append(fn)
    return fn


@mapper
def m_sysctl(r):
    if not r.short.startswith("sysctl_"):
        return None
    m = re.search(r'sysctl\s+(?:-\S+\s+)*-w\s+(\S+?)=["\']?([^"\'\n]+)', r.bash or "")
    if not m:
        return None
    key, val = m.group(1), m.group(2).strip().strip('"\'')
    conf = "/etc/sysctl.d/" + key.replace(".", "_") + ".conf"
    return SaltState(
        f"sysctl_{key}", "sysctl.present",
        [("name", key), ("value", val), ("config", conf)],
        "sysctl", r,
    )


@mapper
def m_package(r):
    m = re.match(r"^package_(.+)_(installed|removed)$", r.short)
    if not m:
        return None
    pkg, action = m.group(1), m.group(2)
    if action == "installed":
        return SaltState(f"pkg_present_{pkg}", "pkg.installed", [("name", pkg)], "packages", r)
    return SaltState(f"pkg_absent_{pkg}", "pkg.removed", [("name", pkg)], "packages", r)


@mapper
def m_service(r):
    m = re.match(r"^service_(.+)_(enabled|disabled)$", r.short)
    if not m:
        return None
    svc, action = m.group(1), m.group(2)
    if action == "enabled":
        return SaltState(f"svc_on_{svc}", "service.running",
                         [("name", svc), ("enable", True)], "services", r)
    return SaltState(f"svc_off_{svc}", "service.dead",
                     [("name", svc), ("enable", False)], "services", r)


@mapper
def m_file_perms(r):
    if not r.short.startswith(("file_permissions_", "file_owner_", "file_groupowner_")):
        # file_*_not_exist rules: ensure file is absent
        if r.short.startswith("file_") and r.short.endswith("_not_exist"):
            bash = r.bash or ""
            rm_m = re.search(r'rm\s+(?:-\S+\s+)*["\']?(/[^\s"\'\\]+)', bash)
            if rm_m:
                p = rm_m.group(1)
                return SaltState(f"file_absent_{re.sub(r'[^A-Za-z0-9]', '_', p)}",
                                 "file.absent", [("name", p)], "permissions", r)
        return None
    bash = r.bash or ""
    mode = own = grp = path = None

    # Numeric chmod: chmod [flags] NNNN /path
    mm = re.search(r"chmod\s+(?:-\S+\s+)*([0-7]{3,4})\s+['\"]?(/[^\s'\"]+)", bash)
    if mm:
        mode, path = mm.group(1), mm.group(2)

    # Symbolic chmod: chmod [flags] u-xs,g-xws,... /path  (path extractable; mode not recoverable)
    if not path:
        ms = re.search(r"chmod\s+(?:-\S+\s+)*([ugoa][^\s]+)\s+['\"]?(/[^\s'\"\\]+)", bash)
        if ms:
            path = ms.group(2)

    # find-exec chmod: find [flags] /path ... -exec chmod MODE {} \;  (directory perms)
    if not path and "chmod" in bash:
        mf = re.search(r'find\s+(?:-\S+\s+)*(/[^\s]+).*-exec\s+chmod', bash, re.DOTALL)
        if mf:
            path = mf.group(1).rstrip("/")

    # Literal chown: chown [flags] OWNER /path
    mo = re.search(r"chown\s+(?:-\S+\s+)*([A-Za-z0-9_.-]+)\s+['\"]?(/[^\s'\"]+)", bash)
    if mo:
        own, path = mo.group(1).split(":")[0], path or mo.group(2)
    elif "chown" in bash:
        # Variable chown: newown=""; if id "OWNER" ...; chown --no-dereference "$newown" /path
        # Also handles find-exec: find [flags] /path ... -exec chown "$newown" {} \;
        uid_m = re.search(r'if id "([^"]+)"', bash)
        path_m = re.search(r'chown\s+(?:-\S+\s+)*\S*\$newown\S*\s+["\']?(/[^\s"\'\\\}]+)', bash)
        if not path_m and "$newown" in bash:
            path_m = re.search(r'find\s+(?:-\S+\s+)*(/[^\s]+)', bash)
        if uid_m and path_m:
            own = uid_m.group(1)
            path = path or path_m.group(1).rstrip("\"'")

    # Literal chgrp: chgrp [flags] GROUP /path
    mg = re.search(r"chgrp\s+(?:-\S+\s+)*([A-Za-z0-9_.-]+)\s+['\"]?(/[^\s'\"]+)", bash)
    if mg:
        grp, path = mg.group(1), path or mg.group(2)
    elif "chgrp" in bash:
        # Variable chgrp: newgroup=""; if getent group "GRP" ...; chgrp "$newgroup" /path
        # Also handles find-exec: find [flags] /path ... -exec chgrp "$newgroup" {} \;
        grp_m = re.search(r'getent group "([^"]+)"', bash)
        path_m = re.search(r'chgrp\s+(?:-\S+\s+)*\S*\$newgroup\S*\s+["\']?(/[^\s"\'\\\}]+)', bash)
        if not path_m and "$newgroup" in bash:
            path_m = re.search(r'find\s+(?:-\S+\s+)*(/[^\s]+)', bash)
        if grp_m and path_m:
            grp = grp_m.group(1)
            path = path or path_m.group(1).rstrip("\"'")

    if not path:
        return None
    args = [("name", path)]
    if mode:
        args.append(("mode", mode))
    if own:
        args.append(("user", own))
    if grp:
        args.append(("group", grp))
    args.append(("replace", False))  # enforce metadata only, never clobber content
    return SaltState(f"file_meta_{re.sub(r'[^A-Za-z0-9]', '_', path)}",
                     "file.managed", args, "permissions", r)


@mapper
def m_kmod(r):
    m = re.match(r"^kernel_module_(.+)_disabled$", r.short)
    if not m:
        return None
    mod = m.group(1)
    bm = re.search(r"install\s+(\S+)\s+/bin/true", r.bash or "")
    if bm:
        mod = bm.group(1)
    return SaltState(
        f"kmod_disable_{mod}", "file.managed",
        [("name", f"/etc/modprobe.d/{mod}.conf"),
         ("mode", "0644"),
         ("contents", [f"install {mod} /bin/true", f"blacklist {mod}"])],
        "kernel_modules", r,
    )


# Fallback directives for sshd rules whose value isn't a literal in the bash.
SSHD_TABLE = {
    "sshd_disable_root_login": ("PermitRootLogin", "no"),
    "sshd_disable_empty_passwords": ("PermitEmptyPasswords", "no"),
    "sshd_disable_user_known_hosts": ("IgnoreUserKnownHosts", "yes"),
    "sshd_do_not_permit_user_env": ("PermitUserEnvironment", "no"),
    "sshd_enable_warning_banner": ("Banner", "/etc/issue.net"),
    "sshd_set_loglevel_info": ("LogLevel", "INFO"),
}
# sshd rules that are not a single config directive (skip — handled elsewhere / N/A).
SSHD_SKIP = {"sshd_use_strong_rng", "sshd_install_libpam_ssh"}
SSHD_DROPIN = "/etc/ssh/sshd_config.d/00-pci-hardening.conf"


@mapper
def m_sshd(r):
    if not r.short.startswith("sshd_") or r.short in SSHD_SKIP:
        return None
    directive = value = None
    bash = r.bash or ""
    # 1) preferred: the literal line written via the standard printf idiom
    for lit in re.findall(r"""printf\s+'%s\\n'\s+"([^"]+)" """.strip(), bash):
        mm = re.match(r"^([A-Z][A-Za-z0-9]+)\s+(.+)$", lit.strip())
        if mm:
            directive, value = mm.group(1), mm.group(2).strip()
            break
    # 2) table fallback
    if directive is None and r.short in SSHD_TABLE:
        directive, value = SSHD_TABLE[r.short]
    # 3) last resort: a bare "Directive value" line in the bash
    if directive is None:
        mm = re.search(r"^\s*([A-Z][A-Za-z0-9]+)\s+(\S.*?)\s*$", bash, re.M)
        if mm:
            directive, value = mm.group(1), mm.group(2)
    if directive is None:
        return None
    return SaltState(
        f"sshd_{directive}", "file.replace",
        [("name", SSHD_DROPIN),
         ("pattern", f"^{re.escape(directive)}\\s.*$"),
         ("repl", f"{directive} {value}"),
         ("append_if_not_found", True),
         ("create_if_not_found", True)],
        "sshd", r,
    )


@mapper
def m_lineinfile(r):
    """Generic config-line setter (CaC set_config_file / lineinfile idiom).

    Resolved bash always contains:  printf '%s\\n' "<LINE>" >> "<PATH>"
    We turn that into an idempotent file.replace keyed on the line's parameter.
    """
    bash = r.bash or ""
    m = re.search(r"""printf\s+'%s\\n'\s+"([^"]+)"\s+>>?\s+"(/[^"]+)" """.strip(),
                  bash)
    if not m:
        return None
    line, path = m.group(1), m.group(2)
    if line.strip().startswith(("-w ", "-a ")) or "audit" in path:
        return None  # audit rules handled separately
    # derive an anchor pattern from the parameter (key=value or 'key value')
    if re.match(r"^\s*\S+=", line):
        key = line.split("=", 1)[0].strip()
        pattern = f"^\\s*{re.escape(key)}=.*$"
    else:
        key = line.split()[0]
        pattern = f"^\\s*{re.escape(key)}\\s.*$"
    return SaltState(
        f"line_{re.sub(r'[^A-Za-z0-9]', '_', path)}_{re.sub(r'[^A-Za-z0-9]', '_', key)}",
        "file.replace",
        [("name", path), ("pattern", pattern), ("repl", line),
         ("append_if_not_found", True), ("create_if_not_found", True)],
        "lineinfile", r,
    )


@mapper
def m_mount(r):
    m = re.match(r"^mount_option_(.+?)_(nodev|nosuid|noexec)$", r.short)
    if not m:
        return None
    target, opt = m.group(1), m.group(2)
    mp = "/" + target.replace("_", "/") if target not in ("tmp", "var", "home", "boot") else "/" + target
    # /dev/shm, /var/tmp etc.
    mp = {"dev_shm": "/dev/shm", "var_tmp": "/var/tmp", "var_log": "/var/log",
          "var_log_audit": "/var/log/audit", "tmp": "/tmp", "home": "/home",
          "boot": "/boot"}.get(target, mp)
    return SaltState(
        f"mount_{re.sub(r'[^A-Za-z0-9]', '_', mp)}_{opt}", "mount.mounted",
        [("name", mp), ("device", "auto"), ("fstype", "auto"),
         ("opts", opt), ("mount", False), ("persist", True),
         ("match_on", "name")],
        "mounts", r,
    )


@mapper
def m_audit(r):
    """Audit rules: reconstruct watch (-w) and syscall (-a) lines into a
    per-rule fragment under /etc/audit/rules.d/ (augenrules concatenates them)."""
    if not (r.short.startswith("audit_rules_") or r.short.startswith("audit_")):
        return None
    bash = r.bash or ""
    lines = []
    # 1) literal -w/-a rules written via the standard printf idiom (clean)
    for lit in re.findall(r"""printf\s+'%s\\n'\s+"([^"]+)" """.strip(), bash):
        if lit.startswith(("-w ", "-a ")):
            lines.append(lit.strip())
    # 1b) any remaining bare watch rules (strip stray trailing quote)
    for w in re.findall(r"(-w\s+/\S+\s+-p\s+\S+(?:\s+-k\s+[^\s\"']+)?)", bash):
        w = w.strip().rstrip('"\'')
        if w not in lines:
            lines.append(w)
    # 2) syscall rules reconstructed from the literal variable assignments
    def grab(name):
        mm = re.search(rf'{name}="([^"]*)"', bash)
        return mm.group(1).strip() if mm else ""
    syscall = grab("SYSCALL")
    key = grab("KEY")
    auid = grab("AUID_FILTERS")
    other = grab("OTHER_FILTERS")
    if syscall:
        for arch in ("b32", "b64"):
            parts = [f"-a always,exit -F arch={arch}"]
            if other:
                parts.append(other)
            parts += [f"-S {s}" for s in syscall.split()]
            if auid:
                parts.append(auid)
            if key:
                parts.append(f"-k {key}")
            lines.append(" ".join(parts))
    if not lines:
        return None
    lines = list(dict.fromkeys(lines))
    frag = f"/etc/audit/rules.d/pci-{r.short}.rules"
    st = SaltState(
        f"audit_frag_{r.short}", "file.managed",
        [("name", frag), ("mode", "0640"), ("contents", lines)],
        "audit", r,
    )
    st.audit_fragment = True  # marks it for the augenrules reload trigger
    return st


@mapper
def m_dconf(r):
    """GNOME dconf rules: write a settings fragment + lock fragment into the
    target dconf db dir (dconf merges all files), reloaded by `dconf update`."""
    if not r.short.startswith("dconf_"):
        return None
    bash = r.bash or ""
    fm = re.search(r'DCONFFILE="([^"]+)"', bash)
    pm = re.search(r"""printf\s+'%s\\n'\s+"\[([^\]]+)\]" """.strip(), bash)
    vm = re.search(r'escaped_value="\$\(sed[^<]*<<<\s*"([^"]*)"\)"', bash)
    km = re.search(r'\|a\\([^=\n]+)=\$\{escaped_value\}', bash) \
        or re.search(r'grep -q "\^\\s\*([^\\"]+?)\\s\*=', bash)
    if not (fm and pm and vm and km):
        return None
    dconffile, path, value, key = fm.group(1), pm.group(1), vm.group(1), km.group(1).strip()
    dbdir = os.path.dirname(dconffile)
    settings = f"{dbdir}/00-pci-{r.short}"
    sid = f"dconf_set_{r.short}"
    st = SaltState(
        sid, "file.managed",
        [("name", settings), ("makedirs", True), ("mode", "0644"),
         ("contents", [f"[{path}]", f"{key}={value}"])],
        "dconf", r,
    )
    st.dconf_reload = True
    # lock fragment so the user cannot override the policy
    lm = re.search(r'echo "(/[^"]+)" >> "/etc/dconf/db/[^"]+/locks/', bash)
    if lm:
        lock_id = f"dconf_lock_{r.short}"
        st.extra_states.append((
            lock_id, "file.managed",
            [("name", f"{dbdir}/locks/00-pci-{r.short}"), ("makedirs", True),
             ("mode", "0644"), ("contents", [lm.group(1)])],
        ))
    return st


AIDE_SERVICE = ("[Unit]\nDescription=Aide Check\n\n[Service]\nType=simple\n"
                "ExecStart=/usr/sbin/aide --check\n\n[Install]\nWantedBy=multi-user.target")
AIDE_TIMER = ("[Unit]\nDescription=Aide check every day at 05:00\n\n[Timer]\n"
              "OnCalendar=*-*-* 05:00:00\n\n[Install]\nWantedBy=multi-user.target")


@mapper
def m_aide(r):
    if r.short == "aide_build_database":
        st = SaltState(
            "aide_build_database", "cmd.run",
            [("name", "aide --init && mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db"),
             ("creates", "/var/lib/aide/aide.db"),
             ("require", ["pkg: aide"])],
            "aide", r,
        )
        st.operational = True
        return st
    if r.short == "aide_periodic_checking_systemd_timer":
        st = SaltState(
            "aidecheck_service", "file.managed",
            [("name", "/etc/systemd/system/aidecheck.service"), ("mode", "0644"),
             ("contents", AIDE_SERVICE.split("\n"))],
            "aide", r,
        )
        st.extra_states = [
            ("aidecheck_timer", "file.managed",
             [("name", "/etc/systemd/system/aidecheck.timer"), ("mode", "0644"),
              ("contents", AIDE_TIMER.split("\n"))]),
            ("aidecheck_daemon_reload", "cmd.run",
             [("name", "systemctl daemon-reload"),
              ("onchanges", ["file: aidecheck_service", "file: aidecheck_timer"])]),
            ("aidecheck_timer_enabled", "service.running",
             [("name", "aidecheck.timer"), ("enable", True),
              ("require", ["file: aidecheck_timer", "cmd: aidecheck_daemon_reload"])]),
        ]
        st.operational = True
        return st
    return None


@mapper
def m_rpm(r):
    if r.short == "ensure_gpgcheck_globally_activated":
        # SUSE master switch in /etc/zypp/zypp.conf (covers repo + package).
        return SaltState(
            "zypp_gpgcheck", "file.replace",
            [("name", "/etc/zypp/zypp.conf"),
             ("pattern", "^#?\\s*gpgcheck\\s*=.*$"),
             ("repl", "gpgcheck = 1"),
             ("append_if_not_found", True)],
            "rpm", r,
        )
    if r.short == "ensure_gpgcheck_never_disabled":
        st = SaltState(
            "zypp_repo_gpgcheck", "cmd.run",
            [("name", "sed -ri 's/^([[:space:]]*)(repo_|pkg_)?gpgcheck[[:space:]]*=[[:space:]]*(0|off)/\\1\\2gpgcheck = 1/' /etc/zypp/repos.d/*.repo"),
             ("onlyif", "grep -rqiE '^[[:space:]]*(repo_|pkg_)?gpgcheck[[:space:]]*=[[:space:]]*(0|off)' /etc/zypp/repos.d/")],
            "rpm", r,
        )
        st.operational = True
        return st
    if r.short == "ensure_suse_gpgkey_installed":
        st = SaltState(
            "import_suse_gpgkeys", "cmd.run",
            [("name", "for k in /usr/lib/rpm/gpg/*; do rpm --import \"$k\" 2>/dev/null || true; done"),
             ("onlyif", "test -d /usr/lib/rpm/gpg")],
            "rpm", r,
        )
        st.operational = True
        return st
    if r.short in ("rpm_verify_permissions", "rpm_verify_ownership"):
        flag = "--setperms" if r.short.endswith("permissions") else "--setugids"
        st = SaltState(
            r.short, "cmd.run",
            [("name", f"rpm -qa | xargs -r -n1 rpm {flag}")],
            "rpm", r,
        )
        st.operational = True
        return st
    # rpm_verify_hashes has no safe automatic remediation (would reinstall pkgs) -> unmapped
    return None


@mapper
def m_auditd_conf(r):
    """auditd.conf / audisp plugin key=value settings (not rules.d fragments)."""
    if not r.short.startswith("auditd_"):
        return None
    bash = r.bash or ""
    # config file: AUDITCONFIG=.../auditd.conf, AUDISP_SYSLOGCONFIG=.../syslog.conf, or literal path
    fm = re.search(r'\b[A-Z_]*CONFIG=(/etc/audit/\S+)', bash) \
        or re.search(r'(/etc/audit/(?:auditd\.conf|plugins\.d/\S+))', bash)
    km = re.search(r'<<<\s*"\^([A-Za-z_][\w-]*)"', bash)
    vm = re.search(r'printf -v formatted_output "%s = %s" "\$stripped_key" "([^"]+)"', bash)
    if fm and km and vm:                         # printf -v idiom
        conf, key = fm.group(1), km.group(1)
        val = shell_resolve(vm.group(1), bash).split("|")[0].strip()
    else:                                        # inline "key = $var" idiom (echo/printf/sed)
        im = re.search(r'([a-z_]+)\s*=\s*\$\{?(var_\w+)\}?', bash)
        if not (fm and im):
            return None
        conf, key = fm.group(1), im.group(1)
        val = shell_resolve("$" + im.group(2), bash).split("|")[0].strip()
    st = SaltState(
        f"auditd_conf_{key}", "file.replace",
        [("name", conf),
         ("pattern", f"^{re.escape(key)}\\s*=.*$"),
         ("repl", f"{key} = {val}"),
         ("append_if_not_found", True),
         ("create_if_not_found", True)],
        "audit", r,
    )
    st.auditd_restart = True
    return st


# PAM module-argument rules sharing CaC's VALUES/VALUE_NAMES/ARGS macro.
def m_pam(r):
    bash = r.bash or ""
    if "VALUE_NAMES+=" not in bash or "pam_" not in bash:
        return None
    # line type + control + module from the canonical echo line CaC emits
    em = re.search(r'echo "(\w+)\s+(\w+)\s+pam_(\w+)\.so', bash)
    if not em:
        return None
    ltype, ctrl, mod = em.group(1), em.group(2), em.group(3)
    fm = re.search(r'\[ -e "(/etc/pam\.d/[\w.-]+)"', bash) \
        or re.search(r'>> "(/etc/pam\.d/[\w.-]+)"', bash)
    if not fm:
        return None
    pam_file = fm.group(1)
    values = re.findall(r'VALUES\+=\("([^"]*)"\)', bash)
    names = re.findall(r'VALUE_NAMES\+=\("([^"]*)"\)', bash)
    newargs = re.findall(r'NEW_ARGS\+=\("([^"]*)"\)', bash)
    opts = []       # (name, value)
    for nm, vl in zip(names, values):
        if nm:
            opts.append((nm, shell_resolve(vl, bash)))
    bare = [a for a in newargs if a]
    if not opts and not bare:
        return None
    base = f"{ltype} {ctrl} pam_{mod}.so"
    # Build a faithful, idempotent shell remediation (no declarative PAM primitive
    # exists in core Salt): ensure the module line exists, then ensure each option.
    cmds = [f'f={pam_file}',
            f'grep -qE "^[[:space:]]*{ltype}[[:space:]]+{ctrl}[[:space:]]+pam_{mod}\\.so" "$f" '
            f'|| echo "{base}" >> "$f"']
    checks = []
    for nm, vl in opts:
        cmds.append(
            f'if grep -qE "^[[:space:]]*{ltype}[[:space:]]+{ctrl}[[:space:]]+pam_{mod}\\.so.*\\b{nm}=" "$f"; '
            f'then sed -ri "s|(^[[:space:]]*{ltype}[[:space:]]+{ctrl}[[:space:]]+pam_{mod}\\.so.*\\b{nm}=)[^[:space:]]*|\\1{vl}|" "$f"; '
            f'else sed -ri "s|(^[[:space:]]*{ltype}[[:space:]]+{ctrl}[[:space:]]+pam_{mod}\\.so\\S*)|\\1 {nm}={vl}|" "$f"; fi')
        checks.append(f'grep -qE "^[[:space:]]*{ltype}[[:space:]]+{ctrl}[[:space:]]+pam_{mod}\\.so.*\\b{nm}={vl}\\b" "$f"')
    for arg in bare:
        cmds.append(
            f'grep -qE "^[[:space:]]*{ltype}[[:space:]]+{ctrl}[[:space:]]+pam_{mod}\\.so.*\\b{arg}\\b" "$f" '
            f'|| sed -ri "s|(^[[:space:]]*{ltype}[[:space:]]+{ctrl}[[:space:]]+pam_{mod}\\.so\\S*)|\\1 {arg}|" "$f"')
        checks.append(f'grep -qE "^[[:space:]]*{ltype}[[:space:]]+{ctrl}[[:space:]]+pam_{mod}\\.so.*\\b{arg}\\b" "$f"')
    st = SaltState(
        f"pam_{mod}_{r.short}", "cmd.run",
        [("name", "; ".join(cmds)), ("unless", "f=" + pam_file + "; " + " && ".join(checks))],
        "pam", r,
    )
    st.operational = True
    return st


@mapper
def _m_pam(r):
    return m_pam(r)


@mapper
def m_sudoers(r):
    """sudo Defaults options -> a validated /etc/sudoers.d drop-in (clean & safe)."""
    if not r.short.startswith("sudo_"):
        return None
    bash = r.bash or ""
    sm = re.search(r'echo "(Defaults[^"]+)"\s*>>', bash)
    if not sm:
        return None  # e.g. sudo_require_authentication (NOPASSWD removal) -> unmapped
    line = shell_resolve(sm.group(1), bash)
    return SaltState(
        f"sudoers_{r.short}", "file.managed",
        [("name", f"/etc/sudoers.d/99-pci-{r.short}"),
         ("mode", "0440"),
         ("contents", [line])],
        "sudo", r,
    )


@mapper
def m_coredump(r):
    """systemd coredump.conf [Coredump] key=value -> a drop-in fragment."""
    if not r.short.startswith("coredump_"):
        return None
    bash = r.bash or ""
    am = re.search(r'/a\s+(\w+)=([^\s"]+)', bash)
    sm = re.search(r'\[(Coredump)\]', bash)
    if not (am and sm):
        return None
    section, key, val = sm.group(1), am.group(1), am.group(2)
    return SaltState(
        f"coredump_{key}", "file.managed",
        [("name", f"/etc/systemd/coredump.conf.d/00-pci-{r.short}.conf"),
         ("makedirs", True), ("mode", "0644"),
         ("contents", [f"[{section}]", f"{key}={val}"])],
        "coredump", r,
    )


@mapper
def m_grub_audit(r):
    """grub2_audit_* kernel cmdline args -> /etc/default/grub (+ grub2-mkconfig)."""
    if not r.short.startswith("grub2_audit"):
        return None
    bash = r.bash or ""
    em = re.search(r"""echo\s+['"]GRUB_CMDLINE_LINUX="([^"]+)"['"]""", bash)
    if not em:
        return None
    param = shell_resolve(em.group(1), bash)
    return _grub_cmdline_state(f"grub_{r.short}", param, r, category="grub")


@mapper
def m_securetty(r):
    if r.short == "no_direct_root_logins":
        # Truncate /etc/securetty so root cannot log in on any tty.
        return SaltState(
            "securetty_empty", "file.managed",
            [("name", "/etc/securetty"), ("mode", "0600"), ("contents", [""])],
            "lineinfile", r,
        )
    if r.short == "securetty_root_login_console_only":
        # Remove virtual-console (vc/N) entries, leaving only physical consoles.
        return SaltState(
            "securetty_no_vc", "file.replace",
            [("name", "/etc/securetty"),
             ("pattern", "^vc/[0-9].*$"), ("repl", "")],
            "lineinfile", r,
        )
    return None


@mapper
def m_tmout(r):
    if r.short != "accounts_tmout":
        return None
    bash = r.bash or ""
    vm = re.search(r"var_accounts_tmout='([^']*)'", bash)
    tmout = vm.group(1) if vm else "900"
    return SaltState(
        "accounts_tmout", "file.managed",
        [("name", "/etc/profile.d/autologout.sh"), ("mode", "0755"),
         ("contents", ["# Interactive session timeout (scap2salt, PCI-DSS)",
                       f"TMOUT={tmout}", "readonly TMOUT", "export TMOUT"])],
        "lineinfile", r,
    )


@mapper
def m_chrony(r):
    if r.short != "chronyd_specify_remote_server":
        return None
    bash = r.bash or ""
    cm = re.search(r'config_file="([^"]+)"', bash)
    sm = re.search(r"var_multiple_time_servers='([^']*)'", bash)
    if not (cm and sm):
        return None
    conf = cm.group(1)
    first = (sm.group(1).split(",") or ["pool.ntp.org"])[0].strip()
    return SaltState(
        "chrony_remote_server", "file.replace",
        [("name", conf),
         ("pattern", "^(server|pool)\\s+\\S+"),
         ("repl", f"pool {first} iburst"),
         ("append_if_not_found", True)],
        "lineinfile", r,
    )


# MAC (Mandatory Access Control) rules — applicability depends on the target.
SELINUX_MAC_RULES = {
    "selinux_state", "selinux_policytype", "selinux_confinement_of_daemons",
    "grub2_enable_selinux",
}


def _grub_cmdline_state(sid, param, rule, category="mac"):
    """Idempotently ensure a kernel arg is in GRUB_CMDLINE_LINUX (SUSE: /etc/default/grub)."""
    key = param.split("=", 1)[0]
    st = SaltState(
        sid, "file.replace",
        [("name", "/etc/default/grub"),
         ("pattern", f"^(GRUB_CMDLINE_LINUX=\")(?![^\"]*{re.escape(key)}=)(.*)\"$"),
         ("repl", f"\\g<1>{param} \\g<2>\""),
         ("append_if_not_found", False)],
        category, rule,
    )
    st.needs_grub_reload = True
    return st


def m_mac(r):
    """selinux_*/grub2_enable_selinux rules.

    On SELinux targets (SLE16+): map natively. On AppArmor targets (SLE15):
    return 'NA' — the equivalent control is enforced by the generated AppArmor
    state set instead (see MAC_EQUIVALENCE.md)."""
    mac = CONFIG["mac"]
    is_selinux_rule = ("selinux" in r.short) or (r.short == "grub2_enable_selinux")
    is_apparmor_rule = "apparmor" in r.short
    if mac == "apparmor":
        return "NA" if is_selinux_rule else None
    # SELinux target
    if is_apparmor_rule:
        return "NA"
    if r.short == "selinux_state":
        return SaltState("selinux_enforcing", "selinux.mode",
                         [("name", "enforcing")], "mac", r)
    if r.short == "selinux_policytype":
        vals = re.findall(r'SELINUXTYPE=([A-Za-z0-9_]+)', r.bash or "")
        val = vals[-1] if vals else "targeted"
        return SaltState("selinux_policytype", "file.replace",
                         [("name", "/etc/selinux/config"),
                          ("pattern", "^SELINUXTYPE=.*$"),
                          ("repl", f"SELINUXTYPE={val}"),
                          ("append_if_not_found", True)], "mac", r)
    if r.short == "grub2_enable_selinux":
        return _grub_cmdline_state("grub_security_selinux", "security=selinux", r)
    if r.short == "selinux_confinement_of_daemons":
        return "NA"   # policy-level; confirm via oscap scan, not a single state
    return None       # package_libselinux_/audit_*_selinux -> handled by other mappers


MAPPERS.insert(0, m_mac)


def map_rule(r):
    for fn in MAPPERS:
        st = fn(r)
        if st is not None:
            return st
    return None


# ----------------------------------------------------------------------------
# Emitters
# ----------------------------------------------------------------------------

CATEGORIES = ["sysctl", "packages", "services", "permissions",
              "kernel_modules", "sshd", "lineinfile", "pam", "sudo",
              "audit", "dconf", "coredump", "grub", "aide", "rpm",
              "mounts", "mac", "misc"]
HEADER = "# Generated by scap2salt — DO NOT EDIT BY HAND.\n# Source: {src}\n# Profile: {prof}\n# Generated: {ts}\n\n"


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def emit_tree(outdir, src, profile_id, mapped, unmapped, na, mac):
    base = os.path.join(outdir, "srv", "salt")
    state_dir = os.path.join(base, "pci_dss")
    meta = dict(src=os.path.basename(src), prof=profile_id,
                ts=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    # group states by category
    by_cat = {c: [] for c in CATEGORIES}
    for st in mapped:
        by_cat.setdefault(st.category, []).append(st)

    used_cats = []
    for cat in CATEGORIES:
        states = by_cat.get(cat) or []
        if not states:
            continue
        used_cats.append(cat)
        body = HEADER.format(**meta)
        body += f"# {len(states)} rule(s) in category '{cat}'.\n\n"
        body += ("{%- set p = salt['pillar.get']('pci_dss', {}) %}\n"
                 "{%- if p.get('enabled', True) and p.get('" + cat + "', True) %}\n\n")
        body += "\n".join(s.render() for s in states)
        if cat == "audit":
            frags = [s.id for s in states if getattr(s, "audit_fragment", False)]
            if frags:
                body += ("\n# Reload audit rules once any fragment changes.\n"
                         "augenrules_load:\n  cmd.run:\n"
                         "    - name: augenrules --load\n"
                         "    - onchanges:\n"
                         + "".join(f"      - file: {salt_quote_id(i)}\n" for i in frags))
            conf = [s.id for s in states if getattr(s, "auditd_restart", False)]
            if conf:
                body += ("\n# Restart auditd after an auditd.conf change.\n"
                         "auditd_restart:\n  cmd.run:\n"
                         "    - name: service auditd restart\n"
                         "    - onchanges:\n"
                         + "".join(f"      - file: {salt_quote_id(i)}\n" for i in conf))
        if cat == "dconf":
            ids = []
            for s in states:
                if getattr(s, "dconf_reload", False):
                    ids.append(s.id)
                    ids += [e[0] for e in s.extra_states]
            if ids:
                body += ("\n# Apply dconf changes to the compiled databases.\n"
                         "dconf_update:\n  cmd.run:\n    - name: dconf update\n"
                         "    - onchanges:\n"
                         + "".join(f"      - file: {salt_quote_id(i)}\n" for i in ids))
        if any(getattr(s, "needs_grub_reload", False) for s in states):
            body += ("\n# Regenerate grub config after a kernel cmdline change.\n"
                     f"grub2_mkconfig_{cat}:\n  cmd.run:\n"
                     "    - name: grub2-mkconfig -o /boot/grub2/grub.cfg\n"
                     "    - onchanges:\n      - file: /etc/default/grub\n")
        body += "\n{%- endif %}\n"
        write(os.path.join(state_dir, f"{cat}.sls"), body)

    # AppArmor MAC equivalence: on AppArmor targets the PCI baseline's SELinux
    # rules are N/A, so synthesise a functionally-equivalent AppArmor state set
    # that satisfies the same control intent (enforce a MAC + audit its config).
    na_mac = [r for r in na if ("selinux" in r.short or r.short == "grub2_enable_selinux")]
    if mac == "apparmor" and na_mac:
        emit_apparmor_mac(state_dir, meta, na_mac)
        if "mac" not in used_cats:
            used_cats.append("mac")

    # init.sls
    init = HEADER.format(**meta) + "include:\n"
    init += "".join(f"  - pci_dss.{c}\n" for c in used_cats)
    write(os.path.join(state_dir, "init.sls"), init)

    # top.sls (state)
    top = HEADER.format(**meta)
    top += ("base:\n"
            "  # Target your PCI in-scope SUSE clients here (grain/group match).\n"
            "  'G@os_family:Suse and G@pci_scope:true':\n"
            "    - match: compound\n"
            "    - pci_dss\n")
    write(os.path.join(base, "top.sls"), top)

    # pillar
    pbase = os.path.join(outdir, "srv", "pillar")
    ptop = ("base:\n  'G@os_family:Suse and G@pci_scope:true':\n"
            "    - match: compound\n    - pci_dss\n")
    write(os.path.join(pbase, "top.sls"), ptop)
    pil = HEADER.format(**meta)
    pil += "pci_dss:\n  enabled: True\n"
    for c in used_cats:
        pil += f"  {c}: True\n"
    write(os.path.join(pbase, "pci_dss.sls"), pil)

    # verify / scan scripts
    emit_verify(state_dir, src, profile_id, meta)
    # MLM (Uyuni / SUSE Multi-Linux Manager) formula-with-form metadata
    emit_formula(outdir, meta, used_cats, mac)

    # reports
    emit_unmapped(state_dir, unmapped, meta, profile_id)
    emit_na(state_dir, na, meta, mac)
    emit_readme(state_dir, meta, mapped, unmapped, na, used_cats, mac)
    return state_dir, used_cats


def emit_apparmor_mac(state_dir, meta, na_mac):
    refs = sorted({x for r in na_mac for x in r.pci_refs()})
    covered = ", ".join(r.short for r in na_mac)
    body = HEADER.format(**meta)
    body += ("# AppArmor MAC equivalence (target uses AppArmor, not SELinux).\n"
             f"# Satisfies the control intent of: {covered}\n"
             f"# PCI-DSS: {', '.join(refs) or '-'}\n\n"
             "{%- set p = salt['pillar.get']('pci_dss', {}) %}\n"
             "{%- if p.get('enabled', True) and p.get('mac', True) %}\n\n"
             "apparmor_packages:\n  pkg.installed:\n    - pkgs:\n"
             "        - apparmor-parser\n        - apparmor-profiles\n        - apparmor-utils\n\n"
             "apparmor_service:\n  service.running:\n    - name: apparmor\n    - enable: True\n"
             "    - require:\n      - pkg: apparmor_packages\n\n"
             "# Equivalent of grub2_enable_selinux: ensure the MAC is enabled at boot.\n"
             "apparmor_grub_cmdline:\n  file.replace:\n    - name: /etc/default/grub\n"
             "    - pattern: '^(GRUB_CMDLINE_LINUX=\")(?![^\"]*security=)(.*)\"$'\n"
             "    - repl: '\\g<1>security=apparmor \\g<2>\"'\n    - append_if_not_found: False\n\n"
             "grub2_mkconfig:\n  cmd.run:\n    - name: grub2-mkconfig -o /boot/grub2/grub.cfg\n"
             "    - onchanges:\n      - file: apparmor_grub_cmdline\n\n"
             "# Equivalent of selinux_state=enforcing: put all profiles in enforce mode.\n"
             "apparmor_enforce_all:\n  cmd.run:\n"
             "    - name: aa-enforce /etc/apparmor.d/*\n"
             "    - onchanges:\n      - service: apparmor_service\n\n"
             "# Equivalent of audit_rules_mac_modification_etc_selinux: audit MAC config edits.\n"
             "apparmor_audit_config:\n  file.managed:\n"
             "    - name: /etc/audit/rules.d/pci-mac-apparmor.rules\n    - mode: \"0640\"\n"
             "    - contents:\n        - -w /etc/apparmor.d/ -p wa -k MAC-policy\n"
             "        - -w /etc/apparmor/ -p wa -k MAC-policy\n\n"
             "{%- endif %}\n")
    write(os.path.join(state_dir, "mac.sls"), body)

    eq = [f"# MAC equivalence — AppArmor target\n",
          f"Generated {meta['ts']}.\n",
          "The PCI-DSS baseline expresses Mandatory Access Control via SELinux rules. "
          "This target runs **AppArmor** (SLE/Leap 15), so those rules are Not Applicable; "
          "`mac.sls` enforces the same control intent with AppArmor.\n",
          "| SELinux rule (N/A here) | AppArmor equivalent | PCI |",
          "|---|---|---|"]
    rowmap = {
        "selinux_state": "all profiles set to enforce (`aa-enforce`)",
        "selinux_policytype": "apparmor-profiles package providing the policy set",
        "selinux_confinement_of_daemons": "apparmor service active + profiles enforced",
        "grub2_enable_selinux": "`security=apparmor` on the kernel cmdline",
        "package_libselinux_installed": "apparmor-parser / apparmor-utils packages",
        "audit_rules_mac_modification_etc_selinux": "audit watch on /etc/apparmor.d",
    }
    for r in sorted(na_mac, key=lambda x: x.short):
        eq.append(f"| `{r.short}` | {rowmap.get(r.short, 'apparmor MAC enforcement')} "
                  f"| {', '.join(r.pci_refs()) or '-'} |")
    write(os.path.join(state_dir, "MAC_EQUIVALENCE.md"), "\n".join(eq) + "\n")


def emit_na(state_dir, na, meta, mac):
    if not na:
        return
    lines = [f"# Not-applicable rules ({mac} target)", "",
             f"Generated {meta['ts']}.", "",
             f"{len(na)} selected rule(s) are not applicable to this target's MAC "
             f"framework ({mac}). Where the control intent still matters (enforce a MAC), "
             "it is covered by `mac.sls` / `MAC_EQUIVALENCE.md`.", ""]
    for r in sorted(na, key=lambda x: x.short):
        lines.append(f"- `{r.short}` — {r.title} (PCI {', '.join(r.pci_refs()) or '-'})")
    write(os.path.join(state_dir, "SKIPPED_NA.md"), "\n".join(lines) + "\n")


def emit_report(outdir, meta, mapped, unmapped, na, mac, n_selected):
    """Dry-run: write a single coverage report, no state files."""
    from collections import Counter
    applicable = len(mapped) + len(unmapped)
    pct = 100 * len(mapped) // max(applicable, 1)
    by_cat = Counter(s.category for s in mapped)
    ops = [s for s in mapped if getattr(s, "operational", False)]

    L = [f"# PCI-DSS coverage report (dry run)", "",
         f"- Datastream: `{meta['src']}`",
         f"- Profile: `{meta['prof']}`",
         f"- MAC framework: `{mac}`",
         f"- Generated: {meta['ts']}", "",
         f"**Selected:** {n_selected}  |  **Applicable:** {applicable}  |  "
         f"**N/A ({mac}):** {len(na)}", "",
         f"**Native coverage: {len(mapped)}/{applicable} ({pct}%)** "
         f"— of which {len(ops)} guarded operational state(s).", "",
         "## Mapped by category", "", "| Category | Rules |", "|---|---|"]
    for cat in CATEGORIES:
        if by_cat.get(cat):
            L.append(f"| {CAT_LABELS.get(cat, cat)} | {by_cat[cat]} |")

    if ops:
        L += ["", f"## Guarded operational states ({len(ops)})",
              "_Imperative remediations (no declarative Salt primitive); "
              "idempotent via creates/onlyif/unless._", ""]
        for s in sorted(ops, key=lambda x: x.rule.short):
            L.append(f"- `{s.rule.short}` ({', '.join(s.rule.pci_refs()) or '-'})")

    L += ["", f"## Unmapped ({len(unmapped)})",
          "_No native handler — add a mapper or handle via a reviewed state._", ""]
    fam = {}
    for r in unmapped:
        fam.setdefault(r.short.split("_")[0], []).append(r)
    for k in sorted(fam):
        L.append(f"### {k}_* ({len(fam[k])})")
        for r in sorted(fam[k], key=lambda x: x.short):
            L.append(f"- `{r.short}` — {r.title} (PCI {', '.join(r.pci_refs()) or '-'}; sev {r.severity})")
        L.append("")

    L += [f"## Not applicable — {mac} ({len(na)})",
          "_Covered by the MAC equivalence set where the control intent still applies._", ""]
    for r in sorted(na, key=lambda x: x.short):
        L.append(f"- `{r.short}` — {r.title} (PCI {', '.join(r.pci_refs()) or '-'})")

    path = os.path.join(outdir, "coverage-report.md")
    write(path, "\n".join(L) + "\n")
    return path


CAT_LABELS = {
    "sysctl": "Kernel parameters (sysctl)",
    "packages": "Package install / removal",
    "services": "Service enable / disable",
    "permissions": "File permissions & ownership",
    "kernel_modules": "Disabled kernel modules",
    "sshd": "SSH server hardening",
    "lineinfile": "Config-file settings (login.defs, securetty, etc.)",
    "pam": "PAM module arguments (pwquality, pam_unix, pam_wheel)",
    "sudo": "sudo Defaults (sudoers.d drop-ins)",
    "audit": "Audit (auditd rules + auditd.conf)",
    "dconf": "GNOME desktop (dconf) policy",
    "coredump": "systemd core dump policy",
    "grub": "GRUB kernel command-line arguments",
    "aide": "File integrity (AIDE)",
    "rpm": "Package signatures & verification (RPM/GPG)",
    "mounts": "Filesystem mount options",
    "mac": "Mandatory Access Control (SELinux / AppArmor)",
    "misc": "Miscellaneous",
}


def emit_formula(outdir, meta, used_cats, mac):
    """Write Uyuni / SUSE Multi-Linux Manager 'formula with form' metadata so the
    pillar toggles render as checkboxes in the Web UI (Formulas tab)."""
    fdir = os.path.join(outdir, "srv", "formula_metadata", "pci_dss")
    # form.yml: a 'pci_dss' group whose members become pillar pci_dss:{...}
    form = ["# Generated by scap2salt — renders in the MLM Web UI 'Formulas' tab.",
            "pci_dss:",
            "  $type: group",
            "  $name: PCI-DSS v4 Hardening",
            f"  $help: 'Native Salt enforcement generated from {meta['prof']} "
            f"(MAC: {mac}). Untick a category to skip it.'",
            "  enabled:",
            "    $type: boolean",
            "    $default: True",
            "    $name: Enable PCI-DSS hardening"]
    for c in used_cats:
        form += [f"  {c}:",
                 "    $type: boolean",
                 "    $default: True",
                 f"    $name: \"{CAT_LABELS.get(c, c)}\""]
    write(os.path.join(fdir, "form.yml"), "\n".join(form) + "\n")

    metadata = (f'description: "PCI-DSS v4 hardening generated from {meta["prof"]} '
                f'(MAC: {mac})"\n'
                "group: Security & Compliance\n"
                "after: []\n")
    write(os.path.join(fdir, "metadata.yml"), metadata)


def emit_verify(state_dir, src, profile_id, meta):
    d = os.path.join(state_dir, "_verify")
    ds = os.path.basename(src)
    scan = f"""#!/bin/sh
# oscap evaluation: produces an HTML + ARF report WITHOUT changing the system.
set -eu
DS="${{1:-/usr/share/xml/scap/ssg/content/{ds}}}"
PROFILE="{profile_id}"
OUT="${{2:-/var/log/pci_dss-scan}}"
mkdir -p "$OUT"
oscap xccdf eval \\
  --profile "$PROFILE" \\
  --results-arf "$OUT/arf.xml" \\
  --report "$OUT/report.html" \\
  "$DS" || true   # non-zero exit == some rules failed; report is still written
echo "Report: $OUT/report.html"
"""
    sverify = """#!/bin/sh
# Dry-run the generated Salt states: shows drift without applying.
set -eu
salt-call --local state.apply pci_dss test=True
"""
    remediate = f"""#!/bin/sh
# Cross-check / fallback: let oscap remediate directly (independent of Salt).
# Use only to compare against the Salt result, not as the primary path.
set -eu
DS="${{1:-/usr/share/xml/scap/ssg/content/{ds}}}"
oscap xccdf eval --profile "{profile_id}" --remediate \\
  --results-arf /var/log/pci_dss-remediate-arf.xml "$DS" || true
"""
    write(os.path.join(d, "oscap_scan.sh"), scan)
    write(os.path.join(d, "salt_verify.sh"), sverify)
    write(os.path.join(d, "oscap_remediate.sh"), remediate)
    for f in ("oscap_scan.sh", "salt_verify.sh", "oscap_remediate.sh"):
        os.chmod(os.path.join(d, f), 0o755)


def emit_unmapped(state_dir, unmapped, meta, profile_id):
    lines = [f"# Unmapped rules — {profile_id}", "",
             f"Generated {meta['ts']} from `{meta['src']}`.", "",
             f"{len(unmapped)} selected rule(s) have **no native Salt handler** and were "
             "skipped (native-only mode). Add a mapper in `scap2salt.py` or handle these "
             "via a separate reviewed state.", ""]
    by_fam = {}
    for r in unmapped:
        fam = r.short.split("_")[0]
        by_fam.setdefault(fam, []).append(r)
    for fam in sorted(by_fam):
        lines.append(f"## {fam}* ({len(by_fam[fam])})")
        for r in sorted(by_fam[fam], key=lambda x: x.short):
            pci = ", ".join(r.pci_refs()) or "-"
            lines.append(f"- `{r.short}` — {r.title} (PCI {pci}; sev {r.severity})")
        lines.append("")
    write(os.path.join(state_dir, "UNMAPPED.md"), "\n".join(lines))


def emit_readme(state_dir, meta, mapped, unmapped, na, cats, mac):
    total = len(mapped) + len(unmapped)  # N/A rules excluded from the denominator
    pct = (100 * len(mapped) / total) if total else 0
    txt = f"""# PCI-DSS Salt states (generated)

Source datastream: `{meta['src']}`
Profile: `{meta['prof']}`
MAC framework: `{mac}`
Generated: {meta['ts']}

Coverage: **{len(mapped)}/{total}** applicable rules mapped to native Salt ({pct:.0f}%).
{len(unmapped)} unmapped (`UNMAPPED.md`); {len(na)} not applicable to this MAC (`SKIPPED_NA.md`{', equivalence in `MAC_EQUIVALENCE.md`' if mac == 'apparmor' and na else ''}).

## Layout
- `init.sls` — includes every category below
- categories: {', '.join(cats)}
- `_verify/oscap_scan.sh` — read-only oscap report
- `_verify/salt_verify.sh` — `state.apply test=True` drift check
- `_verify/oscap_remediate.sh` — independent oscap remediation (cross-check)

## Deploy on Multi-Linux Manager
1. Copy `srv/salt/pci_dss/` and `srv/salt/top.sls` into the Salt state tree
   (the MLM/Uyuni server's `/srv/salt`), and the pillar files into `/srv/pillar`.
2. Tag in-scope clients: `salt '<minion>' grains.setval pci_scope true`.
3. Dry run:   `_verify/salt_verify.sh`
4. Apply:     `salt -C 'G@pci_scope:true' state.apply pci_dss`
5. Verify:    `_verify/oscap_scan.sh` and review `report.html`.

Toggle whole categories via pillar `pci_dss:{{category}}: False`.

## Use as an MLM 'formula with form' (Web UI toggles)
1. Copy `srv/salt/pci_dss/` to `/srv/salt/pci_dss/` and
   `srv/formula_metadata/pci_dss/` to `/srv/formula_metadata/pci_dss/` on the
   MLM/Uyuni server.
2. In the Web UI the formula **PCI-DSS v4 Hardening** appears under a system's or
   group's *Formulas* tab. Tick it, then use the generated *PCI-DSS v4 Hardening*
   sub-tab to toggle categories (these write the `pci_dss:` pillar consumed by the
   states). Save, then apply the highstate.
"""
    write(os.path.join(state_dir, "README.md"), txt)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Generate native Salt states from a SCAP datastream.")
    ap.add_argument("--target", default="sle15", help="SSG product id (default: sle15)")
    ap.add_argument("--profile", default="pci-dss-4",
                    help="XCCDF profile id (short or full). Default: pci-dss-4")
    ap.add_argument("--datastream", help="Path to an existing ssg-*-ds.xml (skips download)")
    ap.add_argument("--out", default="./out", help="Output directory (default: ./out)")
    ap.add_argument("--cache", default="./.cache", help="Download cache dir")
    ap.add_argument("--mac", choices=["selinux", "apparmor"],
                    help="MAC framework of the target (default: inferred from --target)")
    ap.add_argument("--report-only", action="store_true",
                    help="Dry run: classify rules and write only a coverage report (no state tree)")
    args = ap.parse_args()

    CONFIG["mac"] = args.mac or mac_for_target(args.target)
    print(f"[*] Target {args.target}: MAC framework = {CONFIG['mac']}")

    ds = acquire_datastream(args.target, args.datastream, args.cache)
    bench = load_benchmark(ds)
    XCCDF_VALUES.update(load_values(bench))
    profile_id, selected = resolve_profile(bench, args.profile)
    rules = index_rules(bench)
    print(f"[*] Profile {profile_id}: {len(selected)} selected rules")

    mapped, unmapped, na = [], [], []
    for rid in sorted(selected):
        el = rules.get(rid)
        if el is None:
            continue
        ri = RuleInfo(rid, el)
        st = map_rule(ri)
        if st == "NA":
            na.append(ri)
        elif st:
            mapped.append(st)
        else:
            unmapped.append(ri)

    applicable = len(mapped) + len(unmapped)
    ops = sum(1 for s in mapped if getattr(s, "operational", False))

    if args.report_only:
        meta = dict(src=os.path.basename(ds), prof=profile_id,
                    ts=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        path = emit_report(args.out, meta, mapped, unmapped, na, CONFIG["mac"], len(selected))
        print(f"[*] Coverage: {len(mapped)}/{applicable} applicable mapped "
              f"({100*len(mapped)//max(applicable,1)}%); {ops} operational; "
              f"{len(unmapped)} unmapped; {len(na)} N/A ({CONFIG['mac']})")
        print(f"[*] Report written: {path}  (no state files — dry run)")
        return

    state_dir, cats = emit_tree(args.out, ds, profile_id, mapped, unmapped, na, CONFIG["mac"])
    print(f"[*] Mapped {len(mapped)}/{applicable} applicable rules to native Salt "
          f"({100*len(mapped)//max(applicable,1)}%) across: {', '.join(cats)}")
    if ops:
        print(f"[*] of which {ops} are guarded operational states (cmd.run + creates/onlyif/unless)")
    print(f"[*] {len(unmapped)} unmapped -> UNMAPPED.md ; "
          f"{len(na)} not-applicable ({CONFIG['mac']}) -> SKIPPED_NA.md")
    print(f"[*] Output tree: {os.path.join(args.out, 'srv')}")


if __name__ == "__main__":
    main()
