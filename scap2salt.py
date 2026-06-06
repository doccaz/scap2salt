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
import shutil
import subprocess
import sys
import tarfile
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
    """Return (pid, selected rule idrefs, {value_id: selector}) for a profile,
    resolving 'extends' for both <select> and <refine-value>."""
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
    refinements = {}

    def apply(p):
        parent = p.get("extends")
        if parent and parent in profiles:
            apply(profiles[parent])
        for sel in p:
            tag = ln(sel)
            if tag == "select":
                ref = sel.get("idref")
                if sel.get("selected", "false") == "true":
                    selected.add(ref)
                else:
                    selected.discard(ref)
            elif tag == "refine-value":
                ref, selector = sel.get("idref"), sel.get("selector")
                if ref and selector:
                    refinements[ref] = selector

    apply(profiles[pid])
    return pid, selected, refinements


def load_values(bench, refinements=None):
    """Return a dict of XCCDF Value id -> resolved value string (for <sub>).

    When the chosen profile refines a value (`<refine-value selector="...">`),
    use the matching `<value selector="...">`; otherwise fall back to the
    no-selector default. Without this, profile-tuned values (e.g. pci-dss-4 sets
    var_password_pam_minlen=12, var_auditd_name_format=fqd) silently use the
    benchmark default instead, producing states the profile's own checks reject."""
    refinements = refinements or {}
    out = {}
    for el in bench.iter():
        if ln(el) != "Value":
            continue
        vid = el.get("id")
        if not vid:
            continue
        wanted = refinements.get(vid)
        default = refined = None
        for child in el:
            if ln(child) != "value" or child.text is None:
                continue
            csel = child.get("selector")
            if wanted is not None and csel == wanted:
                refined = child.text.strip()
            elif not csel:
                default = child.text.strip()
        chosen = refined if refined is not None else default
        if chosen is not None:
            out[vid] = chosen
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
    __slots__ = ("id", "short", "title", "severity", "refs", "bash", "desc", "has_fix")

    def __init__(self, rid, el):
        self.id = rid
        self.short = re.sub(r"^xccdf_org\.ssgproject\.content_rule_", "", rid)
        self.title = text_of(el, "title") or self.short
        self.severity = el.get("severity", "unknown")
        self.refs = []
        self.bash = None
        self.has_fix = False   # True if the rule ships ANY <fix> (sh or other)
        self.desc = text_of(el, "description") or ""
        for c in el:
            if ln(c) == "reference":
                href = c.get("href", "")
                txt = (c.text or "").strip()
                if "pci" in href.lower() or "pci" in txt.lower() or txt:
                    self.refs.append((txt, href))
            elif ln(c) == "fix":
                self.has_fix = True
                if c.get("system", "").endswith("script:sh"):
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
    if s == "" or "\n" in s or re.search(r"[:#{}\[\],&*?|<>=!%@`\"']", s) or s != s.strip():
        return ('"' + s.replace("\\", "\\\\").replace('"', '\\"')
                .replace("\n", "\\n") + '"')
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
    val = shell_resolve(val, r.bash or "").split("|")[0].strip()
    conf = "/etc/sysctl.d/" + key.replace(".", "_") + ".conf"
    st = SaltState(
        f"sysctl_{key}", "sysctl.present",
        [("name", key), ("value", val), ("config", conf)],
        "sysctl", r,
    )
    # net.ipv4.ip_forward=0 does not persist on firewalld hosts: firewalld 1.0+
    # enables intra-zone forwarding by default and flips ip_forward back to 1 at
    # boot, AFTER systemd-sysctl applies our 0. Also disable firewalld forwarding
    # on the default zone so the hardened value survives a reboot. Guarded so it
    # only acts when firewalld is active and forwarding is currently on.
    if key == "net.ipv4.ip_forward" and val == "0":
        st.extra_states.append((
            "firewalld_disable_forwarding", "cmd.run",
            [("name", 'zone="$(firewall-cmd --get-default-zone)"; '
                      'firewall-cmd --permanent --zone="$zone" --remove-forward '
                      '&& firewall-cmd --reload'),
             ("onlyif", ["systemctl is-active --quiet firewalld",
                         "firewall-cmd --query-forward"])],
        ))
    return st


def _pkg_name_from_bash(bash, action):
    """The real package name lives in the fix's zypper command and can differ
    from the rule id (e.g. package_libselinux_installed -> libselinux1 on SLE16)."""
    verb = "install" if action == "installed" else "remove"
    m = re.search(rf'zypper\s+(?:-\S+\s+)*{verb}\s+(?:-\S+\s+)*["\']([A-Za-z0-9][\w.+-]*)["\']',
                  bash or "")
    return m.group(1) if m else None


@mapper
def m_package(r):
    m = re.match(r"^package_(.+)_(installed|removed)$", r.short)
    if not m:
        return None
    pkg, action = m.group(1), m.group(2)
    # State ID stays keyed on the (unique) rule id; the installed/removed package
    # name comes from the fix bash, which is authoritative (e.g. libselinux ->
    # libselinux1). Two rules can resolve to the same package, so deriving the ID
    # from the name would collide — keep them distinct.
    name = _pkg_name_from_bash(r.bash, action) or pkg
    if action == "installed":
        return SaltState(f"pkg_present_{pkg}", "pkg.installed", [("name", name)], "packages", r)
    return SaltState(f"pkg_absent_{pkg}", "pkg.removed", [("name", name)], "packages", r)


@mapper
def m_service(r):
    m = re.match(r"^service_(.+)_(enabled|disabled)$", r.short)
    if not m:
        return None
    svc, action = m.group(1), m.group(2)
    if svc == "chronyd_or_ntpd":
        svc = "chronyd"
    if action == "enabled":
        return SaltState(f"svc_on_{svc}", "service.running",
                         [("name", svc), ("enable", True)], "services", r)
    return SaltState(f"svc_off_{svc}", "service.dead",
                     [("name", svc), ("enable", False)], "services", r)


def _symbolic_mode_max(spec):
    """Translate a relative symbolic chmod spec (e.g. 'u-xs,g-xws,o-xwrt') into
    the maximum octal mode it permits: 0o7777 with every removed bit cleared.

    CaC's file_permissions_* fixes use such specs — they only *clear* the
    disallowed bits, never set an absolute mode. The matching OVAL check passes
    for any mode lacking those bits, so the loosest compliant mode is the right
    declarative target (and tightens the currently-failing, too-permissive
    files). Returns a 4-digit octal string, or None if it can't be parsed."""
    WHO = {
        "u": {"r": 0o400, "w": 0o200, "x": 0o100, "s": 0o4000, "t": 0},
        "g": {"r": 0o040, "w": 0o020, "x": 0o010, "s": 0o2000, "t": 0},
        "o": {"r": 0o004, "w": 0o002, "x": 0o001, "s": 0, "t": 0o1000},
    }
    mode = 0o7777
    for clause in spec.split(","):
        m = re.match(r"^([ugoa]+)([-+=])([rwxst]+)$", clause.strip())
        if not m:
            return None
        whos, op, perms = m.group(1), m.group(2), m.group(3)
        whos = "ugo" if "a" in whos else whos
        bits = 0
        for w in whos:
            for p in perms:
                bits |= WHO[w].get(p, 0)
        if op == "-":
            mode &= ~bits
        elif op == "+":
            mode |= bits
        else:  # '=' : set exactly for the named scope(s)
            for w in whos:
                mode &= ~sum(WHO[w].values())
            mode |= bits
    return format(mode & 0o7777, "04o")


# Files whose OVAL requires mode 0000 on SLE (root accesses them via
# capabilities). CaC's generic relative chmod only reaches 0640 for these.
_PERMS_ZERO_MODE = frozenset({"/etc/shadow", "/etc/shadow-",
                              "/etc/gshadow", "/etc/gshadow-"})


@mapper
def m_file_perms(r):
    if not r.short.startswith(("file_permissions_", "file_owner_", "file_groupowner_")):
        # file_*_not_exist rules: ensure file is absent
        if r.short.startswith("file_") and r.short.endswith("_not_exist"):
            bash = r.bash or ""
            rm_m = re.search(r'rm\s+(?:-\S+\s+)*["\']?(/[^\s"\'\\]+)', bash)
            if rm_m:
                p = rm_m.group(1)
                return SaltState(f"file_absent_{re.sub(r'[^A-Za-z0-9]', '_', r.short)}",
                                 "file.absent", [("name", p)], "permissions", r)
        return None
    bash = r.bash or ""
    mode = own = grp = path = None

    # Numeric chmod: chmod [flags] NNNN /path
    mm = re.search(r"chmod\s+(?:-\S+\s+)*([0-7]{3,4})\s+['\"]?(/[^\s'\"]+)", bash)
    if mm:
        mode, path = mm.group(1), mm.group(2)

    # Symbolic chmod: chmod [flags] u-xs,g-xws,... /path  (relative spec -> max octal)
    if not path:
        ms = re.search(r"chmod\s+(?:-\S+\s+)*([ugoa][-+=][^\s]+)\s+['\"]?(/[^\s'\"\\]+)", bash)
        if ms:
            path = ms.group(2)
            mode = mode or _symbolic_mode_max(ms.group(1))

    # find-exec chmod on a single target: find /dir -maxdepth 0 ... -exec chmod MODE {} \;
    # A find WITHOUT -maxdepth 0 is a filesystem-wide sweep (e.g. world-writable /
    # suid hunts that loop over partitions) — it has no safe declarative form and
    # must not be collapsed to a single file.directory (that would, e.g., set /tmp
    # to a bogus mode). Leave such sweeps unmapped.
    if not path and "chmod" in bash and "-maxdepth 0" in bash:
        mf = re.search(r'find\s+(?:-\S+\s+)*(/[^\s]+).*-exec\s+chmod', bash, re.DOTALL)
        if mf:
            path = mf.group(1).rstrip("/")
            em = re.search(r'-exec\s+chmod\s+(?:-\S+\s+)*(\S+)', bash)
            if em:
                spec = em.group(1)
                mode = mode or (spec if re.fullmatch(r"[0-7]{3,4}", spec)
                                else _symbolic_mode_max(spec))

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
    # Detect directory paths: trailing slash from bash or known directory set.
    _DIR_PATHS = frozenset({
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.monthly", "/etc/cron.weekly",
        "/etc/ssh",   # sshd_pub_key rule targets the dir via find -exec chmod
    })
    is_dir = path.endswith("/") or path.rstrip("/") in _DIR_PATHS
    path = path.rstrip("/")
    # Shadow-family files must be 0000 on SLE (root reads via capabilities) — the
    # OVAL requires it. CaC's generic relative chmod only yields 0640, which both
    # fails the check and would loosen the secure default; force 0000. Documented
    # deviation; see README "Deviations from upstream CaC".
    if r.short.startswith("file_permissions_") and path in _PERMS_ZERO_MODE:
        mode = "0000"
    func = "file.directory" if is_dir else "file.managed"
    args = [("name", path)]
    if mode:
        # file.directory ignores `mode`; the directory's own mode is `dir_mode`.
        args.append(("dir_mode" if is_dir else "mode", mode))
    if own:
        args.append(("user", own))
    if grp:
        args.append(("group", grp))
    if not is_dir:
        args.append(("replace", False))  # enforce metadata only, never clobber content
        args.append(("create", False))   # only fix perms of an existing file; never
                                         # create an empty one (e.g. /etc/ssh/sshd_config
                                         # is shipped in /usr/etc on SLE16 — creating an
                                         # empty /etc copy would shadow it and disable all
                                         # sshd drop-ins)
    return SaltState(f"file_meta_{re.sub(r'[^A-Za-z0-9]', '_', r.short)}",
                     func, args, "permissions", r)


@mapper
def m_var_log_perms(r):
    """permissions_local_var_log: clear exec/setuid/setgid/group-write/other bits
    from files under /var/log. CaC uses a relative `find ... -exec chmod` sweep
    over the tree (no -maxdepth 0), which has no declarative Salt primitive, so
    emit a guarded operational cmd.run mirroring it (idempotent via onlyif)."""
    if r.short != "permissions_local_var_log":
        return None
    find_sel = "find /var/log/ -perm /u+xs,g+xws,o+xwrt -type f"
    st = SaltState(
        "permissions_local_var_log", "cmd.run",
        [("name", f"{find_sel} -exec chmod u-xs,g-xws,o-xwrt {{}} +"),
         ("onlyif", f'test -n "$({find_sel} -print -quit 2>/dev/null)"')],
        "permissions", r,
    )
    st.operational = True
    return st


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
    # Resolve any $var_* / $sshd_* references in the value (CaC assigns them
    # earlier in the same fix script, e.g. sshd_idle_timeout_value='300').
    if "$" in value:
        value = shell_resolve(value, bash)
    if "$" in value:
        fo = _resolve_formatted_output(bash)
        if fo and " " in fo:
            value = fo.split(None, 1)[1]
        else:
            return None  # unresolved value -> don't write a broken literal
    return SaltState(
        f"sshd_{directive}", "file.replace",
        [("name", SSHD_DROPIN),
         ("pattern", f"^{re.escape(directive)}\\s.*$"),
         ("repl", f"{directive} {value}"),
         ("append_if_not_found", True)],
        "sshd", r,
    )


def _resolve_formatted_output(bash):
    """Resolve CaC's printf-v formatted_output idiom to a plain 'KEY value' string.

    The idiom:
        printf -v formatted_output "%s %s" "$stripped_key" "$var_xxx"
        LC_ALL=C sed -i ... "s/^KEYNAME\\>.../$escaped_formatted_output/..." /path
        printf '%s\\n' "$formatted_output" >> /path

    stripped_key is derived at runtime from the file; the actual key name appears
    in the sed expression. The value is the last argument to printf -v and is
    resolvable via shell_resolve() because resolve_fix_bash() has already
    substituted XCCDF values into $var_* assignments.
    """
    key_m = re.search(r'"s/\^\\?([A-Z][A-Z_0-9]+)', bash)
    if not key_m:
        return None
    key = key_m.group(1)
    pfv_m = re.search(r'printf\s+-v\s+formatted_output\s+"[^"]*"\s+"[^"]*"\s+"(\$[^"]+)"', bash)
    if not pfv_m:
        return None
    val = shell_resolve(pfv_m.group(1), bash)
    if "$" in val:
        return None
    return f"{key} {val}"


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
    # Resolve any shell variable references in the captured line.
    if "$" in line:
        line = shell_resolve(line, bash)
    # CaC's printf-v formatted_output idiom: $formatted_output can't be
    # resolved by shell_resolve() because it uses 'printf -v', not '='.
    # Fall back to the sed-key extractor.
    if "$" in line:
        line = _resolve_formatted_output(bash)
        if line is None:
            return None
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
         ("append_if_not_found", True)],
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
    bash = r.bash or ""
    # Accept the audit_* family, plus any rule built from the audit rules.d macro
    # (e.g. directory_access_var_log_audit, whose id is in the directory_* family).
    if not (r.short.startswith(("audit_rules_", "audit_"))
            or "rules.d" in bash and ("OTHER_FILTERS=" in bash or "SYSCALL=" in bash)):
        return None

    # Special case: make the auditd config immutable. '-e 2' must be the LAST
    # rule augenrules loads, so name the fragment to sort after the others.
    if r.short == "audit_rules_immutable":
        st = SaltState(
            "audit_frag_immutable", "file.managed",
            [("name", "/etc/audit/rules.d/zz-pci-immutable.rules"),
             ("mode", "0640"),
             ("contents", ["# Set the audit configuration immutable (scap2salt)",
                           "-e 2"])],
            "audit", r,
        )
        st.audit_fragment = True
        return st

    # Special case: enable syscall auditing by disabling the '-a task,never' rule.
    # This edits existing fragments, so it is an idempotent operational state.
    if r.short == "audit_rules_enable_syscall_auditing":
        st = SaltState(
            "audit_enable_syscall", "cmd.run",
            [("name", "sed -ri 's/^([[:space:]]*-a[[:space:]]+task,never)/#\\1/' "
                      "/etc/audit/rules.d/*.rules"),
             ("onlyif", "grep -rqE '^[[:space:]]*-a[[:space:]]+task,never' "
                        "/etc/audit/rules.d/")],
            "audit", r,
        )
        st.operational = True
        return st

    lines = []
    # 1) literal -w/-a rules written via the standard printf idiom (clean)
    for lit in re.findall(r"""printf\s+'%s\\n'\s+"([^"]+)" """.strip(), bash):
        if lit.startswith(("-w ", "-a ")):
            lines.append(lit.strip())
    # 1b) -w/-a rules written via 'echo "..." >>' (resolve any $var in the path/key)
    for lit in re.findall(r'echo\s+"(-[wa]\s[^"]+)"\s*>>', bash):
        lines.append(shell_resolve(lit, bash).strip())
    # 1c) any remaining bare watch rules (strip stray trailing quote)
    for w in re.findall(r"(-w\s+/\S+\s+-p\s+\S+(?:\s+-k\s+[^\s\"']+)?)", bash):
        w = w.strip().rstrip('"\'')
        if w not in lines:
            lines.append(w)
    # 2) syscall / file-filter rules reconstructed from the literal assignments
    def grab(name):
        mm = re.search(rf'{name}="([^"]*)"', bash)
        return mm.group(1).strip() if mm else ""
    syscall = grab("SYSCALL")
    key = grab("KEY")
    auid = grab("AUID_FILTERS")
    other = grab("OTHER_FILTERS")
    # Emit when there are syscalls OR a non-syscall filter (e.g. -F dir=... watch).
    if syscall or other:
        for arch in ("b32", "b64"):
            # Match CaC's canonical field order exactly — the audit OVAL checks the
            # rules.d file textually and is order-sensitive:
            #   -a always,exit -F arch=ARCH -S SYSCALL(s) OTHER_FILTERS AUID -F key=KEY
            parts = [f"-a always,exit -F arch={arch}"]
            parts += [f"-S {s}" for s in syscall.split()]
            if other:
                parts.append(other)
            if auid:
                parts.append(auid)
            if key:
                parts.append(f"-F key={key}")
            lines.append(" ".join(parts))
    if not lines:
        return None
    lines = list(dict.fromkeys(lines))
    # stime (sys_stime) was removed from x86_64 in Linux 5.x; strip it from b64
    # rules so augenrules --load does not fail on modern kernels.  b32 rules keep
    # it for 32-bit compatibility.
    _B64_DROPPED = frozenset({"stime"})
    cleaned = []
    for line in lines:
        if "arch=b64" in line and any(f"-S {sc}" in line for sc in _B64_DROPPED):
            for sc in _B64_DROPPED:
                line = re.sub(rf'\s*-S\s+{re.escape(sc)}\b', '', line).strip()
            if re.fullmatch(r'-a always,exit -F arch=b64(\s+-F key=\S+)?', line):
                continue  # nothing left but the action header — drop entirely
        cleaned.append(line)
    lines = cleaned
    if not lines:
        return None
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
            [("name", f"rpm -qa | xargs -r -n1 rpm {flag} 2>/dev/null || true")],
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
         ("append_if_not_found", True)],
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
    servers = [x.strip() for x in sm.group(1).split(",") if x.strip()] or ["pool.ntp.org"]
    add = "\n".join(f"server {srv}" for srv in servers)
    # CaC's fix only acts when NO server/pool line exists: it appends the
    # configured servers. Mirror that exactly. The pattern matches any existing
    # server/pool line and `repl: \g<0>` rewrites it to itself — so existing
    # lines are left untouched (idempotent; we never clobber an admin's NTP
    # config), and `not_found_content` is appended only when none is present.
    return SaltState(
        "chrony_remote_server", "file.replace",
        [("name", conf),
         ("pattern", r"^\s*(server|pool)\s+\S+"),
         ("repl", r"\g<0>"),
         ("append_if_not_found", True),
         ("not_found_content", add)],
        "lineinfile", r,
    )


@mapper
def m_chronyd_user(r):
    """Run chronyd under the chrony user via /etc/sysconfig/chronyd OPTIONS."""
    if r.short != "chronyd_run_as_chrony_user":
        return None
    return SaltState(
        "chronyd_run_as_chrony", "file.replace",
        [("name", "/etc/sysconfig/chronyd"),
         ("pattern", "^OPTIONS=.*$"),
         ("repl", 'OPTIONS="-u chrony"'),
         ("append_if_not_found", True)],
        "lineinfile", r,
    )


@mapper
def m_libuser_hash(r):
    """Password hashing algorithm in /etc/libuser.conf [defaults] crypt_style."""
    if r.short != "set_password_hashing_algorithm_libuserconf":
        return None
    vm = re.search(r"var_password_hashing_algorithm_pam='([^']*)'", r.bash or "")
    alg = (vm.group(1).split("|")[0] if vm else "sha512")
    # SUSE's stock libuser.conf ships a [defaults] section with crypt_style.
    return SaltState(
        "libuser_crypt_style", "file.replace",
        [("name", "/etc/libuser.conf"),
         ("pattern", "^\\s*crypt_style\\s*=.*$"),
         ("repl", f"crypt_style = {alg}"),
         ("append_if_not_found", False),
         ("onlyif", "test -f /etc/libuser.conf")],
        "lineinfile", r,
    )


@mapper
def m_timer(r):
    """timer_<unit>_enabled -> enable the corresponding systemd .timer."""
    m = re.match(r"^timer_(.+)_enabled$", r.short)
    if not m:
        return None
    unit = m.group(1) + ".timer"
    return SaltState(
        f"timer_{m.group(1)}", "service.running",
        [("name", unit), ("enable", True)],
        "services", r,
    )


@mapper
def m_limits(r):
    """Disable user core dumps via a /etc/security/limits.d drop-in."""
    if r.short != "disable_users_coredumps":
        return None
    return SaltState(
        "limits_disable_coredumps", "file.managed",
        [("name", "/etc/security/limits.d/10-pci-coredump.conf"),
         ("makedirs", True),
         ("mode", "0644"),
         ("contents", ["# Disable core dumps for all users (scap2salt, PCI-DSS)",
                       "* hard core 0"])],
        "limits", r,
    )


def _iptables_state(sid, family, line, rule):
    """Translate one `ip[6]tables -A CHAIN ... -j TARGET` line into iptables.append."""
    cm = re.search(r"-A\s+(\w+)", line)
    jm = re.search(r"-j\s+(\w+)", line)
    if not (cm and jm):
        return None
    args = [("table", "filter"), ("chain", cm.group(1)), ("jump", jm.group(1))]
    im = re.search(r"-i\s+(\S+)", line)
    om = re.search(r"-o\s+(\S+)", line)
    sm = re.search(r"-s\s+(\S+)", line)
    if im:
        args.append(("in-interface", im.group(1)))
    if om:
        args.append(("out-interface", om.group(1)))
    if sm:
        args.append(("source", sm.group(1)))
    args += [("family", family), ("save", True)]
    return SaltState(sid, "iptables.append", args, "firewall", rule)


@mapper
def m_iptables(r):
    """Loopback traffic rules -> native iptables.append states (idempotent, persisted).

    NOTE: SLE 15 defaults to firewalld/nftables; these raw iptables rules are
    faithful to the SCAP check but may need firewalld coexistence review."""
    if r.short not in ("set_loopback_traffic", "set_ipv6_loopback_traffic"):
        return None
    bash = r.bash or ""
    family = "ipv6" if r.short.startswith("set_ipv6") else "ipv4"
    bin_re = "ip6tables" if family == "ipv6" else r"iptables"
    lines = re.findall(rf"^\s*({bin_re}\s+-A\s+.*?-j\s+\w+)\s*$", bash, re.M)
    states = []
    for i, line in enumerate(lines):
        st = _iptables_state(f"fw_{r.short}_{i}", family, line, r)
        if st:
            states.append(st)
    if not states:
        return None
    main = states[0]
    # remaining rules become sibling states rendered after the first
    for s in states[1:]:
        main.extra_states.append((s.id, s.fun, s.args))
    return main


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

# NOTE: 'rpm' is intentionally early (right after 'packages'). rpm_verify_ownership
# runs a system-wide `rpm --setugids` sweep that restores package-default file
# metadata (owner AND mode on SUSE) — it must run BEFORE the targeted file-metadata
# hardening in 'permissions', otherwise it reverts it (e.g. /etc/cron.d 0700 -> 0755).
# Salt executes states in include order, so category order here is the run order.
CATEGORIES = ["sysctl", "packages", "rpm", "services", "permissions",
              "kernel_modules", "sshd", "lineinfile", "pam", "sudo",
              "audit", "dconf", "coredump", "grub", "firewall", "limits",
              "aide", "mounts", "mac", "misc"]
HEADER = "# Generated by scap2salt — DO NOT EDIT BY HAND.\n# Source: {src}\n# Profile: {prof}\n# Generated: {ts}\n\n"


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def emit_tree(outdir, src, profile_id, mapped, unmapped, na, mac, noremed=()):
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
        body += f"# {len(states)} rule(s) in category '{cat}'.\n"
        if cat == "firewall":
            body += ("# NOTE: SLE 15 defaults to firewalld (nftables backend). These raw\n"
                     "# iptables rules are faithful to the SCAP check but may need review for\n"
                     "# coexistence with a firewalld-managed ruleset. Requires the iptables\n"
                     "# package + Salt iptables module on the minion.\n")
        body += "\n"
        body += ("{%- set p = salt['pillar.get']('pci_dss', {}) %}\n"
                 "{%- if p.get('enabled', True) and p.get('" + cat + "', True) %}\n\n")
        if cat == "services":
            if any(s.id == "svc_on_auditd" for s in states):
                # audit-rules.service can fail in two ways:
                # 1. "Rule exists" — duplicate lines in rule fragments (pre-v1.0.8 stale files)
                # 2. "Operation not permitted" — auditctl rules are locked by -e 2 (immutable),
                #    so augenrules --load cannot reload them until the next reboot.
                #
                # We install a systemd drop-in that wraps augenrules with an immutable check.
                # When the kernel reports 'enabled 2', the drop-in prints a message and exits 0
                # so that audit-rules.service succeeds and auditd can start.
                # The ExecStart wrapper command — single-quoted bash inside double-quoted YAML.
                # Inner " must be backslash-escaped so YAML parses them correctly.
                _exec_raw = (
                    "ExecStart=/bin/sh -c "
                    "'if auditctl -s 2>/dev/null | grep -q \"enabled 2\"; "
                    "then echo \"Audit rules immutable (-e 2), skipping reload\"; "
                    "exit 0; fi; /sbin/augenrules --load'"
                )
                # Wrap in double-quoted YAML string, escaping inner double-quotes.
                _exec_yaml = '"' + _exec_raw.replace('"', '\\"') + '"'
                body += ("# Install a drop-in for audit-rules.service so it exits cleanly\n"
                         "# when audit rules are already locked (immutable -e 2 flag set).\n"
                         "audit_rules_dropin_dir:\n"
                         "  file.directory:\n"
                         "    - name: /etc/systemd/system/audit-rules.service.d\n"
                         "    - mode: '0755'\n\n"
                         "audit_rules_immutable_dropin:\n"
                         "  file.managed:\n"
                         "    - name: /etc/systemd/system/audit-rules.service.d/pci-immutable.conf\n"
                         "    - mode: '0644'\n"
                         "    - contents:\n"
                         "        - '[Service]'\n"
                         "        - 'ExecStart='\n"
                         f"        - {_exec_yaml}\n\n"
                         # auditd.service itself crash-loops at boot once the rules
                         # are immutable (-e 2): its ExecStopPost (auditctl -R
                         # audit-stop.rules) can't change rules, marking the unit
                         # failed, and a brief boot race on registering the audit
                         # pid ("Cannot daemonize") exhausts the default restart
                         # limit. This drop-in ignores the immutable ExecStopPost
                         # and gives auditd more retry headroom so it settles.
                         "auditd_dropin_dir:\n"
                         "  file.directory:\n"
                         "    - name: /etc/systemd/system/auditd.service.d\n"
                         "    - mode: '0755'\n\n"
                         "auditd_immutable_dropin:\n"
                         "  file.managed:\n"
                         "    - name: /etc/systemd/system/auditd.service.d/pci-immutable.conf\n"
                         "    - mode: '0644'\n"
                         "    - contents:\n"
                         "        - '[Unit]'\n"
                         "        - 'StartLimitIntervalSec=120'\n"
                         "        - 'StartLimitBurst=10'\n"
                         "        - '[Service]'\n"
                         "        - 'RestartSec=5'\n"
                         "        - 'ExecStopPost='\n"
                         "        - 'ExecStopPost=-/sbin/auditctl -R /etc/audit/audit-stop.rules'\n\n"
                         "audit_rules_dropin_reload:\n"
                         "  cmd.run:\n"
                         "    - name: systemctl daemon-reload\n"
                         "    - onchanges:\n"
                         "        - file: audit_rules_immutable_dropin\n"
                         "        - file: auditd_immutable_dropin\n\n"
                         "audit_prereq_reset:\n"
                         "  cmd.run:\n"
                         "    - name: \"systemctl reset-failed audit-rules.service auditd.service 2>/dev/null || true\"\n"
                         "    - onlyif: \"systemctl is-failed --quiet audit-rules.service || systemctl is-failed --quiet auditd.service\"\n"
                         "    - require:\n"
                         "        - cmd: audit_rules_dropin_reload\n\n")
                for s in states:
                    if s.id == "svc_on_auditd":
                        s.args.append(("require", ["cmd: audit_prereq_reset"]))
                        break
        if cat == "sshd":
            body += ("# Ensure the sshd drop-in directory and file exist before any file.replace.\n"
                     "sshd_dropin_create:\n"
                     "  file.managed:\n"
                     f"    - name: {SSHD_DROPIN}\n"
                     "    - makedirs: True\n"
                     "    - replace: False\n"
                     "    - mode: \"0600\"\n\n")
        if cat == "audit":
            # CaC time-related rules (adjtimex, settimeofday, stime) all generate
            # the same combined rule line.  When augenrules concatenates multiple
            # fragment files containing identical lines it gets "Rule exists" errors
            # and exits non-zero.  Deduplicate rule lines globally across fragments
            # before rendering; drop any fragment that becomes empty.
            _seen = set()
            _deduped = []
            for s in states:
                if not getattr(s, "audit_fragment", False):
                    _deduped.append(s)
                    continue
                ci = next((i for i, (k, _) in enumerate(s.args) if k == "contents"), None)
                if ci is None:
                    _deduped.append(s)
                    continue
                orig = s.args[ci][1]
                new_lines = [l for l in orig if l not in _seen]
                _seen.update(orig)
                if not new_lines:
                    # All lines already covered by an earlier fragment.  Keep the
                    # state so Salt overwrites the on-disk file (which may have
                    # stale content from a previous run) with just a comment.
                    s.args[ci] = ("contents", [
                        f"# Duplicate rules omitted — covered by an earlier fragment."
                    ])
                else:
                    s.args[ci] = ("contents", new_lines)
                _deduped.append(s)
            states = _deduped
        if cat == "lineinfile":
            # Optional app config files: skip state if the file is not present
            # (package may not be installed on this system).
            _LINEINFILE_OPTIONAL = frozenset({"/etc/postfix/main.cf"})
            # Core config files that may be absent on minimal installs: create before replacing.
            _LINEINFILE_PRECREATE = frozenset({
                "/etc/login.defs",
                "/etc/login.defs.d/oscap.login.defs",
                "/etc/default/useradd",
                "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf",
            })
            precreated = set()
            for s in states:
                if s.fun != "file.replace":
                    continue
                path = next((v for k, v in s.args if k == "name"), None)
                if path in _LINEINFILE_OPTIONAL:
                    s.args.append(("onlyif", f"test -f {path}"))
                elif path in _LINEINFILE_PRECREATE and path not in precreated:
                    safe = re.sub(r"[^A-Za-z0-9]", "_", path)
                    body += (f"# Ensure {path} exists before modifying it.\n"
                             f"ensure_{safe}:\n"
                             f"  file.managed:\n"
                             f"    - name: {path}\n"
                             f"    - makedirs: True\n"
                             f"    - replace: False\n\n")
                    precreated.add(path)
        body += "\n".join(s.render() for s in states)
        if cat == "audit":
            frags = [s.id for s in states if getattr(s, "audit_fragment", False)]
            if frags:
                onch = "".join(f"      - file: {salt_quote_id(i)}\n" for i in frags)
                # Reload rules on change. If the ruleset was ALREADY immutable
                # (-e 2) before this load, the kernel rejects the new rules until
                # the next boot, so drop a reboot-required marker in /run (tmpfs,
                # so it auto-clears on reboot).
                body += ("\n# Reload audit rules once any fragment changes.\n"
                         "augenrules_load:\n  cmd.run:\n"
                         "    - name: '"
                         "imm=no; auditctl -s 2>/dev/null | grep -q \"^enabled 2\" && imm=yes; "
                         "augenrules --load 2>/dev/null || true; "
                         "if [ \"$imm\" = yes ]; then "
                         "echo \"scap2salt: audit rules changed but the audit config is immutable "
                         "(-e 2) - reboot required to load them.\" > /run/scap2salt-audit-reboot-required; "
                         "logger -t scap2salt \"audit rules changed; reboot required (audit immutable -e 2)\" "
                         "2>/dev/null || true; fi'\n"
                         "    - onchanges:\n" + onch)
                # Surface the pending reboot in MLM: this state fails (shows red in
                # the system's States/Events) ONLY while a reboot is genuinely
                # pending, i.e. the marker exists. Green otherwise.
                body += ("\n# Flag a pending audit-rule reboot (red in MLM until rebooted).\n"
                         "audit_reboot_required:\n  cmd.run:\n"
                         "    - name: 'cat /run/scap2salt-audit-reboot-required; exit 1'\n"
                         "    - onlyif: 'test -e /run/scap2salt-audit-reboot-required'\n")
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
    if noremed:
        emit_noremed(state_dir, noremed, meta, profile_id)
    emit_readme(state_dir, meta, mapped, unmapped, na, used_cats, mac, noremed)
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
             "# Guard: only apply AppArmor states if AppArmor is the active LSM.\n"
             "# On SELinux systems (e.g. SLE 16) this directory does not exist and\n"
             "# all states below are skipped.  Redeploy with --target sle16 for SELinux.\n"
             "{%- if salt['file.directory_exists']('/sys/kernel/security/apparmor') %}\n\n"
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
             "{%- else %}\n"
             "# AppArmor LSM not active on this system — MAC states skipped.\n"
             "{%- endif %}\n\n"
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


def emit_report(outdir, meta, mapped, unmapped, na, mac, n_selected, noremed=()):
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
         f"**Selected:** {n_selected}  |  **Remediable:** {applicable}  |  "
         f"**No remediation:** {len(noremed)}  |  **N/A ({mac}):** {len(na)}", "",
         f"**Native coverage: {len(mapped)}/{applicable} remediable ({pct}%)** "
         f"— of which {len(ops)} guarded operational state(s).", "",
         "_Denominator excludes N/A rules and rules the SSG ships no remediation for._", "",
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

    if noremed:
        L += ["", f"## No remediation shipped ({len(noremed)})",
              "_SSG ships no `<fix>` (shell or Ansible) — detective-only, nothing to "
              "automate. Excluded from the coverage denominator._", ""]
        nfam = {}
        for r in noremed:
            nfam.setdefault(r.short.split("_")[0], []).append(r)
        for k in sorted(nfam):
            L.append(f"### {k}_* ({len(nfam[k])})")
            for r in sorted(nfam[k], key=lambda x: x.short):
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
    "sysctl":        "Kernel parameters (sysctl)",
    "packages":      "Package install / removal",
    "services":      "Service enable / disable",
    "permissions":   "File permissions & ownership",
    "kernel_modules":"Disabled kernel modules",
    "sshd":          "SSH server hardening",
    "lineinfile":    "Config-file settings (login.defs, securetty…)",
    "pam":           "PAM module arguments (pwquality, pam_unix, pam_wheel)",
    "sudo":          "Sudo defaults (sudoers.d drop-ins)",
    "audit":         "Audit rules & auditd configuration",
    "dconf":         "GNOME desktop (dconf) policy",
    "coredump":      "Systemd core dump policy",
    "grub":          "GRUB kernel command-line arguments",
    "firewall":      "Firewall (iptables loopback rules)",
    "limits":        "Resource limits (security/limits.d)",
    "aide":          "File integrity monitoring (AIDE)",
    "rpm":           "Package signatures & verification (RPM/GPG)",
    "mounts":        "Filesystem mount options",
    "mac":           "Mandatory Access Control (SELinux / AppArmor)",
    "misc":          "Miscellaneous",
}

CAT_HELP = {
    "sysctl": (
        "PCI-DSS §2.2.7 — Kernel parameter hardening via /etc/sysctl.d/. "
        "Covers network security (TCP SYN cookies, ICMP redirects, IPv6 RA, "
        "source routing), ASLR, restricted kernel pointer exposure, and "
        "core dump disabling."
    ),
    "packages": (
        "PCI-DSS §2.2.4, §6.3 — Ensures required security packages are installed "
        "(audispd-plugins, libreswan, openssl, etc.) and prohibited packages are "
        "absent (telnet, rsh, ypbind, X11 client libs, etc.)."
    ),
    "services": (
        "PCI-DSS §2.2.4, §6.3.3 — Controls systemd unit state. Enables "
        "security-critical services (auditd, firewalld, chronyd, rsyslog, "
        "aide-check.timer) and disables unnecessary or insecure services "
        "(avahi-daemon, nfs, rpcbind, cups, etc.)."
    ),
    "permissions": (
        "PCI-DSS §2.2.6, §8.6 — Enforces POSIX ownership and mode on sensitive "
        "files: passwd, shadow, sudoers, cron files, at.allow/deny, audit logs, "
        "SSH host keys, and more. Uses file.managed with replace: False so "
        "file content is never overwritten."
    ),
    "kernel_modules": (
        "PCI-DSS §2.2.4 — Prevents insecure kernel modules from loading by "
        "installing 'install <mod> /bin/true' drop-ins. Covers unused network "
        "protocols (dccp, sctp, rds, tipc) and legacy filesystems (cramfs, "
        "freevxfs, jffs2, hfs, hfsplus, squashfs, udf)."
    ),
    "sshd": (
        "PCI-DSS §2.2.4, §2.2.7, §8.3.1 — Hardens /etc/ssh/sshd_config.d/. "
        "Disables root login and empty passwords, restricts FIPS-validated "
        "ciphers/MACs/KexAlgorithms, sets idle timeout (ClientAliveInterval / "
        "CountMax), disables X11 and TCP forwarding, enables PAM."
    ),
    "lineinfile": (
        "PCI-DSS §8.2, §8.3.9 — Config-file line enforcement for miscellaneous "
        "settings: login.defs (PASS_MAX_DAYS 60, PASS_WARN_AGE 7, "
        "ENCRYPT_METHOD SHA512), /etc/default/useradd (INACTIVE=35), securetty "
        "(restrict root console), session timeout (/etc/profile.d/autologout.sh "
        "TMOUT=600), and chronyd remote server."
    ),
    "pam": (
        "PCI-DSS §8.3.6 — PAM module argument enforcement. Sets password "
        "complexity via pam_pwquality (minlen, dcredit, ucredit, lcredit, "
        "ocredit, maxrepeat, difok), SHA-512 hashing via pam_unix, and "
        "restricts su to the wheel group via pam_wheel."
    ),
    "sudo": (
        "PCI-DSS §8.6.1 — Writes /etc/sudoers.d/ drop-ins enforcing sudo "
        "security defaults: requires a TTY (requiretty), disables environment "
        "variable passing (env_reset), and restricts the sudo log file path."
    ),
    "audit": (
        "PCI-DSS §10.2, §10.3, §10.5 — Deploys auditd rule fragments to "
        "/etc/audit/rules.d/ (loaded via augenrules). Covers time changes, "
        "user/group modifications, network config changes, login/logout, file "
        "deletion, sudo usage, privileged commands, module load/unload, and "
        "MAC policy changes. Ends with the -e 2 immutable flag "
        "(zz-pci-immutable.rules)."
    ),
    "dconf": (
        "PCI-DSS §8.6.1 — Enforces GNOME desktop policy via /etc/dconf/db/ "
        "fragments. Locks screen on idle (idle-delay, idle-activation-enabled), "
        "disables autorun, enforces screensaver lock, and restricts removable "
        "media automount."
    ),
    "coredump": (
        "PCI-DSS §12.3.3 — Configures systemd coredump via "
        "/etc/systemd/coredump.conf.d/. Sets Storage=none and ProcessSizeMax=0 "
        "to prevent core dumps from leaking sensitive memory contents to disk."
    ),
    "grub": (
        "PCI-DSS §2.2.7 — Writes GRUB2 kernel command-line arguments via "
        "/etc/default/grub.d/. Enables audit at boot (audit=1, "
        "audit_backlog_limit) and sets the MAC framework kernel parameter "
        "(security=apparmor or selinux=1 enforcing=1)."
    ),
    "firewall": (
        "PCI-DSS §1.3, §1.4 — Enforces loopback firewall rules via "
        "iptables.append states. Ensures traffic to 127.0.0.0/8 on "
        "non-loopback interfaces is DROPped, and lo interface traffic is "
        "ACCEPTed (IPv4 and IPv6). Review for coexistence with "
        "firewalld/nftables."
    ),
    "limits": (
        "PCI-DSS §12.3 — Writes /etc/security/limits.d/ drop-ins to restrict "
        "resource usage. Sets '* hard core 0' to prevent user-space core dumps "
        "from any account."
    ),
    "aide": (
        "PCI-DSS §10.3.3, §11.5 — Sets up AIDE file integrity monitoring: "
        "runs aide --init to build the initial database (guarded, runs once), "
        "and enables the aide-check.timer systemd unit for periodic scheduled "
        "integrity checks."
    ),
    "rpm": (
        "PCI-DSS §6.3 — Enforces RPM/Zypper GPG signature checking. Ensures "
        "gpgcheck=1 in /etc/zypp/zypp.conf, verifies the SUSE GPG key is "
        "imported, and enables signature verification for all configured "
        "repositories."
    ),
    "mounts": (
        "PCI-DSS §2.2.4 — Enforces mount options on security-sensitive "
        "filesystems. Adds nodev, nosuid, and/or noexec to /tmp, /dev/shm, "
        "/var/tmp, /home, and /boot via persistent fstab entries "
        "(mount.mounted with persist: True)."
    ),
    "mac": (
        "PCI-DSS §1.2.6, §6.3 — Mandatory Access Control. On AppArmor targets: "
        "enforces aa-enforce on all profiles, ensures the apparmor service is "
        "running, installs apparmor-profiles, sets security=apparmor on the "
        "kernel cmdline, and adds an audit watch on /etc/apparmor.d/. On "
        "SELinux targets: enforces enforcing mode and the targeted policy type."
    ),
}


def emit_formula(outdir, meta, used_cats, mac):
    """Write Uyuni / SUSE Multi-Linux Manager 'formula with form' metadata so the
    pillar toggles render as checkboxes in the Web UI (Formulas tab)."""
    fdir = os.path.join(outdir, "srv", "formula_metadata", "pci_dss")
    # form.yml: a 'pci_dss' group whose members become pillar pci_dss:{cat}: True/False.
    # Individual booleans use $help for the tooltip; the group-level $help is shown
    # inline below the section header.
    mac_label = "SELinux" if mac == "selinux" else "AppArmor"
    mac_note = (
        " AppArmor states are silently skipped on SLE 16 (SELinux) — "
        "the formula checks /sys/kernel/security/apparmor at runtime."
    )
    form = ["# Generated by scap2salt — renders in the MLM Web UI 'Formulas' tab.",
            "pci_dss:",
            "  $type: group",
            "  $name: PCI-DSS v4 Hardening",
            ("  $help: 'Native Salt enforcement generated from "
             + meta['prof'] + " (MAC: " + mac_label + "). "
             + "The MAC category auto-detects the active LSM at runtime. "
             + "Uncheck a category to STOP ENFORCING it on the next highstate. "
             + "Unchecking does NOT revert changes already applied — it only "
             + "stops further enforcement.'"),
            "  enabled:",
            "    $type: boolean",
            "    $default: True",
            "    $name: Enable PCI-DSS v4 hardening (master switch)",
            "    $help: >-",
            "      Apply-time master gate, NOT a rollback. When checked, every"
            " enabled",
            "      category is enforced on each highstate. When unchecked, all",
            "      category states are skipped on the next highstate (a no-op run)",
            "      — but any hardening ALREADY applied stays in place; nothing is",
            "      reverted. To undo prior changes you must restore the affected",
            "      files/services manually."]
    for c in used_cats:
        label = CAT_LABELS.get(c, c)
        help_text = CAT_HELP.get(c, "")
        if c == "mac":
            help_text = help_text + mac_note
        entry = [f"  {c}:",
                 "    $type: boolean",
                 "    $default: True",
                 f"    $name: \"{label}\""]
        if help_text:
            entry.append(f"    $help: \"{help_text}\"")
        form += entry
    write(os.path.join(fdir, "form.yml"), "\n".join(form) + "\n")

    metadata = ("name: PCI-DSS v4 Hardening\n"
                f'description: "PCI-DSS v4 hardening generated from {meta["prof"]} '
                f'(MAC: {mac_label}; MAC category auto-detects LSM at runtime)"\n'
                "group: Security & Compliance\n"
                "after: []\n")
    write(os.path.join(fdir, "metadata.yml"), metadata)


# ---------------------------------------------------------------------------
# MLM formula RPM packaging
# ---------------------------------------------------------------------------
PKG_NAME = "pci-dss-hardening-formula"
FORMULA = "pci_dss"
PKG_AUTHOR = "Erico Mendonca <erico.mendonca@suse.com>"

SPEC_TEMPLATE = """\
%define formula {formula}

Name:           {name}
Version:        {version}
Release:        {release}
Summary:        PCI-DSS v4 hardening Salt formula for SUSE Multi-Linux Manager
License:        MIT
Group:          System/Management
URL:            https://github.com/doccaz/scap2salt
Packager:       {author}
Vendor:         {author}
Source0:        %{{name}}-%{{version}}.tar.gz
BuildArch:      noarch

%description
Native Salt states enforcing the {prof} profile (MAC: {mac}), generated by
scap2salt. Installs as a SUSE Multi-Linux Manager / Uyuni *formula with form*:
the files land under the salt-formulas metadata and states directories (both on
the MLM server's Salt file roots), so the formula appears in the Web UI Formulas
tab. Assign it to a system or group, toggle categories, and apply the highstate.

%prep
%setup -q

%build

%install
install -d %{{buildroot}}%{{_datadir}}/salt-formulas/metadata/%{{formula}}
install -d %{{buildroot}}%{{_datadir}}/salt-formulas/states/%{{formula}}
cp -a metadata/%{{formula}}/. %{{buildroot}}%{{_datadir}}/salt-formulas/metadata/%{{formula}}/
cp -a states/%{{formula}}/. %{{buildroot}}%{{_datadir}}/salt-formulas/states/%{{formula}}/

%files
%dir %{{_datadir}}/salt-formulas
%dir %{{_datadir}}/salt-formulas/metadata
%dir %{{_datadir}}/salt-formulas/states
%{{_datadir}}/salt-formulas/metadata/%{{formula}}
%{{_datadir}}/salt-formulas/states/%{{formula}}

%post
# Containerised MLM 5.x (podman-based): copy the formula into the live
# podman volumes so the Salt master container can see it.
# Traditional (non-containerised) deployments need /usr/share/salt-formulas
# added to their file_roots configuration instead.
_meta="" _salt=""
if command -v podman >/dev/null 2>&1; then
    _meta=$(podman volume inspect srv-formulametadata --format '{{{{.Mountpoint}}}}' 2>/dev/null || true)
    _salt=$(podman volume inspect srv-salt --format '{{{{.Mountpoint}}}}' 2>/dev/null || true)
fi
# Fallback for transactional-update installs (SL Micro): %post runs in a
# chroot where podman cannot inspect live volumes, but /var is bind-mounted
# so the volume data directories are reachable by their well-known path.
[ -z "$_meta" ] && _meta=/var/lib/containers/storage/volumes/srv-formulametadata/_data
[ -z "$_salt" ] && _salt=/var/lib/containers/storage/volumes/srv-salt/_data
if [ -d "$_meta" ] && [ -d "$_salt" ]; then
    mkdir -p "$_meta/%{{formula}}" "$_salt/%{{formula}}"
    cp -a %{{_datadir}}/salt-formulas/metadata/%{{formula}}/. "$_meta/%{{formula}}/"
    cp -a %{{_datadir}}/salt-formulas/states/%{{formula}}/. "$_salt/%{{formula}}/"
    echo "%{{name}}: formula deployed to containerised MLM volumes."
fi

%preun
# On final removal (not upgrade) clean up the containerised volume copies.
if [ $1 -eq 0 ]; then
    _meta="" _salt=""
    if command -v podman >/dev/null 2>&1; then
        _meta=$(podman volume inspect srv-formulametadata --format '{{{{.Mountpoint}}}}' 2>/dev/null || true)
        _salt=$(podman volume inspect srv-salt --format '{{{{.Mountpoint}}}}' 2>/dev/null || true)
    fi
    [ -z "$_meta" ] && _meta=/var/lib/containers/storage/volumes/srv-formulametadata/_data
    [ -z "$_salt" ] && _salt=/var/lib/containers/storage/volumes/srv-salt/_data
    rm -rf "$_meta/%{{formula}}" "$_salt/%{{formula}}"
fi

%changelog
* {rpmdate} {author} - {version}-{release}
- Generated from {prof} (MAC: {mac})
"""

BUILD_SH = """\
#!/bin/sh
# Build the formula RPM locally. Requires the 'rpm-build' package (rpmbuild).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(mktemp -d)
mkdir -p "$top/SOURCES" "$top/SPECS"
cp "$here/{name}-{version}.tar.gz" "$top/SOURCES/"
cp "$here/{name}.spec" "$top/SPECS/"
rpmbuild --define "_topdir $top" -bb "$top/SPECS/{name}.spec"
cp "$top"/RPMS/noarch/*.rpm "$here/"
rm -rf "$top"
echo "RPM(s) written to $here:"
ls -1 "$here"/*.rpm
"""

PKG_README = """\
# {name} — MLM formula package

Generated by scap2salt from `{prof}` (MAC: {mac}) on {ts}.
Author/packager: {author}

## Build (if no prebuilt .rpm is present)

    ./build.sh            # needs the rpm-build package

This produces `{name}-{version}-{release}.noarch.rpm`.

## Install on the SUSE Multi-Linux Manager / Uyuni server

    sudo zypper install ./{name}-{version}-{release}.noarch.rpm

The files install to:

    /usr/share/salt-formulas/metadata/{formula}/   (form.yml, metadata.yml)
    /usr/share/salt-formulas/states/{formula}/      (the Salt state tree)

**MLM 5.x (containerised / podman-based):** the `%post` scriptlet automatically
detects the podman volumes `srv-formulametadata` and `srv-salt` and copies the
formula there, so the Salt master container picks it up immediately — no extra
steps needed.

**Traditional (non-containerised) MLM / Uyuni:** `/usr/share/salt-formulas/` must
be in the server's `file_roots` configuration. If the formula does not appear,
add the path and restart the spacewalk/uyuni services, or refresh the web page.

## Use

1. In the Web UI go to a **system** or **system group** -> **Formulas**.
2. Tick **PCI-DSS v4 Hardening**, then Save.
3. Open the new **Pci Dss** sub-tab; toggle categories as needed, Save. This
   writes the `pci_dss:` pillar the states read.
4. Apply the highstate (Schedule -> Apply Highstate, or `state.apply` from the
   command line). Use the scripts in `_verify/` for a read-only oscap check.

No `top.sls` or pillar files are shipped: MLM generates the highstate and feeds
the pillar from the form. (The standalone `top.sls`/`pillar/` tree under
`out/srv/` remains available for the manual `state.apply {formula}` model.)
"""


def emit_package(outdir, meta, mac, version="1.0.14", release="0"):
    """Build a SUSE/MLM Salt formula RPM from the generated tree.

    Stages the canonical salt-formulas layout, writes a .spec + source tarball +
    build.sh + README, and runs rpmbuild if available. Returns the .rpm path (or
    the spec path if rpmbuild is unavailable)."""
    srv = os.path.join(outdir, "srv")
    src_meta = os.path.join(srv, "formula_metadata", FORMULA)
    src_states = os.path.join(srv, "salt", FORMULA)
    if not (os.path.isdir(src_meta) and os.path.isdir(src_states)):
        return None

    pkgdir = os.path.join(outdir, "package")
    if os.path.isdir(pkgdir):
        shutil.rmtree(pkgdir)
    os.makedirs(pkgdir)

    # Stage <name>-<ver>/{metadata,states}/pci_dss for the source tarball.
    stage = os.path.join(pkgdir, f"{PKG_NAME}-{version}")
    shutil.copytree(src_meta, os.path.join(stage, "metadata", FORMULA))
    shutil.copytree(src_states, os.path.join(stage, "states", FORMULA))

    tarball = os.path.join(pkgdir, f"{PKG_NAME}-{version}.tar.gz")
    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(stage, arcname=f"{PKG_NAME}-{version}")
    shutil.rmtree(stage)  # keep only the tarball in the package dir

    rpmdate = datetime.now(timezone.utc).strftime("%a %b %d %Y")
    spec_path = os.path.join(pkgdir, f"{PKG_NAME}.spec")
    write(spec_path, SPEC_TEMPLATE.format(
        name=PKG_NAME, version=version, release=release, formula=FORMULA,
        prof=meta["prof"], mac=mac, rpmdate=rpmdate, author=PKG_AUTHOR))

    bsh = os.path.join(pkgdir, "build.sh")
    write(bsh, BUILD_SH.format(name=PKG_NAME, version=version))
    os.chmod(bsh, 0o755)

    write(os.path.join(pkgdir, "README.md"), PKG_README.format(
        name=PKG_NAME, version=version, release=release, formula=FORMULA,
        prof=meta["prof"], mac=mac, ts=meta["ts"], author=PKG_AUTHOR))

    return _build_rpm(pkgdir, spec_path, tarball, version, release) or spec_path


def _build_rpm(pkgdir, spec_path, tarball, version, release):
    """Run rpmbuild if present; copy the resulting .rpm into pkgdir. Returns path or None."""
    if not shutil.which("rpmbuild"):
        return None
    top = os.path.join(pkgdir, "_rpmbuild")
    for d in ("SOURCES", "SPECS"):
        os.makedirs(os.path.join(top, d), exist_ok=True)
    shutil.copy(tarball, os.path.join(top, "SOURCES"))
    shutil.copy(spec_path, os.path.join(top, "SPECS"))
    try:
        subprocess.run(
            ["rpmbuild", "--define", f"_topdir {os.path.abspath(top)}",
             "-bb", os.path.join(top, "SPECS", os.path.basename(spec_path))],
            check=True, capture_output=True, text=True)
    except (subprocess.CalledProcessError, OSError) as e:
        out = getattr(e, "stderr", "") or str(e)
        print(f"[!] rpmbuild failed ({out.strip().splitlines()[-1] if out.strip() else e});"
              f" spec + tarball left in {pkgdir} — run ./build.sh to retry.")
        shutil.rmtree(top, ignore_errors=True)
        return None
    rpms = []
    for root, _, files in os.walk(os.path.join(top, "RPMS")):
        for f in files:
            if f.endswith(".rpm"):
                dst = os.path.join(pkgdir, f)
                shutil.copy(os.path.join(root, f), dst)
                rpms.append(dst)
    shutil.rmtree(top, ignore_errors=True)
    return rpms[0] if rpms else None


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


def emit_noremed(state_dir, noremed, meta, profile_id):
    lines = [f"# Rules with no remediation — {profile_id}", "",
             f"Generated {meta['ts']} from `{meta['src']}`.", "",
             f"{len(noremed)} selected rule(s) ship **no `<fix>` of any kind** in the SSG "
             "(no shell, no Ansible). These are detective-only — there is nothing to "
             "automate. They require manual or site-specific remediation and are **not** "
             "counted against native coverage.", ""]
    by_fam = {}
    for r in noremed:
        by_fam.setdefault(r.short.split("_")[0], []).append(r)
    for fam in sorted(by_fam):
        lines.append(f"## {fam}* ({len(by_fam[fam])})")
        for r in sorted(by_fam[fam], key=lambda x: x.short):
            pci = ", ".join(r.pci_refs()) or "-"
            lines.append(f"- `{r.short}` — {r.title} (PCI {pci}; sev {r.severity})")
        lines.append("")
    write(os.path.join(state_dir, "NO_REMEDIATION.md"), "\n".join(lines))


def emit_readme(state_dir, meta, mapped, unmapped, na, cats, mac, noremed=()):
    total = len(mapped) + len(unmapped)  # N/A + no-remediation rules excluded from denominator
    pct = (100 * len(mapped) / total) if total else 0
    txt = f"""# PCI-DSS Salt states (generated)

Source datastream: `{meta['src']}`
Profile: `{meta['prof']}`
MAC framework: `{mac}`
Generated: {meta['ts']}

Coverage: **{len(mapped)}/{total}** remediable rules mapped to native Salt ({pct:.0f}%).
{len(unmapped)} unmapped (`UNMAPPED.md`); {len(noremed)} ship no remediation (`NO_REMEDIATION.md`); {len(na)} not applicable to this MAC (`SKIPPED_NA.md`{', equivalence in `MAC_EQUIVALENCE.md`' if mac == 'apparmor' and na else ''}).

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
    ap.add_argument("--package", action="store_true",
                    help="Also build an MLM Salt formula RPM under out/package/")
    ap.add_argument("--pkg-version", default="1.0.13",
                    help="Version for the formula RPM (default: 1.0.0)")
    args = ap.parse_args()

    CONFIG["mac"] = args.mac or mac_for_target(args.target)
    print(f"[*] Target {args.target}: MAC framework = {CONFIG['mac']}")

    ds = acquire_datastream(args.target, args.datastream, args.cache)
    bench = load_benchmark(ds)
    profile_id, selected, refinements = resolve_profile(bench, args.profile)
    XCCDF_VALUES.update(load_values(bench, refinements))
    rules = index_rules(bench)
    print(f"[*] Profile {profile_id}: {len(selected)} selected rules")

    mapped, unmapped, na, noremed = [], [], [], []
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
        elif not ri.has_fix:
            noremed.append(ri)   # SSG ships no remediation -> not a closable gap
        else:
            unmapped.append(ri)

    # Remediable applicable rules (exclude N/A and rules with no fix at all).
    applicable = len(mapped) + len(unmapped)
    ops = sum(1 for s in mapped if getattr(s, "operational", False))

    if args.report_only:
        meta = dict(src=os.path.basename(ds), prof=profile_id,
                    ts=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        path = emit_report(args.out, meta, mapped, unmapped, na, CONFIG["mac"],
                           len(selected), noremed)
        print(f"[*] Coverage: {len(mapped)}/{applicable} remediable mapped "
              f"({100*len(mapped)//max(applicable,1)}%); {ops} operational; "
              f"{len(unmapped)} unmapped; {len(noremed)} no-remediation; "
              f"{len(na)} N/A ({CONFIG['mac']})")
        print(f"[*] Report written: {path}  (no state files — dry run)")
        return

    state_dir, cats = emit_tree(args.out, ds, profile_id, mapped, unmapped, na,
                                CONFIG["mac"], noremed)
    print(f"[*] Mapped {len(mapped)}/{applicable} remediable rules to native Salt "
          f"({100*len(mapped)//max(applicable,1)}%) across: {', '.join(cats)}")
    if ops:
        print(f"[*] of which {ops} are guarded operational states (cmd.run + creates/onlyif/unless)")
    print(f"[*] {len(unmapped)} unmapped -> UNMAPPED.md ; "
          f"{len(noremed)} no-remediation -> NO_REMEDIATION.md ; "
          f"{len(na)} not-applicable ({CONFIG['mac']}) -> SKIPPED_NA.md")
    print(f"[*] Output tree: {os.path.join(args.out, 'srv')}")

    if args.package:
        meta = dict(src=os.path.basename(ds), prof=profile_id,
                    ts=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        artifact = emit_package(args.out, meta, CONFIG["mac"], version=args.pkg_version)
        if artifact and artifact.endswith(".rpm"):
            print(f"[*] Built MLM formula RPM: {artifact}")
        elif artifact:
            print(f"[*] Formula package staged (spec + tarball + build.sh) in "
                  f"{os.path.dirname(artifact)} — run ./build.sh to produce the RPM.")


if __name__ == "__main__":
    main()
