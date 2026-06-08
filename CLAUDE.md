# CLAUDE.md — scap2salt

Read automatically by Claude Code at the start of every session.
Full architecture, design decisions, concepts, and acronyms for `scap2salt.py`.

---

## Project purpose

`scap2salt.py` converts an **SCAP Security Guide (SSG)** datastream XML file into a
ready-to-deploy native **Salt** state tree, targeting SUSE Linux Enterprise systems
managed through **MLM** (SUSE Multi-Linux Manager / Uyuni).

Default use case: generate PCI-DSS v4 enforcement states for SLE 15 with AppArmor.

---

## Current coverage snapshot

Latest full runs of the `pci-dss-4` profile (PCI-DSS v4.0.1) against the upstream datastreams:

| Metric | SLE 15 (AppArmor) | SLE 16 (SELinux) |
|---|---|---|
| Rules selected by profile | 262 | 247 |
| Remediable (coverage denominator) | 238 | 230 |
| No remediation shipped (detective-only) | 18 | 16 |
| N/A for this MAC framework | 6 | 1 |
| **Native coverage** | **209/238 — 87%** | **197/230 — 85%** |
| Guarded operational states | 18 | 13 |
| Remediable rules still unmapped | 29 | 33 |

Regenerate with `./scap2salt.py --report-only` (SLE 15) or `./scap2salt.py --target sle16 --report-only` (SLE 16); each writes `out/coverage-report.md`. Keep these numbers in sync with the README's "Current coverage" section when handlers change.

---

## Key concepts and acronyms

| Term | Meaning |
|---|---|
| **SCAP** | Security Content Automation Protocol — a NIST standard for expressing security rules and scanning results in machine-readable XML |
| **SSG** | SCAP Security Guide — the open-source project (ComplianceAsCode/content) that ships pre-built datastreams for RHEL, SUSE, Fedora, etc. |
| **Datastream** | A single XML file that bundles XCCDF + OVAL + CPE into one artifact (`ssg-sle15-ds.xml`) |
| **XCCDF** | Extensible Configuration Checklist Description Format — the XML schema used to describe benchmark rules and profiles inside a datastream |
| **OVAL** | Open Vulnerability and Assessment Language — the check language embedded in datastreams; scap2salt does **not** parse OVAL |
| **Benchmark** | The top-level XCCDF element; contains Profiles and Rules |
| **Profile** | A named subset of rules from a Benchmark (e.g. `xccdf_org.ssgproject.content_profile_pci-dss-4`) |
| **Rule** | A single XCCDF requirement with a title, severity, references, and optionally a bash remediation script (`<fix system="urn:xccdf:fix:script:sh">`) |
| **CaC** | ComplianceAsCode — the GitHub project that maintains SSG |
| **Salt** | SaltStack configuration management tool; states are YAML+Jinja files |
| **SLS** | Salt state file format (`.sls`); YAML with optional Jinja templating |
| **Pillar** | Salt's secure per-minion data store; used here for per-category boolean toggles (`pci_dss:<category>: True/False`) |
| **MLM** | SUSE Multi-Linux Manager — the SUSE-branded Uyuni/Spacewalk server for managing SUSE fleets |
| **Uyuni** | The open-source upstream of MLM |
| **Formula with form** | MLM/Uyuni feature: a Salt formula accompanied by `form.yml` that renders as a Web UI form in the Formulas tab, writing pillar data from checkboxes |
| **MAC** | Mandatory Access Control — kernel-enforced security policy; SLE 15 uses AppArmor, SLE 16+ uses SELinux |
| **AppArmor** | Profile-based MAC on SLE 15 / Leap 15 / MicroOS 5 |
| **SELinux** | Label-based MAC on SLE 16 / Leap 16 / MicroOS 6 / Tumbleweed |
| **AIDE** | Advanced Intrusion Detection Environment — file integrity monitor |
| **augenrules** | Tool that assembles `/etc/audit/rules.d/*.rules` fragments into the active auditd rule set |
| **dconf** | GNOME settings database; policies pushed via fragment files in `/etc/dconf/db/` |
| **NVS** | (not used here — belongs to the ESP32 project) |
| **PCI-DSS** | Payment Card Industry Data Security Standard — the compliance framework targeted by default |

---

## Source file

```
scap2salt/
├── CLAUDE.md               ← you are here
├── README.md               ← user-facing documentation
├── scap2salt.py            ← the entire tool; stdlib only, single file
├── sample-sle15-ds.xml     ← small test datastream (not a full SSG file)
├── sample-coverage-report.md
├── sample-salt-trees.zip
├── sle15-apparmor/         ← example output: SLE 15 + AppArmor + PCI-DSS v4
└── sle16-selinux/          ← example output: SLE 16 + SELinux + PCI-DSS v4
```

---

## Architecture

### Datastream acquisition (`acquire_datastream`)

Resolution order:
1. `--datastream` CLI flag (explicit path)
2. Locally installed RPM content (`/usr/share/xml/scap/ssg/content/ssg-<target>-ds.xml`)
3. Cached prior download (`.cache/ssg-<target>-ds.xml`)
4. Download the ComplianceAsCode release **zip** from GitHub, extract the single needed XML file in memory, and write only that to the cache

> **Important:** CaC releases no longer ship individual `ssg-*-ds.xml` files as GitHub release assets. Since (at least) v0.1.42 they only ship tarballs and a zip bundle. The zip contains the compiled datastreams at `scap-security-guide-<ver>/ssg-<target>-ds.xml`.

### XCCDF parsing

- `load_benchmark()` — parses the XML, unwraps the `<Benchmark>` from a source datastream if needed. Namespace-tolerant (matches on local tag name, not `{ns}tag`).
- `resolve_profile()` — walks `<select>` elements inside the chosen Profile, respecting `extends` inheritance. Returns a `set` of active rule ID strings.
- `index_rules()` — builds a `{rule_id: Element}` dict for O(1) lookup.
- `RuleInfo` — thin wrapper around a rule element; extracts title, severity, PCI-DSS references, and the embedded bash fix script.

### Rule mappers

An ordered list of functions (`MAPPERS`). Each takes a `RuleInfo` and returns a `SaltState`, `"NA"` (not applicable to the current MAC), or `None` (pass to next mapper).

| Mapper | Trigger | Output category |
|---|---|---|
| `m_mac` | `selinux_*`, `apparmor_*`, `grub2_enable_selinux` | `mac` |
| `m_sysctl` | `sysctl_*` | `sysctl` |
| `m_package` | `package_*_installed/removed` | `packages` |
| `m_service` | `service_*_enabled/disabled` | `services` |
| `m_file_perms` | `file_permissions_*`, `file_owner_*`, `file_groupowner_*`, `file_*_not_exist` | `permissions` |
| `m_kmod` | `kernel_module_*_disabled` | `kernel_modules` |
| `m_sshd` | `sshd_*` | `sshd` |
| `m_lineinfile` | rules using `printf '%s\n' "<line>" >> "<path>"` | `lineinfile` |
| `m_mount` | `mount_option_*_nodev/nosuid/noexec` | `mounts` |
| `m_audit` | `audit_rules_*`, `audit_*`, + rules using the `rules.d` macro (e.g. `directory_access_var_log_audit`) | `audit` |
| `m_auditd_conf` | `auditd_*` (auditd.conf / audisp plugin `key = value`) | `audit` |
| `m_pam` | PAM module-arg rules using CaC's `VALUES/VALUE_NAMES/ARGS` macro (cracklib pwquality, `pam_unix` hashing, `pam_wheel`) | `pam` |
| `m_sudoers` | `sudo_*` with an `echo "Defaults …" >>` fix | `sudo` |
| `m_coredump` | `coredump_*` (systemd `[Coredump]` key=value) | `coredump` |
| `m_grub_audit` | `grub2_audit_*` (kernel cmdline args) | `grub` |
| `m_securetty` | `no_direct_root_logins`, `securetty_root_login_console_only` | `lineinfile` |
| `m_tmout` | `accounts_tmout` (`/etc/profile.d/autologout.sh`) | `lineinfile` |
| `m_chrony` | `chronyd_specify_remote_server` (`/etc/chrony.conf`) | `lineinfile` |
| `m_iptables` | `set_loopback_traffic`, `set_ipv6_loopback_traffic` | `firewall` |
| `m_chronyd_user` | `chronyd_run_as_chrony_user` (`/etc/sysconfig/chronyd`) | `lineinfile` |
| `m_libuser_hash` | `set_password_hashing_algorithm_libuserconf` (`/etc/libuser.conf`) | `lineinfile` |
| `m_timer` | `timer_*_enabled` (systemd `.timer`) | `services` |
| `m_limits` | `disable_users_coredumps` (`/etc/security/limits.d/`) | `limits` |
| `m_dconf` | `dconf_*` | `dconf` |
| `m_aide` | `aide_build_database`, `aide_periodic_checking_systemd_timer` | `aide` |
| `m_rpm` | `ensure_gpgcheck_*`, `ensure_suse_gpgkey_*`, `rpm_verify_*` | `rpm` |

`m_mac` is prepended to the front of MAPPERS (it must run before the generic `m_package` and `m_service` mappers that would otherwise partially handle SELinux/AppArmor package rules).

### PAM handler (`m_pam`) — why it is operational

PAM module-argument rules have no declarative primitive in core Salt (no `pam` state module), and a naïve whole-line `file.replace` would clobber co-located options on the same module line (e.g. setting `minlen` would drop an existing `retry`). So `m_pam` emits a **guarded operational `cmd.run`** that faithfully mirrors CaC's logic: ensure the `<type> <control> pam_<mod>.so` line exists, then for each option either update its value in place or append it, leaving sibling options intact. An `unless` guard makes it idempotent. Built from the `VALUES`/`VALUE_NAMES` (option=value) and `NEW_ARGS` (bare flags like `use_uid`, `sha512`) arrays, with `$var_*` resolved via `shell_resolve()`.

### `shell_resolve()`

Several handlers (`m_auditd_conf`, `m_sudoers`, `m_grub_audit`, `m_pam`) read a literal that still contains a `$var_*` / `${var_*}` reference. `shell_resolve(val, bash)` substitutes each with the value of its in-script assignment (`var_x='...'`). This complements the XCCDF `<sub>` resolution: `<sub>` fills the variable's *assignment*, `shell_resolve()` expands a later *reference* to it.

### Firewall handler (`m_iptables`) — one rule, several states

`m_iptables` handles only the two loopback-traffic rules (`set_loopback_traffic` IPv4, `set_ipv6_loopback_traffic` IPv6). Each ships three `ip[6]tables -A CHAIN … -j TARGET` lines; the handler translates each into an `iptables.append` state (`-i`→`in-interface`, `-o`→`out-interface`, `-s`→`source`, `-j`→`jump`, with `family` and `save: True`). Because `map_rule()` returns a single `SaltState`, the first line becomes the main state and the rest are attached as `extra_states`. **Caveat:** SLE 15 defaults to firewalld/nftables; these raw iptables rules are faithful to the SCAP check but may need firewalld-coexistence review — a note to that effect is emitted at the top of `firewall.sls`. The other four firewall rules in the PCI baseline (`set_firewalld_default_zone`, `set_ip6tables_default_rule`, `nftables_ensure_default_deny_policy`, `ensure_firewall_rules_for_open_ports`) ship **no fix** and land in `NO_REMEDIATION.md`.

### Audit special cases (`m_audit`)

Beyond the standard `-w`/`-a` reconstruction, `m_audit` handles three extras:
- **`audit_rules_immutable`** → a fragment named `zz-pci-immutable.rules` containing `-e 2`. The `zz-` prefix makes augenrules concatenate it **last**, as the immutable directive must be the final rule.
- **`audit_rules_enable_syscall_auditing`** → a guarded operational `cmd.run` that comments out any `-a task,never` line in existing fragments (it edits existing files rather than adding one).
- **`echo "-w … -k …" >>` watches and `OTHER_FILTERS`-only rules** (no `-S` syscall, e.g. `-F dir=… -F perm=…`) are now emitted; `$var` watch paths are expanded with `shell_resolve()`. The family guard also admits rules outside the `audit_*` id space that are built from the `rules.d` macro (e.g. `directory_access_var_log_audit`).

### MLM formula RPM (`emit_package`, `--package`)

`emit_package()` repackages the already-generated tree into the canonical SUSE
formula layout and builds an RPM:

- States → `/usr/share/salt-formulas/states/pci_dss/`, metadata (`form.yml`,
  `metadata.yml`) → `/usr/share/salt-formulas/metadata/pci_dss/`. Both are on the
  MLM/Uyuni server's Salt file roots, so the formula appears in the Formulas tab
  with no extra config.
- The **formula model** deliberately omits `top.sls` and the pillar tree — MLM
  generates the highstate and feeds the `pci_dss:` pillar from the form. The
  category guards (`pillar.get('pci_dss', …)`) already match what the form writes.
- `out/package/` holds the `.spec`, a `%{name}-%{version}.tar.gz` source tarball,
  `build.sh` (rebuild where `rpmbuild` is absent), a deploy `README.md`, and the
  built `.rpm`. `_build_rpm()` shells out to `rpmbuild` in a private `_topdir`; if
  `rpmbuild` is missing or fails it leaves the spec+tarball and prints how to
  finish the build. Package name is `pci-dss-hardening-formula`; the formula dir
  (and pillar namespace) stays `pci_dss`.
- `out/package/` lives under the git-ignored `out/`; distribute the `.rpm` via a
  GitHub Release or an MLM software channel, not by committing it.

### "No remediation shipped" classification

`RuleInfo.has_fix` is `True` if the rule carries any `<fix>` element (shell *or* Ansible). In `main()`, an unmapped rule with `has_fix == False` goes to the `noremed` bucket instead of `unmapped`: the SSG ships nothing to automate (detective-only rules like uniqueness checks, BIOS settings, firewall design). These are written to `NO_REMEDIATION.md` and **excluded from the coverage denominator** — so the headline percentage reflects *remediable* rules, not rules we merely haven't written a handler for. `UNMAPPED.md` now means strictly "has a fix we don't yet parse."

### SaltState rendering

`SaltState.render()` produces a YAML block for one state ID. Features:
- `yaml_scalar()` — quotes values only when necessary (YAML special chars, octal file modes, empty strings).
- `salt_quote_id()` — single-quotes state IDs that contain `:`, `#`, or spaces.
- `REQUISITE_KEYS` — the set of Salt requisite keys (`require`, `watch`, etc.) whose list items are YAML mappings and must not be quoted as scalars.
- `extra_states` — additional sibling state blocks appended after the main block (used by `m_dconf` for lock fragments, and `m_aide` for the timer + service pair).
- `audit_fragment = True` — marks a state as an auditd rule fragment, causing `augenrules --load` to be appended with an `onchanges` requisite.
- `auditd_restart = True` — marks an `auditd.conf`/audisp `key = value` state (from `m_auditd_conf`), appending `service auditd restart` with an `onchanges` requisite.
- `dconf_reload = True` — similar trigger for `dconf update`.
- `needs_grub_reload = True` — triggers `grub2-mkconfig` in the mac category.
- `operational = True` — marks a `cmd.run` state that has no declarative alternative; noted in comments and counted separately ("N guarded operational states") in both the run summary and `coverage-report.md`.

### MAC equivalence (AppArmor targets)

On AppArmor targets, SELinux-specific SCAP rules are returned as `"NA"`. Rather than silently dropping them, `emit_apparmor_mac()` synthesises a `mac.sls` that enforces the same control intent:

| SELinux rule | AppArmor equivalent |
|---|---|
| `selinux_state` | `aa-enforce` on all profiles |
| `selinux_policytype` | `apparmor-profiles` package |
| `selinux_confinement_of_daemons` | `apparmor` service running |
| `grub2_enable_selinux` | `security=apparmor` on kernel cmdline |
| `audit_rules_mac_modification_etc_selinux` | audit watch on `/etc/apparmor.d/` |

The rationale is documented per rule in `MAC_EQUIVALENCE.md` (written alongside the state tree).

### Emitters

| Function | Output |
|---|---|
| `emit_tree()` | Full state tree under `out/srv/` |
| `emit_apparmor_mac()` | `mac.sls` + `MAC_EQUIVALENCE.md` for AppArmor targets |
| `emit_na()` | `SKIPPED_NA.md` listing N/A rules |
| `emit_unmapped()` | `UNMAPPED.md` listing rules that have a fix we don't yet parse |
| `emit_noremed()` | `NO_REMEDIATION.md` listing rules the SSG ships no fix for (detective-only) |
| `emit_readme()` | `README.md` inside the generated state dir (deploy instructions) |
| `emit_verify()` | Three shell scripts in `_verify/` |
| `emit_actions()` | `PCI_ACTIONS.md` — full per-rule reference (rule, severity, PCI-DSS refs, concrete action) grouped by category; linked from the form for "dive deeper" |
| `emit_formula()` | `form.yml` + `metadata.yml` for MLM Formulas tab. Transparency model: always-visible `$name` = category + headline PCI-DSS sections (from `cat_pci`) + one-line gist (`CAT_SHORT`); `$help` = hover detail (`CAT_HELP`); group `$help` links to `PCI_ACTIONS.md`. `OPT_IN_CATEGORIES` (e.g. `accounts`) render `$default: False`. |
| `emit_package()` | MLM Salt **formula RPM** under `out/package/` (spec + tarball + `build.sh` + README, and the built `.rpm` if `rpmbuild` is present); gated by `--package` |
| `emit_report()` | Standalone `coverage-report.md` (headline %, per-category mapped table, guarded operational list, unmapped rules grouped by family, N/A list); used by `--report-only` |

### Pillar guard pattern

Every category `.sls` is wrapped in:
```jinja
{%- set p = salt['pillar.get']('pci_dss', {}) %}
{%- if p.get('enabled', True) and p.get('<category>', True) %}
  ... states ...
{%- endif %}
```
This lets operators disable any category without editing state files.

---

## CLI flags

| Flag | Default | Effect |
|---|---|---|
| `--target` | `sle15` | SSG product id; drives MAC inference and datastream filename |
| `--profile` | `pci-dss-4` | XCCDF profile; short id matched with `endswith` against full ids |
| `--datastream` | — | Explicit path; skips all acquisition logic |
| `--out` | `./out` | Root of the generated output tree |
| `--cache` | `./.cache` | Where downloaded datastream XML is cached |
| `--mac` | _(inferred)_ | Override MAC detection (`selinux` or `apparmor`) |
| `--formula-name` | `pci_dss` | Salt formula name = state dir, pillar namespace, and form top-key. Use distinct names (`pci_dss_sle15`, `pci_dss_sle16`) to run per-OS formulas side by side on one MLM server. Threaded via `CONFIG["formula"]`. |
| `--report-only` | — | No state files; writes only `out/coverage-report.md` |

---

## Runtime global

`CONFIG = {"mac": "apparmor", "formula": "pci_dss"}` is set once in `main()` and read by `m_mac()` and several emitters. It is intentionally a module-level dict (not passed through every call) because the MAC setting and formula name cross-cut many mappers and emitters. `CONFIG["formula"]` (from `--formula-name`) drives the state dir, pillar namespace, `init.sls` includes, form top-key, doc link, and RPM/package name — so per-OS formulas (`pci_dss_sle15`, `pci_dss_sle16`) coexist on one MLM server, assigned per system-group. One codebase regenerates both, so fixes apply to both at once.

---

## Adding a new mapper

1. Write a function `def m_<name>(r: RuleInfo) -> SaltState | str | None`.
2. Decorate it with `@mapper` (appends to `MAPPERS`) or use `MAPPERS.insert(0, fn)` for priority.
3. Return `None` to pass to the next mapper, `"NA"` to mark as not-applicable, or a `SaltState` to claim the rule.
4. Add the new category string to `CATEGORIES` and a label to `CAT_LABELS` if it's a new category.

---

## XCCDF `<sub>` value resolution

`RuleInfo.bash` is built with `resolve_fix_bash()`, not bare `itertext()`. XCCDF fix scripts contain `<sub idref="xccdf_org.ssgproject.content_value_var_*"/>` elements whose replacement values are looked up in the `<Value>` elements of the Benchmark. `load_values(bench)` builds the `XCCDF_VALUES` dict once in `main()`; `resolve_fix_bash()` substitutes each `<sub>` with its resolved value before the mapper sees the bash text. Without this, variable-interpolated rules (e.g. `var_accounts_tmout`, `var_auditd_space_left_action`) would see empty values and fall through to `UNMAPPED.md`.

## Known limitations

- Only the first matching mapper wins; there is no merging of multiple states for one rule.
- OVAL checks are not parsed; the script relies entirely on XCCDF rule metadata and bash fix scripts for value extraction.
- Bash fix extraction uses regex heuristics — unusual bash in a fix script may produce `None` and fall through to `UNMAPPED.md`.
- Multi-value sysctl rules (rare) produce one state per rule; no deduplication.
- `rpm_verify_hashes` is deliberately left unmapped — its only automated remediation (reinstalling packages) is unsafe to run autonomously; it is listed in `UNMAPPED.md` for manual review.
- PCI-DSS v3 does not exist as a profile for SLE in ComplianceAsCode — only `pci-dss-4` (v4.0.1) ships for SUSE targets. The `--profile` flag accepts any ID, so a RHEL datastream with a v3 profile still works if needed.
- SLE 16 does not ship native Salt packages; MLM/Uyuni manages SLE 16 clients via its bundled minion. Confirm your CaC release ships `ssg-sle16-ds.xml` before targeting `--target sle16`.
- `--report-only` coverage numbers for `lineinfile`, `audit`, `sshd`, and `dconf` are projections from CaC's deterministic macro idioms — true numbers only appear when running against a real `ssg-*-ds.xml`.
