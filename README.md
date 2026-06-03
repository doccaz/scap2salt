# scap2salt

Generates a native [Salt](https://saltproject.io/) state tree from an [OpenSCAP](https://www.open-scap.org/) / SCAP Security Guide (SSG) datastream. Designed for SUSE Linux Enterprise (SLE 15/16) and deployable through [SUSE Multi-Linux Manager](https://www.suse.com/products/multi-linux-manager/) (Uyuni/MLM).

## What it produces

Given an SSG datastream and a compliance profile (default: PCI-DSS v4), scap2salt emits:

```
out/srv/
├── salt/
│   ├── top.sls                    # grain-filtered state entry point
│   └── pci_dss/
│       ├── init.sls               # includes all active category files
│       ├── sysctl.sls             # kernel parameters
│       ├── packages.sls           # package install / removal
│       ├── services.sls           # service enable / disable
│       ├── permissions.sls        # file ownership & modes
│       ├── kernel_modules.sls     # disabled modules (modprobe.d)
│       ├── sshd.sls               # SSH drop-in config
│       ├── lineinfile.sls         # login.defs, securetty, tmout, chrony
│       ├── pam.sls                # PAM module arguments (pwquality, etc.)
│       ├── sudo.sls               # sudo Defaults (sudoers.d drop-ins)
│       ├── audit.sls              # auditd rules + auditd.conf settings
│       ├── dconf.sls              # GNOME desktop policy
│       ├── coredump.sls           # systemd core dump policy
│       ├── grub.sls               # GRUB kernel command-line args
│       ├── firewall.sls           # iptables loopback rules
│       ├── aide.sls               # file integrity (AIDE)
│       ├── rpm.sls                # GPG checks & RPM verification
│       ├── mounts.sls             # filesystem mount options
│       ├── mac.sls                # SELinux or AppArmor enforcement
│       ├── UNMAPPED.md            # rules with a fix we don't yet parse
│       ├── NO_REMEDIATION.md      # rules the SSG ships no fix for (detective-only)
│       ├── SKIPPED_NA.md          # rules N/A for this MAC framework
│       ├── MAC_EQUIVALENCE.md     # AppArmor ↔ SELinux control mapping
│       └── _verify/
│           ├── oscap_scan.sh      # read-only compliance scan
│           ├── salt_verify.sh     # state.apply test=True drift check
│           └── oscap_remediate.sh # independent oscap remediation (cross-check)
├── pillar/
│   ├── top.sls
│   └── pci_dss.sls                # per-category boolean toggles
└── formula_metadata/pci_dss/
    ├── form.yml                   # MLM/Uyuni Web UI checkboxes
    └── metadata.yml
```

Every state file is wrapped in a Jinja guard so any category can be disabled by setting `pci_dss:<category>: False` in the pillar (or toggling the checkbox in the MLM Formulas tab).

## Design principles

**Native states only.** Each SCAP rule is mapped to a first-class Salt state (`sysctl.present`, `pkg.installed`, `service.running`, `file.managed`, `iptables.append`, `mount.mounted`, etc.). Rules for which no declarative primitive exists are either emitted as guarded `cmd.run` states (idempotent via `creates`/`onlyif`/`unless`) or listed in `UNMAPPED.md`. Nothing is silently wrapped in a bare `cmd.run`.

**Honest coverage.** Rules the SSG ships *no remediation* for (detective-only checks like account uniqueness, BIOS settings, firewall-zone design) are separated into `NO_REMEDIATION.md` and excluded from the coverage denominator — the headline percentage reflects rules that *can* be remediated, not rules a handler merely hasn't been written for yet. `UNMAPPED.md` is strictly "has a fix we don't yet parse."

**MAC framework awareness.** SLE 15/Leap 15 ships AppArmor; SLE 16+ ships SELinux. SELinux-specific SCAP rules are automatically marked N/A on AppArmor targets, and `mac.sls` instead enforces the equivalent control intent via AppArmor. The mapping is documented in `MAC_EQUIVALENCE.md`.

**Stdlib only.** The script has no third-party dependencies and runs on any Python 3, including the Python bundled with an MLM server.

## Usage

```bash
./scap2salt.py [options]
```

| Option | Default | Description |
|---|---|---|
| `--target` | `sle15` | SSG product id (`sle15`, `sle16`, `sle12`, `slmicro5`, `slmicro6`, …) |
| `--profile` | `pci-dss-4` | XCCDF profile id (short or full) |
| `--datastream` | _(auto)_ | Path to an existing `ssg-*-ds.xml` (skips download) |
| `--out` | `./out` | Output directory |
| `--cache` | `./.cache` | Download cache directory |
| `--mac` | _(inferred)_ | Override MAC framework (`selinux` or `apparmor`) |
| `--report-only` | — | Classify rules and write a coverage report only — no state files |

**Quick start:**

```bash
# Generate a full Salt tree for SLE 15 / PCI-DSS v4
./scap2salt.py

# Dry run: see coverage without writing states
./scap2salt.py --report-only

# SLE 16 with an already-downloaded datastream
./scap2salt.py --target sle16 --datastream /path/to/ssg-sle16-ds.xml
```

### Datastream acquisition

The script resolves the datastream in this order:

1. `--datastream` path (if given)
2. Locally installed `/usr/share/xml/scap/ssg/content/ssg-<target>-ds.xml` (from the `scap-security-guide` RPM)
3. Cached download from a previous run (`.cache/ssg-<target>-ds.xml`)
4. Download from the [ComplianceAsCode](https://github.com/ComplianceAsCode/content) GitHub release zip and extract the needed file

On an MLM/Uyuni server the RPM path is preferred; run `zypper in scap-security-guide` to install it.

## How it works

### 1. Parse the XCCDF benchmark

`load_benchmark()` parses the datastream XML and locates the embedded `<Benchmark>` element. `resolve_profile()` walks the profile's `<select>` elements (respecting `extends` inheritance) to build the set of active rule IDs.

### 2. Map rules to Salt states

Each active rule is passed through an ordered list of **mappers**. The first mapper that recognises the rule returns a `SaltState` object; unrecognised rules fall through to `UNMAPPED.md`.

| Mapper | Recognises | Emits |
|---|---|---|
| `m_mac` | `selinux_*`, `apparmor_*`, `grub2_enable_selinux` | `selinux.mode`, `file.replace` on `/etc/default/grub`, or AppArmor equivalents |
| `m_sysctl` | `sysctl_*` | `sysctl.present` with a per-key drop-in under `/etc/sysctl.d/` |
| `m_package` | `package_*_installed` / `*_removed` | `pkg.installed` / `pkg.removed` |
| `m_service` | `service_*_enabled` / `*_disabled` | `service.running` / `service.dead` |
| `m_file_perms` | `file_permissions_*`, `file_owner_*`, `file_groupowner_*` | `file.managed` with `replace: False` (metadata only) |
| `m_kmod` | `kernel_module_*_disabled` | `file.managed` writing `/etc/modprobe.d/<mod>.conf` with `install … /bin/true` + `blacklist` |
| `m_sshd` | `sshd_*` | `file.replace` on `/etc/ssh/sshd_config.d/00-pci-hardening.conf`; values extracted from the rule's bash fix or a curated fallback table |
| `m_lineinfile` | rules that write a config line via `printf '%s\n' … >> /path` | `file.replace` with idempotent pattern + `append_if_not_found` |
| `m_mount` | `mount_option_*_nodev/nosuid/noexec` | `mount.mounted` with `persist: True` |
| `m_audit` | `audit_rules_*`, `audit_*` | `file.managed` writing per-rule fragments to `/etc/audit/rules.d/`; one `augenrules --load` triggered on any change |
| `m_auditd_conf` | `auditd_*` | `file.replace` setting `key = value` in `/etc/audit/auditd.conf` (or the audisp syslog plugin); `service auditd restart` triggered on any change |
| `m_pam` | PAM module-arg rules (cracklib pwquality, `pam_unix` hashing, `pam_wheel`) | guarded `cmd.run` that adds/updates one option on the `pam_*.so` line, preserving siblings (idempotent via `unless`) |
| `m_sudoers` | `sudo_*` with a `Defaults …` fix | `file.managed` writing a `/etc/sudoers.d/99-pci-*` drop-in (mode `0440`) |
| `m_coredump` | `coredump_*` | `file.managed` writing a `[Coredump]` drop-in under `/etc/systemd/coredump.conf.d/` |
| `m_grub_audit` | `grub2_audit_*` | `file.replace` adding the kernel arg to `GRUB_CMDLINE_LINUX`; `grub2-mkconfig` triggered on change |
| `m_securetty` | `no_direct_root_logins`, `securetty_root_login_console_only` | `file.managed`/`file.replace` on `/etc/securetty` |
| `m_tmout` | `accounts_tmout` | `file.managed` writing `/etc/profile.d/autologout.sh` |
| `m_chrony` | `chronyd_specify_remote_server` | `file.replace` ensuring a `pool`/`server` line in `/etc/chrony.conf` |
| `m_iptables` | `set_loopback_traffic`, `set_ipv6_loopback_traffic` | `iptables.append` states (idempotent, `save: True`) for the loopback rules |
| `m_dconf` | `dconf_*` | `file.managed` writing a settings fragment + lock fragment to the dconf db dir; `dconf update` triggered on any change |
| `m_aide` | `aide_build_database`, `aide_periodic_checking_systemd_timer` | guarded `cmd.run` (database init) and `file.managed` (systemd unit + timer) |
| `m_rpm` | `ensure_gpgcheck_*`, `ensure_suse_gpgkey_*`, `rpm_verify_*` | `file.replace` on `/etc/zypp/zypp.conf`, guarded `cmd.run` for per-repo and per-package checks |

Values for `sysctl`, `sshd`, `kmod`, and `lineinfile` states are extracted directly from the rule's embedded bash remediation script using targeted regexes, so they stay in sync with the upstream SSG content automatically.

> **Deliberate exclusion:** `rpm_verify_hashes` is left unmapped and listed in `UNMAPPED.md`. Its only automated remediation is reinstalling packages, which is unsafe to run autonomously.

> **Guarded operational states:** `m_aide` and `m_rpm` include inherently imperative operations (database initialisation, key import, `rpm --setperms`) for which no declarative Salt primitive exists. These are emitted as guarded `cmd.run` states with `creates`/`onlyif`/`unless` guards so they stay idempotent and `test=True`-safe. They are counted separately in the run summary and in the `--report-only` coverage report.

### 3. Emit the state tree

`emit_tree()` groups the `SaltState` objects by category and writes one `.sls` file per category. Additional output includes the pillar, `top.sls`, MLM formula metadata, verification scripts, and the coverage/unmapped/NA markdown reports.

## Deploying on SUSE Multi-Linux Manager

1. Copy `out/srv/salt/pci_dss/` and `out/srv/salt/top.sls` to `/srv/salt/` on the MLM server, and `out/srv/pillar/` contents to `/srv/pillar/`.
2. Tag in-scope clients: `salt '<minion>' grains.setval pci_scope true`
3. Dry run: `out/srv/salt/pci_dss/_verify/salt_verify.sh`
4. Apply: `salt -C 'G@pci_scope:true' state.apply pci_dss`
5. Verify: `_verify/oscap_scan.sh` — produces an HTML report at `/var/log/pci_dss-scan/report.html`

### Using the MLM Formulas tab (Web UI)

1. Copy `out/srv/formula_metadata/pci_dss/` to `/srv/formula_metadata/pci_dss/` on the MLM server.
2. The formula **PCI-DSS v4 Hardening** appears under a system's or group's *Formulas* tab.
3. Tick it and use the generated sub-tab to toggle individual categories. Saving writes the `pci_dss:` pillar consumed by the states.
4. Apply the highstate.

## Notes on targets and profiles

- **PCI-DSS v3 for SLE:** ComplianceAsCode only ships `pci-dss-4` (PCI-DSS v4.0.1) for SUSE targets. A separate PCI-DSS v3 profile never existed for SLE in CaC (it only shipped for RHEL, and PCI SSC retired v3.2.1 in 2024). The `--profile` flag accepts any valid profile ID, so a RHEL datastream with a v3 profile still works.
- **SLE 16 / Salt:** SLE 16 does not ship native Salt packages. MLM/Uyuni manages SLE 16 clients via its bundled minion — the generated states deploy unchanged.
- **SLE 16 datastream availability:** Confirm your ComplianceAsCode release ships `ssg-sle16-ds.xml` before targeting `--target sle16`. Use `--datastream /path/to/ssg-sle16-ds.xml` once the file is available.

## Requirements

- Python 3 (stdlib only — no pip install needed)
- Network access to GitHub, **or** `zypper in scap-security-guide` on the target machine, **or** a pre-downloaded datastream via `--datastream`
- Salt (for applying the generated states); oscap (for the verification scripts)
