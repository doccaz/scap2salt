# PCI-DSS Salt states (generated)

Source datastream: `ssg-sle16-ds.xml`
Profile: `xccdf_org.ssgproject.content_profile_pci-dss-4`
MAC framework: `selinux`
Generated: 2026-10-21T04:10:01+00:00

Coverage: **217/230** remediable rules mapped to native Salt (94%).
13 unmapped (`UNMAPPED.md`); 16 ship no remediation (`NO_REMEDIATION.md`); 1 not applicable to this MAC (`SKIPPED_NA.md`).

## Layout
- `init.sls` — includes every category below
- categories: sysctl, packages, rpm, services, permissions, kernel_modules, sshd, lineinfile, accounts, pam, sudo, audit, dconf, coredump, grub, limits, aide, mac
- `_verify/oscap_scan.sh` — read-only oscap report
- `_verify/salt_verify.sh` — `state.apply test=True` drift check
- `_verify/oscap_remediate.sh` — independent oscap remediation (cross-check)

## Rules that fail an oscap scan by design

These rules are mapped and their **runtime values are hardened**, but the scanner stays red on them because satisfying the check means editing a file that belongs to an RPM. You can have these rules green **or** `rpm_verify_*` green, not both. The formula chooses package integrity.

- `sshd_disable_x11_forwarding` — the vendor `/usr/etc/ssh/sshd_config` carries `X11Forwarding yes`; CaC >= 0.1.82 also checks that file. sshd already ignores it (`sshd -T` shows `x11forwarding no`: our drop-in is read first).
  - *To satisfy it:* delete the `X11Forwarding yes` line from `/usr/etc/ssh/sshd_config` (package `openssh-server`).
  - *Cost:* that file then fails `rpm -V openssh-server`, so `rpm_verify_hashes` goes red, and an openssh update may restore the line.
- `sysctl_fs_suid_dumpable` — systemd ships `fs.suid_dumpable=2` in `/usr/lib/sysctl.d/50-coredump.conf`; the static OVAL check also scans that vendor directory. The runtime value is already `0` (our `/etc/sysctl.d/fs_suid_dumpable.conf` wins).
  - *To satisfy it:* comment out the `fs.suid_dumpable=2` line in `/usr/lib/sysctl.d/50-coredump.conf` (package `systemd`).
  - *Cost:* that file then fails `rpm -V systemd`, so `rpm_verify_hashes` / `rpm_verify_permissions` go red, and a systemd update may restore the line.

## Deploy on Multi-Linux Manager
1. Copy `srv/salt/pci_dss/` and `srv/salt/top.sls` into the Salt state tree
   (the MLM/Uyuni server's `/srv/salt`), and the pillar files into `/srv/pillar`.
2. Tag in-scope clients: `salt '<minion>' grains.setval pci_scope true`.
3. Dry run:   `_verify/salt_verify.sh`
4. Apply:     `salt -C 'G@pci_scope:true' state.apply pci_dss`
5. Verify:    `_verify/oscap_scan.sh` and review `report.html`.

Toggle whole categories via pillar `pci_dss:{category}: False`.

## Use as an MLM 'formula with form' (Web UI toggles)
1. Copy `srv/salt/pci_dss/` to `/srv/salt/pci_dss/` and
   `srv/formula_metadata/pci_dss/` to `/srv/formula_metadata/pci_dss/` on the
   MLM/Uyuni server.
2. In the Web UI the formula **PCI-DSS v4 Hardening** appears under a system's or
   group's *Formulas* tab. Tick it, then use the generated *PCI-DSS v4 Hardening*
   sub-tab to toggle categories (these write the `pci_dss:` pillar consumed by the
   states). Save, then apply the highstate.
