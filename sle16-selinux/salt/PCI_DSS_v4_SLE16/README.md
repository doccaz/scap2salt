# PCI-DSS Salt states (generated)

Source datastream: `ssg-sle16-ds.xml`
Profile: `xccdf_org.ssgproject.content_profile_pci-dss-4`
MAC framework: `selinux`
Generated: 2026-06-06T17:54:04+00:00

Coverage: **197/230** remediable rules mapped to native Salt (86%).
33 unmapped (`UNMAPPED.md`); 16 ship no remediation (`NO_REMEDIATION.md`); 1 not applicable to this MAC (`SKIPPED_NA.md`).

## Layout
- `init.sls` — includes every category below
- categories: sysctl, packages, rpm, services, permissions, kernel_modules, sshd, lineinfile, accounts, pam, sudo, audit, dconf, coredump, grub, limits, aide, mac
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

Toggle whole categories via pillar `pci_dss:{category}: False`.

## Use as an MLM 'formula with form' (Web UI toggles)
1. Copy `srv/salt/pci_dss/` to `/srv/salt/pci_dss/` and
   `srv/formula_metadata/pci_dss/` to `/srv/formula_metadata/pci_dss/` on the
   MLM/Uyuni server.
2. In the Web UI the formula **PCI-DSS v4 Hardening** appears under a system's or
   group's *Formulas* tab. Tick it, then use the generated *PCI-DSS v4 Hardening*
   sub-tab to toggle categories (these write the `pci_dss:` pillar consumed by the
   states). Save, then apply the highstate.
