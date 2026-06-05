# Not-applicable rules (apparmor target)

Generated 2026-06-05T19:21:55+00:00.

6 selected rule(s) are not applicable to this target's MAC framework (apparmor). Where the control intent still matters (enforce a MAC), it is covered by `mac.sls` / `MAC_EQUIVALENCE.md`.

- `audit_rules_mac_modification_etc_selinux` — Record Events that Modify the System's Mandatory Access Controls (/etc/selinux) (PCI Req-10.5.5, 10.3.4, 10.3)
- `grub2_enable_selinux` — Ensure SELinux Not Disabled in /etc/default/grub (PCI 1.2.6, 1.2)
- `package_libselinux_installed` — Install libselinux Package (PCI 1.2.6, 1.2)
- `selinux_confinement_of_daemons` — Ensure No Daemons are Unconfined by SELinux (PCI 1.2.6, 1.2)
- `selinux_policytype` — Configure SELinux Policy (PCI 1.2.6, 1.2)
- `selinux_state` — Ensure SELinux State is Enforcing (PCI 1.2.6, 1.2)
