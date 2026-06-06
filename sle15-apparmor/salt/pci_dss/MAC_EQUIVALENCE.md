# MAC equivalence — AppArmor target

Generated 2026-06-06T14:19:45+00:00.

The PCI-DSS baseline expresses Mandatory Access Control via SELinux rules. This target runs **AppArmor** (SLE/Leap 15), so those rules are Not Applicable; `mac.sls` enforces the same control intent with AppArmor.

| SELinux rule (N/A here) | AppArmor equivalent | PCI |
|---|---|---|
| `audit_rules_mac_modification_etc_selinux` | audit watch on /etc/apparmor.d | Req-10.5.5, 10.3.4, 10.3 |
| `grub2_enable_selinux` | `security=apparmor` on the kernel cmdline | 1.2.6, 1.2 |
| `package_libselinux_installed` | apparmor-parser / apparmor-utils packages | 1.2.6, 1.2 |
| `selinux_confinement_of_daemons` | apparmor service active + profiles enforced | 1.2.6, 1.2 |
| `selinux_policytype` | apparmor-profiles package providing the policy set | 1.2.6, 1.2 |
| `selinux_state` | all profiles set to enforce (`aa-enforce`) | 1.2.6, 1.2 |
