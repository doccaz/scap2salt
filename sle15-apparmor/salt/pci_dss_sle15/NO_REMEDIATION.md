# Rules with no remediation — xccdf_org.ssgproject.content_profile_pci-dss-4

Generated 2026-06-06T17:24:28+00:00 from `ssg-sle15-ds.xml`.

18 selected rule(s) ship **no `<fix>` of any kind** in the SSG (no shell, no Ansible). These are detective-only — there is nothing to automate. They require manual or site-specific remediation and are **not** counted against native coverage.

## account* (2)
- `account_unique_id` — Ensure All Accounts on the System Have Unique User IDs (PCI Req-8.1.1, 8.2.1, 8.2; sev medium)
- `account_unique_name` — Ensure All Accounts on the System Have Unique Names (PCI Req-8.1.1, 8.2.1, 8.2; sev medium)

## accounts* (3)
- `accounts_password_all_shadowed` — Verify All Account Password Hashes are Shadowed (PCI Req-8.2.1, 8.3.2, 8.3; sev medium)
- `accounts_password_last_change_is_in_past` — Ensure all users last password change date is in the past (PCI 8.3.5, 8.3; sev medium)
- `accounts_root_gid_zero` — Verify Root Has A Primary GID 0 (PCI Req-8.1.1, 8.2.1, 8.2; sev high)

## bios* (1)
- `bios_enable_execution_restrictions` — Enable NX or XD Support in the BIOS (PCI 2.2.1, 2.2; sev medium)

## ensure* (1)
- `ensure_firewall_rules_for_open_ports` — Ensure firewall rules exist for all open ports (PCI Req-1.4, 1.3.1, 1.3; sev medium)

## file* (1)
- `file_permissions_ungroupowned` — Ensure All Files Are Owned by a Group (PCI 2.2.6, 2.2; sev medium)

## gid* (1)
- `gid_passwd_group_same` — All GIDs referenced in /etc/passwd must be defined in /etc/group (PCI Req-8.5.a, 8.2.2, 8.2; sev low)

## group* (2)
- `group_unique_id` — Ensure All Groups on the System Have Unique Group ID (PCI 8.2.1, 8.2; sev medium)
- `group_unique_name` — Ensure All Groups on the System Have Unique Group Names (PCI 8.2.1, 8.2; sev medium)

## install* (1)
- `install_PAE_kernel_on_x86-32` — Install PAE Kernel on Supported 32-bit x86 Systems (PCI 2.2.1, 2.2; sev unknown)

## mask* (1)
- `mask_nonessential_services` — Ensure nonessential services are removed or masked (PCI 2.2.4, 2.2; sev low)

## nftables* (1)
- `nftables_ensure_default_deny_policy` — Ensure nftables Default Deny Firewall Policy (PCI 1.3.1, 1.3; sev medium)

## no* (1)
- `no_files_unowned_by_user` — Ensure All Files Are Owned by a User (PCI 2.2.6, 2.2; sev medium)

## set* (2)
- `set_firewalld_default_zone` — Set Default firewalld Zone for Incoming Packets (PCI Req-1.4, 1.3.1, 1.3; sev medium)
- `set_ip6tables_default_rule` — Set Default ip6tables Policy for Incoming Packets (PCI 1.4.1, 1.4; sev medium)

## sshd* (1)
- `sshd_limit_user_access` — Limit Users' SSH Access (PCI Req-2.2.4, 2.2.6, 2.2; sev unknown)
