# PCI-DSS coverage report (dry run)

- Datastream: `ssg-sle15-ds.xml`
- Profile: `xccdf_org.ssgproject.content_profile_pci-dss-4`
- MAC framework: `apparmor`
- Generated: 2026-06-08T13:29:41+00:00

**Selected:** 262  |  **Remediable:** 238  |  **No remediation:** 18  |  **N/A (apparmor):** 6

**Native coverage: 209/238 remediable (87%)** — of which 18 guarded operational state(s).

_Denominator excludes N/A rules and rules the SSG ships no remediation for._

## Mapped by category

| Category | Rules |
|---|---|
| Kernel parameters (sysctl) | 12 |
| Package install / removal | 22 |
| Package signatures & verification (RPM/GPG) | 5 |
| Service enable / disable | 8 |
| File permissions & ownership | 52 |
| Disabled kernel modules | 3 |
| SSH server hardening | 17 |
| Config-file settings (login.defs, securetty…) | 12 |
| Invasive auth hardening: password aging + sudo re-auth (opt-in) | 4 |
| PAM module arguments (pwquality, pam_unix, pam_wheel) | 6 |
| Sudo defaults (sudoers.d drop-ins) | 3 |
| Audit rules & auditd configuration | 49 |
| GNOME desktop (dconf) policy | 7 |
| Systemd core dump policy | 2 |
| GRUB kernel command-line arguments | 2 |
| Firewall (iptables loopback rules) | 2 |
| Resource limits (security/limits.d) | 1 |
| File integrity monitoring (AIDE) | 2 |

## Guarded operational states (18)
_Imperative remediations (no declarative Salt primitive); idempotent via creates/onlyif/unless._

- `accounts_password_set_max_life_existing` (8.3.9, 8.3)
- `accounts_password_set_warn_age_existing` (8.3.9, 8.3)
- `accounts_set_post_pw_existing` (Req-8.1.4, 8.2.6, 8.2)
- `aide_build_database` (Req-11.5, 11.5.2)
- `aide_periodic_checking_systemd_timer` (Req-11.5, 11.5.2)
- `audit_rules_enable_syscall_auditing` (CM-6(b), CM-6.1(iv), SRG-OS-000480-GPOS-00227, SLES-15-030820, SLES-15-750450450, SV-234981r991589_rule)
- `cracklib_accounts_password_pam_dcredit` (Req-8.2.3, 8.3.6, 8.3)
- `cracklib_accounts_password_pam_lcredit` (Req-8.2.3, 8.3.6, 8.3)
- `cracklib_accounts_password_pam_minlen` (Req-8.2.3, 8.3.6, 8.3)
- `cracklib_accounts_password_pam_retry` (Req-8.1.6, Req-8.1.7, 8.3.4, 8.3)
- `ensure_gpgcheck_never_disabled` (Req-6.2, 6.3.3, 6.3)
- `ensure_suse_gpgkey_installed` (Req-6.2, 6.3.3, 6.3)
- `permissions_local_var_log` (10.3.1, 10.3)
- `rpm_verify_ownership` (Req-11.5, 11.5.2)
- `rpm_verify_permissions` (Req-11.5, 11.5.2)
- `set_password_hashing_algorithm_commonauth` (Req-8.2.1, 8.3.2, 8.3)
- `sudo_require_authentication` (2.2.6, 2.2)
- `use_pam_wheel_group_for_su` (2.2.6, 2.2)

## Unmapped (29)
_No native handler — add a mapper or handle via a reviewed state._

### accounts_* (3)
- `accounts_no_uid_except_zero` — Verify Only Root Has UID 0 (PCI Req-8.5, 8.2.1, 8.2; sev high)
- `accounts_passwords_pam_tally2` — Set Deny For Failed Password Attempts (PCI Req-8.1.6, 8.3.4, 8.3; sev medium)
- `accounts_passwords_pam_tally2_unlock_time` — Set Lockout Time for Failed Password Attempts using pam_tally2 (PCI Req-8.1.7, 8.3.4, 8.3; sev medium)

### configure_* (2)
- `configure_crypto_policy` — Configure System Cryptography Policy (PCI 2.2.7, 2.2; sev high)
- `configure_ssh_crypto_policy` — Configure SSH to use System Crypto Policy (PCI Req-2.2, 2.2.7, 2.2; sev medium)

### dconf_* (2)
- `dconf_db_up_to_date` — Make sure that the dconf databases are up-to-date with regards to respective keyfiles (PCI Req-6.2, 8.2.8, 8.2; sev high)
- `dconf_gnome_session_idle_user_locks` — Ensure Users Cannot Change GNOME3 Session Idle Settings (PCI Req-8.1.8, 8.2.8, 8.2; sev medium)

### dir_* (1)
- `dir_perms_world_writable_sticky_bits` — Verify that All World-Writable Directories Have Sticky Bits Set (PCI 2.2.6, 2.2; sev medium)

### display_* (1)
- `display_login_attempts` — Ensure PAM Displays Last Logon/Access Notification (PCI Req-10.2.4, 10.2.1.4, 10.2.1, 10.2; sev low)

### enable_* (1)
- `enable_dconf_user_profile` — Configure GNOME3 DConf User Profile (PCI 8.2.8, 8.2; sev high)

### ensure_* (2)
- `ensure_pam_wheel_group_empty` — Ensure the Group Used by pam_wheel.so Module Exists on System and is Empty (PCI 2.2.6, 2.2; sev medium)
- `ensure_shadow_group_empty` — Ensure shadow Group is Empty (PCI Req-8.2.1, 8.3.2, 8.3; sev medium)

### file_* (5)
- `file_ownership_var_log_audit` — System Audit Logs Must Be Owned By Root (PCI Req-10.5.1, 10.3.2, 10.3; sev medium)
- `file_permissions_sshd_private_key` — Verify Permissions on SSH Server Private *_key Key Files (PCI Req-2.2.4, 2.2.6, 2.2; sev medium)
- `file_permissions_sshd_pub_key` — Verify Permissions on SSH Server Public *.pub Key Files (PCI Req-2.2.4, 2.2.6, 2.2; sev medium)
- `file_permissions_unauthorized_world_writable` — Ensure No World-Writable Files Exist (PCI 2.2.6, 2.2; sev medium)
- `file_permissions_var_log_audit` — System Audit Logs Must Have Mode 0640 or Less Permissive (PCI Req-10.5, 10.3.1, 10.3; sev medium)

### gnome_* (1)
- `gnome_gdm_disable_unattended_automatic_login` — Disable GDM Unattended or Automatic Login (PCI 8.3.1, 8.3; sev high)

### network_* (1)
- `network_sniffer_disabled` — Ensure System is Not Acting as a Network Sniffer (PCI 1.4.5, 1.4; sev medium)

### no_* (3)
- `no_empty_passwords` — Prevent Login to Accounts With Empty Password (PCI Req-8.2.3, 8.3.1, 8.3; sev high)
- `no_empty_passwords_etc_shadow` — Ensure There Are No Accounts With Blank or Null Passwords (PCI 2.2.2, 2.2; sev high)
- `no_shelllogin_for_systemaccounts` — Ensure that System Accounts Do Not Run a Shell Upon Login (PCI 8.2.2, 8.2; sev medium)

### rpm_* (1)
- `rpm_verify_hashes` — Verify File Hashes with RPM (PCI Req-11.5, 11.5.2; sev high)

### rsyslog_* (3)
- `rsyslog_files_groupownership` — Ensure Log Files Are Owned By Appropriate Group (PCI Req-10.5.1, Req-10.5.2, 10.3.2, 10.3; sev medium)
- `rsyslog_files_ownership` — Ensure Log Files Are Owned By Appropriate User (PCI Req-10.5.1, Req-10.5.2, 10.3.2, 10.3; sev medium)
- `rsyslog_files_permissions` — Ensure System Log Files Have Correct Permissions (PCI Req-10.5.1, Req-10.5.2, 10.3.1, 10.3; sev medium)

### security_* (1)
- `security_patches_up_to_date` — Ensure Software Patches Installed (PCI Req-6.2, 6.3.3, 6.3; sev medium)

### set_* (1)
- `set_password_hashing_algorithm_systemauth` — Set PAM Password Hashing Algorithm - system-auth (PCI Req-8.2.1, 8.3.2, 8.3; sev medium)

### wireless_* (1)
- `wireless_disable_interfaces` — Deactivate Wireless Network Interfaces (PCI Req-1.3.3, 1.3.3, 1.3; sev medium)


## No remediation shipped (18)
_SSG ships no `<fix>` (shell or Ansible) — detective-only, nothing to automate. Excluded from the coverage denominator._

### account_* (2)
- `account_unique_id` — Ensure All Accounts on the System Have Unique User IDs (PCI Req-8.1.1, 8.2.1, 8.2; sev medium)
- `account_unique_name` — Ensure All Accounts on the System Have Unique Names (PCI Req-8.1.1, 8.2.1, 8.2; sev medium)

### accounts_* (3)
- `accounts_password_all_shadowed` — Verify All Account Password Hashes are Shadowed (PCI Req-8.2.1, 8.3.2, 8.3; sev medium)
- `accounts_password_last_change_is_in_past` — Ensure all users last password change date is in the past (PCI 8.3.5, 8.3; sev medium)
- `accounts_root_gid_zero` — Verify Root Has A Primary GID 0 (PCI Req-8.1.1, 8.2.1, 8.2; sev high)

### bios_* (1)
- `bios_enable_execution_restrictions` — Enable NX or XD Support in the BIOS (PCI 2.2.1, 2.2; sev medium)

### ensure_* (1)
- `ensure_firewall_rules_for_open_ports` — Ensure firewall rules exist for all open ports (PCI Req-1.4, 1.3.1, 1.3; sev medium)

### file_* (1)
- `file_permissions_ungroupowned` — Ensure All Files Are Owned by a Group (PCI 2.2.6, 2.2; sev medium)

### gid_* (1)
- `gid_passwd_group_same` — All GIDs referenced in /etc/passwd must be defined in /etc/group (PCI Req-8.5.a, 8.2.2, 8.2; sev low)

### group_* (2)
- `group_unique_id` — Ensure All Groups on the System Have Unique Group ID (PCI 8.2.1, 8.2; sev medium)
- `group_unique_name` — Ensure All Groups on the System Have Unique Group Names (PCI 8.2.1, 8.2; sev medium)

### install_* (1)
- `install_PAE_kernel_on_x86-32` — Install PAE Kernel on Supported 32-bit x86 Systems (PCI 2.2.1, 2.2; sev unknown)

### mask_* (1)
- `mask_nonessential_services` — Ensure nonessential services are removed or masked (PCI 2.2.4, 2.2; sev low)

### nftables_* (1)
- `nftables_ensure_default_deny_policy` — Ensure nftables Default Deny Firewall Policy (PCI 1.3.1, 1.3; sev medium)

### no_* (1)
- `no_files_unowned_by_user` — Ensure All Files Are Owned by a User (PCI 2.2.6, 2.2; sev medium)

### set_* (2)
- `set_firewalld_default_zone` — Set Default firewalld Zone for Incoming Packets (PCI Req-1.4, 1.3.1, 1.3; sev medium)
- `set_ip6tables_default_rule` — Set Default ip6tables Policy for Incoming Packets (PCI 1.4.1, 1.4; sev medium)

### sshd_* (1)
- `sshd_limit_user_access` — Limit Users' SSH Access (PCI Req-2.2.4, 2.2.6, 2.2; sev unknown)

## Not applicable — apparmor (6)
_Covered by the MAC equivalence set where the control intent still applies._

- `audit_rules_mac_modification_etc_selinux` — Record Events that Modify the System's Mandatory Access Controls (/etc/selinux) (PCI Req-10.5.5, 10.3.4, 10.3)
- `grub2_enable_selinux` — Ensure SELinux Not Disabled in /etc/default/grub (PCI 1.2.6, 1.2)
- `package_libselinux_installed` — Install libselinux Package (PCI 1.2.6, 1.2)
- `selinux_confinement_of_daemons` — Ensure No Daemons are Unconfined by SELinux (PCI 1.2.6, 1.2)
- `selinux_policytype` — Configure SELinux Policy (PCI 1.2.6, 1.2)
- `selinux_state` — Ensure SELinux State is Enforcing (PCI 1.2.6, 1.2)
