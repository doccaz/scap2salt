# Unmapped rules — xccdf_org.ssgproject.content_profile_pci-dss-4

Generated 2026-06-06T14:19:45+00:00 from `ssg-sle15-ds.xml`.

33 selected rule(s) have **no native Salt handler** and were skipped (native-only mode). Add a mapper in `scap2salt.py` or handle these via a separate reviewed state.

## accounts* (6)
- `accounts_no_uid_except_zero` — Verify Only Root Has UID 0 (PCI Req-8.5, 8.2.1, 8.2; sev high)
- `accounts_password_set_max_life_existing` — Set Existing Passwords Maximum Age (PCI 8.3.9, 8.3; sev medium)
- `accounts_password_set_warn_age_existing` — Set Existing Passwords Warning Age (PCI 8.3.9, 8.3; sev medium)
- `accounts_passwords_pam_tally2` — Set Deny For Failed Password Attempts (PCI Req-8.1.6, 8.3.4, 8.3; sev medium)
- `accounts_passwords_pam_tally2_unlock_time` — Set Lockout Time for Failed Password Attempts using pam_tally2 (PCI Req-8.1.7, 8.3.4, 8.3; sev medium)
- `accounts_set_post_pw_existing` — Set existing passwords a period of inactivity before they been locked (PCI Req-8.1.4, 8.2.6, 8.2; sev medium)

## configure* (2)
- `configure_crypto_policy` — Configure System Cryptography Policy (PCI 2.2.7, 2.2; sev high)
- `configure_ssh_crypto_policy` — Configure SSH to use System Crypto Policy (PCI Req-2.2, 2.2.7, 2.2; sev medium)

## dconf* (2)
- `dconf_db_up_to_date` — Make sure that the dconf databases are up-to-date with regards to respective keyfiles (PCI Req-6.2, 8.2.8, 8.2; sev high)
- `dconf_gnome_session_idle_user_locks` — Ensure Users Cannot Change GNOME3 Session Idle Settings (PCI Req-8.1.8, 8.2.8, 8.2; sev medium)

## dir* (1)
- `dir_perms_world_writable_sticky_bits` — Verify that All World-Writable Directories Have Sticky Bits Set (PCI 2.2.6, 2.2; sev medium)

## display* (1)
- `display_login_attempts` — Ensure PAM Displays Last Logon/Access Notification (PCI Req-10.2.4, 10.2.1.4, 10.2.1, 10.2; sev low)

## enable* (1)
- `enable_dconf_user_profile` — Configure GNOME3 DConf User Profile (PCI 8.2.8, 8.2; sev high)

## ensure* (2)
- `ensure_pam_wheel_group_empty` — Ensure the Group Used by pam_wheel.so Module Exists on System and is Empty (PCI 2.2.6, 2.2; sev medium)
- `ensure_shadow_group_empty` — Ensure shadow Group is Empty (PCI Req-8.2.1, 8.3.2, 8.3; sev medium)

## file* (5)
- `file_ownership_var_log_audit` — System Audit Logs Must Be Owned By Root (PCI Req-10.5.1, 10.3.2, 10.3; sev medium)
- `file_permissions_sshd_private_key` — Verify Permissions on SSH Server Private *_key Key Files (PCI Req-2.2.4, 2.2.6, 2.2; sev medium)
- `file_permissions_sshd_pub_key` — Verify Permissions on SSH Server Public *.pub Key Files (PCI Req-2.2.4, 2.2.6, 2.2; sev medium)
- `file_permissions_unauthorized_world_writable` — Ensure No World-Writable Files Exist (PCI 2.2.6, 2.2; sev medium)
- `file_permissions_var_log_audit` — System Audit Logs Must Have Mode 0640 or Less Permissive (PCI Req-10.5, 10.3.1, 10.3; sev medium)

## gnome* (1)
- `gnome_gdm_disable_unattended_automatic_login` — Disable GDM Unattended or Automatic Login (PCI 8.3.1, 8.3; sev high)

## network* (1)
- `network_sniffer_disabled` — Ensure System is Not Acting as a Network Sniffer (PCI 1.4.5, 1.4; sev medium)

## no* (3)
- `no_empty_passwords` — Prevent Login to Accounts With Empty Password (PCI Req-8.2.3, 8.3.1, 8.3; sev high)
- `no_empty_passwords_etc_shadow` — Ensure There Are No Accounts With Blank or Null Passwords (PCI 2.2.2, 2.2; sev high)
- `no_shelllogin_for_systemaccounts` — Ensure that System Accounts Do Not Run a Shell Upon Login (PCI 8.2.2, 8.2; sev medium)

## rpm* (1)
- `rpm_verify_hashes` — Verify File Hashes with RPM (PCI Req-11.5, 11.5.2; sev high)

## rsyslog* (3)
- `rsyslog_files_groupownership` — Ensure Log Files Are Owned By Appropriate Group (PCI Req-10.5.1, Req-10.5.2, 10.3.2, 10.3; sev medium)
- `rsyslog_files_ownership` — Ensure Log Files Are Owned By Appropriate User (PCI Req-10.5.1, Req-10.5.2, 10.3.2, 10.3; sev medium)
- `rsyslog_files_permissions` — Ensure System Log Files Have Correct Permissions (PCI Req-10.5.1, Req-10.5.2, 10.3.1, 10.3; sev medium)

## security* (1)
- `security_patches_up_to_date` — Ensure Software Patches Installed (PCI Req-6.2, 6.3.3, 6.3; sev medium)

## set* (1)
- `set_password_hashing_algorithm_systemauth` — Set PAM Password Hashing Algorithm - system-auth (PCI Req-8.2.1, 8.3.2, 8.3; sev medium)

## sudo* (1)
- `sudo_require_authentication` — Ensure Users Re-Authenticate for Privilege Escalation - sudo (PCI 2.2.6, 2.2; sev medium)

## wireless* (1)
- `wireless_disable_interfaces` — Deactivate Wireless Network Interfaces (PCI Req-1.3.3, 1.3.3, 1.3; sev medium)
