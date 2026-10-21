# Unmapped rules — xccdf_org.ssgproject.content_profile_pci-dss-4

Generated 2026-10-21T04:10:00+00:00 from `ssg-sle15-ds.xml`.

15 selected rule(s) have **no native Salt handler** and were skipped (native-only mode). Add a mapper in `scap2salt.py` or handle these via a separate reviewed state.

## accounts* (2)
- `accounts_passwords_pam_tally2` — Set Deny For Failed Password Attempts (PCI Req-8.1.6, 8.3.4, 8.3; sev medium)
- `accounts_passwords_pam_tally2_unlock_time` — Set Lockout Time for Failed Password Attempts using pam_tally2 (PCI Req-8.1.7, 8.3.4, 8.3; sev medium)

## dconf* (2)
- `dconf_db_up_to_date` — Make sure that the dconf databases are up-to-date with regards to respective keyfiles (PCI Req-6.2, 8.2.8, 8.2; sev high)
- `dconf_gnome_session_idle_user_locks` — Ensure Users Cannot Change GNOME3 Session Idle Settings (PCI Req-8.1.8, 8.2.8, 8.2; sev medium)

## dir* (1)
- `dir_perms_world_writable_sticky_bits` — Verify that All World-Writable Directories Have Sticky Bits Set (PCI 2.2.6, 2.2; sev medium)

## display* (1)
- `display_login_attempts` — Ensure PAM Displays Last Logon/Access Notification (PCI Req-10.2.4, 10.2.1.4, 10.2.1, 10.2; sev low)

## enable* (1)
- `enable_dconf_user_profile` — Configure GNOME3 DConf User Profile (PCI 8.2.8, 8.2; sev high)

## file* (1)
- `file_permissions_unauthorized_world_writable` — Ensure No World-Writable Files Exist (PCI 2.2.6, 2.2; sev medium)

## network* (1)
- `network_sniffer_disabled` — Ensure System is Not Acting as a Network Sniffer (PCI 1.4.5, 1.4; sev medium)

## rpm* (1)
- `rpm_verify_hashes` — Verify File Hashes with RPM (PCI Req-11.5, 11.5.2; sev high)

## rsyslog* (3)
- `rsyslog_files_groupownership` — Ensure Log Files Are Owned By Appropriate Group (PCI Req-10.5.1, Req-10.5.2, 10.3.2, 10.3; sev medium)
- `rsyslog_files_ownership` — Ensure Log Files Are Owned By Appropriate User (PCI Req-10.5.1, Req-10.5.2, 10.3.2, 10.3; sev medium)
- `rsyslog_files_permissions` — Ensure System Log Files Have Correct Permissions (PCI Req-10.5.1, Req-10.5.2, 10.3.1, 10.3; sev medium)

## security* (1)
- `security_patches_up_to_date` — Ensure Software Patches Installed (PCI Req-6.2, 6.3.3, 6.3; sev medium)

## wireless* (1)
- `wireless_disable_interfaces` — Deactivate Wireless Network Interfaces (PCI Req-1.3.3, 1.3.3, 1.3; sev medium)
