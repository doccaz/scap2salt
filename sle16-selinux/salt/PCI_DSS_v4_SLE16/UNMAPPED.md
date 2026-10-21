# Unmapped rules — xccdf_org.ssgproject.content_profile_pci-dss-4

Generated 2026-10-21T19:12:01+00:00 from `ssg-sle16-ds.xml`.

7 selected rule(s) have **no native Salt handler** and were skipped (native-only mode). Add a mapper in `scap2salt.py` or handle these via a separate reviewed state.

## dir* (1)
- `dir_perms_world_writable_sticky_bits` — Verify that All World-Writable Directories Have Sticky Bits Set (PCI 2.2.6, 2.2; sev medium)

## display* (1)
- `display_login_attempts` — Ensure PAM Displays Last Logon/Access Notification (PCI Req-10.2.4, 10.2.1.4, 10.2.1, 10.2; sev low)

## file* (1)
- `file_permissions_unauthorized_world_writable` — Ensure No World-Writable Files Exist (PCI 2.2.6, 2.2; sev medium)

## network* (1)
- `network_sniffer_disabled` — Ensure System is Not Acting as a Network Sniffer (PCI 1.4.5, 1.4; sev medium)

## rpm* (1)
- `rpm_verify_hashes` — Verify File Hashes with RPM (PCI Req-11.5, 11.5.2; sev high)

## security* (1)
- `security_patches_up_to_date` — Ensure Software Patches Installed (PCI Req-6.2, 6.3.3, 6.3; sev medium)

## wireless* (1)
- `wireless_disable_interfaces` — Deactivate Wireless Network Interfaces (PCI Req-1.3.3, 1.3.3, 1.3; sev medium)
