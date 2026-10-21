# Unmapped rules — xccdf_org.ssgproject.content_profile_pci-dss-4

Generated 2026-10-21T20:52:41+00:00 from `ssg-sle16-ds.xml`.

6 selected rule(s) have **no native Salt handler** and were skipped (native-only mode). Add a mapper in `scap2salt.py` or handle these via a separate reviewed state.

## display* (1)
- `display_login_attempts` — Ensure PAM Displays Last Logon/Access Notification (PCI Req-10.2.4, 10.2.1.4, 10.2.1, 10.2; sev low)
  - unsatisfiable: the upstream fix only edits `pam_lastlog2` (authselect), which SLE 15 and SLE 16 do not use (SLE 16 uses `pam_wtmpdb`), so the remediation is a no-op and the rule cannot pass.

## file* (1)
- `file_permissions_unauthorized_world_writable` — Ensure No World-Writable Files Exist (PCI 2.2.6, 2.2; sev medium)
  - unsafe: strips `o+w` from every regular file on every local filesystem. That can break applications that rely on world-writable files; fix the offenders it reports (`find / -xdev -type f -perm -002`) case by case.

## network* (1)
- `network_sniffer_disabled` — Ensure System is Not Acting as a Network Sniffer (PCI 1.4.5, 1.4; sev medium)
  - unsafe: turns promiscuous mode and multicast off on every interface (`ip link set ... promisc off`), which breaks bridges, container/VM networking and packet capture. Hosts that must not sniff should be fixed by design.

## rpm* (1)
- `rpm_verify_hashes` — Verify File Hashes with RPM (PCI Req-11.5, 11.5.2; sev high)
  - unsafe: the upstream fix reinstalls every package whose files fail `rpm -Va` (`zypper install -f`), which can overwrite legitimate local changes. Review `rpm -Va --noconfig` by hand.

## security* (1)
- `security_patches_up_to_date` — Ensure Software Patches Installed (PCI Req-6.2, 6.3.3, 6.3; sev medium)
  - unsafe: the upstream fix runs `zypper patch -g security`. Patching during a highstate can restart services or require a reboot, and patch management belongs in MLM (channels, CLM, scheduled patch jobs).

## wireless* (1)
- `wireless_disable_interfaces` — Deactivate Wireless Network Interfaces (PCI Req-1.3.3, 1.3.3, 1.3; sev medium)
  - unsafe/site-specific: installs NetworkManager and switches radios off (`nmcli radio all off`), changing the network stack. Servers without wireless hardware already comply; handle wireless hosts individually.
