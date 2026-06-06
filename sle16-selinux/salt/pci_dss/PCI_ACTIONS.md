# PCI-DSS v4 — actions reference

Generated 2026-06-06T17:44:33+00:00 from `ssg-sle16-ds.xml` (profile `xccdf_org.ssgproject.content_profile_pci-dss-4`, MAC: selinux).

Every rule this formula enforces, with its PCI-DSS reference and the concrete action. Sections match the toggles in the MLM Formulas form; the **accounts** category is opt-in (default off).

## Kernel parameters (sysctl) (`sysctl`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `sysctl_fs_suid_dumpable`<br><sub>Disable Core Dumps for SUID programs</sub> | medium | 3.3.1.1, 3.3.1, 3.3 | sysctl `fs.suid_dumpable` = `0` |
| `sysctl_kernel_randomize_va_space`<br><sub>Enable Randomized Layout of Virtual Address Space</sub> | medium | Req-2.2.1, 3.3.1.1, 3.3.1, 3.3 | sysctl `kernel.randomize_va_space` = `2` |
| `sysctl_net_ipv4_conf_all_rp_filter`<br><sub>Enable Kernel Parameter to Use Reverse Path Filtering on all IPv4 Interfaces</sub> | medium | Req-1.4.3, 1.4.3, 1.4 | sysctl `net.ipv4.conf.all.rp_filter` = `1` |
| `sysctl_net_ipv4_conf_all_secure_redirects`<br><sub>Disable Kernel Parameter for Accepting Secure ICMP Redirects on all IPv4 Interfaces</sub> | medium | Req-1.4.3, 1.4.3, 1.4 | sysctl `net.ipv4.conf.all.secure_redirects` = `0` |
| `sysctl_net_ipv4_conf_all_send_redirects`<br><sub>Disable Kernel Parameter for Sending ICMP Redirects on all IPv4 Interfaces</sub> | medium | 1.4.5, 1.4 | sysctl `net.ipv4.conf.all.send_redirects` = `0` |
| `sysctl_net_ipv4_conf_default_accept_redirects`<br><sub>Disable Kernel Parameter for Accepting ICMP Redirects by Default on IPv4 Interfaces</sub> | medium | Req-1.4.3, 1.4.3, 1.4 | sysctl `net.ipv4.conf.default.accept_redirects` = `0` |
| `sysctl_net_ipv4_conf_default_send_redirects`<br><sub>Disable Kernel Parameter for Sending ICMP Redirects on all IPv4 Interfaces by Default</sub> | medium | 1.4.5, 1.4 | sysctl `net.ipv4.conf.default.send_redirects` = `0` |
| `sysctl_net_ipv4_icmp_echo_ignore_broadcasts`<br><sub>Enable Kernel Parameter to Ignore ICMP Broadcast Echo Requests on IPv4 Interfaces</sub> | medium | Req-1.4.3, 1.4.2, 1.4 | sysctl `net.ipv4.icmp_echo_ignore_broadcasts` = `1` |
| `sysctl_net_ipv4_icmp_ignore_bogus_error_responses`<br><sub>Enable Kernel Parameter to Ignore Bogus ICMP Error Responses on IPv4 Interfaces</sub> | unknown | Req-1.4.3, 1.4.2, 1.4 | sysctl `net.ipv4.icmp_ignore_bogus_error_responses` = `1` |
| `sysctl_net_ipv4_ip_forward`<br><sub>Disable Kernel Parameter for IP Forwarding on IPv4 Interfaces</sub> | medium | Req-1.3.1, Req-1.3.2, 1.4.3, 1.4 | sysctl `net.ipv4.ip_forward` = `0` |
| `sysctl_net_ipv4_tcp_syncookies`<br><sub>Enable Kernel Parameter to Use TCP Syncookies on Network Interfaces</sub> | medium | Req-1.4.1, 1.4.3, 1.4 | sysctl `net.ipv4.tcp_syncookies` = `1` |
| `sysctl_net_ipv6_conf_default_accept_source_route`<br><sub>Disable Kernel Parameter for Accepting Source-Routed Packets on IPv6 Interfaces by Default</sub> | medium | Req-1.4.3, 1.4.2, 1.4 | sysctl `net.ipv6.conf.default.accept_source_route` = `0` |

## Package install / removal (`packages`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `package_aide_installed`<br><sub>Install AIDE</sub> | medium | Req-11.5, 11.5.2 | install package `aide` |
| `package_audit-audispd-plugins_installed`<br><sub>Ensure the default plugins for the audit dispatcher are Installed</sub> | medium | Req-10.5.3, 10.3.3, 10.3 | install package `audit-audispd-plugins` |
| `package_audit_installed`<br><sub>Ensure the audit Subsystem is Installed</sub> | medium | Req-10.1, 10.2.1, 10.2 | install package `audit` |
| `package_chrony_installed`<br><sub>The Chrony package is installed</sub> | medium | Req-10.4, 10.6.1, 10.6 | install package `chrony` |
| `package_cron_installed`<br><sub>Install the cron service</sub> | medium | 2.2.6, 2.2 | install package `cronie` |
| `package_dhcp_removed`<br><sub>Uninstall DHCP Server Package</sub> | medium | 2.2.4, 2.2 | remove package `dhcp` |
| `package_firewalld_installed`<br><sub>Install firewalld Package</sub> | medium | 1.2.1, 1.2 | install package `firewalld` |
| `package_libselinux_installed`<br><sub>Install libselinux Package</sub> | high | 1.2.6, 1.2 | install package `libselinux1` |
| `package_logrotate_installed`<br><sub>Ensure logrotate is Installed</sub> | medium | Req-10.7, 10.5.1, 10.5 | install package `logrotate` |
| `package_net-snmp_removed`<br><sub>Uninstall net-snmp Package</sub> | unknown | 2.2.4, 2.2 | remove package `net-snmp` |
| `package_nftables_installed`<br><sub>Install nftables Package</sub> | medium | 1.2.1, 1.2 | install package `nftables` |
| `package_postfix_installed`<br><sub>The Postfix package is installed</sub> | medium | 10.5.1, 10.5 | install package `postfix` |
| `package_sudo_installed`<br><sub>Install sudo Package</sub> | medium | 2.2.6, 2.2 | install package `sudo` |
| `package_telnet-server_removed`<br><sub>Uninstall telnet-server Package</sub> | high | Req-2.2.2, 2.2.4, 2.2 | remove package `telnet-server` |
| `package_telnet_removed`<br><sub>Remove telnet Clients</sub> | low | 2.2.4, 2.2 | remove package `telnet` |
| `package_tftp-server_removed`<br><sub>Uninstall tftp Package</sub> | high | 2.2.4, 2.2 | remove package `tftp` |
| `package_tftp_removed`<br><sub>Remove tftp Daemon</sub> | low | 2.2.4, 2.2 | remove package `tftp` |

## Package signatures & verification (RPM/GPG) (`rpm`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `ensure_gpgcheck_globally_activated`<br><sub>Ensure gpgcheck Enabled In Main zypper Configuration</sub> | high | Req-6.2, 6.3.3, 6.3 | line in `/etc/zypp/zypp.conf`: `gpgcheck = 1` |
| `ensure_gpgcheck_never_disabled`<br><sub>Ensure gpgcheck Enabled for All zypper Package Repositories</sub> | high | Req-6.2, 6.3.3, 6.3 | operational cmd: `sed -ri 's/^([[:space:]]*)(repo_|pkg_)?gpgcheck[[:space:]]*=[[:space:]]*(0|off)/\1\2gpg…` |
| `ensure_suse_gpgkey_installed`<br><sub>Ensure SUSE GPG Key Installed</sub> | high | Req-6.2, 6.3.3, 6.3 | operational cmd: `for k in /usr/lib/rpm/gpg/*; do rpm --import "$k" 2>/dev/null || true; done` |
| `rpm_verify_ownership`<br><sub>Verify and Correct Ownership with RPM</sub> | high | Req-11.5, 11.5.2 | operational cmd: `rpm -qa | xargs -r -n1 rpm --setugids 2>/dev/null || true` |

## Service enable / disable (`services`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `service_auditd_enabled`<br><sub>Enable auditd Service</sub> | medium | Req-10.1, 10.2.1, 10.2 | enable + start `auditd` |
| `service_avahi-daemon_disabled`<br><sub>Disable Avahi Server Software</sub> | medium | 2.2.4, 2.2 | disable + stop `avahi-daemon` |
| `service_chronyd_or_ntpd_enabled`<br><sub>Enable the NTP Daemon</sub> | medium | Req-10.4.1, 10.6.1, 10.6 | enable + start `chronyd` |
| `service_firewalld_enabled`<br><sub>Verify firewalld Enabled</sub> | medium | 1.2.1, 1.2 | enable + start `firewalld` |
| `service_nftables_disabled`<br><sub>Verify nftables Service is Disabled</sub> | medium | 1.2.1, 1.2 | disable + stop `nftables` |
| `service_rpcbind_disabled`<br><sub>Disable rpcbind Service</sub> | low | 2.2.4, 2.2 | disable + stop `rpcbind` |
| `service_rsyncd_disabled`<br><sub>Ensure rsyncd service is disabled</sub> | medium | 2.2.4, 2.2 | disable + stop `rsyncd` |
| `timer_logrotate_enabled`<br><sub>Enable logrotate Timer</sub> | medium | Req-10.7, 10.5.1, 10.5 | enable + start `logrotate.timer` |

## File permissions & ownership (`permissions`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `file_at_deny_not_exist`<br><sub>Ensure that /etc/at.deny does not exist</sub> | medium | 2.2.6, 2.2 | ensure `/etc/at.deny` absent |
| `file_cron_deny_not_exist`<br><sub>Ensure that /etc/cron.deny does not exist</sub> | medium | 2.2.6, 2.2 | ensure `/etc/cron.deny` absent |
| `file_groupowner_at_allow`<br><sub>Verify Group Who Owns /etc/at.allow file</sub> | medium | 2.2.6, 2.2 | manage `/etc/at.allow` |
| `file_groupowner_backup_etc_group`<br><sub>Verify Group Who Owns Backup group File</sub> | medium | Req-8.7, 2.2.6, 2.2 | manage `/etc/group-` |
| `file_groupowner_backup_etc_passwd`<br><sub>Verify Group Who Owns Backup passwd File</sub> | medium | Req-8.7, 2.2.6, 2.2 | manage `/etc/passwd-` |
| `file_groupowner_backup_etc_shadow`<br><sub>Verify User Who Owns Backup shadow File</sub> | medium | Req-8.7, 2.2.6, 2.2 | manage `/etc/shadow-` |
| `file_groupowner_cron_allow`<br><sub>Verify Group Who Owns /etc/cron.allow file</sub> | medium | 2.2.6, 2.2 | manage `/etc/cron.allow` |
| `file_groupowner_cron_d`<br><sub>Verify Group Who Owns cron.d</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.d` |
| `file_groupowner_cron_daily`<br><sub>Verify Group Who Owns cron.daily</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.daily` |
| `file_groupowner_cron_hourly`<br><sub>Verify Group Who Owns cron.hourly</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.hourly` |
| `file_groupowner_cron_monthly`<br><sub>Verify Group Who Owns cron.monthly</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.monthly` |
| `file_groupowner_cron_weekly`<br><sub>Verify Group Who Owns cron.weekly</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.weekly` |
| `file_groupowner_crontab`<br><sub>Verify Group Who Owns Crontab</sub> | medium | 2.2.6, 2.2 | manage `/etc/crontab` |
| `file_groupowner_etc_group`<br><sub>Verify Group Who Owns group File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/group` |
| `file_groupowner_etc_issue_net`<br><sub>Verify Group Ownership of System Login Banner for Remote Connections</sub> | medium | 1.2.8, 1.2 | manage `/etc/issue.net` |
| `file_groupowner_etc_passwd`<br><sub>Verify Group Who Owns passwd File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/passwd` |
| `file_groupowner_etc_shadow`<br><sub>Verify Group Who Owns shadow File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/shadow` |
| `file_groupowner_grub2_cfg`<br><sub>Verify /boot/grub2/grub.cfg Group Ownership</sub> | medium | Req-7.1, 2.2.6, 2.2 | manage `/boot/grub2/grub.cfg` |
| `file_owner_at_allow`<br><sub>Verify User Who Owns /etc/at.allow file</sub> | medium | 2.2.6, 2.2 | manage `/etc/at.allow` |
| `file_owner_backup_etc_group`<br><sub>Verify User Who Owns Backup group File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/group-` |
| `file_owner_backup_etc_passwd`<br><sub>Verify User Who Owns Backup passwd File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/passwd-` |
| `file_owner_backup_etc_shadow`<br><sub>Verify Group Who Owns Backup shadow File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/shadow-` |
| `file_owner_cron_allow`<br><sub>Verify User Who Owns /etc/cron.allow file</sub> | medium | 2.2.6, 2.2 | manage `/etc/cron.allow` |
| `file_owner_cron_d`<br><sub>Verify Owner on cron.d</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.d` |
| `file_owner_cron_daily`<br><sub>Verify Owner on cron.daily</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.daily` |
| `file_owner_cron_hourly`<br><sub>Verify Owner on cron.hourly</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.hourly` |
| `file_owner_cron_monthly`<br><sub>Verify Owner on cron.monthly</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.monthly` |
| `file_owner_cron_weekly`<br><sub>Verify Owner on cron.weekly</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.weekly` |
| `file_owner_crontab`<br><sub>Verify Owner on crontab</sub> | medium | 2.2.6, 2.2 | manage `/etc/crontab` |
| `file_owner_etc_group`<br><sub>Verify User Who Owns group File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/group` |
| `file_owner_etc_issue_net`<br><sub>Verify ownership of System Login Banner for Remote Connections</sub> | medium | 1.2.8, 1.2 | manage `/etc/issue.net` |
| `file_owner_etc_passwd`<br><sub>Verify User Who Owns passwd File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/passwd` |
| `file_owner_etc_shadow`<br><sub>Verify User Who Owns shadow File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/shadow` |
| `file_owner_grub2_cfg`<br><sub>Verify /boot/grub2/grub.cfg User Ownership</sub> | medium | Req-7.1, 2.2.6, 2.2 | manage `/boot/grub2/grub.cfg` |
| `file_permissions_at_allow`<br><sub>Verify Permissions on /etc/at.allow file</sub> | medium | 2.2.6, 2.2 | manage `/etc/at.allow` (mode 0640) |
| `file_permissions_backup_etc_group`<br><sub>Verify Permissions on Backup group File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/group-` (mode 0644) |
| `file_permissions_backup_etc_passwd`<br><sub>Verify Permissions on Backup passwd File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/passwd-` (mode 0644) |
| `file_permissions_backup_etc_shadow`<br><sub>Verify Permissions on Backup shadow File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/shadow-` (mode 0000) |
| `file_permissions_cron_allow`<br><sub>Verify Permissions on /etc/cron.allow file</sub> | medium | 2.2.6, 2.2 | manage `/etc/cron.allow` (mode 0640) |
| `file_permissions_cron_d`<br><sub>Verify Permissions on cron.d</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.d` (mode 0700) |
| `file_permissions_cron_daily`<br><sub>Verify Permissions on cron.daily</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.daily` (mode 0700) |
| `file_permissions_cron_hourly`<br><sub>Verify Permissions on cron.hourly</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.hourly` (mode 0700) |
| `file_permissions_cron_monthly`<br><sub>Verify Permissions on cron.monthly</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.monthly` (mode 0700) |
| `file_permissions_cron_weekly`<br><sub>Verify Permissions on cron.weekly</sub> | medium | 2.2.6, 2.2 | dir `/etc/cron.weekly` (mode 0700) |
| `file_permissions_crontab`<br><sub>Verify Permissions on crontab</sub> | medium | 2.2.6, 2.2 | manage `/etc/crontab` (mode 0600) |
| `file_permissions_etc_group`<br><sub>Verify Permissions on group File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/group` (mode 0644) |
| `file_permissions_etc_issue_net`<br><sub>Verify permissions on System Login Banner for Remote Connections</sub> | medium | 1.2.8, 1.2 | manage `/etc/issue.net` (mode 0644) |
| `file_permissions_etc_passwd`<br><sub>Verify Permissions on passwd File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/passwd` (mode 0644) |
| `file_permissions_etc_shadow`<br><sub>Verify Permissions on shadow File</sub> | medium | Req-8.7.c, 2.2.6, 2.2 | manage `/etc/shadow` (mode 0000) |
| `file_permissions_grub2_cfg`<br><sub>Verify /boot/grub2/grub.cfg Permissions</sub> | medium | 2.2.6, 2.2 | manage `/boot/grub2/grub.cfg` (mode 0600) |
| `file_permissions_sshd_config`<br><sub>Verify Permissions on SSH Server config file</sub> | medium | 2.2.6, 2.2 | manage `/etc/ssh/sshd_config` (mode 0600) |
| `permissions_local_var_log`<br><sub>Verify permissions of log files</sub> | medium | 10.3.1, 10.3 | operational cmd: `find /var/log/ -perm /u+xs,g+xws,o+xwrt -type f -exec chmod u-xs,g-xws,o-xwrt {} +` |

## Disabled kernel modules (`kernel_modules`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `kernel_module_dccp_disabled`<br><sub>Disable DCCP Support</sub> | medium | Req-1.4.2, 1.4.2, 1.4 | manage `/etc/modprobe.d/dccp.conf` (mode 0644) |
| `kernel_module_sctp_disabled`<br><sub>Disable SCTP Support</sub> | medium | Req-1.4.2, 1.4.2, 1.4 | manage `/etc/modprobe.d/sctp.conf` (mode 0644) |
| `kernel_module_usb-storage_disabled`<br><sub>Disable Modprobe Loading of USB Storage Driver</sub> | medium | 3.4.2, 3.4 | manage `/etc/modprobe.d/usb-storage.conf` (mode 0644) |

## SSH server hardening (`sshd`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `sshd_disable_empty_passwords`<br><sub>Disable SSH Access via Empty Passwords</sub> | high | Req-2.2.4, 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `PermitEmptyPasswords no` |
| `sshd_disable_rhosts`<br><sub>Disable SSH Support for .rhosts Files</sub> | medium | 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `IgnoreRhosts yes` |
| `sshd_disable_root_login`<br><sub>Disable SSH Root Login</sub> | medium | Req-2.2.4, 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `PermitRootLogin no` |
| `sshd_disable_tcp_forwarding`<br><sub>Disable SSH TCP Forwarding</sub> | medium | 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `AllowTcpForwarding no` |
| `sshd_disable_x11_forwarding`<br><sub>Disable X11 Forwarding</sub> | medium | 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `X11Forwarding no` |
| `sshd_do_not_permit_user_env`<br><sub>Do Not Allow SSH Environment Options</sub> | medium | Req-2.2.4, 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `PermitUserEnvironment no` |
| `sshd_enable_pam`<br><sub>Enable PAM</sub> | medium | 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `UsePAM yes` |
| `sshd_set_idle_timeout`<br><sub>Set SSH Client Alive Interval</sub> | medium | Req-8.1.8, 8.2.8, 8.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `ClientAliveInterval 900` |
| `sshd_set_keepalive`<br><sub>Set SSH Client Alive Count Max</sub> | medium | Req-8.1.8, 8.2.8, 8.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `ClientAliveCountMax 1` |
| `sshd_set_login_grace_time`<br><sub>Ensure SSH LoginGraceTime is configured</sub> | medium | 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `LoginGraceTime 60` |
| `sshd_set_loglevel_verbose`<br><sub>Set SSH Daemon LogLevel to VERBOSE</sub> | medium | Req-2.2.4, 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `LogLevel VERBOSE` |
| `sshd_set_max_auth_tries`<br><sub>Set SSH authentication attempt limit</sub> | medium | 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `MaxAuthTries 4` |
| `sshd_set_max_sessions`<br><sub>Set SSH MaxSessions limit</sub> | medium | 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `MaxSessions 10` |
| `sshd_set_maxstartups`<br><sub>Ensure SSH MaxStartups is configured</sub> | medium | 2.2.6, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `MaxStartups 10:30:100` |
| `sshd_use_strong_kex`<br><sub>Use Only Strong Key Exchange algorithms</sub> | medium | Req-2.3, 2.2.7, 2.2 | line in `/etc/ssh/sshd_config.d/00-pci-hardening.conf`: `KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256` |

## Config-file settings (login.defs, securetty…) (`lineinfile`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `account_disable_post_pw_expiration`<br><sub>Set Account Expiration Following Inactivity</sub> | medium | Req-8.1.4, 8.2.6, 8.2 | line in `/etc/default/useradd`: `INACTIVE=90` |
| `accounts_maximum_age_login_defs`<br><sub>Set Password Maximum Age</sub> | medium | Req-8.2.4, 8.3.9, 8.3 | line in `/etc/login.defs`: `PASS_MAX_DAYS 90` |
| `accounts_password_warn_age_login_defs`<br><sub>Set Password Warning Age</sub> | medium | Req-8.2.4, 8.3.9, 8.3 | line in `/etc/login.defs.d/oscap.login.defs`: `PASS_WARN_AGE 7` |
| `accounts_tmout`<br><sub>Set Interactive Session Timeout</sub> | medium | 8.6.1, 8.6 | manage `/etc/profile.d/autologout.sh` (mode 0755) |
| `chronyd_run_as_chrony_user`<br><sub>Ensure that chronyd is running under chrony user account</sub> | medium | 10.6.3, 10.6 | line in `/etc/sysconfig/chronyd`: `OPTIONS="-u chrony"` |
| `chronyd_specify_remote_server`<br><sub>A remote time server for Chrony is configured</sub> | medium | Req-10.4.3, 10.6.2, 10.6 | line in `/etc/chrony.conf`: `\g<0>` |
| `disable_host_auth`<br><sub>Disable Host-Based Authentication</sub> | medium | 8.3.1, 8.3 | line in `/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf`: `HostbasedAuthentication no` |
| `no_direct_root_logins`<br><sub>Direct root Logins Not Allowed</sub> | medium | 8.6.1, 8.6 | manage `/etc/securetty` (mode 0600) |
| `postfix_network_listening_disabled`<br><sub>Disable Postfix Network Listening</sub> | medium | 1.4.2, 1.4 | line in `/etc/postfix/main.cf`: `inet_interfaces=loopback-only` |
| `securetty_root_login_console_only`<br><sub>Restrict Virtual Console Root Logins</sub> | medium | 8.6.1, 8.6 | edit `/etc/securetty` |
| `set_password_hashing_algorithm_logindefs`<br><sub>Set Password Hashing Algorithm in /etc/login.defs</sub> | medium | Req-8.2.1, 8.3.2, 8.3 | line in `/etc/login.defs.d/oscap.login.defs`: `ENCRYPT_METHOD SHA512` |

## Invasive auth hardening: password aging + sudo re-auth (opt-in) (`accounts`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `accounts_password_set_max_life_existing`<br><sub>Set Existing Passwords Maximum Age</sub> | medium | 8.3.9, 8.3 | operational cmd: `awk -v var=90 -F: '(/^[^:]+:[^!*]/ && ($5 > var || $5 == "")) {print $1}' /etc/shadow |…` |
| `accounts_password_set_warn_age_existing`<br><sub>Set Existing Passwords Warning Age</sub> | medium | 8.3.9, 8.3 | operational cmd: `awk -v var=7 -F: '(($6 < var || $6 == "") && $2 ~ /^\$/) {print $1}' /etc/shadow | whil…` |
| `accounts_set_post_pw_existing`<br><sub>Set existing passwords a period of inactivity before they been locked</sub> | medium | Req-8.1.4, 8.2.6, 8.2 | operational cmd: `awk -v var=90 -F: '(($7 > var || $7 == "") && $2 ~ /^\$/) {print $1}' /etc/shadow | whi…` |
| `sudo_require_authentication`<br><sub>Ensure Users Re-Authenticate for Privilege Escalation - sudo</sub> | medium | 2.2.6, 2.2 | operational cmd: `for f in /etc/sudoers /etc/sudoers.d/*; do [ -e "$f" ] || continue; sed -ri '/^[[:space…` |

## PAM module arguments (pwquality, pam_unix, pam_wheel) (`pam`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `set_password_hashing_algorithm_commonauth`<br><sub>Set PAM's Common Authentication Hashing Algorithm</sub> | medium | Req-8.2.1, 8.3.2, 8.3 | operational cmd: `f=/etc/pam.d/common-auth; grep -qE "^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+…` |
| `use_pam_wheel_group_for_su`<br><sub>Enforce Usage of pam_wheel with Group Parameter for su Authentication</sub> | medium | 2.2.6, 2.2 | operational cmd: `f=/etc/pam.d/su; grep -qE "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.…` |

## Sudo defaults (sudoers.d drop-ins) (`sudo`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `sudo_add_use_pty`<br><sub>Ensure Only Users Logged In To Real tty Can Execute Sudo - sudo use_pty</sub> | medium | Req-10.2.5, 2.2.6, 2.2 | manage `/etc/sudoers.d/99-pci-sudo_add_use_pty` (mode 0440) |
| `sudo_custom_logfile`<br><sub>Ensure Sudo Logfile Exists - sudo logfile</sub> | low | Req-10.2.5, 2.2.6, 2.2 | manage `/etc/sudoers.d/99-pci-sudo_custom_logfile` (mode 0440) |
| `sudo_require_reauthentication`<br><sub>Require Re-Authentication When Using the sudo Command</sub> | medium | 2.2.6, 2.2 | manage `/etc/sudoers.d/99-pci-sudo_require_reauthentication` (mode 0440) |

## Audit rules & auditd configuration (`audit`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `audit_rules_dac_modification_chmod`<br><sub>Record Events that Modify the System's Discretionary Access Controls - chmod</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_chmod.rules` (mode 0640) |
| `audit_rules_dac_modification_chown`<br><sub>Record Events that Modify the System's Discretionary Access Controls - chown</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_chown.rules` (mode 0640) |
| `audit_rules_dac_modification_fchmod`<br><sub>Record Events that Modify the System's Discretionary Access Controls - fchmod</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_fchmod.rules` (mode 0640) |
| `audit_rules_dac_modification_fchmodat`<br><sub>Record Events that Modify the System's Discretionary Access Controls - fchmodat</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_fchmodat.rules` (mode 0640) |
| `audit_rules_dac_modification_fchown`<br><sub>Record Events that Modify the System's Discretionary Access Controls - fchown</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_fchown.rules` (mode 0640) |
| `audit_rules_dac_modification_fchownat`<br><sub>Record Events that Modify the System's Discretionary Access Controls - fchownat</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_fchownat.rules` (mode 0640) |
| `audit_rules_dac_modification_fremovexattr`<br><sub>Record Events that Modify the System's Discretionary Access Controls - fremovexattr</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_fremovexattr.rules` (mode 0640) |
| `audit_rules_dac_modification_fsetxattr`<br><sub>Record Events that Modify the System's Discretionary Access Controls - fsetxattr</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_fsetxattr.rules` (mode 0640) |
| `audit_rules_dac_modification_lchown`<br><sub>Record Events that Modify the System's Discretionary Access Controls - lchown</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_lchown.rules` (mode 0640) |
| `audit_rules_dac_modification_lremovexattr`<br><sub>Record Events that Modify the System's Discretionary Access Controls - lremovexattr</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_lremovexattr.rules` (mode 0640) |
| `audit_rules_dac_modification_lsetxattr`<br><sub>Record Events that Modify the System's Discretionary Access Controls - lsetxattr</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_lsetxattr.rules` (mode 0640) |
| `audit_rules_dac_modification_removexattr`<br><sub>Record Events that Modify the System's Discretionary Access Controls - removexattr</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_removexattr.rules` (mode 0640) |
| `audit_rules_dac_modification_setxattr`<br><sub>Record Events that Modify the System's Discretionary Access Controls - setxattr</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_dac_modification_setxattr.rules` (mode 0640) |
| `audit_rules_enable_syscall_auditing`<br><sub>Remove Default Configuration to Disable Syscall Auditing</sub> | medium | SRG-OS-000480-GPOS-00227, SLES-16-16016520 | operational cmd: `sed -ri 's/^([[:space:]]*-a[[:space:]]+task,never)/#\1/' /etc/audit/rules.d/*.rules` |
| `audit_rules_file_deletion_events_rename`<br><sub>Ensure auditd Collects File Deletion Events by User - rename</sub> | medium | Req-10.2.7, 10.2.1.7, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_file_deletion_events_rename.rules` (mode 0640) |
| `audit_rules_file_deletion_events_renameat`<br><sub>Ensure auditd Collects File Deletion Events by User - renameat</sub> | medium | Req-10.2.7, 10.2.1.7, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_file_deletion_events_renameat.rules` (mode 0640) |
| `audit_rules_file_deletion_events_renameat2`<br><sub>Ensure auditd Collects File Deletion Events by User - renameat2</sub> | medium | 10.2.1.7, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_file_deletion_events_renameat2.rules` (mode 0640) |
| `audit_rules_file_deletion_events_rmdir`<br><sub>Ensure auditd Collects File Deletion Events by User - rmdir</sub> | medium | Req-10.2.7, 10.2.1.7, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_file_deletion_events_rmdir.rules` (mode 0640) |
| `audit_rules_file_deletion_events_unlink`<br><sub>Ensure auditd Collects File Deletion Events by User - unlink</sub> | medium | Req-10.2.7, 10.2.1.7, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_file_deletion_events_unlink.rules` (mode 0640) |
| `audit_rules_file_deletion_events_unlinkat`<br><sub>Ensure auditd Collects File Deletion Events by User - unlinkat</sub> | medium | Req-10.2.7, 10.2.1.7, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_file_deletion_events_unlinkat.rules` (mode 0640) |
| `audit_rules_immutable`<br><sub>Make the auditd Configuration Immutable</sub> | medium | Req-10.5.2, 10.3.2, 10.3 | manage `/etc/audit/rules.d/zz-pci-immutable.rules` (mode 0640) |
| `audit_rules_login_events_faillock`<br><sub>Record Attempts to Alter Logon and Logout Events - faillock</sub> | medium | Req-10.2.3, 10.2.1.3, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_login_events_faillock.rules` (mode 0640) |
| `audit_rules_login_events_lastlog`<br><sub>Record Attempts to Alter Logon and Logout Events - lastlog</sub> | medium | Req-10.2.3, 10.2.1.3, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_login_events_lastlog.rules` (mode 0640) |
| `audit_rules_mac_modification`<br><sub>Record Events that Modify the System's Mandatory Access Controls</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_mac_modification.rules` (mode 0640) |
| `audit_rules_mac_modification_etc_selinux`<br><sub>Record Events that Modify the System's Mandatory Access Controls (/etc/selinux)</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_mac_modification_etc_selinux.rules` (mode 0640) |
| `audit_rules_media_export`<br><sub>Ensure auditd Collects Information on Exporting to Media (successful)</sub> | medium | Req-10.2.7, 10.2.1.7, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_media_export.rules` (mode 0640) |
| `audit_rules_networkconfig_modification`<br><sub>Record Events that Modify the System's Network Environment</sub> | medium | Req-10.5.5, 10.3.4, 10.3 | manage `/etc/audit/rules.d/pci-audit_rules_networkconfig_modification.rules` (mode 0640) |
| `audit_rules_session_events_btmp`<br><sub>Record Attempts to Alter Process and Session Initiation Information btmp</sub> | medium | 10.2.1.3, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_session_events_btmp.rules` (mode 0640) |
| `audit_rules_session_events_utmp`<br><sub>Record Attempts to Alter Process and Session Initiation Information utmp</sub> | medium | 10.2.1.3, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_session_events_utmp.rules` (mode 0640) |
| `audit_rules_session_events_wtmp`<br><sub>Record Attempts to Alter Process and Session Initiation Information wtmp</sub> | medium | 10.2.1.3, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_session_events_wtmp.rules` (mode 0640) |
| `audit_rules_suid_privilege_function`<br><sub>Record Events When Privileged Executables Are Run</sub> | medium | 10.2.1.2, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_suid_privilege_function.rules` (mode 0640) |
| `audit_rules_sysadmin_actions`<br><sub>Ensure auditd Collects System Administrator Actions</sub> | medium | Req-10.2.2, Req-10.2.5.b, 10.2.1.5, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_sysadmin_actions.rules` (mode 0640) |
| `audit_rules_time_adjtimex`<br><sub>Record attempts to alter time through adjtimex</sub> | medium | Req-10.4.2.b, 10.6.3, 10.6 | manage `/etc/audit/rules.d/pci-audit_rules_time_adjtimex.rules` (mode 0640) |
| `audit_rules_time_clock_settime`<br><sub>Record Attempts to Alter Time Through clock_settime</sub> | medium | Req-10.4.2.b, 10.6.3, 10.6 | manage `/etc/audit/rules.d/pci-audit_rules_time_clock_settime.rules` (mode 0640) |
| `audit_rules_time_settimeofday`<br><sub>Record attempts to alter time through settimeofday</sub> | medium | Req-10.4.2.b, 10.6.3, 10.6 | manage `/etc/audit/rules.d/pci-audit_rules_time_settimeofday.rules` (mode 0640) |
| `audit_rules_time_stime`<br><sub>Record Attempts to Alter Time Through stime</sub> | medium | Req-10.4.2.b, 10.6.3, 10.6 | manage `/etc/audit/rules.d/pci-audit_rules_time_stime.rules` (mode 0640) |
| `audit_rules_time_watch_localtime`<br><sub>Record Attempts to Alter the localtime File</sub> | medium | Req-10.4.2.b, 10.6.3, 10.6 | manage `/etc/audit/rules.d/pci-audit_rules_time_watch_localtime.rules` (mode 0640) |
| `audit_rules_usergroup_modification_group`<br><sub>Record Events that Modify User/Group Information - /etc/group</sub> | medium | Req-10.2.5, 10.2.1.5, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_usergroup_modification_group.rules` (mode 0640) |
| `audit_rules_usergroup_modification_gshadow`<br><sub>Record Events that Modify User/Group Information - /etc/gshadow</sub> | medium | Req-10.2.5, 10.2.1.5, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_usergroup_modification_gshadow.rules` (mode 0640) |
| `audit_rules_usergroup_modification_opasswd`<br><sub>Record Events that Modify User/Group Information - /etc/security/opasswd</sub> | medium | Req-10.2.5, 10.2.1.5, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_usergroup_modification_opasswd.rules` (mode 0640) |
| `audit_rules_usergroup_modification_passwd`<br><sub>Record Events that Modify User/Group Information - /etc/passwd</sub> | medium | Req-10.2.5, 10.2.1.5, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_usergroup_modification_passwd.rules` (mode 0640) |
| `audit_rules_usergroup_modification_shadow`<br><sub>Record Events that Modify User/Group Information - /etc/shadow</sub> | medium | Req-10.2.5, 10.2.1.5, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_rules_usergroup_modification_shadow.rules` (mode 0640) |
| `audit_sudo_log_events`<br><sub>Record Attempts to perform maintenance activities</sub> | medium | Req-10.2.2, Req-10.2.5.b, 10.2.1.3, 10.2.1, 10.2 | manage `/etc/audit/rules.d/pci-audit_sudo_log_events.rules` (mode 0640) |
| `auditd_audispd_syslog_plugin_activated`<br><sub>Configure auditd to use audispd's syslog plugin</sub> | medium | Req-10.5.3, 10.3.3, 10.3 | line in `/etc/audit/plugins.d/syslog.conf`: `active = yes` |
| `auditd_data_retention_admin_space_left_action`<br><sub>Configure auditd admin_space_left Action on Low Disk Space</sub> | medium | Req-10.7, 10.5.1, 10.5 | line in `/etc/audit/auditd.conf`: `admin_space_left_action = single` |
| `auditd_data_retention_space_left`<br><sub>Configure auditd space_left on Low Disk Space</sub> | medium | Req-10.7, 10.5.1, 10.5 | line in `/etc/audit/auditd.conf`: `space_left = 100` |
| `auditd_data_retention_space_left_action`<br><sub>Configure auditd space_left Action on Low Disk Space</sub> | medium | Req-10.7, 10.5.1, 10.5 | line in `/etc/audit/auditd.conf`: `space_left_action = email` |
| `auditd_name_format`<br><sub>Set type of computer node name logging in audit logs</sub> | medium | 10.2.2, 10.2 | line in `/etc/audit/auditd.conf`: `name_format = fqd` |
| `directory_access_var_log_audit`<br><sub>Record Access Events to Audit Log Directory</sub> | medium | 10.3.1, 10.3 | manage `/etc/audit/rules.d/pci-directory_access_var_log_audit.rules` (mode 0640) |

## GNOME desktop (dconf) policy (`dconf`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `dconf_gnome_disable_automount`<br><sub>Disable GNOME3 Automounting</sub> | medium | 3.4.2, 3.4 | manage `/etc/dconf/db/gdm.d/00-pci-dconf_gnome_disable_automount` (mode 0644) |
| `dconf_gnome_disable_automount_open`<br><sub>Disable GNOME3 Automount Opening</sub> | medium | 3.4.2, 3.4 | manage `/etc/dconf/db/gdm.d/00-pci-dconf_gnome_disable_automount_open` (mode 0644) |
| `dconf_gnome_screensaver_idle_activation_enabled`<br><sub>Enable GNOME3 Screensaver Idle Activation</sub> | medium | Req-8.1.8, 8.2.8, 8.2 | manage `/etc/dconf/db/gdm.d/00-pci-dconf_gnome_screensaver_idle_activation_enabled` (mode 0644) |
| `dconf_gnome_screensaver_idle_delay`<br><sub>Set GNOME3 Screensaver Inactivity Timeout</sub> | medium | Req-8.1.8, 8.2.8, 8.2 | manage `/etc/dconf/db/gdm.d/00-pci-dconf_gnome_screensaver_idle_delay` (mode 0644) |
| `dconf_gnome_screensaver_lock_delay`<br><sub>Set GNOME3 Screensaver Lock Delay After Activation Period</sub> | medium | Req-8.1.8, 8.2.8, 8.2 | manage `/etc/dconf/db/gdm.d/00-pci-dconf_gnome_screensaver_lock_delay` (mode 0644) |
| `dconf_gnome_screensaver_lock_enabled`<br><sub>Enable GNOME3 Screensaver Lock After Idle Period</sub> | medium | Req-8.1.8, 8.2.8, 8.2 | manage `/etc/dconf/db/gdm.d/00-pci-dconf_gnome_screensaver_lock_enabled` (mode 0644) |
| `dconf_gnome_screensaver_mode_blank`<br><sub>Implement Blank Screensaver</sub> | medium | Req-8.1.8, 8.2.8, 8.2 | manage `/etc/dconf/db/gdm.d/00-pci-dconf_gnome_screensaver_mode_blank` (mode 0644) |

## Systemd core dump policy (`coredump`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `coredump_disable_backtraces`<br><sub>Disable core dump backtraces</sub> | medium | Req-3.2, 3.3.1.1, 3.3.1, 3.3 | manage `/etc/systemd/coredump.conf.d/00-pci-coredump_disable_backtraces.conf` (mode 0644) |
| `coredump_disable_storage`<br><sub>Disable storing core dump</sub> | medium | Req-3.2, 3.3.1.1, 3.3.1, 3.3 | manage `/etc/systemd/coredump.conf.d/00-pci-coredump_disable_storage.conf` (mode 0644) |

## GRUB kernel command-line arguments (`grub`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `grub2_audit_argument`<br><sub>Enable Auditing for Processes Which Start Prior to the Audit Daemon</sub> | low | Req-10.3, 10.7.2, 10.7 | line in `/etc/default/grub`: `\g<1>audit=1 \g<2>"` |
| `grub2_audit_backlog_limit_argument`<br><sub>Extend Audit Backlog Limit for the Audit Daemon</sub> | low | 10.7.2, 10.7 | line in `/etc/default/grub`: `\g<1>audit_backlog_limit=8192 \g<2>"` |

## Resource limits (security/limits.d) (`limits`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `disable_users_coredumps`<br><sub>Disable Core Dumps for All Users</sub> | medium | 3.3.1.1, 3.3.1, 3.3 | manage `/etc/security/limits.d/10-pci-coredump.conf` (mode 0644) |

## File integrity monitoring (AIDE) (`aide`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `aide_build_database`<br><sub>Build and Test AIDE Database</sub> | medium | Req-11.5, 11.5.2 | operational cmd: `aide --init && mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db` |
| `aide_periodic_checking_systemd_timer`<br><sub>Configure Systemd Timer Execution of AIDE</sub> | medium | Req-11.5, 11.5.2 | manage `/etc/systemd/system/aidecheck.service` (mode 0644) |

## Mandatory Access Control (SELinux / AppArmor) (`mac`)

| Rule | Sev | PCI-DSS | Action |
|---|---|---|---|
| `grub2_enable_selinux`<br><sub>Ensure SELinux Not Disabled in /etc/default/grub</sub> | medium | 1.2.6, 1.2 | line in `/etc/default/grub`: `\g<1>security=selinux \g<2>"` |
| `selinux_policytype`<br><sub>Configure SELinux Policy</sub> | medium | 1.2.6, 1.2 | line in `/etc/selinux/config`: `SELINUXTYPE=targeted` |
| `selinux_state`<br><sub>Ensure SELinux State is Enforcing</sub> | high | 1.2.6, 1.2 | SELinux mode `enforcing` |

