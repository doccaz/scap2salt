# Remaining PCI-DSS v4 failures — triage

Snapshot of rules that still fail an OpenSCAP `pci-dss-4` scan after applying the
generated formula (SLE 16 / SELinux test minion), classified by what the formula
does for each and whether it is worth pursuing.

Regenerate the underlying data with `./scap2salt.py --target sle16 --report-only`
and an `oscap xccdf eval` on a hardened host.

## 🟦 Implemented but OPT-IN (default-off `accounts` category)

These are real, working remediations but they **mutate existing accounts/access**
and can lock out users or management agents, so they live in the `accounts`
category which is **default-off** (`$default: False`). Enable it deliberately
(and exclude service/admin accounts) — note an expired account can't even be
fixed with `chage` afterwards (PAM refuses); recovery needs a direct
`/etc/shadow` edit.

| Rule | Action |
|---|---|
| `accounts_password_set_max_life_existing` | `passwd -x 90` on existing users with older/unset max-age |
| `accounts_password_set_warn_age_existing` | `chage --warndays 7` |
| `accounts_set_post_pw_existing` | `chage --inactive 90` |
| `sudo_require_authentication` | comment out `NOPASSWD`/`!authenticate` in sudoers |

Enabling `accounts` also clears `accounts_maximum_age_login_defs` (its OVAL is
coupled to existing-user max-age, not just `/etc/login.defs`).

## 🟩 Done — handlers/fixes added

| Rule | Status |
|---|---|
| `permissions_local_var_log` | ✅ guarded `find /var/log -exec chmod` sweep |
| `account_disable_post_pw_expiration` | ✅ fixed `_resolve_formatted_output` separator → `/etc/default/useradd` now gets `INACTIVE=90` (was `INACTIVE 90`) |

## 🟥 Won't-fix — not a formula gap

CaC ships **no remediation** (detective-only; `NO_REMEDIATION.md`):
`ensure_firewall_rules_for_open_ports`, `set_firewalld_default_zone`,
`file_permissions_ungroupowned`, `no_files_unowned_by_user`,
`sshd_limit_user_access`.

Host-role / framework conflicts:

| Rule | Why |
|---|---|
| `selinux_confinement_of_daemons` | policy-level; covered by enforcing mode (`SKIPPED_NA`) |
| `service_nftables_disabled` | firewalld's backend *is* nftables and other rules need firewalld |
| `file_permissions_unauthorized_world_writable` | filesystem-wide sweep; no safe declarative form |
| `sysctl_net_ipv4_ip_forward` | Docker/Podman/libvirt force `ip_forward=1` |

N/A or unsafe on SLE:

| Rule | Why |
|---|---|
| `set_password_hashing_algorithm_systemauth` | `system-auth` doesn't exist on SLE (uses `common-auth`) |
| `display_login_attempts` | needs `pam_lastlog2.so`, not shipped on SLE 16 |
| `no_empty_passwords` | edits/locks existing blank-password accounts (host data) |
| `ensure_pam_wheel_group_empty` | depends on current group membership |

## 🟨 Investigate — emit a state but the check still fails

| Rule | Likely cause |
|---|---|
| `set_password_hashing_algorithm_commonauth` | guarded PAM `cmd.run`; verify it satisfies the OVAL |
| `audit_rules_suid_privilege_function` | format now canonical; loaded-vs-file/immutability nuance or multi-condition OVAL |
| `aide_periodic_checking_systemd_timer` | timer enabled; OVAL may want a specific unit name/schedule |
| `audit_rules_login_events_faillock` | watch dir refined to `/var/run/faillock` but the companion `pam_faillock dir=` rule isn't selected → OVAL wants a watch on the *effective* dir |

## Summary

Default-safe (no opt-in): `permissions_local_var_log` and
`account_disable_post_pw_expiration` now pass (+2). Opting into the `accounts`
category clears ~5 more (existing-account aging, `accounts_maximum_age_login_defs`,
`sudo_require_authentication`) at the cost of expiring passwords / removing
NOPASSWD. The rest are won't-fix (no CaC fix, host-role conflicts, SLE-N/A) or a
small investigate set, mostly OVAL-format nuances.
