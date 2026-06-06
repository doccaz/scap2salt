# Remaining PCI-DSS v4 failures — triage

Snapshot of rules that still fail an OpenSCAP `pci-dss-4` scan after applying the
generated formula (SLE 16 / SELinux test minion). Each is classified by what the
formula does for it and whether it is worth pursuing.

Regenerate the underlying data with `./scap2salt.py --target sle16 --report-only`
and an `oscap xccdf eval` on a hardened host.

## 🟥 Won't-fix — not a formula gap

CaC ships **no remediation** (detective-only; see `NO_REMEDIATION.md`):

| Rule | Why |
|---|---|
| `ensure_firewall_rules_for_open_ports` | firewall *design* review; nothing to automate |
| `set_firewalld_default_zone` | no fix shipped |
| `file_permissions_ungroupowned` | system-wide audit, no fix |
| `no_files_unowned_by_user` | system-wide audit, no fix |
| `sshd_limit_user_access` | site-specific `AllowUsers`, no fix |

Host-role / framework conflicts:

| Rule | Why |
|---|---|
| `selinux_confinement_of_daemons` | policy-level; covered by enforcing mode (`SKIPPED_NA`) |
| `service_nftables_disabled` | firewalld's backend *is* nftables and other PCI rules require firewalld — disabling it breaks the firewall |
| `file_permissions_unauthorized_world_writable` | filesystem-wide `find` sweep; no safe declarative form (`UNMAPPED`) |
| `sysctl_net_ipv4_ip_forward` | Docker/Podman/libvirt force `ip_forward=1`; can't be 0 on a container/router host |

## 🟧 Won't-fix / risky — mutate existing accounts, reflect host data, or N/A on SLE

| Rule | Why |
|---|---|
| `accounts_password_set_max_life_existing` | runs `chage` on every existing user (disruptive to automate) |
| `no_empty_passwords` | edits/locks existing accounts with blank passwords |
| `ensure_pam_wheel_group_empty` | depends on current group membership |
| `set_password_hashing_algorithm_systemauth` | `system-auth` doesn't exist on SLE (uses `common-auth`) — N/A |
| `sudo_require_authentication` | CaC comments out every `NOPASSWD`/`!authenticate` line; on MLM minions the management user relies on `NOPASSWD` sudo, so this would break agent access. Site decision. |
| `display_login_attempts` | CaC adds `pam_lastlog2.so` to PAM, but that module is **not shipped on SLE 16** — adding it would break logins. Effectively N/A. |

## 🟩 Done — handlers added this round

| Rule | Status |
|---|---|
| `permissions_local_var_log` | ✅ now emitted as a guarded `find /var/log -exec chmod` sweep (idempotent via `onlyif`); verified pass |

## 🟨 Investigate — emit a state but the check still fails

| Rule | Likely cause |
|---|---|
| `accounts_maximum_age_login_defs` | OVAL also checks **existing** users → gated on `accounts_password_set_max_life_existing` |
| `account_disable_post_pw_expiration` | same: gated on the existing-accounts companion |
| `set_password_hashing_algorithm_commonauth` | guarded PAM `cmd.run`; verify it satisfies the OVAL |
| `audit_rules_suid_privilege_function` | format now canonical; loaded-vs-file/immutability nuance or multi-condition OVAL |
| `aide_periodic_checking_systemd_timer` | timer is enabled; OVAL may want a specific unit name/schedule |
| `audit_rules_login_events_faillock` | the profile refines the watch dir to `/var/run/faillock`, but the companion `pam_faillock dir=` rule is **not selected**, so the effective faillock dir stays the default and the OVAL wants a watch on *that*. Needs the watch path to track the effective dir (or set `faillock.conf dir=`). |

## Summary

Of ~22 remaining: **~16 won't-fix** (no CaC fix, host-role conflicts, unsafe
account mutations, or modules/idioms N/A on SLE), **1 fixed this round**
(`permissions_local_var_log`), and **~5 to investigate** — mostly coupled to the
"existing accounts" rules, which would clear several investigate-items at once.

> On closer inspection, 3 of the 4 originally-listed "clean TODOs" turned out to
> be unsafe on SLE/MLM (`sudo_require_authentication` breaks NOPASSWD agent
> access; `display_login_attempts` needs a PAM module SLE doesn't ship;
> `audit_rules_login_events_faillock` is a cross-rule dependency). Only
> `permissions_local_var_log` was a safe, clean addition.
