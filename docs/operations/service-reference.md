# Fixture package and service reference

The H03 package is fixture-only and tested on Debian 13/Ubuntu 24.04 amd64 userspaces. It does not provision a PostgreSQL server, DB grants, credentials, config, keys or an enabled timer. Installation is not production authorization. [H03 contract/evidence](../development/h03-systemd-package.md) and the [configuration/report reference](cli-reference.md) define the boundaries. This reference introduces no new operating flow.

## Package, identity and custody

A reviewed fixture package has an accompanying SHA256SUMS; compare its digest with the trusted build evidence before installation. A checksum transported alongside the same untrusted file does not authenticate its source. CI artifacts are verification outputs, not signed production releases. The local package command is `sudo dpkg -i PACKAGE.deb` after target dependencies are satisfied; explicit version/architecture/native-runtime compatibility remains the administrator's responsibility. `dpkg --remove backupctl` stops/disables known backup instances; `dpkg --purge backupctl` also preserves administrator-created recovery material and the static service identity. Neither command is a key-destruction operation. Reinstall starts no scheduler. Upgrade reloads unit definitions without restarting a current job or enabling a new timer.

| Path | Package-created custody | Administrator material |
|---|---|---|
| `/usr/bin/backupctl`, `/usr/lib/systemd/system/backupctl-backup@.*` | root-owned packaged files | No local edits; explicit systemd drop-ins own overrides. |
| `/etc/backupctl`, `/etc/backupctl/profiles` | root:backupctl, 0750 | Reviewed service-owned 0600 `NAME.toml`; NAME matches a simple configured profile (letters/digits/underscore/hyphen). |
| `/etc/backupctl/keys` | backupctl:backupctl, 0700 | Independently backed-up generations, secret files 0600, public files 0644 with protected ancestry. |
| `/etc/backupctl/credentials` | backupctl:backupctl, 0700 | Explicit service-owned passfile 0600 or stricter; target/maintenance DB entries where required. |
| `/var/lib/backupctl` | backupctl:backupctl, 0700 | Store state, private plans/jobs/temporary plaintext; preserve consistent inventory with artifacts. |
| `/usr/share/doc/backupctl/examples/writer.example.toml` | Inert root-owned example | Edit a reviewed copy, matching client major/auth/source/profile before installing as config. Never put passwords in TOML. |

Unsafe pre-existing custody refuses installation/reconfiguration; the package never recursively chmod/chowns recovery data. Source-major native clients must be installed separately at the configured trusted absolute directory, e.g. `/usr/lib/postgresql/17/bin`. PostgreSQL 16/17/18 same-major policy applies; different endpoint/major/cross-server restore is unsupported. Service user `backupctl` has no login shell and receives no DB privileges automatically. A backup role should be provisioned for the required read/content privileges; DR/admin capabilities require a separately controlled recovery configuration/account. H03's isolated acceptance uses a privileged fixture role to test recovery, not a production grant recipe. [Privilege matrix](../postgres/privilege-matrix.md) remains a V01 test obligation.

The administrator supplies credentials privately, config and independent verifier trust. Key bootstrap/status commands run explicitly as the service account outside the read-only backup unit. Representative invocations, valid only with fully provisioned fixture config and protected parents:

```sh
sudo -u backupctl /usr/bin/backupctl --config /etc/backupctl/profiles/daily.toml --output json-v1 config check
sudo -u backupctl /usr/bin/backupctl --config /etc/backupctl/profiles/daily.toml --output json-v1 key status
sudo -u backupctl /usr/bin/backupctl --config /etc/backupctl/profiles/daily.toml --output json-v1 backup create --profile daily --dry-run
```

`key generate` is only for empty validated writer destinations; all four paths must be unused. `key publish` reconstructs missing public halves only when surviving seeds are valid. Neither overwrites an existing destination. Multi-file publication is not atomic: partial receipt/crash survivors require explicit custody inspection. Do not blindly rerun generate or delete surviving material. The unchanged [generation/custody operating document](../security/key-lifecycle.md) describes generation retention; versioned no-overwrite/partial rules are in the [bootstrap contract](../development/h02-key-bootstrap-custody.md).

## Service and opt-in scheduling

| Reference command | Meaning and required state |
|---|---|
| `sudo systemctl start backupctl-backup@daily.service` | One signed fixture backup with config daily.toml/profile daily; resources/credentials must already be provisioned. Uses existing core scope claim. |
| `sudo systemctl enable --now backupctl-backup@daily.timer` | Explicit administrator opt-in; daily 02:00 UTC with up to 15-minute random delay and one-minute accuracy, persistent missed-event catch-up. Does not certify backup success. |
| `sudo systemctl stop backupctl-backup@daily.timer` | Stops future activations; does not stop a running backup service. |
| `sudo systemctl disable --now backupctl-backup@daily.timer` | Stops activations and removes this instance's persistent enablement. |
| `sudo systemctl stop backupctl-backup@daily.service` | Requests CLI SIGTERM cleanup; remaining service-cgroup processes receive SIGKILL after the configured grace. Partial DB/artifact effects remain inspectable. |
| `systemctl show backupctl-backup@daily.service -p Result -p MainPID -p ActiveState` | Actual manager state, separate from application result/job durability. |
| `journalctl -u backupctl-backup@daily.service` | Command envelope and manager events; authenticated result data can contain private metadata, so restrict access/export. |

Repeated timer activation of an already-running instance starts no second service. A separate manual CLI process meets existing same-scope exclusion; different profile names follow existing scope semantics. Refusal/failure is not success and no automatic retry is configured. Pausing a timer does not pause manual activity or provide store maintenance ownership. Never unlink locks or kill PostgreSQL workers blindly to force progress.

Service defaults: oneshot deadline two hours, stop grace 30 seconds, 2 GiB memory, 128 tasks, 1024 descriptors, no core dumps. Its native tools retain per-tool timeouts. Explicit reviewed `/etc/systemd/system/backupctl-backup@daily.service.d/*.conf` drop-ins can change measured deployment limits; use `systemctl daemon-reload` after administrator unit changes. Do not relax key ownership or the fixture guard. The sandbox protects system/home/kernel and config/key/credential writes, grants no capabilities/delegation and permits state-directory/private temporary writes and local peer/loopback access. CLI protected paths/resource limits still apply inside it. Hard stops, machine loss or SQLite/filesystem blocking can leave nonterminal jobs or plaintext scratch; consult recovery facts before any retry.

## Monitoring policy

The timer alone is not an alert system. A proposed initial policy is daily backup, stale warning after 26 hours and weekly isolated recovery validation; these are configurable operator targets, not achieved RPO/RTO guarantees. H04 adds no exporter or notification daemon. An external monitor should evaluate both service failures and authenticated successful backup age for the intended source/profile/key generation. Job completion alone or file mtime is insufficient: an artifact can later be removed/corrupted and local history can be lost/replaced. A signature-only public listing authenticates neither private completion time nor database contents. Use a consistent read-only copy plus reader checksum/archive inspection, or an explicit independently verified restore, for stronger evidence; exact custody/report limits are in [recovery reference](recovery-reference.md).

Useful evidence is latest successful signed creation time/artifact ID, current validity/digests, job/effects and latest independent recovery validation date. Alert separately on missed/failed runs, stale usable snapshots, resource exhaustion and failed recovery. Protect private config/results/keys; never put secrets into alerts. Define alert ownership and test a missing/failed backup deliberately before relying on the policy. A local artifact shares its host's failure domain; no off-host or host-loss recovery is claimed without a separately implemented and verified copy workflow.
