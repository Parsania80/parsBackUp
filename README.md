# backupctl

A Rust PostgreSQL backup platform under development. The current CLI creates backups of **synthetic local fixture databases only**, optionally through a named profile whose scope is resolved against the live catalog, verifies them, and restores them fully or section by section, either as a full DR rebuild (roles, memberships, ownership, privileges) or as a contents-only portable restore. A selective backup is refused when the selection would depend on objects `pg_dump` does not write. A store that configures an `[encryption]` block seals every artifact it writes with a hybrid ML-KEM-768 + X25519 age recipient, so payload plaintext never enters the store; those artifacts are still unsigned, so real data must wait for M4b. It does not yet provide scheduling or an API. The [roadmap](project.md) defines the milestones and release limits.

## Current commands

```text
backupctl --config /absolute/path/to/m4a.toml key generate
backupctl --config /absolute/path/to/m4a.toml key status
backupctl --config /absolute/path/to/m3.toml config check
backupctl --config /absolute/path/to/m3.toml profile list
backupctl --config /absolute/path/to/m3.toml profile validate PROFILE_NAME
backupctl --config /absolute/path/to/m3.toml backup create --confirm-synthetic
backupctl --config /absolute/path/to/m3.toml backup create --profile PROFILE_NAME --dry-run
backupctl --config /absolute/path/to/m3.toml backup create --profile PROFILE_NAME --confirm-synthetic
backupctl --config /absolute/path/to/m3.toml backup list
backupctl --config /absolute/path/to/m3.toml backup inspect BACKUP_UUID
backupctl --config /absolute/path/to/m3.toml backup verify BACKUP_UUID --level archive
backupctl --config /absolute/path/to/m3.toml restore plan BACKUP_UUID --target backupctl_fixture_dr --security dr
backupctl --config /absolute/path/to/m3.toml restore plan BACKUP_UUID --target backupctl_fixture_sel --security portable --section pre-data
backupctl --config /absolute/path/to/m3.toml restore run PLAN_UUID --confirm-target backupctl_fixture_dr
```

See the [M1 local backup guide](docs/development/m1-local-backup.md), the [M2 restore and verification guide](docs/development/m2-restore-verify.md), the [M3 profiles and selective operations guide](docs/development/m3-profiles-selective.md), and the [example configs](config). PostgreSQL 16–18 Docker smoke tests are available at [tests/m1_docker_smoke.sh](tests/m1_docker_smoke.sh), [tests/m2_docker_smoke.sh](tests/m2_docker_smoke.sh), [tests/m3_docker_smoke.sh](tests/m3_docker_smoke.sh), and [tests/m4a_docker_smoke.sh](tests/m4a_docker_smoke.sh); they use isolated synthetic databases and check native restore independently of the CLI. The M4a run wraps every PostgreSQL client so each one records the file arguments it was handed and the first bytes of those files, which is how it shows that a tool only ever opens a decrypted archive from the store's transient `scratch/` view and that no plaintext, role name, or key material reaches the encrypted store.

Architecture, threat, PostgreSQL content, and artifact contracts are linked from [ARCHITECTURE.md](ARCHITECTURE.md). A public license will be selected before a release; no license grant is implied by this development snapshot.
