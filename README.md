# backupctl

A Rust PostgreSQL backup platform under development. The current M2 CLI creates **plaintext backups of synthetic local fixture databases only**, verifies them, and restores them either as a full DR rebuild (roles, memberships, ownership, privileges) or as a contents-only portable restore. It does not yet provide encrypted production artifacts, scheduling, or an API. The [roadmap](project.md) defines the milestones and release limits.

## Current commands

```text
backupctl --config /absolute/path/to/m2.toml config check
backupctl --config /absolute/path/to/m2.toml backup create --confirm-synthetic
backupctl --config /absolute/path/to/m2.toml backup list
backupctl --config /absolute/path/to/m2.toml backup inspect BACKUP_UUID
backupctl --config /absolute/path/to/m2.toml backup verify BACKUP_UUID --level archive
backupctl --config /absolute/path/to/m2.toml restore plan BACKUP_UUID --target backupctl_fixture_dr --security dr
backupctl --config /absolute/path/to/m2.toml restore run PLAN_UUID --confirm-target backupctl_fixture_dr
```

See the [M1 local backup guide](docs/development/m1-local-backup.md), the [M2 restore and verification guide](docs/development/m2-restore-verify.md), and the [example configs](config). PostgreSQL 16–18 Docker smoke tests are available at [tests/m1_docker_smoke.sh](tests/m1_docker_smoke.sh) and [tests/m2_docker_smoke.sh](tests/m2_docker_smoke.sh); they use isolated synthetic databases and check native restore independently of the CLI.

Architecture, threat, PostgreSQL content, and artifact contracts are linked from [ARCHITECTURE.md](ARCHITECTURE.md). A public license will be selected before a release; no license grant is implied by this development snapshot.
