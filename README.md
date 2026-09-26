# backupctl

A Rust PostgreSQL backup platform under development. The current M1 CLI creates **plaintext backups of synthetic local fixture databases only**. It does not yet provide encrypted production artifacts, restore execution, scheduling, or an API. The [roadmap](project.md) defines the milestones and release limits.

## Current commands

```text
backupctl --config /absolute/path/to/m1.toml config check
backupctl --config /absolute/path/to/m1.toml backup create --confirm-synthetic
backupctl --config /absolute/path/to/m1.toml backup list
backupctl --config /absolute/path/to/m1.toml backup inspect BACKUP_UUID
```

See the [M1 local backup guide](docs/development/m1-local-backup.md) and [example config](config/m1.example.toml). A PostgreSQL 16–18 Docker smoke test is available at [tests/m1_docker_smoke.sh](tests/m1_docker_smoke.sh); it uses isolated synthetic databases and checks native restore independently of the CLI.

Architecture, threat, PostgreSQL content, and artifact contracts are linked from [ARCHITECTURE.md](ARCHITECTURE.md). A public license will be selected before a release; no license grant is implied by this development snapshot.
