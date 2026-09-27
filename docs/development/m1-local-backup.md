# M1 synthetic local backup guide

This milestone implements only full logical `pg_dump -Fc` backup, local artifact publication, and CLI list/inspect. It is a development tool for **synthetic fixture databases only**. The plaintext `m1-development-plaintext` artifact is not the signed/encrypted v1 production format; real data must wait for M4.

## Requirements

- Rust toolchain supporting edition 2024.
- PostgreSQL 16, 17, or 18 server and the matching versioned `pg_dump`, `pg_dumpall`, `pg_restore`, `psql`, and `createdb` binaries in one absolute directory (the Debian `postgresql-client-NN` package provides all five). The CLI rejects a client/server major mismatch or a missing tool.
- A disposable database whose name begins `backupctl_fixture_`, populated from [`core.sql`](../../tests/fixtures/postgres/core.sql). The service only accepts a local socket or loopback address.
- Optional password file outside the repository with mode 0600. M1 never accepts a password in TOML or the command line.

Copy [`config/m1.example.toml`](../../config/m1.example.toml) to a private local config path and adjust the host port, versioned client directory, and storage root. The example uses a loopback PostgreSQL 16 connection. It contains no credentials.

## Commands

```text
cargo run -p backupctl -- --config /absolute/path/to/m1.toml config check
cargo run -p backupctl -- --config /absolute/path/to/m1.toml backup create --confirm-synthetic
cargo run -p backupctl -- --config /absolute/path/to/m1.toml backup list
cargo run -p backupctl -- --config /absolute/path/to/m1.toml backup inspect BACKUP_UUID
```

Add `--output json` before or after the subcommand for structured output. `config check` validates the file and synthetic-use constraints without connecting to PostgreSQL. `backup create` checks the server/client major, runs `pg_dump` without a shell, rejects warnings/errors/timeouts, checks `pg_restore --list`, hashes the nonempty archive, and publishes it with a completion marker. `list` and `inspect` rehash the payload and reject a corrupt completed artifact. No restore or deletion command exists yet.

Artifact layout under the configured root:

```text
staging/<uuid>/                # private, removed on ordinary failure
artifacts/<uuid>/payload.dump  # plaintext synthetic fixture only
artifacts/<uuid>/manifest.json # development record, not v1
artifacts/<uuid>/complete      # publication marker
```

M1 uses mode 0700 directories and mode 0600 created files. An interrupted process can leave a staging directory or an artifact without a completion marker; these are not listed as complete. M1 does not yet provide automatic stale-stage reconciliation, encrypted storage, restore execution, retention, or a daemon.

## Validation boundary

Run the [fixture plan](../postgres/fixture-plan.md) on PostgreSQL 16–18 before claiming all supported majors. A full same-major restore into a fresh disposable database with [`assertions.sql`](../../tests/fixtures/postgres/assertions.sql) is the M1 artifact smoke test, but restore orchestration belongs to M2. The pre-M1 PostgreSQL 15 SQL smoke test does not satisfy the support matrix.

## Reproducible integration check

Run `tests/m1_docker_smoke.sh` from the repository root with Docker access and the PostgreSQL 16–18 images available. It uses network-disabled containers and temporary bind-mounted storage; wrappers invoke the version-matched client inside each container so the host does not need PostgreSQL tools installed. It checks backup/list/inspect and independently restores each artifact, plus M1 failure guards on PostgreSQL 16. The script removes containers and temporary files on exit.
