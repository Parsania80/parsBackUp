# M2 safe restore and verification guide

This milestone adds restore planning, restore execution, and artifact verification on top of the M1 backup path. It reconstructs the database **and** its security environment: roles, role attributes, role memberships, schema/table ownership, and granted privileges. It remains a development tool for **synthetic fixture databases only**; the plaintext artifact becomes the encrypted/signed v1 format in M4.

## Requirements

- The M1 requirements: edition-2024 Rust toolchain, PostgreSQL 16/17/18, and version-matched `pg_dump`, `pg_dumpall`, `pg_restore`, `psql`, and `createdb` in one absolute `client_bin_dir`. The preflight rejects a client/server major mismatch or a missing tool.
- A source database whose name begins `backupctl_fixture_`, populated from [`core.sql`](../../tests/fixtures/postgres/core.sql).
- [`config/m2.example.toml`](../../config/m2.example.toml) sets `export_globals = true`; without it a backup carries no security metadata and only a portable restore is possible.

## Commands

```text
cargo run -p backupctl -- --config /absolute/path/to/m2.toml backup create --confirm-synthetic
cargo run -p backupctl -- --config /absolute/path/to/m2.toml backup verify BACKUP_UUID --level checksum
cargo run -p backupctl -- --config /absolute/path/to/m2.toml backup verify BACKUP_UUID --level archive
cargo run -p backupctl -- --config /absolute/path/to/m2.toml restore plan BACKUP_UUID --target backupctl_fixture_dr --security dr
cargo run -p backupctl -- --config /absolute/path/to/m2.toml restore run PLAN_UUID --confirm-target backupctl_fixture_dr
```

Verification levels: `checksum` rehashes the payload and `globals.sql` against the manifest; `archive` additionally parses the archive with `pg_restore --list`. A successful DR restore raises the artifact to `restore-tested`, which `backup inspect` reports.

## Restore security policy

`RestoreSecurityPolicy` carries three booleans and is selected by `--security`:

| Preset | `roles` | `ownership` | `privileges` | Native behavior |
| --- | --- | --- | --- | --- |
| `dr` | yes | yes | yes | Applies the exported role statements, then `pg_restore` without `--no-owner`/`--no-privileges` |
| `portable` | no | no | no | Skips the globals apply, restores contents with `--no-owner --no-privileges` |

Nothing is permanently forced: `--no-owner`/`--no-privileges` are derived from the selected policy per plan, never from a global default.

`restore plan` writes `<storage-root>/plans/<uuid>.json` (mode 0600) that binds the artifact ID, the source database name, the source major, the client version, the target database, the policy, and an expiry of 15 minutes. `restore run` re-validates expiry, re-opens the artifact so the payload and `globals.sql` digests are recomputed against the manifest, re-checks that no cluster major changed, and requires `--confirm-target` to equal the planned target verbatim, so an executed restore can never silently differ from the reviewed plan.

Planning refuses, deterministically and before touching the cluster: a target that already exists, a target equal to the source database, a `dr` plan over an artifact without security metadata, a client/server major drift, and a cluster where *every* exported role already exists (a rebuilt cluster that still has only `postgres` is not a conflict).

## Applied order and conflict handling

`restore run` executes: validate plan and artifact → apply roles (`CREATE ROLE`, `ALTER ROLE`, then `GRANT <member> TO <grantee>`) → re-check the target is still absent → `createdb --template=template0` → `pg_restore --exit-on-error` with the policy flags → raise the artifact to `restore-tested`. Role statements are filtered against the live cluster: a role that already exists is skipped, including its `ALTER ROLE`, so existing roles are never modified or dropped. After applying, the adapter re-reads `pg_roles` and fails if any exported role is still absent, which turns a silently no-op script into an error.

If `pg_restore` fails partway, the command reports that the target was left in place for operator inspection instead of dropping it: `pg_restore` can leave partial objects, and an automatic `DROP DATABASE` could destroy data an operator wanted to examine.

## Restore trust boundary

`pg_restore` executes SQL stored in the artifact with the privileges of the connecting role. A restore is therefore a code-execution step against a file, not just a data copy, and is only safe when the artifact and its storage are trusted. Combined with the `--confirm-target` requirement and the plan digest, this is why restore is a two-step plan/run operation. See [threat model](../security/threat-model.md).

## Sensitive metadata and known limitations

- The export uses `pg_dumpall --roles-only --no-role-passwords`, so no SCRAM or MD5 verifier ever enters the artifact. The adapter re-checks the file for a `PASSWORD` clause and refuses to apply it, and the smoke test asserts a fake sentinel password and `SCRAM-SHA-256` never appear in the store or CLI output. **Consequence: restored roles exist with their attributes but cannot authenticate until an operator assigns a password.** This is a deliberate M2 limitation, not a workaround; recovering verifiers would require direct `pg_authid` access, which this project does not attempt.
- `globals.sql` is plaintext on disk until M4a encryption and holds role names and attributes, which are themselves information. File modes are 0600/0700; the directory is not a secret boundary.
- Only roles, attributes, and memberships are exported. Database-level `GRANT ... ON DATABASE`, tablespaces, `ALTER DEFAULT PRIVILEGES` in other databases, and shared descriptors are **not** reconstructed and must be treated as cluster prerequisites.
- Ownership and privileges are restored only for objects inside the dumped database.
- One database per artifact, no scheduling, retention, deletion, remote storage, encryption, or concurrent-operation locking yet.

## Validation boundary

The support claim comes from the Docker matrix below, not from unit tests. `assertions.sql` proves content and [`security-assertions.sql`](../../tests/fixtures/postgres/security-assertions.sql) proves the security model (role attributes, membership via `pg_has_role`, schema/table ownership, `has_table_privilege` grants, and the absence of any `pg_authid.rolpassword` for fixture roles).

## Reproducible integration check

Run `tests/m2_docker_smoke.sh` from the repository root with Docker access and the PostgreSQL 16–18 images available. For each major it starts a network-disabled source container and a second target container on a host port, with temporary bind-mounted storage, and drives the real CLI through wrapper scripts that invoke version-matched clients inside each container. It covers: globals export with sentinel/`PASSWORD`/`SCRAM-SHA-256` leakage checks, both verification levels, the M1 native restore compatibility path, DR refusal while roles already exist, clean-cluster DR restore plus both assertion files, a second DR refusal, portable restore onto a cluster with no fixture roles, plan JSON policy binding, expired-plan refusal, mismatched `--confirm-target`, `export_globals = false` gating, and globals/payload tamper detection. Containers and temporary storage are removed on exit.
