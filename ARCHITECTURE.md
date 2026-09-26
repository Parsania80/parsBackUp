# Architecture contract

Status: M0 design contract, 2026-09-26. See [project.md](project.md) for sequencing and [ADR 0001](docs/architecture/adr-0001-foundations.md) for alternatives.

## Product boundary

`backupctl` is one Rust modular monolith. CLI, systemd invocation, and future HTTP API call the same application use cases. The browser UI calls the API. PostgreSQL 16–18 is the first engine family; a new engine implements a capability interface rather than inheriting PostgreSQL-specific flags. M1–M2 use synthetic data only. Real-data publication requires M4 encrypted artifact v1.

The application promises logical, snapshot-time backup of one database. It does not promise cluster backup, WAL recovery, point-in-time recovery, application files, or host-loss recovery. [PostgreSQL backup methods](https://www.postgresql.org/docs/18/backup.html).

## Dependency and ownership rules

```text
CLI / scheduler / future API -> application -> domain
                                 |      |
                                 v      v
                         engine, store, catalog, crypto ports
                                 ^      ^
                 PostgreSQL/local/SQLite/age implementations
```

- Domain: IDs, profile snapshot, resolved selection, artifact schema, job state, retention invariants, compatibility result. No I/O or CLI/HTTP types.
- Application: plan/create/inspect/verify/restore use cases, orchestration, cancellation, audit decision. It depends on ports, not subprocess or filesystem modules.
- PostgreSQL adapter: source and destination preflight, native tool version selection, safe argv construction, TOC inspection, capability/limitation reporting. It owns PostgreSQL-specific selection and restore flags.
- Storage adapter: staged writes, durable commit, read, inventory, quarantine, deletion; no profile or SQL decisions.
- Crypto adapter: age recipient/identity access, streaming encryption/decryption, detached Ed25519 signing/verification, complete authentication; no database knowledge.
- Catalog adapter (M5): index and job/audit state. Published artifacts remain discoverable with the recovery identity after catalog loss.
- Interfaces: parse/present requests only; they cannot bypass application preflight or authorization.

Introduce a port when it has a concrete production adapter and a useful test fake, or when a second production adapter is imminent. Do not define MySQL/MongoDB methods until their capabilities are researched.

## Use-case contracts

| Use case | Input | Output / invariant |
| --- | --- | --- |
| `plan_backup` | source reference, immutable profile snapshot, actor | Resolved exact scope, PostgreSQL/client versions, warnings, required privileges, estimated resources. No backup side effect. |
| `create_backup` | approved plan | A staged artifact or failed job; `complete` only after native process success, durable write, checksum, and selected verification level. |
| `inspect_backup` | opaque ID | Validated public fields and authenticated private fields when identity is available; public fields are marked untrusted before authentication. |
| `verify_backup` | ID, level | Explicit result: ciphertext checksum, authenticated archive parse, or isolated restore test. Do not conflate levels. |
| `plan_restore` | ID, target identity, selection, conflict policy | Stable plan digest bound to target fingerprint, versions, TOC selection, expiry, and actor; no SQL executed. |
| `execute_restore` | plan and required confirmation | Supervised restore and validation; failed/interrupted may leave target partial and never silently retry. |

`DatabaseEngine` reports capabilities and takes an engine-specific typed plan. `ArtifactStore` supports stage/commit/read/quarantine and declares atomic-rename/conditional-create semantics. `RecipientProvider`, `IdentityProvider`, `Signer`, and `Verifier` resolve keys by opaque ID; the verifier trusts public keys from independent configuration. `Catalog` is introduced with M5; M1 scans local artifacts. The engine produces/consumes a native archive stream; application layers do not rewrite PostgreSQL SQL.

## Job and artifact lifecycle

`planned -> running -> staged -> verified -> complete`; any intermediate state can enter `failed`, `cancelled`, or `quarantined`. Interrupted jobs do not become complete on restart. The durable artifact consists of `public.json`, `manifest.age`, `payload.age`, `signature.ed25519`, and a completion marker. Stage on the same filesystem, fsync payload/manifest/header and directory, rename to immutable ID, then create/fsync the marker. A reader accepts only a valid marker **and** a verified artifact. The public header and SQLite records are discovery hints; trusted signature and authenticated manifest are authoritative. See [artifact v1](docs/backup-format/manifest-v1.md).

Backups use `pg_dump -Fc`; restores use `pg_restore`. The subprocess runner uses fixed absolute binaries, argv vectors, bounded stderr, timeouts, process-group cancellation, a restricted environment, and a dedicated password file or peer authentication. No shell or connection string with a password in argv. The selected client major matches the source server major. Source-to-target major upgrades require separate matrix tests and are not initially supported. [PostgreSQL `pg_dump` version rules](https://www.postgresql.org/docs/18/app-pgdump.html).

## Restore trust boundary

Treat a PostgreSQL archive as executable input. PostgreSQL warns that restoring a dump can run code chosen by a source superuser, even after partial selection. A successful checksum/age authentication establishes integrity relative to an artifact/key; it does not establish that its SQL is safe. Default restore creates a new database on a controlled target. Destructive restore requires a fresh plan digest and explicit target confirmation. Never automatically restore globals or activate subscriptions. [PostgreSQL warning](https://www.postgresql.org/docs/18/app-pgdump.html).

## Compatibility and release gates

| Axis | Initial contract | Gate |
| --- | --- | --- |
| Source server | PostgreSQL 16, 17, 18 | Same-major client; fixture matrix for every major. |
| Restore target | Same major as source | Full fixture round trip; cross-major pair requires its own gate. |
| Deployment | Debian 13 or Ubuntu 24.04 LTS, amd64 | Package install/upgrade/remove and service permission tests. |
| Extension | Installed and compatible on target | Preflight name/version and fixture test; no implicit installation. |
| Artifact | Published v1 starts in M4 | Known-version reader; reject unknown critical fields and partial commits. |

M0 produces contracts and fixtures. It does **not** prove runtime behavior; the first executable validation occurs in M1/M2 with PostgreSQL 16–18. The [content matrix](docs/postgres/content-matrix.md), [privilege matrix](docs/postgres/privilege-matrix.md), [fixture plan](docs/postgres/fixture-plan.md), and [threat model](docs/security/threat-model.md) define those gates.
