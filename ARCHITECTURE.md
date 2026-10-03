# Architecture contract

Status: M0 design contract, 2026-09-26; artifact section revised 2026-10-01 for the M4b freeze; M5a inventory/lifecycle summary aligned 2026-10-03. See [project.md](project.md) for sequencing, [ADR 0001](docs/architecture/adr-0001-foundations.md) for the foundations alternatives, and [ADR 0002](docs/architecture/adr-0002-artifact-v1-and-signing.md) for the M4b origin-signature and the v1 freeze it accepted.

## Product boundary

`backupctl` is one Rust modular monolith. CLI, systemd invocation, and future HTTP API call the same application use cases. The browser UI calls the API. PostgreSQL 16–18 is the first engine family; a new engine implements a capability interface rather than inheriting PostgreSQL-specific flags. M1–M3 use synthetic data only. Real-data publication requires the M4a hybrid encryption and the M4b origin signature, which together froze artifact v1 on 2026-10-01: a store that writes real data must configure both `[encryption]` and `[signing]`, because the encryption-only shape this build still writes is unsigned and its manifest is plaintext. The CLI keeps requiring `--confirm-synthetic` on every write regardless of shape; that guard is a statement about this build's certification (M6 packaging), not a per-run toggle for the format.

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
- Crypto adapter: age recipient/identity access, streaming encryption/decryption with our own hybrid `mlkem768x25519` recipient (ML-KEM-768 first, then X25519) inside age's standard authenticated stream, so a v1 artifact is decryptable by `backupctl` alone, detached hybrid Ed25519 + ML-DSA-65 signing/verification, and complete authentication; it reports the suite it used and knows nothing about databases. See the [hybrid rationale](docs/security/post-quantum-hybrid.md) and the [key lifecycle procedure](docs/security/key-lifecycle.md).
- Inventory adapter (M5a in progress): separate `backup-inventory` crate for key-free SQLite index and job/audit state, without a crypto dependency; DELETE journal with synchronous=FULL and per-source/profile flock. Reconciliation and rebuild are still pending. Published artifacts remain discoverable with the recovery identity after catalog loss.
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

The delivered M5a backup job lifecycle is `running -> staged -> complete`, with `failed` on an unfinished guard drop and `interrupted` when a later writable inventory open finds a non-terminal row whose scope lock is free. Job state and its audit event are transactional. Verification outcomes belong to inventory events rather than mutable v1 manifests; their persistence is still pending. `planned`, `verified`, `cancelled` and `quarantined` are future vocabulary, not implemented job states. Interrupted jobs do not become complete on restart. Startup cleanup currently assumes a single owner and can remove live staging/scratch before locking; this is an M5a completion blocker recorded in project.md §32. The durable v1 artifact consists of `public.json`, `manifest.age`, `payload.age`, `globals.age` when globals are exported, `signature.hybrid`, and a completion marker. Stage on the same filesystem, fsync payload/manifest/header and directory, rename to immutable ID, then create/fsync the marker. A reader accepts only a valid marker **and** a verified artifact: `complete`, a split-manifest refusal, the bounded `public.json`, both ciphertext digests and sizes recomputed from the files, then the detached hybrid signature — and only after that is the manifest decrypted and compared field by field against the header. `globals.age` is bound one step further in, by the digest inside the signed manifest rather than by the signature tuple. The public header and SQLite records are discovery hints; the trusted signature and the authenticated manifest are authoritative, which includes the suite strings: the header's claim is checked against the readable list at discovery, and a disagreement with the manifest is a refusal at the next level. See [artifact v1](docs/backup-format/manifest-v1.md).

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
| Artifact | v1 frozen 2026-10-01: written and read by this build, matrix-verified on PostgreSQL 16–18 | Known-version reader; reject unknown critical fields, unaccepted suites, and partial commits. A cross-build golden fixture is deliberately not checked in yet — [artifact v1](docs/backup-format/manifest-v1.md) states what pins the shape instead. |

M0 produces contracts and fixtures. It does **not** prove runtime behavior; the first executable validation occurs in M1/M2 with PostgreSQL 16–18. The [content matrix](docs/postgres/content-matrix.md), [privilege matrix](docs/postgres/privilege-matrix.md), [fixture plan](docs/postgres/fixture-plan.md), and [threat model](docs/security/threat-model.md) define those gates.
