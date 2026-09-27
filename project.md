# PostgreSQL Backup Platform — Project Roadmap

## 1. Project vision

Build `backupctl`, a reusable Rust backup service whose CLI, scheduled runner, future API, and future UI invoke the same application core. The first release backs up and restores PostgreSQL databases with a predictable artifact, verifiable completion, explicit restore safeguards, and Debian deployment. It is a modular monolith. Additional database engines must be possible through a narrow engine capability boundary, but PostgreSQL semantics must not be flattened into misleading generic promises.

**Evidence labels used below:** **PG** means behavior documented by PostgreSQL; **Tool** means a practice observed in an existing backup product; **Decision** means this project's proposed design. PostgreSQL behavior is cited to the [PostgreSQL 18 backup chapter](https://www.postgresql.org/docs/18/backup.html), [`pg_dump`](https://www.postgresql.org/docs/18/app-pgdump.html), [`pg_restore`](https://www.postgresql.org/docs/18/app-pgrestore.html), [`pg_dumpall`](https://www.postgresql.org/docs/18/app-pg-dumpall.html), and [`pg_basebackup`](https://www.postgresql.org/docs/18/app-pgbasebackup.html). Before coding, recheck version-specific behavior for the selected 16–18 support matrix.

## 2. Goals and non-goals

**Goals:** consistent logical backup; explicit content selection; local encrypted artifacts; inspect, verify, list, restore, retention, scheduling, job status; secure service operation; documented limits and restore drills; stable core usable by future interfaces. Prioritize a small, tested set of promises over feature count.

**Non-goals for the first production release:** physical/base backups, WAL archiving, PITR, zero data loss, cluster failover, incremental/differential backups, row filtering, arbitrary SQL object filtering, secrets/OS file backup, remote stores, cloud KMS, multi-tenancy, and a browser UI. A logical dump has an RPO of its snapshot time; it cannot recover intermediate transactions.

## 3. Requirements and release boundaries

| Stage | Capability | Release bar |
| --- | --- | --- |
| Development MVP (M1–M2) | One database, full logical custom archive, local store, inspect/list, checksum, safe restore into a new database | Synthetic fixtures only; failure never publishes a complete artifact. Real-data use begins after M4a hybrid encryption. |
| Hardened CLI | Profiles and supported selection, encryption, retention, scheduling, SQLite job catalog, Debian service | Documented restores, interrupted-job recovery, privilege tests, audit trail. |
| Service | Authenticated asynchronous API and API-backed UI | Same core behavior, authorization, idempotency, rate limits, observability. |

**Initial support policy (September 2026):** PostgreSQL 16, 17, and 18 sources; same-major restore first. Cross-major restore remains unsupported until each source/target pair passes real fixture tests. Select `pg_dump` and `pg_restore` from a configured absolute path matching the source major, record exact tool versions, and refuse missing/mismatched clients. The first `.deb` targets Debian 13 and Ubuntu 24.04 LTS on amd64. Depend on `postgresql-client-common`; operators install the required `postgresql-client-N` package from their distribution or the official PostgreSQL Apt repository. Review the matrix each release. PostgreSQL 19 is prerelease and 14 nears end of support as of this decision. [Version policy](https://www.postgresql.org/support/versioning/), [Debian packaging](https://www.postgresql.org/download/linux/debian/), [Ubuntu packaging](https://www.postgresql.org/download/linux/ubuntu/).

RPO and RTO are deployment properties. The example policy is daily backup, alert after 26 hours without a verified backup, and a weekly isolated restore drill. The nominal RPO is one day; actual RPO is the age of the latest *restorable* snapshot and can be worse after failures. Report measured restore time, not a universal RTO guarantee. Require two copies on different failure domains before claiming recovery from host loss; the first local-store release makes no such claim.

## 4. PostgreSQL backup model

### Mechanisms and limits

| Mechanism | Strengths | Limits and choice |
| --- | --- | --- |
| `pg_dump -Fc` + `pg_restore` | One database; portable logical archive; table of contents (TOC), selective restore, parallel restore | **MVP choice.** Single dump process; downtime-free consistent snapshot, but concurrent DDL/locks can interrupt it. |
| `pg_dump -Fd` | TOC plus parallel dump and restore | Later performance option; multiple files require atomic directory publication and transport. `-j` uses `j+1` connections and raises server load. |
| Plain SQL | Inspectable, restored with `psql` | No `pg_restore` TOC; poorer selective restore. Export/interoperability option only. |
| Tar archive | Archive but constrained ordering and no built-in compression | No MVP advantage. |
| `pg_dumpall` | Cluster SQL dump or globals-only roles/tablespaces | Global objects are separate from a database dump; `--globals-only` is opt-in and privileged. Do not silently attach it to every database backup. |
| `pg_basebackup` + WAL | Entire physical cluster, foundation for PITR | Separate subsystem and operational contract. Cannot selectively back up a database/table. Future work. |

**PG:** `pg_dump` is a consistent export of one database, not an entire deployment. Archive formats allow TOC selection. A newer `pg_dump` cannot dump a newer server; loading into an older target major is not guaranteed. Client and server versions and extensions must be preflighted. [Source](https://www.postgresql.org/docs/18/app-pgdump.html). **PG:** physical backups cover the cluster, while PITR requires a usable base backup plus a continuous WAL chain. [Source](https://www.postgresql.org/docs/18/continuous-archiving.html). **Decision:** do not describe logical backups as PITR or use `pg_verifybackup` on logical archives; it validates physical base backups.

### Content inventory and policy

In the tables, **tool** identifies the native mechanism; **place** says whether it logically belongs to a database backup; **plan** gives support/optionality; **restore** states the consequence; **record** states metadata needs. “Dump” means native `pg_dump` behavior subject to source privileges, version, and selection. The inventory must be turned into version-specific fixture tests before a support claim is published. [Sources: `pg_dump`](https://www.postgresql.org/docs/18/app-pgdump.html), [`pg_restore`](https://www.postgresql.org/docs/18/app-pgrestore.html), [`pg_dumpall`](https://www.postgresql.org/docs/18/app-pg-dumpall.html).

| Category | Tool; place | Plan and optionality | Restore and record |
| --- | --- | --- | --- |
| Schemas; tables; table data; views; materialized views | Dump; database | Full profile default; schema/table/data selection where native flags permit | Restore dependencies and ownership; record selected schemas, resolved objects, TOC digest. Materialized view definitions/data need fixture checks. |
| Indexes; primary, foreign, unique and check constraints; triggers; rules | Dump; database | Included with full schema; do not promise independently selectable dependency closure | Post-data order matters; filtered restore may lack referenced tables; record TOC entries. |
| Sequences and current state; identity/generated columns; partitioning; inheritance | Dump; database | Full default; selective profile requires explicit dependency warnings | Restore state with data, not schema-only; partition children and parent selection need tested semantics; record selection and source version. |
| Functions; procedures; types; domains; enums; collations; text-search objects | Dump; database | Full default; exact-object selection deferred to TOC research | May depend on extensions, OS locale, installed libraries; record dependency warnings and TOC. |
| Extensions; foreign data wrappers; foreign servers; user mappings | Dump definitions where supported; database plus external dependencies | Full default for definitions; always treat the native archive as sensitive and encrypt it before real-data publication | Extension binaries and endpoints are not supplied by dump. User-mapping options **can contain passwords in the archive**; never echo them in metadata/logs. |
| Grants, ownership, default privileges; comments; row-level-security policies; security labels | Dump; database | Full default; portable mode may opt out of owner/ACL; do not claim RLS enforces row filtering of a dump | Destination roles/provider must exist; record inclusion flags. Dump may bypass RLS or fail under insufficient privileges; test the privilege mode. |
| Large objects | Dump by default for whole database, with selection caveats; database | Full default; explicit include for schema/table filtered dumps | Large-object references may not track selected tables; record inclusion and warn about orphans. |
| Publications and subscriptions | Dump definitions according to tool/version; database with external replication state | Publication default; `--no-subscriptions` for first release, omission recorded | Subscription connection strings can contain passwords. Future opt-in restore requires separate activation; never silently connect or recreate slots. |
| Database creation, database-level settings and privileges | `pg_dump` options / catalog; database-level, not schema-level | Capture supported definitions for full-database restore; optional `--create` workflow | Target names/settings may be unsafe or unavailable; record database attributes and validate before create. |
| Roles/users, role memberships, role passwords, tablespaces, global parameter grants | `pg_dumpall --globals-only`; cluster-global | Separate privileged, opt-in global artifact in a later milestone; password hashes excluded by default | Can conflict with existing roles/paths and require superuser; never auto-apply; record global artifact reference and privileges. |

| External category | Tool; place | Plan and optionality | Restore and record |
| --- | --- | --- | --- |
| OS cron, systemd units/timers, application jobs | No PostgreSQL dump; host/app | Outside database artifact. Document as deployment dependencies; later configuration export only if safe. | Never auto-install or start on restore; record operator checklist only. |
| External files, filesystem data, environment variables, secrets, certificates | No PostgreSQL dump; host/app | Out of scope for MVP; separate file/secret backup mechanism | Never embed secrets; record dependency names and recovery checklist, not values. |
| `postgresql.conf`, `pg_hba.conf`, `pg_ident.conf`, server TLS settings | No logical dump; server | Separate privileged configuration backup, future only | Unsafe to apply blindly across hosts/versions; record expected settings and validation steps. |
| WAL archives and replication slots | No logical dump; cluster/replication | Separate physical backup/WAL subsystem, future only | Required for PITR, not part of logical restore; record that this artifact has no PITR coverage. |

**Selective operations:** support full, schema-only, data-only, named schemas, and named tables using native `pg_dump`/`pg_restore` switches. Resolve user patterns to exact source objects in preflight, fail on zero or ambiguous matches, and record both requested and resolved selection. Filtered dumps do **not** include all external dependencies; `pg_restore -t` is not a dependency resolver. Sequence state, large objects, extension-owned objects, foreign keys, partition children, and cross-schema references may make a partial archive unrestorable on a clean target. Table-data-only restore requires existing compatible schema. For selected partitioned/inherited parents, use `--table-and-children` and record all resolved children; reject parent-only selection as a full-family backup. Child-only selection remains an advanced partial operation. For schema/table filters, large objects are excluded by default; explicit `--large-objects` includes **all** large objects, not just referenced ones. [PostgreSQL 16 `pg_dump`](https://www.postgresql.org/docs/16/app-pgdump.html). Exact TOC item editing is an expert, later feature with a generated `pg_restore -l` plan; arbitrary object filters and row filters are not MVP promises. [Sources: `pg_dump`](https://www.postgresql.org/docs/18/app-pgdump.html), [`pg_restore`](https://www.postgresql.org/docs/18/app-pgrestore.html).

## 5. Architecture

Workspace layout (planned, not yet implemented):

```text
crates/
  backup-domain/       # IDs, policies, artifact schema, capability types
  backup-application/  # backup/restore/verify/prune use cases and ports
  backup-postgres/     # pg_dump/pg_restore adapter and preflight
  backup-local/        # local artifact storage and SQLite catalog
  backup-crypto/       # streaming authenticated encryption and key providers
  backupctl/           # CLI and optional daemon entry points
  backup-api/          # future HTTP adapter
deploy/ docs/ tests/
```

The dependency direction is interface → application → domain; infrastructure implements application ports. A `DatabaseEngine` port owns capability discovery, backup planning/execution, and restore planning/execution. Keep engine-specific PostgreSQL selection and restore controls in typed PostgreSQL requests, not a lowest-common-denominator global interface. `ArtifactStore`, `Catalog`, `RecipientProvider`, `IdentityProvider`, `Signer`, `Verifier`, `Clock`, and `JobRunner` are separate ports where multiple implementations or deterministic tests justify them. The UI consumes the API; neither CLI nor API duplicates use-case rules. Avoid distributed queues or microservices until measured scaling requires them.

| Execution option | Pros | Cons | Decision |
| --- | --- | --- | --- |
| PostgreSQL CLI tools | Mature, versioned native semantics, TOC support | Process supervision and tool provisioning | **Use** `pg_dump`/`pg_restore` with fixed executable paths and argv arrays. |
| PostgreSQL client libraries | Direct catalog access and precise preflight | No replacement for complete dump/restore logic | Use only for metadata/preflight if it adds value. |
| Custom dump engine | Full control | High compatibility and correctness burden | Reject. |

Processes never pass through a shell. Cap stdout/stderr capture, redact connection data, set timeouts and cancellation, verify executable provenance/version, and restrict inherited environment. Avoid passwords in argv and logged URLs.

## 6. Domain model

`BackupProfile` is immutable per job via a versioned snapshot. `Source` identifies an engine and connection reference, not a password. `Selection` is an engine-specific resolved scope. `BackupPlan` captures source capability/version, intended archive format, storage, compression, encryption, and estimated risks. `BackupRecord` holds status (`planned → running → staged → verified → complete`, or `failed/cancelled/quarantined`), artifact reference, hashes, and timestamps. `RestorePlan` holds target identity, selected TOC, compatibility checks, conflict mode, and an expiring plan digest. `Job` captures state, actor, retry/cancel state, and safe diagnostics. `RetentionPolicy` selects candidates but cannot delete until protected-backup invariants pass.

Ports should stream bounded chunks; no use case loads a whole archive into memory. Version artifact schemas and catalog migrations independently. Use UUID/ULID IDs, UTC timestamps, and stable JSON field names; never infer truth from a directory name alone.

## 7. Backup artifact design

**Published artifact v1:** `artifacts/<opaque-id>/public.json`, `manifest.age`, `payload.age`, `signature.hybrid`, and a completion marker. `payload.age` decrypts to a native PostgreSQL custom archive. The encrypted manifest and `public.json` name the **algorithm suite** — recipient construction (`x25519` or `x25519+ml-kem-768`), signature construction (`ed25519` or `ed25519+ml-dsa-65`), and the implementing versions — because a reader must be able to tell a hybrid artifact from a classical-only one and refuse a silent downgrade rather than assume. `public.json` contains only format version, opaque ID, suite, recipient/signer IDs, encrypted file sizes, and ciphertext checksums; it is untrusted until verified. The encrypted manifest contains ID, PostgreSQL/client/application versions, redacted source fingerprint, profile snapshot/hash, requested/resolved scope, TOC digest/summary, compression, timestamps, byte counts, duration, verification level, ciphertext digest, compatibility warnings, and status. It never copies passwords, connection strings, raw SQL, or key material into fields. The PostgreSQL archive itself may contain secrets.

The decrypted manifest binds its ID and the SHA-256 digest of `payload.age`. On read: check the recorded suite is one this reader is allowed to accept, verify the detached hybrid signature against an independently trusted verifying key over ID and both ciphertext digests; authenticate/decrypt manifest; compare ID with path/public header; check payload digest; authenticate the entire payload before restore. A public header is a discovery aid, not security truth. Stage privately on the same filesystem, fsync files and directory, atomically publish, then write the completion marker; a missing marker or mismatch is incomplete. SQLite indexes validated manifests and job state; recovery with the decryption identity rebuilds it. M1 plaintext output is synthetic-data development output only, never a public artifact. Freeze published v1 at M4b after interoperability, corruption, and suite-downgrade tests. Readers accept known versions, reject unknown critical fields, and never rewrite immutable artifacts in place. Future remote storage commits payload, encrypted manifest, public header, then marker. Offline rollback/deletion still needs independent inventory or immutability; a signature does not reject an older valid artifact.

## 8. Security model

**Decision:** compress before encryption because ciphertext does not compress meaningfully. Use `pg_dump -Fc` with zstd if the source-major client supports it, otherwise gzip; record the exact method and do not double-compress. Use the maintained Rust [`age` crate](https://docs.rs/age/latest/age/) and its standard streaming format with a **hybrid classical + post-quantum recipient**: the payload key is agreed with X25519 *and* ML-KEM (FIPS 203) combined per [RFC 10024](https://www.rfc-editor.org/info/rfc10024/), never with the post-quantum primitive alone and never with the classical primitive alone for new writes. Age provides per-file data keys, recipient wrapping, authenticated streaming, and truncation detection. Whether the hybrid recipient is carried by age's own `age-encryption.org/v1` container or by a thin suite-labeled envelope around the same authenticated stream is the M4a spike's decision, not a settled fact; either way finish the stream writer and authenticate a complete read before passing plaintext to `pg_restore`, and do not design custom AEAD framing. [Age streaming API](https://docs.rs/age/latest/age/struct.Encryptor.html), [Age crate](https://docs.rs/age/latest/age/), [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).

The initial provider reads a service-owned age identity file, mode 0600, outside the artifact store; the identity holds both halves of the hybrid recipient (X25519 and ML-KEM), so key files, sizes, and recovery instructions are named per suite rather than assumed. Configure the public recipient separately and maintain an offline recovery copy. A recipient/identity provider boundary permits later OS keyring, Vault, and cloud KMS integration. In v1, rotation decrypts and re-encrypts to a new recipient as a new validated artifact generation; do not promise cheap header-only rewrap. Password mode is deferred: standard age passphrase recipients use scrypt, whereas the earlier proposed Argon2id KEK would require another envelope format. If added, use age's standard passphrase mode with a human-provided secret, never an argv value. SHA-256 detects accidental corruption; age authenticates encrypted content but its public recipient does not authenticate the sender. Published v1 therefore requires a detached **hybrid Ed25519 + ML-DSA-65** signature from a distinct signing key outside the artifact store, with its verifying key trusted independently; keeping the classical half alongside the post-quantum half means a break in either primitive alone does not yield a forgery. See [ADR 0001](docs/architecture/adr-0001-foundations.md). Encryption and signatures cannot prevent deletion, rollback of an older valid artifact, or exfiltration from a compromised live host. Plaintext restore staging uses a private capacity-checked directory and best-effort removal, with SSD deletion limits documented.

PostgreSQL credentials: prefer peer auth for local operation or a dedicated `PGPASSFILE` with mode 0600; require TLS verification for remote connections. The [PostgreSQL password-file documentation](https://www.postgresql.org/docs/current/libpq-pgpass.html) describes permission rules. No credentials in profiles, manifests, argv, logs, error messages, or environment inherited by unrelated children. Document minimum privileges by operation and test them: dump needs CONNECT/USAGE/SELECT or equivalent on selected objects; full cluster globals and some restore operations can require elevated privileges. Decline a requested feature when its privilege requirement cannot be met safely. `pg_dump` warns that restoring dumps can execute code selected by a source superuser; treat untrusted artifacts as executable input and require trusted origin/review before restore. [Source](https://www.postgresql.org/docs/18/app-pgdump.html).

## 9. Threat model

Maintain [the M0 threat model](docs/security/threat-model.md) at encryption, API, and release gates. Each entry records attacker, asset, attack, impact, mitigation, and residual risk.

| Attacker / asset | Attack and impact | Mitigation |
| --- | --- | --- |
| Backup-file thief / data | Copy artifact and metadata; disclose now and decrypt later, when a quantum adversary makes a classical-only key exchange breakable | Hybrid AEAD encryption (X25519 + ML-KEM), separate KEK, minimal manifest, restrictive permissions. |
| Compromised backup host / keys and data | Read live keys or plaintext; broad disclosure | Least privilege, key isolation, short secret lifetime, off-host monitoring; state residual risk explicitly. |
| Stolen database credential / source | Unauthorized reads or modifications | Least-privilege dump role, TLS, credential rotation, connection audit. |
| Malicious local user / artifact store | Path traversal, symlink swap, overwrite | Private dirs, relative opaque IDs, `openat`-style no-follow handling, ownership checks, atomic publication. |
| Malicious API client / jobs | Restore/deletion abuse, replay, resource exhaustion | AuthN/AuthZ by operation, idempotency keys, quotas/rate limits, audit, explicit restore approval token. |
| Tampering storage provider / backups | Replace/delete/replay old artifacts | Required hybrid (Ed25519 + ML-DSA-65) origin signature over recorded suite and ciphertext digests detects replacement; independent inventory/immutable copies and audit address deletion or replay. |
| Crafted identifier or filename / process | Command injection or arbitrary file access | Typed inputs, argv arrays, no shell, canonical source-object resolution, fixed tool paths. |
| Compromised backup SQL / target | Execute malicious SQL on restore | Trust boundary and review, isolated target, restricted restore role, preflight; never auto-restore unknown artifacts. |
| Operator mistake / production | Destructive overwrite or incompatible restore | Target fingerprint, dry-run plan, explicit digest confirmation, default new database, version/extension checks. |
| Privileged administrator / deletion | Remove all recoverable copies | Retention floor, protected backups, off-host copies/immutability later, audited break-glass flow. |

## 10. Storage architecture

`ArtifactStore` provides stage/write/read/commit/list/delete with immutable IDs and capability flags (atomic rename, conditional create, consistency). Local MVP uses a dedicated directory, restrictive umask, capacity checks, fsync of file and parent directory before commit, and quarantine of stale stages. Never follow user-controlled symlinks. Future S3/MinIO/SFTP adapters use multipart/resumable upload and commit markers; no reliance on rename. The core owns lifecycle rules; adapters own transport. An independent copy on a different failure domain is required for a strong disaster-recovery claim.

Retention policies: `keep_last`, age limit, and later daily/weekly/monthly buckets, plus per-backup legal/protection flags. Preview is default for `prune`; execution requires explicit confirmation and audit. Never delete the only known valid backup for a source, an active/restoring backup, a protected backup, or a backup needed by an in-progress job. Count only verified/complete artifacts as valid. Tool observations: [pgBackRest](https://pgbackrest.org/user-guide.html) expires after successful new backup, [Barman](https://docs.pgbarman.org/release/3.13.1/user_guide/retention_policies.html) supports redundancy and recovery windows, and [WAL-G](https://github.com/wal-g/wal-g/blob/master/docs/PostgreSQL.md) protects permanent backups. These inform policy and safety, not implementation copying.

## 11. Restore architecture

1. Resolve artifact and verify manifest schema, checksum, AEAD, archive TOC, key availability, tool version, and source trust.
2. Build a deterministic plan: target server/database identity, source/target versions, extensions/collations, roles/ownership, tablespaces, selected TOC entries, required privileges, likely conflicts, estimated size, and dry-run warnings. A dry-run does **not** execute SQL and cannot prove success.
3. Default to a new database and `pg_restore --exit-on-error`; require a destination-name confirmation or exact plan digest for any operation that can replace existing objects. Destructive `--clean`, `--create`, and role/global restore are separate explicit choices. Noninteractive API requires an authorized plan token bound to target fingerprint, scope, expiration, and actor.
4. Choose full, schema-only, data-only, selected schema, or selected table as supported by `pg_restore` and the artifact. No implicit dependency reconstruction. Ownership policy is explicit (`preserve` versus `--no-owner`); ACL policy likewise. Check extension availability. After restore, run required validation and `ANALYZE` where appropriate.
5. Treat interrupted restore as potentially partial. Record exact state and recovery instructions; never auto-retry a destructive restore. `--single-transaction` is an optional compatible mode; parallel restore and single transaction are not combined. Prefer a fresh disposable target for test restore.

Cross-server restore is allowed only after preflight and explicit target identity check. Active connections and database creation/drop privileges are checked before overwrite. Never assume a newer-to-older PostgreSQL restore works. [Source](https://www.postgresql.org/docs/18/app-pgrestore.html).

## 12. CLI architecture

| Command | Behavior |
| --- | --- |
| `backupctl backup create --profile NAME` | Plan, run, publish; `--dry-run` reports resolved scope. |
| `backupctl backup list`, `inspect ID`, `verify ID`, `protect ID`, `delete ID`, `prune` | Search and lifecycle; delete/prune preview by default. |
| `backupctl restore plan ID --target NAME`, `restore run PLAN_ID --confirm-target NAME` | Review then execute; destructive modes require a plan digest confirmation. |
| `backupctl profile validate/list`, `schedule list/run`, `job list/inspect/cancel`, `config check`, `status`, `version`, `completion` | Administration and diagnostics. |

Human tables by default, stable `--output json` for machines, `--quiet` for success output suppression, and `-v`/structured logs to stderr. Define exit codes: 0 success, 2 usage/config, 3 preflight/authorization, 4 backup/restore execution, 5 verification/integrity, 6 partial/cancelled. JSON errors carry machine code, safe message, job ID, and retryability. Config precedence: explicit CLI > allowlisted environment overrides > TOML file > defaults; secrets are references, not inline values. Shell completion is generated from the CLI parser.

## 13. API architecture

Future Rust HTTP adapter calls application use cases. `POST /api/v1/backups` and `/restores` create asynchronous jobs and return `202` plus job URL; `GET /api/v1/jobs/{id}`, `/backups`, `/backups/{id}`, `/profiles`, `/health` expose status. Use cursor pagination and a stable problem-style error shape. Backup creation and restore submission require idempotency keys bound to actor/request digest. Authentication can start with local service tokens or trusted reverse-proxy identity only after threat review; operation-level authorization separates backup, restore, delete, profile, and admin. Bind to loopback by default, require TLS at the deployment boundary, rate-limit expensive operations, redact request logs, and audit actor/target/decision. Never accept arbitrary paths or shell options from HTTP. API versioning covers wire contracts; artifact schema versions are separate.

## 14. UI architecture

After the API stabilizes, build a small independent web client (TypeScript with a mature component framework chosen at that milestone). It consumes only the API. Views: dashboard/health, backups/details, restore plan and confirmation, profiles, schedules, storage/key status without secrets, jobs/logs, and audit history. Present verification level and partial-backup warnings prominently. The UI cannot bypass plan confirmation or privilege checks. Accessibility and clear destructive-action UX are acceptance gates.

## 15. Configuration and profile system

**Decision:** versioned TOML for human-edited service config and profiles; JSON is API/artifact interchange; YAML adds parsing ambiguity without a needed feature. Strict schema validation rejects unknown fields and impossible combinations. Example shape (illustrative, no secrets):

```toml
version = 1
name = "application-data-only"
source = "production"
format = "custom"
mode = "schema-and-data"
schemas = ["app"]
tables = []
large_objects = false
compression = "zstd"
storage = "local"
encryption_key = "age:primary"
```

Profiles specify database/source reference, selection, mode, archive format, compression, storage, encryption-key reference, verification level, retention policy, and schedule reference. Global-object export is a distinct privileged operation, never a boolean silently merged into the same archive. Distinguish include from exclude rules, preserve exact resolved scope in each job, and reject profiles that advertise unsupported combinations. Config reload affects only new jobs.

## 16. Metadata database

| Option | Pros | Cons | Decision |
| --- | --- | --- | --- |
| SQLite | Zero extra server; transactional local jobs and migrations | Single-host writer; needs careful backup/rebuild | **Choose** for monolith MVP; WAL mode, busy timeout, one owner. |
| PostgreSQL | Multi-host concurrency and richer operations | Dependency cycle if service database shares source cluster | Defer until multi-node requirement exists. |

Tables: sources (secret references only), profile versions, backup records, artifact locations, job leases/events, schedules, retention decisions, audit events, schema migrations. No payload bytes. Reconcile catalog from authenticated manifests after crash using the recovery identity; catalog loss must not make valid artifacts undiscoverable to a key holder. Keep catalog backups separate from the PostgreSQL sources it protects.

## 17. Scheduling

| Scheduler | Pros | Cons | Decision |
| --- | --- | --- | --- |
| systemd timer | Native Debian lifecycle, persistence, service isolation | Linux-specific, one unit/profile or generated units | **MVP** scheduled invocation; package example timer, operator enablement. |
| Internal scheduler | Dynamic API-managed schedules | Needs leader election, restart semantics, clock handling | Add only when API-managed schedules become necessary. |
| cron | Widely known | Weak job state and package ownership | Document as external invocation option, no native management. |

OS timers and cron jobs are not PostgreSQL objects and are absent from database dumps. Use UTC schedule definitions, document missed-run behavior, single-instance lock, overlap policy, and manual run interaction. Do not start a second dump for the same source/profile while one runs.

## 18. Reliability and concurrency

Use a persisted job state machine and bounded worker pool: initial default one backup and one restore globally, with per-source exclusive restore lock and configurable dump limits. Reserve disk headroom before dump; enforce duration/size limits and cancellation by terminating the process group, then quarantine staged data. Retry only idempotent stages (e.g., future upload); a new dump is a new snapshot/job. On restart, mark orphaned running jobs interrupted, inspect/quarantine stages, and never infer success from process exit alone. Check exit status, stderr warnings, payload existence, checksum, archive TOC readability, durable commit, and catalog update before `complete`.

Failure matrix to test: PostgreSQL unavailable, lock timeout, disk full, killed process, encryption/key failure, corrupt archive, SQLite failure, interrupted restore, remote upload interruption, and host restart. Failed restore may have changed target; surface this explicitly and require operator repair. Do not silently delete forensic artifacts until retention policy permits it.

## 19. Observability

Structured JSON logs for service and readable CLI output, with timestamps, job/backup IDs, source alias, phase, duration, bytes, throughput, and redacted failure code. No SQL payloads or credentials. Metrics later expose job counts/states, age of last verified backup, durations, throughput, verification failures, storage free space, scheduler misses, and queue depth. Prometheus-compatible endpoint belongs with authenticated service metrics, not a world-readable default. Audit records for backup, restore plan/run, delete, retention, key operations, and permission denials. Trace IDs connect API requests to jobs.

## 20. Testing strategy

Unit tests cover profile validation, state transitions, retention invariants, manifest parsing, and plan digests. Integration tests run real PostgreSQL containers across supported majors and fixtures containing every content-inventory category, including large objects, extensions, partitions, RLS, roles, and globals where privileges allow. Round-trip restores into clean and populated targets validate schema, row counts/checksums, sequences, ownership/ACLs, constraints, and expected warnings. CLI contract tests cover JSON/exit codes; API tests cover authorization/idempotency; storage/crypto tests cover truncation, bit flips, wrong keys, reordered chunks, invalid signatures, manifest/payload swaps, and key rotation. Fault injection covers crash, disk full, subprocess kill, SQLite failure, and interrupted restore. Property tests target selection normalization, retention safety, and path/manifest parsing. Security tests exercise path traversal, symlink races, argv injection, and secret redaction. Mock ports for fast logic tests, but do not replace real PostgreSQL restore tests.

Verification levels: `checksum` means bytes match stored digest; `archive` means `pg_restore --list` parses after decryption; `restore-tested` means isolated full restore and validation. No level alone guarantees future restore on a different version/host. Schedule recurring restore drills and record their result.

## 21. CI/CD

GitHub Actions gates: `cargo fmt --check`, `cargo clippy -- -D warnings`, unit tests, real-PostgreSQL integration/restore tests, build release binaries, build/install/uninstall `.deb`, and publish documentation. Pin action versions and toolchains; generate SBOM and checksums for releases. `cargo audit` checks known advisories; `cargo deny` checks licenses/sources if policy needs it. Keep security checks blocking only after a documented triage process, rather than accumulating noisy gates. Cache builds, but test clean package installs. Benchmark CI is scheduled/manual to avoid flaky PR gates. Release artifacts are signed when a signing key and trust workflow exist.

## 22. Debian packaging

Install `/usr/bin/backupctl`, `/etc/backupctl/config.toml` and profile directory, `/var/lib/backupctl` for catalog/artifacts, and systemd service/timer units. Log to journald; avoid a separate log directory unless an explicit file-log mode is added. Create dedicated `backupctl` system user/group and restrictive directories via package/systemd rules; source database credentials use a separate protected path. Define `StateDirectory`, `ConfigurationDirectory` where supported, `UMask`, filesystem restrictions, and resource limits; test that they still permit PostgreSQL access. Depend on `postgresql-client-common` and require an installed `postgresql-client-16`, `-17`, or `-18` matching the source major; resolve its absolute path and check its version before each operation. Test Debian 13 and Ubuntu 24.04 LTS on amd64. Upgrades migrate SQLite transactionally with backup and rollback guidance; never delete artifacts or private keys on package removal. Purge requires an explicit documented data/key retention policy. APT repository publication is future distribution work.

## 23. Docker and development environment

Compose provides PostgreSQL, the service, and test volumes; optional MinIO and second PostgreSQL major are profile-gated future additions. Fixtures seed object categories and privilege modes. Container images run nonroot and are for development/integration testing; Debian/systemd remains the primary production target. Document Docker-free local development for contributors with PostgreSQL client tools.

## 24. Benchmark strategy

Use reproducibly generated 100 MB, 1 GB, and 10+ GB datasets with compressible and incompressible fields, many small tables, large tables, indexes, and large objects. Record PostgreSQL/client versions, schema/data generator seed, hardware, filesystem, compression/encryption settings, worker count, cache state, and command line. Measure backup and restore throughput, compression ratio, encryption overhead, CPU, peak RSS, I/O, server load, and total time including verification. Run repeated trials and report median/range; compare `-Fc` versus `-Fd`, and supported compression choices. Benchmarks inform defaults, not marketing claims.

## 25. Documentation strategy

Start `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`, `CHANGELOG.md`, and `docs/`. Add focused guides for PostgreSQL content/privileges, artifact schema, backup/restore runbooks, profiles, CLI, API, deployment, development, threat model, and benchmarks as their features land. Show a worked recovery drill and explicit exclusions/RPO limits. Maintain versioned configuration and artifact migration notes. Keep `project.md` current through minimal edits when decisions change.

## 26. Milestone roadmap

The following milestones are implementation handoffs. Paths are planned. Each milestone must update the relevant docs and pass its listed tests before the next starts. “DB” refers to service metadata schema; “none” is intentional. Do not implement during this roadmap phase.

### M0 — Research and contracts

- **Objective/why:** turn PostgreSQL content and threat assumptions into testable contracts before writing the engine.
- **Prerequisites:** none. **Architecture/files:** `ARCHITECTURE.md`, `docs/postgres/content-matrix.md`, `docs/security/threat-model.md`, `docs/backup-format/manifest-v1.md`, ADRs.
- **APIs/DB/CLI:** versioned manifest and capability sketches; no DB migration or CLI command.
- **Tests/security/docs:** synthetic fixtures and versioned test matrix, restore-trust boundary, privilege matrix, source citations; runtime validation follows in M1/M2.
- **Acceptance/DoD:** supported version matrix, fixture SQL and assertions, artifact spec, threat model, and decisions recorded; no unsupported runtime restore claim.
- **Pitfalls:** assuming all PostgreSQL versions or extension ecosystems behave alike. **Portfolio:** database internals, architecture, threat modeling.

### M1 — Local full backup and inspect

- **Objective/why:** establish a complete, durable local logical artifact. **Prerequisites:** M0.
- **Architecture/files:** domain/application/PostgreSQL/local crates, `backupctl`, integration fixtures.
- **APIs/DB/CLI:** `DatabaseEngine::backup`, `ArtifactStore::stage/commit`, development-only artifact record (not published v1); SQLite not required yet; `backup create/list/inspect`, `config check`.
- **Tests/security/docs:** real `pg_dump -Fc`, zero-byte/disk-full/kill failures, redacted process invocation, local backup guide.
- **Acceptance/DoD:** restored synthetic fixture can be read by native tools; only fully written/checksummed archive is listed complete; version and tool path recorded. Plaintext output remains development-only.
- **Pitfalls:** `pg_dump` warnings, filesystem atomicity, permissions. **Portfolio:** Rust systems code, process supervision.

**M1 status (2026-09-26):** Implemented for synthetic local fixture databases in the five-crate Rust workspace. The CLI create/list/inspect path, checksum-validated staged publication, same-major client preflight, and independent restore smoke checks pass on PostgreSQL 16–18. PostgreSQL 16 failure checks cover missing synthetic confirmation, simulated write error, empty output, timeout, client-version mismatch, and config-error redaction. Plaintext M1 artifacts remain development-only; encrypted/signed v1 and restore orchestration remain M4 and M2 work respectively. See [M1 guide](docs/development/m1-local-backup.md).

### M2 — Safe full restore and verification

- **Objective/why:** prove backups are usable. **Prerequisites:** M1.
- **Architecture/files:** restore planner/executor, verification module, restore runbook.
- **APIs/DB/CLI:** `plan_restore`, `execute_restore`, `verify`; no DB migration; `backup verify`, `restore plan/run`.
- **Tests/security/docs:** clean-target round trip, incompatible version/extension, wrong target, corrupted bytes, interrupted restore; explicit trust warning.
- **Acceptance/DoD:** new-target restore succeeds and validates; destructive target requires bound confirmation; failure reports partial state.
- **Pitfalls:** `pg_restore` can execute untrusted SQL and partial failure may leave objects. **Portfolio:** recovery engineering.

**M2 status (2026-09-27):** Implemented for synthetic fixtures. `backup verify --level checksum|archive`, `restore plan`/`restore run` with an explicit `RestoreSecurityPolicy` (`dr` restores roles, memberships, ownership, and privileges; `portable` restores contents only), and JSON plans under `<storage-root>/plans/` with a 15-minute expiry and a `--confirm-target` equality check. Role, attribute, and membership metadata comes from opt-in `pg_dumpall --roles-only --no-role-passwords`, so no password verifier can enter an artifact and restored roles need an operator-assigned password; database-level `GRANT ... ON DATABASE` and tablespaces remain cluster prerequisites. Partial restore failure leaves the target in place and is reported. The Docker matrix passes on PostgreSQL 16–18 for DR restore, portable restore, plan expiry/binding, and tamper detection. See [M2 guide](docs/development/m2-restore-verify.md).

### M3 — Profiles and selective logical operations

- **Objective/why:** support explicit scope without false dependency promises. **Prerequisites:** M2.
- **Architecture/files:** TOML schema/validator, PostgreSQL selection resolver, TOC inspection fixtures, content matrix.
- **APIs/DB/CLI:** typed profile and selection; no DB migration; `profile validate/list`, selective `backup create` and `restore plan`.
- **Tests/security/docs:** schemas/tables, schema/data-only, sequence/large-object/partition/extension cases, zero matches, cross-schema dependencies.
- **Acceptance/DoD:** manifest records exact resolved scope; unsupported or risky selections fail or issue actionable warnings; selective restores tested.
- **Pitfalls:** native filters omit dependencies. **Portfolio:** PostgreSQL semantics, API design.

**M3 status (2026-09-27):** Implemented for synthetic fixtures. Typed `[[profile]]` blocks in the service TOML (exact lower-case names, no wildcards, no system schemas, tables and schema filters mutually exclusive because `pg_dump` discards one) feed a catalog resolver that resolves the selection with `psql` before `pg_dump` runs: zero-match selections, selections over 512 relations, and any reference from an in-scope object to an out-of-scope one are refused, with the dangling kinds covering foreign-key targets, parent relations, sequence defaults, enum/domain/composite/array column types, view and materialized-view base relations, and trigger or default-expression functions. Partitioned parents expand through `pg_inherits` to exact child names, large objects are refused in every filtered profile and in whole-database profiles that omit them, and `--exclude-extension` requires a 17 or newer client. The manifest records the requested and resolved scope plus a `toc_sha256` over `pg_restore --list` output that `verify --level archive` re-checks, keeping `m1-development-plaintext` so earlier artifacts still load. `profile validate/list`, `backup create --profile|--dry-run`, and repeatable `restore plan --section` were added; section sets must start at pre-data and cannot claim the `dr` policy, a table-selected run creates the schemas its resolved relations need, and a partial run never raises the verification level. `tests/m3_docker_smoke.sh` passes on PostgreSQL 16–18, and the M1 and M2 matrices still pass unchanged. `mode = "data-only"` profiles stay accepted at validation but cannot be restored by this CLI, because every restore creates an empty target database; the guide documents that as a known limitation rather than a supported selection. See [M3 guide](docs/development/m3-profiles-selective.md).

### M4a — Hybrid encryption and key providers

- **Objective/why:** protect stolen backups against a harvest-now-decrypt-later adversary, so neither the payload nor the metadata is ever plaintext in the published store. **Prerequisites:** M2; M3 profiles proceeded separately.
- **Spike first (the container decision, not optional):** prove whether the upstream [`age` crate](https://docs.rs/age/latest/age/)'s native hybrid post-quantum recipient (`tagpq`, built on [`ml-kem`](https://docs.rs/ml-kem) plus `x25519-dalek`) works with a **software file identity** — encrypt with the crate, decrypt with the crate, then decrypt with the stock `rage`/`age` CLI, and record whether the recipient demands a plugin or a hardware key. Result written into [ADR 0001](docs/architecture/adr-0001-foundations.md). If it is usable, keep the standard `age-encryption.org/v1` container and prove interoperability; if not, wrap a per-artifact data key with the hybrid KEM (X25519 + ML-KEM-768, combined per [RFC 10024](https://www.rfc-editor.org/info/rfc10024/)) and feed age's authenticated stream, then document explicitly that the artifact is no longer stock-age-decryptable. Either way: no hand-rolled AEAD framing, and no third-party PQ file-encryption container.
- **Architecture/files:** `backup-crypto` crate, `RecipientProvider`/`IdentityProvider` ports, named algorithm suite, service-owned key files outside the store, key recovery docs.
- **APIs/DB/CLI:** streaming encrypt/decrypt and identity ports; no DB migration; `key status`, `backup verify` levels. Rotation creates a new validated encrypted generation.
- **Tests/security/docs:** hybrid recipient round trip, truncation/reorder/bit-flip/wrong-key and manifest/payload swap cases, key-loss and rotation drill, no secret leakage, the spike's interop or documented-divergence result tested.
- **Acceptance/DoD:** plaintext never enters the published store; wrong key, tampering, and truncation fail before restore; the recipient suite and parameter set are recorded in the encrypted manifest; decryption key recovery tested; the container decision is written down, not implicit.
- **Pitfalls:** identity loss, finishing age streams, temporary plaintext, treating an unaudited PQ implementation as settled. **Portfolio:** applied cryptography.

### M4b — Origin signature and artifact v1 freeze

- **Objective/why:** let a holder of the decryption identity still detect a replaced or downgraded artifact, then freeze the published format. **Prerequisites:** M4a.
- **Architecture/files:** `Signer`/`Verifier` ports, hybrid detached signature (Ed25519 + ML-DSA-65 per [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)), independently trusted verifying key, published artifact v1 reader/writer, `public.json`.
- **APIs/DB/CLI:** signature ports and artifact v1 writer/reader; no DB migration; `key status`, `backup verify` gaining the signature level. Rotation re-signs into a new validated generation.
- **Tests/security/docs:** Ed25519 and ML-DSA signature vectors, artifact-swap and suite-downgrade rejection (a new write never selects a classical-only suite; a reader reports the recorded suite instead of guessing), truncation and reorder, no signing key material in logs, signing-key recovery drill.
- **Acceptance/DoD:** artifact v1 frozen with its suite fields; bad signature, swap, and downgrade fail before restore; signing key recovery procedure tested; readers accept known versions and reject unknown critical fields.
- **Pitfalls:** binding the signature to plaintext instead of ciphertext, trusting the same host for both keys, freezing a format whose suite is not recorded. **Portfolio:** applied cryptography.

### M5 — Catalog, jobs, concurrency, retention

- **Objective/why:** make lifecycle observable and deletion safe. **Prerequisites:** M1–M4b.
- **Architecture/files:** SQLite catalog/migrations, job runner, reconciliation, retention policy.
- **APIs/DB/CLI:** job/catalog/retention ports; initial tables for backups, jobs, events, audit, profiles; `job *`, `backup protect/delete/prune`.
- **Tests/security/docs:** crash recovery, overlapping jobs, catalog rebuild, protected/only-valid backup invariant, dry-run deletion.
- **Acceptance/DoD:** bounded workers and persisted states; no incomplete backup marked complete; retention preview matches executed deletion set.
- **Pitfalls:** catalog/artifact split-brain and race with restore. **Portfolio:** transactional state machines, reliability.

### M6 — Scheduler and Debian service

- **Objective/why:** run unattended on Debian safely. **Prerequisites:** M5.
- **Architecture/files:** systemd units/timer, packaging scripts, deployment guide.
- **APIs/DB/CLI:** scheduled job invocation; schedules table only if needed for listing policy; `schedule list/run`, `status`.
- **Tests/security/docs:** package install/upgrade/remove, timer overlap/missed run, service sandbox and file permissions.
- **Acceptance/DoD:** `.deb` installs reproducibly, scheduled backup runs as dedicated user, data/keys survive upgrade/removal.
- **Pitfalls:** client tool version mismatch and overly strict systemd sandbox. **Portfolio:** Linux packaging/operations.

### M7 — API and asynchronous service

- **Objective/why:** let other applications integrate without blocking HTTP. **Prerequisites:** M5–M6 and updated threat review.
- **Architecture/files:** `backup-api`, OpenAPI spec, auth/audit middleware.
- **APIs/DB/CLI:** v1 backup/restore/job/profile endpoints; token/actor and idempotency records; CLI may use core locally, with remote mode separately specified.
- **Tests/security/docs:** authz matrix, replay/idempotency, rate limits, request size, redaction, API contract tests.
- **Acceptance/DoD:** `202` job lifecycle, stable error contract, no unauthenticated destructive action.
- **Pitfalls:** duplicate jobs after client retry, target authorization. **Portfolio:** backend/API security.

### M8 — UI and operator workflow

- **Objective/why:** expose verified state and guided restores. **Prerequisites:** M7.
- **Architecture/files:** UI app and UX docs; backend unchanged except needed read APIs.
- **APIs/DB/CLI:** API-only client; no mandatory DB/CLI change.
- **Tests/security/docs:** accessibility, XSS, restore confirmation and failure states, browser/API integration.
- **Acceptance/DoD:** operator can inspect, plan, submit, and monitor using API; dangerous actions still require server-side authorization.
- **Pitfalls:** UI implying checksum equals successful restore. **Portfolio:** product integration.

### M9 — Production validation and release

- **Objective/why:** back claims with drills and measured limits. **Prerequisites:** M1–M8 for full platform release; CLI-only release may precede UI.
- **Architecture/files:** release workflow, benchmark reports, runbooks, changelog, support matrix.
- **APIs/DB/CLI:** freeze v1 contracts; migration tests for all metadata/artifact versions; no unplanned feature.
- **Tests/security/docs:** full failure matrix, 100 MB/1 GB/10+ GB benchmarks, restore drills, dependency review, package upgrade tests.
- **Acceptance/DoD:** published versioned artifacts and docs, measured restore duration and last-restorable-snapshot age, reproducible release, resolved critical security findings; no unsupported RPO/RTO or host-loss claim.
- **Pitfalls:** equating successful checksum with recoverability. **Portfolio:** testing, CI/CD, observability, release engineering.

## 27. Cross-cutting acceptance criteria

A production release requires: one complete artifact reconstructs a representative database on a supported target; verification reports its exact level; encrypted backup is unreadable without a separately stored identity and its origin signature verifies against an independently trusted key; backup interruption cannot produce a complete record; catalog can be rebuilt from artifacts; destructive restore and prune require explicit authorized plans; service connection credentials never appear in logs or service metadata, and native artifacts that may contain database-held credentials are encrypted; package install/upgrade preserve data and keys; and a documented restore drill has been performed on every supported PostgreSQL major. A feature is done only when its docs, threat review, and failure tests match its actual behavior.

## 28. Architectural decisions

1. Modular Rust monolith with a narrow database-engine capability boundary.
2. Native `pg_dump`/`pg_restore`; custom archive first, directory only after benchmarking.
3. Initial source support: PostgreSQL 16–18. Require a configured source-major client binary; same-major restore only until cross-major pairs pass fixture tests. Initial packages: Debian 13 and Ubuntu 24.04 LTS on amd64. Versioned clients come from the distribution or official PostgreSQL Apt repository. [PostgreSQL version policy](https://www.postgresql.org/support/versioning/), [Debian repository](https://www.postgresql.org/download/linux/debian/), [Ubuntu repository](https://www.postgresql.org/download/linux/ubuntu/).
4. Local filesystem and SQLite first; the catalog is rebuildable from encrypted manifests with a recovery identity.
5. TOML profiles, JSON API and public artifact fields, encrypted private metadata.
6. Published encryption uses a **hybrid classical + post-quantum** construction: the recipient key agreement combines X25519 with ML-KEM (FIPS 203), and the detached origin signature combines Ed25519 with ML-DSA-65 (FIPS 204). Private keys stay outside the artifact store. No custom AEAD framing; the container stays the maintained [`age` crate](https://docs.rs/age/latest/age/) stream format if its native hybrid recipient proves usable in software (see the M4a spike), otherwise a thin suite-labeled envelope around that same authenticated stream. [Age crate](https://docs.rs/age/latest/age/), [PQ/T hybrid key agreement](https://www.rfc-editor.org/info/rfc10024/), [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
7. Fresh-target restore by default; destructive work requires a bound plan confirmation. Subscriptions are excluded and global objects are documented manual prerequisites initially.
8. systemd timer for Debian scheduling; no internal scheduler in MVP.
9. No physical/PITR or host-loss recovery claim from local logical backup.
10. Published artifact v1 is frozen at M4b; M1 plaintext output is synthetic-data development output only.

## 29. Open questions and validation gates

The original eight questions have design resolutions. The remaining checks are empirical release gates.

| Former question | Resolution | Gate before support claim |
| --- | --- | --- |
| Versions/packages | PostgreSQL 16–18, same-major restore, Debian 13 and Ubuntu 24.04 amd64, matching client | Package CI and real fixture restores for every supported combination. |
| Encryption | Hybrid classical + post-quantum recipient (X25519 + ML-KEM, FIPS 203, combined per RFC 10024) inside the maintained `age` stream format; container choice fixed by the M4a spike | Tamper, truncation, swap, signature, interoperability or documented divergence, and recovery-key drills, with the suite recorded in the manifest. |
| Archive format | `-Fc` first; `-Fd` only if measured backup window requires parallelism | Benchmark 1 GB and 10+ GB datasets. |
| Privileged objects | Preflight extensions/FDWs; exclude subscriptions by default | Non-superuser fixtures; reject unsupported plans. |
| Globals | Delivered in M2 as opt-in `pg_dumpall --roles-only --no-role-passwords`; verifiers and database-level ACLs stay manual prerequisites | Privilege and secret-content review. |
| RPO/RTO | No universal guarantee; example daily backup, 26-hour stale alert, weekly restore drill | Measure last-restorable-snapshot age and restore duration; require off-host copy before host-loss claim. |
| Partitions/large objects | Selected parent includes children; filtered large objects excluded or all included explicitly | Versioned selection and restore fixtures. |
| Artifact v1 | Opaque ID, `public.json`, `manifest.age`, `payload.age`, `signature.hybrid`, recorded suite, validated binding | Versioned reader, corruption/replay/suite-downgrade tests, remote-store review before freeze. |

**Security correction:** PostgreSQL user mappings may contain passwords, and subscription connection strings may contain passwords. The native archive is sensitive even when the service manifest contains no secrets. Encrypt before publishing an artifact with real data; `--no-subscriptions` does not remove all possible embedded credentials. [User mappings](https://www.postgresql.org/docs/18/sql-createusermapping.html), [subscription catalog](https://www.postgresql.org/docs/18/catalog-pg-subscription.html), [`pg_dump`](https://www.postgresql.org/docs/18/app-pgdump.html).

## 30. Risks and reductions

| Risk | Reduction |
| --- | --- |
| Partial dumps/restores look successful | State machine, staged commit, native tool exit/error checks, archive parse, real restore tests. |
| Selective archive lacks dependencies | Resolve scope, show warnings, fixtures, disallow unsupported combinations. |
| Key loss or compromise | Recovery runbook, separate key backup, rotation drills, least-privilege host. |
| Local disk and host are same failure domain | State limitation prominently; add off-host store before strong DR promise. |
| PostgreSQL version/extension drift | Version matrix, pinned client compatibility checks, multi-version CI. |
| Post-quantum primitive or implementation immaturity | Hybrid rather than post-quantum alone, so a classical break and a lattice break must both land; upstream maintained implementations only; suite and parameter set recorded in every manifest so a generation can be re-encrypted to a better one; no unaudited third-party PQ container format. |
| Backup load harms production | Bounded concurrency, timeouts, benchmarked defaults, observability. |
| Restore harms production or executes untrusted SQL | New-target default, plan digest, authz, trust warning, isolated restore drill. |
| Metadata database lost/corrupt | Rebuild from manifests, transactional migrations, catalog backup. |
| Too many abstractions before evidence | One PostgreSQL adapter and one local store first; add ports only at tested seams. |

## 31. Future extensions

Future engine adapters: MySQL/MariaDB, MongoDB, Redis. Future stores: S3, MinIO, SFTP, with resumable transfer and remote consistency tests. Future key providers: OS keyring, Vault, AWS KMS, Azure Key Vault, Google Cloud KMS. A separate physical PostgreSQL subsystem may support `pg_basebackup`, WAL archiving, PITR, incremental chains, cross-region replication, and a backup verification server; it needs its own retention and recovery semantics. Multi-tenant mode requires tenant isolation, quotas, key separation, and authorization redesign. None of these are implied by the MVP logical backup contract.

**Crypto agility:** because the algorithm suite is recorded in every encrypted manifest and `public.json`, a future suite change is a migration path rather than a format break. Retire a suite by rotating: decrypt with the old identity, re-encrypt and re-sign under the newly approved suite as a new validated artifact generation, verify the result, then let the old generation age out under normal retention. Existing artifacts are never rewritten in place and readers never guess a suite. This is the intended answer to a post-quantum primitive being weakened later, and it assumes the decryption identity for the old generation is still available; an algorithm break that exposes an old identity is a key-compromise event, not a rotation.
