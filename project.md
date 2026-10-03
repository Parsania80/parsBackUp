# PostgreSQL Backup Platform — Implementation Roadmap

Revision: 2026-10-03. This rewrite is authorized by the operator. It replaces the earlier mixed design/status document with an implementation handoff and adds a dedicated clean-code phase. It changes the work plan; it does not claim that planned behavior is implemented.

## 1. Project vision and how to use this document

Build `backupctl`, a Rust modular monolith for PostgreSQL logical backup and recovery. CLI commands, systemd invocations, and a future API must call the same application services. A future browser UI calls the API. Prefer a small number of testable recovery promises to a large feature list.

The target is reproducible behavior and maintainable architecture across implementations. Identical source text is not required. Artifact bytes, cryptographic transcripts, validation order, public command contracts, persistence rules, and failure semantics are compatibility boundaries.

An implementing model must first read [AGENT.md](AGENT.md), this document, the latest entries of [session-log.md](session-log.md), and the contract documents for its task. Inspect the current working tree before editing: implemented increments may be uncommitted. Never discard another session's changes or reconstruct existing code from the roadmap alone.

Use these meanings throughout:

| Label | Meaning |
|---|---|
| Implemented | Exists in the current working tree; acceptance evidence is stated separately. |
| Verified this review | Checked on 2026-10-03 by the review preceding this rewrite. |
| Historical evidence | Recorded in session history; not rerun by this documentation revision. |
| Required | A condition the named future task must satisfy. |
| Planned baseline | The concrete implementation direction introduced by this roadmap; record its design before code, and do not describe it as an older accepted ADR decision. |
| Decision gate | An unresolved product/dependency choice that must be recorded before dependent implementation. |

Contract authority: operator instructions and AGENT.md govern work; the [frozen v1 contract](docs/backup-format/manifest-v1.md) governs artifact bytes; accepted ADRs govern their recorded decisions; this roadmap governs sequencing and task acceptance. Historical ADR context describes its original date, not necessarily today's implementation. If an implementation requires changing an accepted contract, identify the conflict and resolve it explicitly before coding that change. Do not reinterpret old artifacts or silently widen a support claim.

## 2. Goals, scope and exclusions

The first production product is a hardened CLI: full and supported selective logical backups, signed encrypted local artifacts, inspect/list/verify, fresh-target restore, inventory/jobs, safe retention, systemd scheduling, Debian packaging and measured restore drills. API/UI are later releases; a CLI release must not wait for them.

Initial scope is one configured source and one local storage root per configuration, with named profiles of that source. Multiple source estates in one inventory are not supported. A backup is a consistent logical snapshot of one database, not a complete deployment.

First-release exclusions: physical/base backups, WAL archiving, PITR, incremental/differential backups, failover, zero data loss, row filtering, arbitrary SQL object filtering, arbitrary TOC editing, remote stores, cloud KMS, multi-tenancy, OS files, secrets and server configuration backups. A future engine implements a researched capability boundary; do not translate PostgreSQL flags into imaginary generic database promises.

Local artifacts share the host's failure domain. Do not claim host-loss recovery without an independently verified copy in another failure domain. RPO is the age of the latest restorable snapshot; RTO is measured restore duration in a stated environment. Example operating policy: daily backup, stale alert after 26 hours, weekly isolated restore drill. These are policy targets, not guarantees.

## 3. Current status and release boundaries

| Area | Delivered behavior | Remaining limitation |
|---|---|---|
| M0–M3 | Contracts, fixtures, local backup/inspect, safe fresh-target restore, profiles and restricted selection | Synthetic local fixture sources only. |
| M4a | Streaming hybrid age encryption, key generation/publication/status and recovery drills | Unsigned development shape retains plaintext metadata. |
| M4b | Signed artifact v1 with encrypted private manifest; frozen 2026-10-01 | Signature-only verification does not authenticate all public header claims. |
| M5a increment 1 | `backup-inventory`, schema v1, estate binding, SQLite open rules and scope flock | Inventory reads/rebuild are not yet exposed through the CLI. |
| M5a increment 2 | Signed publication registers an artifact row after the completion marker | Development artifacts remain unregistered. |
| M5a increment 3 | Schema v2 jobs/audit; backup creation drives running/staged/complete | Restore jobs, verification events, reconcile/rebuild and crash matrix remain. |
| Concurrency review | Same-scope job acquisition is tested mid-dump | Store initialization deletes live staging/scratch before locking: confirmed blocker. |
| Operations/service | None yet | Scheduling, packaging, production hardening, API and UI remain planned. |

Review evidence: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` passed; 167 tests passed, zero failed. Existing PostgreSQL 16/17/18 matrices have historical passing records through M4b. They were not rerun in the review or this rewrite. Test counts describe the baseline, not a target future count.

Current guard: writes require `--confirm-synthetic`, source connections are local, and database names start with `backupctl_fixture_`. Encryption and signatures are necessary but insufficient to permit production use. Removing this guard belongs to the explicit CLI release gate after M5/M6 and production validation.

Chosen compatibility policy: PostgreSQL 16, 17 and 18 source servers, absolute source-major client directory, matching `pg_dump`/`pg_restore`, same-major restore. Cross-major restore requires a separately tested source/target pair and documented support change. Initial packaging targets are Debian 13 and Ubuntu 24.04 LTS, amd64. Recheck the supported-version lifecycle and package availability before release; this is a project policy, not a claim about the latest upstream version.

## 4. Tech Stack Lock

| Layer | Approved stack | Constraint |
|---|---|---|
| Core | Rust edition 2024, Cargo workspace | Synchronous core until M7 has a demonstrated async boundary. |
| Database execution | Native PostgreSQL `pg_dump`, `pg_dumpall`, `pg_restore`, `psql`, `createdb` | Fixed absolute tools and argv vectors; no shell and no custom dump engine. |
| Configuration | TOML through `toml` and `serde` | Strict fields; secrets referenced by protected paths. |
| Interchange | JSON through `serde_json` | Versioned artifacts/plans; closed schemas at security boundaries. |
| Inventory | `rusqlite` = 0.40.2, defaults disabled, bundled SQLite | DELETE journal, FULL synchronous writes, explicit timeout. |
| Encryption | `age` = 0.12.1, `age-core` = 0.12.0, existing custom hybrid recipient | Keep the pinned pair and tested format compatible. |
| Signatures | `ed25519-dalek` 2.2 line and `ml-dsa` 0.1.1 or reviewed compatible update | Required zeroization features; both signature legs verify. |
| CLI | `clap` derive | Existing human/JSON modes; parsing/presentation only. |
| Local coordination | Unix `flock` through `libc` | Kernel ownership; nonblocking scope acquisition; never unlink live lock files. |

Approved direct workspace libraries: `anyhow`, `clap`, `serde`, `serde_json`, `sha2`, `toml`, `uuid`, `age`, `age-core`, `base64`, `hkdf`, `libc`, `hpke`, `ml-kem`, `rand`, `sha3`, `typenum`, `x25519-dalek`, `rusqlite`, `ed25519-dalek`, `ml-dsa`, `zeroize`. [Cargo.toml](Cargo.toml) is the declaration and [Cargo.lock](Cargo.lock) records resolved versions and transitive dependencies. Preserve feature flags and exact pins unless a named task requires a reviewed upgrade.

No new runtime, ORM, SQL driver, encryption container, logging framework, job queue, web framework or UI library during the cleanup/refactor phase. M7/M8 choose their framework at their decision gates. New dependencies need a concrete need, alternatives, compatibility/security/licensing review and a recorded decision. Do not add a dependency merely to replace a small readable helper.

## 5. Architecture and code ownership

Current workspace:

```text
crates/
  backup-domain/       pure configuration, profiles, selection, artifact and plan contracts
  backup-application/  ports and backup/verify/restore orchestration
  backup-postgres/     tool execution, catalog resolution, dump and restore adapter
  backup-local/        local files, publication, plaintext views and crypto boundary
  backup-crypto/       key files, hybrid recipient, age streams and signatures
  backup-inventory/    key-free SQLite artifacts, jobs, audit, schema and scope locks
  backupctl/           command parsing, dependency composition and reports
docs/                 contracts, ADRs, security and operator/development guides
config/               tested example configurations
tests/                PostgreSQL matrices, drills and synthetic SQL fixtures
archive/              preserved completed-session history
```

Dependency direction: CLI/future API compose application services and concrete adapters; application depends on domain and port traits; PostgreSQL/local adapters implement those ports; local depends on crypto and inventory; crypto and inventory do not depend on local. Domain has no filesystem, database, subprocess or CLI dependencies. Its current crypto dependency is test-only, for suite-contract checks, and must not become a runtime dependency.

Keep PostgreSQL-specific selection, globals and restore controls typed and visible. The implemented engine port is `DatabaseAdapter`; do not rename it to a speculative `DatabaseEngine` during a readability refactor. A future engine can justify a new boundary through a separate design decision.

Application determines operation order and policy. Store adapter owns paths, atomic publication, scratch ownership and cleanup. Crypto owns key parsing, streams and transcript bytes. Inventory owns SQL persistence and kernel scope locks, and receives only typed key-free facts. CLI performs no retention, trust or restore policy decisions.

Add an application port when a use case needs an independently testable adapter boundary. Do not add traits for pure helpers or manufacture a generic repository framework. Existing `ArtifactStore`, `JobHandle`, sink/view/handle traits are the starting point; future inventory operations can have a small dedicated port instead of indefinitely widening `ArtifactStore`.

## 6. Domain, identity and state contracts

| Concept | Exact meaning |
|---|---|
| Backup ID/job ID/plan ID | UUIDv4 identities. They are never chronological sequences. |
| Source fingerprint | Existing 16-hex, domain-separated digest; binds one source estate. Preserve its input and encoding. |
| Profile fingerprint | Existing 16-hex digest of the profile name; no-profile uses reserved `whole-database`. It is not a hash of resolved content. |
| Profile snapshot | Immutable configured profile copied into the manifest; describes content even when profile names are later reused. |
| Artifact state | Existence/lifecycle facts in inventory; distinct from job state and verification results. |
| Verification event | A host's observation about specific artifact bytes at a time; never a mutable claim inserted into v1. |
| Restore/deletion plan | Immutable, expiring intent bound to exact inputs and explicit execution confirmation. |

Delivered backup job transitions: `running -> staged -> complete`. `running` or `staged` may end in `failed` on unfinished guard drop, or `interrupted` when a writable recovery open finds the scope lock free. Terminal states do not transition back. `JobGuard` currently permits running directly to complete; the real backup path still writes staged, and its trail test pins that sequence. Do not confuse a helper's permissive transition with an alternative backup workflow.

A job state write and its audit event must be one transaction. Audit order is monotone `event_id`, not second-resolution timestamps or random IDs. `Drop` does not panic; failure to write a terminal state leaves a recoverable non-terminal row. Reasons stay in safe command diagnostics; do not put arbitrary error chains, SQL or names into key-free SQLite columns.

Future restore jobs use running/complete/failure/interrupted without inventing a staged artifact phase. Add an operation kind and appropriate target/artifact associations through a migration before sharing job logic. Future cancellation states require an actual writer and tested semantics in M7; do not add unused enum variants now.

## 7. Artifact v1, crypto and publication contracts

The [v1 contract](docs/backup-format/manifest-v1.md), [ADR 0001](docs/architecture/adr-0001-foundations.md) and [ADR 0002](docs/architecture/adr-0002-artifact-v1-and-signing.md) define exact fields, encodings, transcript values and key rules. Read them before modifying readers/writers. Do not derive wire formats from this summary.

```text
artifacts/<backup-uuid>/
  public.json          bounded discovery header, no descriptive source data
  manifest.age         encrypted private JSON manifest
  payload.age          encrypted native custom archive
  globals.age          only for explicit globals export
  signature.hybrid     64-byte Ed25519 signature followed by 3309-byte ML-DSA-65
  complete             completion marker written last
```

New signed writes use `mlkem768x25519-v0` and `ed25519+ml-dsa-65`. The recipient combines ML-KEM-768 then X25519 using the existing versioned combiner/transcript inside age's authenticated stream. It is project-specific and stock `rage` cannot decrypt it. Exactly one hybrid recipient stanza is allowed, with age's supported grease stanza; another recipient is refused. Never add classical-only recovery access to the same file key.

The 3373-byte signature authenticates the existing binary tuple containing the domain, backup ID and two ciphertext digests. It does not directly authenticate `public.json` suite/key claims or completion time. The encrypted manifest is authenticated indirectly through its ciphertext digest. `globals.age` is bound through the authenticated manifest's digest. Changing this tuple or the combiner is a version/suite change, not clean-code work.

Read order is required: check marker and allowed file shapes; parse bounded closed-schema header and ID; recompute ciphertext sizes/digests; verify both signature legs against an independently configured public key; when private metadata is required, authenticate/decrypt manifest and compare all bindings; authenticate the complete payload before PostgreSQL restore uses plaintext. Reject symlinks, unknown critical fields/versions, mismatches, truncation and unsupported suite combinations.

Signature-level verification checks origin of the signed tuple and ciphertext bytes, without decrypting. A header whose suite claim was downgraded can still pass this level; checksum/archive/restore paths reject the mismatch against the decrypted manifest. Preserve that distinction in results and tests. A successful signature is not a trustworthy database or safe SQL guarantee.

Writer sequence: privately stage on the destination filesystem; stream native dumps through completed encryption sinks; inspect staged native archive/record TOC digest; seal the private manifest; derive public facts and sign; sync files and directory; atomically publish the immutable ID; write/sync completion marker and parent; register inventory; mark job complete. Use the frozen writer order in the canonical contract for exact details.

Registration currently follows publication. If registration fails, report that the artifact is published and restorable but unregistered; do not remove the artifact to make the error look atomic. Never modify published v1 in place. `verification_level` remains `none`; writer records TOC digest at creation. Later verification belongs in inventory.

Three shapes remain distinct: `plaintext-dev`, `age-unsigned`, `v1-signed`. Plaintext and unsigned development shapes are synthetic-only. Mixed-store discovery must report each shape without treating development output as trusted v1.

## 8. Security and process boundary

Keep secret files outside the artifact root. Identity/signing secrets are regular non-symlink files with restrictive owner permissions and existing length/marker checks. Verify public keys from independent configuration. Preserve recovery copies and rotation-by-new-generation behavior described in [key lifecycle](docs/security/key-lifecycle.md). Every signing scheme and secret-bearing type retains required zeroization; compile-time bounds and golden vectors must remain.

Source archives can contain database-held passwords even when subscriptions and role password hashes are excluded. Never publish real data in the development shapes. Never log raw SQL, native stderr/stdout, connection strings or private keys. Fingerprints are labels, not authorization proofs or anonymization against an attacker who can guess inputs.

Native processes use absolute executables, version checks, argv arrays, an allowlisted environment, bounded diagnostic capture and timeouts. No shell, no password in argv, no implicit inherited `.pgpass`. Current synthetic execution uses local connections with TLS disabled and kills the immediate child on timeout. Process-group cancellation and secure remote TLS are production-hardening tasks, not implemented guarantees.

Private staging/scratch must remain private throughout success, failure and interruption. Best-effort deletion is not secure erasure on SSDs. A compromised live host can see its usable keys/plaintext; signatures/encryption do not prevent deletion or targeted rollback of both artifacts and local inventory.

## 9. Threat model and review triggers

[Threat model](docs/security/threat-model.md) is the detailed register. Reassess it after storage/concurrency changes, production configuration, API authorization, and release. Important open boundaries:

| Threat | Required treatment |
|---|---|
| Storage tamper/substitution | Preserve signature-first checks and manifest/payload/globals binding. |
| Replay/deletion (T03) | Local ledger is an accident warning only; off-host signed/immutable inventory remains future work. |
| Inventory loss/corruption (T12) | Explicit scan/rebuild, unknown lifecycle facts, real integrity checks. |
| Metadata disclosure (T13) | No database/host/profile names, resolved scope, SQL, credentials or arbitrary errors in SQLite. |
| Overlap/resource exhaustion (T15) | Whole-operation scope locks, safe scratch ownership, bounded service work later. |
| Restore SQL | Trusted origin still requires a controlled target and explicit operator intent. |
| Path/symlink races | Validate paths and use no-follow/descriptor-based operations where needed; a path precheck alone is insufficient under concurrent mutation. |

Do not mark a threat closed because one happy-path test passed. Record the attacker, trust assumption, test scene and residual risk. Preserve currently documented signature-only suite and lost-key limitations until an explicitly versioned change closes them.

## 10. Storage, ownership and deletion invariants

Files are authoritative for artifact existence; inventory is authoritative for what this host recorded. Missing files never count as a remaining valid backup. An artifact absent from inventory is unregistered and never an automatic retention candidate. Reconciliation must not imply adoption or authenticated verification.

The confirmed blocker is `LocalStore::open` removing all directories below staging/scratch before a job lock is acquired. A second `backup list` can remove live working data while a scope flock remains held. Fix it before further feature work; do not rely on the current same-process overlap test to prove safety.

Planned S02 ownership baseline: ordinary read opening never performs cleanup. Backup/restore/verify operations that use working directories hold shared store-activity ownership for the entire relevant resource lifetime. A cleanup operation requires exclusive store-activity ownership and fails/skips without deleting when an active operation holds it. Scope locks still reject duplicate source/profile backups; shared activity ownership must not serialize different profiles. Keep a fixed lock inode outside immutable artifact directories and never unlink it. Attach ownership to stage/plaintext guards so it outlives their users, not merely an early helper call.

Record this new maintenance/activity design and lock acquisition order in `docs/architecture/adr-0004-working-directory-ownership.md` before implementation. It supplements ADR 0003 rather than pretending the old scope lock covers every scratch user. A nonmutating read can avoid the activity lock when it uses no working data. If a read-only artifact root requires decrypted scratch, use a separately private writable scratch area only after its configuration/lifetime contract is recorded; never write into the read-only root or silently fall back to a public temp directory.

Cleanup treats errors as errors, not as evidence an entry is abandoned. Process age/PID alone is not liveness. Crash recovery preserves published artifacts, reports abandoned staging, and removes only working directories it owns exclusively. Do not reset protected or verified facts during reconciliation.

M5b deletion has four hard exclusions: protected artifact, active/restoring artifact, artifact required by an in-progress job, and the last known valid artifact in its source/profile scope. Revalidate before execution, remove the completion marker first, sync the directory, remove files, retain tombstone/audit history. Interrupted deletion is never reported as an intact valid backup.

## 11. PostgreSQL content and restore contracts

Use [content matrix](docs/postgres/content-matrix.md), [privilege matrix](docs/postgres/privilege-matrix.md) and [fixture plan](docs/postgres/fixture-plan.md) for version-specific behavior and privileges. Required fixture coverage includes:

| Group | Coverage and limit |
|---|---|
| Relations | Schemas, tables/data, views/materialized views, partition/inheritance families. |
| Dependencies | Indexes, constraints, triggers/rules, sequences/state, identity/generated columns, functions/types/domains/collations/text search. |
| Security | Roles/memberships where exported, ownership, ACL/default privileges, RLS, comments/security labels. |
| External dependencies | Extensions/FDW definitions; external binaries, endpoints and files are not supplied by the dump. |
| Special data | Large objects with explicit selection semantics; test references/state rather than row counts alone. |
| Replication/globals | Subscriptions excluded; roles export opt-in; tablespaces and database-level ACL/config remain documented manual prerequisites. |

Current selection accepts exact lower-case names, not arbitrary patterns. Resolve schemas/tables against the source catalog, reject missing/unsupported/dangling dependencies, expand selected partition families, and preserve requested plus resolved scope. Do not promise dependency closure beyond implemented/tested catalog checks; dynamic SQL references can escape catalog dependency analysis. Extension exclusion is version-gated; preserve current PostgreSQL 16 refusal.

Data-only profiles can validate, but the current fresh-database restore cannot reconstruct absent schema. Do not advertise data-only restore to an existing database until a separately designed schema-compatibility and target-safety contract is implemented. Large-object behavior follows the current M3 refusals and fixtures; do not silently replace them with broader native-tool support claims.

Restore plan validates artifact trust before any target creation, source identity, tool/server major, exact sections, role conflicts and target absence. Plan expires after the existing 15-minute interval; preserve the current digest encoding and bound fields until a versioned plan change. Execute repeats all relevant checks because artifact/target/configuration may have changed.

Current policies: `dr` restores explicit exported roles/memberships, ownership and privileges; `portable` skips them. A section-limited restore requires portable policy and starts at pre-data, with no pre-data/post-data gap. Table-selected restore prepares required namespaces because the native table dump does not create them. Default target is a new database; do not add destructive overwrite during refactoring.

Execution order: authenticate artifact; validate plan/confirmation/current source; recheck DR role conflicts; apply opt-in validated globals; recheck target absence; create fresh database; prepare required schemas; restore native archive; report outcome. Failure may leave cluster roles or target objects partially changed. Leave them for explicit operator repair, report that fact, and never auto-retry or auto-drop them.

M5a adds restore job/resource ownership and audit. Successful native restore is `restore-completed`; `restore-tested` requires an isolated restore plus stated validation of the required fixture/content. Keep the distinction explicit so a partial section restore or successful process exit never claims more than it proves. Preserve legacy development-manifest updates for compatibility until an explicit migration decision removes them; do not alter v1.

## 12. CLI contract and planned commands

Implemented commands are defined in [cli.rs](crates/backupctl/src/cli.rs): `config check`, `key generate|publish|status`, `profile list|validate`, `backup create|list|inspect|verify`, `restore plan|run`. Current machine output is JSON, human mode is default. Current runtime result convention is success/failure; Clap has its own usage handling. The older proposed 0–6 error taxonomy is not shipped.

Preserve existing command syntax, serialized keys, successful output meaning and asserted refusal text during C1. Correct unsafe behavior in S tasks; improve diagnostics in explicit A/H tasks with matching test/document changes. Avoid raw TOML parser snippets, which may reproduce secret input.

New surface baseline, to be implemented in the named tasks:

```text
backupctl --config CONFIG job list
backupctl --config CONFIG job inspect JOB_UUID
backupctl --config CONFIG inventory check
backupctl --config CONFIG inventory reconcile
backupctl --config CONFIG inventory adopt BACKUP_UUID --source-fingerprint FINGERPRINT
backupctl --config CONFIG inventory rebuild --source-fingerprint FINGERPRINT --dry-run
backupctl --config CONFIG inventory rebuild --source-fingerprint FINGERPRINT --confirm-rebuild
backupctl --config CONFIG backup protect BACKUP_UUID
backupctl --config CONFIG backup unprotect BACKUP_UUID
backupctl --config CONFIG backup prune --keep-last N
backupctl --config CONFIG backup prune run PLAN_UUID --confirm-digest DIGEST
backupctl --config CONFIG backup delete BACKUP_UUID
backupctl --config CONFIG backup delete run PLAN_UUID --confirm-digest DIGEST
```

`--output json` applies to new commands too. Preview never deletes; execution always loads the saved plan. Rebuild is a distinct loss-of-lifecycle operation and its confirmation must explain lost protection/events; do not disguise it as an ordinary read. Adoption of a single ID and replacing the whole inventory are different actions.

Before A01/B01, record JSON field names, operation/error codes, sort order, optional/null handling and examples in `docs/development/m5a-inventory.md` and `docs/development/m5b-retention.md` respectively. `--source-fingerprint` is the existing validated 16-lowercase-hex estate label; reject disagreement with an existing bound inventory before mutation. These keyless commands do not connect to PostgreSQL to guess an estate. Use UUID/digest inputs, never user-supplied arbitrary artifact paths. Pagination is only needed once a measured output-size problem exists; do not add a speculative cursor system to the synchronous CLI.

## 13. API architecture — future M7

The API calls application services, returns asynchronous job IDs and does not run long backups within an HTTP request. Planned routes: backups/restores creation, jobs and artifact reads, profiles and health, with a versioned OpenAPI contract. Use 202 for accepted jobs, explicit resource URLs, safe structured errors and bounded requests.

M7 decision gates: HTTP/async framework, token custody/authentication, actor-to-operation authorization, idempotency storage and worker/cancellation strategy. Record choices before dependencies or routes land. Bind to loopback by default; require an explicit secure deployment boundary before remote exposure. No arbitrary executable paths, shell options or plaintext secret values in requests.

Idempotency is bound to actor and request digest; retries must not create duplicate destructive work. Workers have bounded queues/concurrency; restart and cancellation states have real writers. API auth distinguishes backup, restore, delete, profile and administration. CLI can remain a direct local core caller; remote CLI mode is a separate contract.

## 14. UI architecture — future M8

Choose the UI framework only after M7/OpenAPI stabilizes. Use TypeScript and an API-only client after recording the dependency choice. Views: health, artifacts/verification, restore plan/confirmation, jobs/audit, profiles/schedules, storage/key status without secrets. Server enforces authorization and plan confirmation regardless of UI controls.

Acceptance includes accessible navigation, XSS/error/loading states, clear partial-backup and verification levels, deliberate destructive confirmation and a full browser-to-API restore workflow. A green dashboard cannot imply host-loss recovery or restored-data validation.

## 15. Configuration and profiles

Current configuration is one `Source`, one local `Storage`, optional encryption/signing blocks, `export_globals`, timeout and `[[profile]]` entries. Examples under [config](config) are the current schema. Do not implement the earlier illustrative profile fields such as `schedule`, `retention`, compression or alternate source references as if they already existed.

No key blocks means plaintext development output; encryption only means unsigned age development output; encryption plus signing secret means signed v1 writer. Signing without a signing secret selects the DR reader shape. Current constructors eagerly load configured identity/key pairs; public-only inventory discovery/rebuild needs an explicit keyless construction path in A03, not a claim that current CLI already needs no private key.

For production, introduce a versioned configuration with explicit local/remote connection security and read/write roles after H01's decision gate. Configuration reload affects only new jobs. Reject unknown fields and incompatible combinations before database or store mutation. Profiles are snapped per job; reusing a name groups retention under the existing name fingerprint, so changed selection must be visible to operators. A content-hash scope redesign is a separate decision.

The initial CLI release can remain local-only. Remote access, separate cross-server target connections, data-only restore and writer-without-identity operation are explicit extensions, not incidental outcomes of removing the fixture-name check.

## 16. Inventory schema and migration rules

Implemented schema v2: `meta` estate binding, `artifact` discovery/lifecycle fields, `job` rows and `audit_event`. Exact existing SQL is [schema.rs](crates/backup-inventory/src/schema.rs). Preserve dense migration history: fresh initialization runs the same steps an older database upgrades through. Never edit an already released migration to express a future schema.

Use `journal_mode=DELETE`, `synchronous=FULL`, current explicit 2000 ms busy timeout; read back required pragmas. Read paths use `SQLITE_OPEN_READ_ONLY`, create/migrate nothing and do not sweep. Reject unknown/newer schema and foreign estate. Do not use `immutable=1` on a live store. Run `integrity_check`; a database answering a query can still be corrupt.

Every column is an opaque ID, fingerprint, digest, bounded algorithm label, byte count, UTC timestamp, state, flag or safe event code. No source/target names, hosts, ports, profile names, resolved selection, SQL, credentials or arbitrary error chains. Nullable profile/completion means unknown. Keyless rebuild cannot invent values from UUID order, directory modification time or untrusted public header fields.

Artifact schema changes, plan formats and wire artifact v1 version independently. Future additions: job operation/target associations, verification observations bound to current ciphertext digests, missing/deleted states, protection and local ledger. Add only what the next task writes. Use one transaction for each state/event pair and for each related protection/verification change.

Current artifact registration uses replacement of all discovery columns. Before lifecycle columns exist, change it to a merge/upsert that preserves protection, observations and tombstones; a keyless refresh must not erase authenticated profile/time facts already known for the same bytes. If bytes changed, invalidate dependent observations and report conflict instead of carrying old verification forward.

Rebuild restores discovery, not lost audit/protection/verification history. Stage a replacement inventory, validate it, take exclusive maintenance ownership, preserve a recoverable copy of the old database, then replace durably. No replacement while live jobs use it. Document the restart/copy and lost-history consequences.

## 17. Scheduling and deployment policy

M6 uses systemd service/timer, one explicit configuration/profile invocation per unit. No internal scheduler, distributed queue or worker pool in the CLI milestone. Document UTC schedule definitions, missed-run behavior, overlap refusal, operator enablement and manual-run interaction. A persistent timer does not mean every missed occurrence is replayed; measure the chosen unit behavior.

Scheduled backup must use the same application and locking paths as manual backup. Dedicated service user, restrictive umask, explicit resource limits, protected credential references and a tested filesystem sandbox are required. Preserve data and key files on package upgrade/removal. Stale-backup alerts and recurring restore drills need an actual runner/integration before they are claimed.

## 18. Reliability, locking and recovery

Maintain separate purposes: source/profile lock rejects duplicate dumps; store activity protects live working resources from maintenance; target/artifact-use locks protect restore and deletion; SQLite transactions protect rows. Document acquisition order before combining them, and acquire nonblocking or under a stated bounded wait to avoid deadlocks. Do not hold a SQL transaction while streaming a dump/restore.

Interrupted sweep must not overwrite a job that completed after a snapshot read. Use a conditional transition of a still-non-terminal row in its transaction, and hold sufficient lock ownership while deciding liveness. Cover restarting the same scope as well as unrelated profiles; the new holder must not hide old abandoned rows forever.

Failures to test: unavailable server, lock timeout, client mismatch, disk/write failure, killed client and wrapper descendants, key failure, corrupt/truncated/swap artifacts, SQLite busy/corrupt/write failures, restart between publish/register/job completion, interrupted restore and interrupted deletion. A complete artifact and a failed/interrupted job can coexist if post-publication recording failed; expose both facts honestly.

Reserve/check resource headroom before expensive work and bound decrypted size, capture, process duration and service concurrency. Do not claim a free-space check guarantees no disk-full failure. Retry only stages whose idempotence is documented; a new dump is a new snapshot/job.

## 19. Observability and audit

CLI reports safe operation/job/artifact IDs, state and exact verification level. M5a adds durable events for reads/verification/restore in writable mode. Truly read-only operation cannot persist an audit event; report `audit_recorded=false` rather than failing a valid read or secretly reopening read-write. This explicitly resolves the tension between audit reads and read-only DR media.

Future service logs: UTC time, operation/phase, safe IDs, duration, bytes and stable failure code. No raw tool output/configuration/request bodies. Metrics later: last known restorable snapshot age, durations/throughput, failures, free space, scheduler misses and queue depth. A successful checksum and a successful validated restore remain separate observations.

Audit is local lifecycle history, not independent anti-tamper evidence. Events bind to operation and artifact bytes when relevant. Keep diagnostics understandable without violating the key-free inventory rule.

## 20. Test strategy and required commands

Fast checks, in this order:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git diff --check
```

Run the smallest meaningful tests during development. After a phase changes shared core/storage/process behavior, run the affected PostgreSQL fixture matrices, and at phase acceptance run all M1–M4b regressions:

```bash
bash tests/m1_docker_smoke.sh
bash tests/m2_docker_smoke.sh
bash tests/m3_docker_smoke.sh
bash tests/m4a_docker_smoke.sh
bash tests/m4b_docker_smoke.sh
bash tests/m4a_key_drill.sh
```

Inspect each script's prerequisites, runtime and existing cleanup before execution. Use isolated synthetic databases, matching clients and disposable roots. Do not run fixtures against an operator's production database. A script file existing is not passing evidence; capture tested majors and failed scenes. If prerequisites are unavailable, report the gate unverified.

Unit tests target pure policy and parsing; integration tests compose application with real local/crypto/inventory adapters; process tests exercise the full CLI startup path; Docker matrices validate native PostgreSQL behavior. Keep existing negative controls where valuable, revert them and inspect the diff. Avoid tests that only mirror helper implementation or reward an arbitrary function/file size.

Golden cryptographic vectors, frozen v1 field/byte contracts and existing plan encoding are mandatory regression boundaries. Add a cross-build artifact fixture when there is an independently produced artifact; do not fabricate interoperability by checking in bytes generated by the same tested build and calling that cross-build proof.

## 21. CI/CD

No GitHub Actions workflow is currently delivered. Add minimum formatting/lint/unit jobs at H04; pin toolchain/action references and run PostgreSQL matrix jobs with matching native clients. Keep package install/upgrade/remove and release checks distinct from ordinary unit tests.

Release pipeline must build reproducible artifacts, emit checksums/SBOM, check dependency advisories/licenses under a recorded policy and document exceptions. Bundled SQLite C source is part of the audit surface; a Rust advisory check alone does not cover it. Benchmark jobs are manual/scheduled with recorded environments, not flaky per-commit assertions. Never publish releases automatically before the applicable release gate is complete.

## 22. Debian packaging

Planned installation: `/usr/bin/backupctl`, `/etc/backupctl/`, `/var/lib/backupctl/`, dedicated `backupctl` user/group and explicit systemd unit/timer. Credentials and private keys live separately with recorded ownership/permissions; they are never package contents. Depend on `postgresql-client-common`; document installation of the chosen major's client package through distribution/official repository. The binary still checks the absolute tool versions.

Build on Debian 13 and Ubuntu 24.04 amd64. Include the C toolchain needed by bundled SQLite in build dependencies. Test install, upgrade through an old inventory schema, ordinary removal, reinstall and purge policy. Ordinary removal never deletes artifacts/keys; purge behavior is explicit and cannot silently destroy operator recovery copies.

Use journald and service sandboxing/StateDirectory/UMask/resource controls as supported and verified on targets. Prove the sandbox permits PostgreSQL access, staging, scratch, locks and durable publication while refusing unrelated filesystem access.

## 23. Development and Docker environment

Existing shell matrices are the delivered integration environment. Compose/service/MinIO profiles are future conveniences, not prerequisites already implemented. Keep Docker-free development with installed matching clients possible; no native database install is required merely to run unit tests.

Fixtures cover normal and insufficient privileges, optional extensions/FDWs/publication where available, security objects and selection dependencies. Record optional-category skips. Ensure test teardown removes only its own containers/directories and leaves enough failure evidence to diagnose a refused gate.

## 24. Benchmarks and production limits

At V02 generate reproducible 100 MB, 1 GB and 10+ GB datasets with compressible/incompressible data, many/small/large relations, indexes and large objects. Record generator seed, hardware/filesystem, OS, PostgreSQL/client/application versions, compression, concurrency and cache conditions.

Measure full backup + verification + restore time, throughput, compression ratio, CPU, peak RSS, I/O and source load. Repeat and report median/range. Current v1 writes gzip compression; zstd/directory parallel dumps are future options only after native-version/format and restore tests. Never silently change recorded compression during cleanup.

Benchmarks determine documented limits and operating policy, not a universal RTO. Include disk headroom and scratch amplification. A data-integrity assertion accompanies every restore measurement.

## 25. Documentation and handoff rules

Maintain this canonical lower-case `project.md`, [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md), contracts, operator guides and append-only [session-log.md](session-log.md). Follow AGENT.md for log archival, file-change reporting and Q-prefixed questions. No new flow document is authorized by this roadmap rewrite.

Each task handoff records: task ID/status, exact files changed, behavior before/after, contract/version impact, executed checks and results, unexecuted gates, decisions and the next eligible task. Mark done only after its acceptance passes. Keep old evidence in logs rather than embedding long transcripts in this roadmap.

A new model should be able to resume from status plus contracts without trusting comments that contradict code. Update stale claims in touched areas. Before release add SECURITY, CONTRIBUTING, selected LICENSE, CHANGELOG, deployment/recovery/retention guides and versioned compatibility notes. No license grant is implied by the current development snapshot.

## 26. Roadmap and implementation tasks

| # | Task | Status | Notes |
|---|---|---|---|
| 1 | M0 research/contracts/fixtures | ✅ Done | Historical evidence in archived logs. |
| 2 | M1 local backup/inspect | ✅ Done | Synthetic PG16–18 native round trip. |
| 3 | M2 fresh-target restore/verification | ✅ Done | DR/portable policies and expiring plans. |
| 4 | M3 profiles/selective operations | ✅ Done | Restricted names/dependencies/sections. |
| 5 | M4a hybrid encryption/keys | ✅ Done | Streams, custody, recovery drills. |
| 6 | M4b signing/v1 freeze | ✅ Done | Frozen 2026-10-01 with explicit limits. |
| 7 | S — M5a cleanup/concurrency correction | 🔄 Current | Confirmed blocker; implementation not yet started. |
| 8 | C1 — clean code and human readability | ⬜ Todo | Next, after S accepts; before new M5a features. |
| 9 | A — complete M5a inventory/jobs/recovery | ⬜ Todo | Three earlier increments already implemented. |
| 10 | B — M5b retention/protection/deletion | ⬜ Todo | Requires complete M5a and C1. |
| 11 | H — M6 hardened CLI/systemd/Debian | ⬜ Todo | Production configuration and process/permission gates. |
| 12 | V — CLI production validation/release | ⬜ Todo | Original M9 CLI track; precedes API/UI. |
| 13 | P — M7 API/asynchronous service | ⬜ Todo | Requires hardened core and explicit decisions. |
| 14 | U — M8 API-backed UI | ⬜ Todo | Requires stable API. |
| 15 | F — platform validation/release | ⬜ Todo | Original M9 full-platform track. |

### ➡️ Current: #7 - S — M5a cleanup/concurrency correction
### ⏭️ Next: #8 - C1 — clean code and human readability

Task IDs below remain stable even if a phase is split into several commits. Complete dependent tasks in listed order. Independent documentation can proceed alongside its owning task; later feature coding waits for the phase prerequisites.

### Completed milestones M0–M4b: preserve this baseline

M0: architecture/ADRs/threat/content/privilege contracts and synthetic fixtures. M1: five initial crates, guarded local backup, bounded tools, publication and inspect/list. M2: opt-in role globals without passwords, DR/portable security policy, plan/run, checksum/archive verification. M3: profile validation, catalog-resolved exact scopes/dependency refusal, TOC digest, section-limited restore and namespace preparation. M4a: `backup-crypto`, custom hybrid recipient, age streaming, safe plaintext view ownership, key lifecycle and rotation/recovery drill. M4b: hybrid origin signature, encrypted manifest/public header, signature-first reads, DR without signing secret and frozen v1.

Historical matrix evidence covers PostgreSQL 16/17/18; archives are [September](archive/SESSION-LOG-2026-09.md) and [October completed M4b](archive/SESSION-LOG-2026-10.md). Active M5 increments remain in session-log.md. Do not reopen these milestones merely to rename types or broaden selection. Their guides and tests define compatibility.

### S — Correct ownership before feature development

Prerequisites: baseline review; read storage/job implementation and ADR 0003. Owners: `backup-local`, application restore/verify resource lifetime, full-CLI integration tests. No artifact version change.

1. **S01 — failing full-startup regression.** Add a controlled mid-dump barrier and launch a second real CLI process opening the same store. Cover duplicate backup, `backup list`, archive verify and restore scratch access. Demonstrate that the baseline loses live working paths; assert the first operation's paths and bytes survive after the fix. Synchronize with a pipe/file barrier owned by the test; avoid timing-only sleeps.
2. **S02 — activity/maintenance ownership.** Implement §10's shared-operation/exclusive-cleanup baseline in a small local guard. Document acquire/release order, reader initialization and descriptor/resource lifetimes first. Ordinary open no longer purges directories. All stage and plaintext-view users retain ownership until their last file access/drop. Cleanup with a busy activity lock preserves every working directory and reports why it skipped/refused. Scope locks remain independent and nonblocking. Validate regular lock files, permissions and no-follow access.
3. **S03 — safe interruption recovery.** On an explicit writable recovery path, take exclusive maintenance ownership, conditionally mark genuinely abandoned jobs interrupted, and clean/report only abandoned work. Reopening the same scope must recover its old rows before the new job makes the scope appear busy. A concurrently completed job cannot be overwritten as interrupted. Add two-process SIGKILL scenes, repeated recovery/idempotence and changed-files/symlink refusals.

Acceptance: active backup/restore/verify survives unrelated reads and refused competing commands; different backup profiles may still run; killed operations release ownership and recover without a complete artifact; no plaintext leak, live directory deletion or silent terminal-state rewrite. Existing negative same-scope acquisition control still fails when exclusivity is removed. Run fast checks and affected M1–M4b matrices. Do not proceed to C1 until these scenes pass.

### C1 — Clean code and human readability

Purpose: make routine behavior understandable from named modules and straight-line orchestration. This is a separate phase, not permission to rewrite cryptography or change product behavior. Prerequisite: S acceptance. Preserve runtime dependencies and public contracts; the full refactor diff should explain structural moves, not new features.

Current pressure points: `backup-local/src/lib.rs` has 2202 lines, application lib.rs 1158 and inventory lib.rs 1217 including tests. Counts identify inspection targets, not quality thresholds. Long tests are not a reason to fragment coherent production logic, and a smaller file is not proof of simpler code.

| Task | Ordered changes | Acceptance |
|---|---|---|
| C01 | Capture current exported APIs, CLI examples, JSON/error contracts and passing baseline. Identify repeated logic and mixed ownership with concrete call sites. | Inventory of refactor scope; no speculative abstraction list. |
| C02 | Split local store responsibilities: opening/keys, stage/sinks, signed publication/reader, development reader/writer, scratch/activity, plans, inventory bridge. Move cohesive tests with their subject. | Crate-root reexports preserve callers; no artifact bytes, publication/read ordering, key rules or path behavior changes. |
| C03 | Split application into ports, backup, verify, restore and shared artifact facts; split inventory connection/open/recovery from SQL operations/tests where useful. | Use cases read in operation order; SQL stays in inventory; filesystem/crypto stays in local/crypto. |
| C04 | Simplify names, branches and comments; extract repeated semantic helpers, remove dead/stale prose, consolidate fixture helpers. Review before/after call paths and docs. | A reviewer can trace create/verify/restore/recovery without jumping through unnecessary wrappers; all contracts and regression gates pass. |

Proposed private module destinations, adjusted only when code review shows a clearer cohesion boundary:

```text
backup-application/src/{lib,ports,backup,verify,restore,artifact_facts}.rs
backup-local/src/{lib,layout,store,stage,signed,development,scratch,activity,plans,keys,inventory}.rs
backup-inventory/src/{lib,connection,artifact,job,job_lock,recovery,schema}.rs
```

Do not create empty modules to satisfy the diagram. Keep a small crate facade with explicit reexports; use `pub(crate)`/private helpers and narrow fields rather than exposing internals for convenience. Preserve `LocalJob`'s legitimate cross-crate adapter; do not work around Rust's orphan rule by reversing dependencies.

Readability rules: meaningful nouns/verbs and explicit types at important boundaries; early input guards; one clear sequence for resource acquisition, work, completion and cleanup; match enums rather than magic strings where this reduces invalid states; no boolean parameter bundles with unclear call sites; comments explain invariant/reason, not narrate every statement. Share rules only when they have the same semantics. Separate development/v1 paths where forcing them together hides trust differences.

Keep safety-relevant RAII and error contexts. Do not replace guards with manual cleanup scattered across branches. Do not hide signature verification or destructive actions behind a generic callback pipeline. Do not add helper chains/macros just to shorten functions. Move crypto modules only if necessary for a demonstrated readability problem, preserving all transcript constants/vectors and zeroization bounds.

Implementation unit: one responsibility move per reviewable change, update imports/reexports, run relevant tests, inspect the diff, then continue. A bug found during refactoring is a separately documented behavior fix with its own failing test and validation; never conceal it inside a move-only change.

Phase acceptance: all fast checks, S full-process regressions, M1–M4b matrices and key drill pass; compare CLI/JSON/plan examples and deterministic crypto vectors; dependencies/versions unchanged; no claimed readability improvement based solely on line count. Write a concise module-ownership summary and remaining complexity notes. Add no new clean-code policy dependency.

### A — Finish M5a without deletion

Prerequisites: S and C1. Owners: inventory persistence, application inventory/job services, local scan/read bridge, CLI/report. Preserve v1.

1. **A01 — job/inventory read surface.** Add `job list`, `job inspect`, `inventory check`. Read-only open never creates/migrates/sweeps. List deterministic timestamp/ID order, report exact state/operation/known associations, distinguish absent job from damaged database, and run structural integrity checks in check. Establish JSON/error contracts before implementation.
2. **A02 — unified discovery and reconciliation.** Scan IDs/shapes with bounded validated filenames and report registered/unregistered/missing/incomplete/conflicting entries. Discovery does not authenticate descriptive public claims. Normal reads do not auto-adopt. Writable reconcile updates observed missing/conflict state with audit while preserving protection/verification/tombstones and known private facts. Refuse malformed/symlink entries per entry with understandable diagnostics rather than letting one development shape abort every mixed-store list.
3. **A03 — explicit adoption and keyless rebuild.** Add discovery-only construction that does not load identity/signing secrets. `inventory adopt ID` records bounded public discovery facts and estate provenance, with trust level distinct from authenticated verification. Public v1 contains no source fingerprint: bind a keyless rebuild to an explicit expected estate, mark it provisional/unconfirmed where necessary, and refuse foreign source when private authentication later supplies the actual fingerprint. Never claim signature proves estate/profile/time. Rebuild preview reports IDs/shapes/unknowns/lost facts; confirmed execution follows §16's staged replacement and exclusive maintenance rules. Preserve old inventory recoverably.
4. **A04 — authenticated enrichment and verification events.** Record successful/failed verification with level, UTC time, artifact ID and ciphertext digests; no secret-bearing diagnostic text. Authenticated manifest enrichment supplies profile/time only after binding checks. Checksum and signature observations remain distinct from archive validation. Keyless refresh preserves known facts for unchanged bytes; changed bytes invalidate observations and produce conflict. Read-only verification reports that no event was persisted.
5. **A05 — restore jobs and resource associations.** Add operation kind/target fingerprint/artifact-use associations through the next migration. Acquire target/use/activity locks before side effects and retain through native restore/validation. Record running/complete/failure/interrupted and safe events; partial failure leaves target for repair. Do not automatically sweep a live backup or a finished restore. Shared use of an artifact blocks future deletion. Add no worker pool/cancel command.
6. **A06 — recovery and integrity drill.** Implement `tests/m5a_docker_smoke.sh` on PG16/17/18: kill backup/restore mid-operation, duplicate startup, unrelated read, same-scope restart, publication-before-registration failure, db loss/rebuild, wrong-estate refusal, mixed shapes, malformed headers, schema v1->v2->current and newer-schema refusal, populated-db corruption and single-file read-only copy. Tests run through actual CLI initialization.
7. **A07 — metadata leakage and audit checks.** Grep raw SQLite files/journals and captured machine/human output for fixture database/host/profile/scope, fake credentials and generated seeds. Exercise normal writes, failed writes, enrich/rebuild and restore. Demonstrate the sentinel is detectable in a positive control. Confirm state/event transaction rollback and no event claiming work that failed before it started.
8. **A08 — close M5a.** Operator guide with read/write/keyless/DR modes, unknown facts, adoption/rebuild/lost-history rules and interrupted-state behavior. Run all regressions and ADR 0003 M5a gates. Update phase statuses and threat review. No protect/delete/prune command before acceptance.

Migration ordering: add only A04/A05 fields when their writers land; preserve old schema steps and use a new numbered step for each durable change. Fresh/upgrade/read-only paths must be tested against real older schema files, not just a database hand-built to match the new schema.

### B — M5b protection, retention and deletion

Prerequisite: M5a accepted. Owners: pure retention policy in domain, application planning/execution, inventory lifecycle, local marker-first deletion, CLI. This is the first irreversible feature phase; review all invariants against a real inventory before enabling execution.

1. **B01 — policy and plan contract.** Start with per-(source fingerprint, profile fingerprint) `keep_last N`, with N >= 1. Defer age limits/buckets until this passes. Known valid means current complete files, authenticated v1 bindings and a matching archive-validation or stronger validated-restore observation. This is the conservative B01 policy baseline introduced by this revision; record it with examples before enabling retention, because ADR 0003 did not freeze a minimum verification level. Unknown profile/time, missing/conflict/development/unregistered/deleted entries never count as valid or candidates. Refuse prune when the requested scope cannot be established. Define deterministic completion-time ordering and tie-break only equal times with ID; UUID alone never means newer.
2. **B02 — protection and preservation.** Add protected flag/event via migration; protect/unprotect change only inventory. Update registration/enrichment merge logic first so refresh cannot erase protection. A rebuilt index has lost flags and must state that fact; it does not silently inherit a safe-to-delete assumption. Last valid copy, active/use-held artifacts and job dependencies are exclusions even if unprotected.
3. **B03 — saved deletion plans.** Persist versioned immutable plans under plans/: operation, estate/scope, sorted exact ID set, ciphertext digests, relevant policy/inventory facts, created/expiry times and canonical digest. Use the existing 15-minute expiry as baseline. `delete ID` shares the same planner/executor with a singleton set. Preview only prints/saves intent, never modifies artifacts.
4. **B04 — confirmed execution.** Load plan, require exact digest/estate/expiry, take maintenance/artifact exclusion locks in recorded order, and revalidate all candidates/retained backups. If bytes, protection, validity, active usage or policy facts changed, refuse the whole unstarted plan and require a new preview; do not recompute a broader set. Remove marker/sync before deleting contents. Persist deleting/deleted state and each completed action; errors expose exact completed and remaining IDs. Tombstones/events remain.
5. **B05 — local rollback warning.** Maintain per-(source fingerprint, signer ID) authenticated completion high-water mark. Older restore plan/list produces a clear older-snapshot warning; explicit acknowledgement is bound into a new restore plan version without changing v1. This detects accidents when ledger survives, not an attacker who rewrites both files and inventory. Unknown authenticated time cannot advance the mark.
6. **B06 — retention drill and close.** Add `tests/m5b_retention_drill.sh`: plan/executed IDs match, each exclusion fires, unknown/keyless rebuild refuses, refresh preserves protection, a corrupted/removed retained copy prevents unsafe execution, two deleters cannot interleave, restore/delete race is refused, interruption after marker removal is recoverable and never valid, deleted history survives. Rerun M5a/M1–M4b and publish guide/threat status.

Deletion is non-atomic across several directories. Report partial execution honestly; never claim transaction rollback can resurrect removed files. Keep maintenance checks simple and testable before adding age/bucket retention or break-glass overrides.

### H — M6 harden CLI and deploy safely

Prerequisites: B acceptance. Implement in reviewable increments; do not enable production data merely because a package installs.

1. **H01 — configuration/release policy.** Record versioned production configuration, allowed connection/target topologies, secure local credential modes and any remote TLS extension. Preserve old fixture configuration for tests. Record error/JSON version policy and public-only/read-only key custody. Decide full/data-only/overwrite support explicitly; excluded behavior stays refused.
2. **H02 — process/filesystem hardening.** Implement process-group timeout/cancellation for descendants; tests include a wrapper retaining pipes after the client dies. Verify tool provenance/matching versions, permission/ownership/no-follow paths, disk/scratch bounds and stable safe errors. Resolve key-command partial writes by validation before mutation or a documented transactional creation path. Validate true read-only discovery/verification and explicitly configured private scratch where decryption needs writes.
3. **H03 — systemd/package.** Build .deb targets/units under deploy/, install dedicated user and mode-controlled paths, wire profile invocation and chosen timer semantics, preserve data/keys on upgrade/removal. Verify process locks and SQLite migration under actual service permissions/sandbox. Test package reinstall/purge policy.
4. **H04 — CI and operating guides.** Add pinned fast/matrix/package workflows; document installation, matching clients, credentials, key backup, inventory-copy consistency, recovery, stale alerts and isolated restore drills. A live SQLite database copy must use a consistent backup/export or quiescent maintenance ownership; DELETE journal does not make arbitrary concurrent raw copying safe.
5. **H05 — clean-code checkpoint.** Review modules introduced by A/B/H against C1 rules, remove redundant adapters/branches and update ownership comments. Keep fixes and refactors distinguishable. Run affected regressions and package lifecycle gates; no global rewrite.

Acceptance: tested Debian/Ubuntu install+upgrade+remove, dedicated-user timer creates signed backups without overlap or leaks, restore with recovery keys works, limits/errors/read-only modes match docs. Production-source enablement waits for V03.

### V — CLI production validation and release

Prerequisites: H plus all core acceptance gates; API/UI not required.

1. **V01 — content/security/failure matrix.** Run supported majors and privilege modes, full and supported selective restores, key loss/rotation, corruption, schema upgrades, restart/write/disk failure and target conflicts. Confirm compatibility/limits with recorded environments. Review custom crypto transcript/custody assumptions and dependencies; tests are evidence of behavior, not an independent cryptographic audit.
2. **V02 — benchmarks and real recovery rehearsal.** Execute §24 sizes and validate restored rows/schema/security/sequence state. Measure snapshot age/restore time and load. Demonstrate off-host recovery only if an independent copy workflow is actually implemented/tested; otherwise retain the limitation.
3. **V03 — release decision.** Resolve critical findings, choose license, publish SECURITY/CHANGELOG/support matrix and reproducible checksummed release. Enable production source configuration only in a separately reviewed change after these gates. Require signed encrypted writes for real data; refuse plaintext/unsigned production publication. Do not treat `--confirm-synthetic` as a production opt-out flag.

Acceptance: CLI install/run/restore/retention/recovery meets the documented local product promise, no unsupported host-loss/PITR/RPO/RTO claim, and every untested/excluded capability is visible. Mark original M9 CLI track complete independently from M7/M8.

### P — M7 API and asynchronous jobs

Prerequisites: hardened validated core; dependency/auth/worker decisions recorded.

1. **P01 — design contract.** Select framework/runtime; define OpenAPI, actors/permissions, safe errors, idempotency, token custody, TLS/deployment and queue/cancel ownership. Bound target authorization and destructive plan tokens to actor/request/expiry.
2. **P02 — worker adapter.** Add bounded queue/workers invoking existing core, persisted accepted/running/terminal states with real writers, restart reconciliation and cancellation by process group. Do not insert runtime dependencies into pure domain/crypto just to host HTTP.
3. **P03 — routes and observability.** Implement 202 jobs, artifact/profile/job reads, authenticated metrics/health and operation-specific access. Reject oversized/unknown fields, arbitrary paths and duplicate/conflicting idempotency keys before execution.
4. **P04 — verification and cleanup.** Authz/replay/rate/queue/cancel/restart/redaction tests, API-to-core equivalence and full destructive confirmation scenes. Apply C1 readability rules to new code, publish versioned API guide and threat review.

Acceptance: retries do not duplicate operations, no unauthenticated destructive access, cancellation accurately reports partial restore/deletion, and API behavior is the same core policy as CLI.

### U — M8 UI

Prerequisites: P accepted and OpenAPI stable. U01 chooses/records framework and operator workflow; U02 implements API-only health/artifacts/jobs and restore planning/confirmation; U03 adds profile/schedule/key-status views only for delivered API features; U04 tests accessibility/XSS/failure/partial states and complete browser/API flows, then cleans up code under C1 rules.

Acceptance: an operator can inspect verification, plan/confirm restore and monitor jobs without bypassing backend safeguards. No secrets in browser state/reports. No UI-created policy logic that disagrees with core.

### F — Full-platform release

Prerequisites: V/P/U accepted. F01 reruns end-to-end and package/migration/compatibility tests across all interfaces; F02 benchmarks actual worker concurrency and reviews API/UI security/operations; F03 performs final focused clean-code/doc review and publishes versioned platform release/support notes. Original M9 full-platform track closes here.

## 27. Universal acceptance and Definition of Done

A task is done only when its implementation, public examples, relevant contracts, tests and safe failure behavior agree. Required checks are executed and evidence recorded, or the task remains incomplete with the exact missing gate. No phase completion by elapsed time or test count alone.

Production conditions: a signed encrypted artifact reconstructs the representative supported database; full validation is distinguished from signature/checksum/archive; lost/corrupt inventory has an honest recovery path; crash cannot invent a complete artifact; destructive actions require bound plans and retain known valid copies; secrets do not leak; keys/data survive package lifecycle; an isolated restore drill passes on every claimed major.

Clean-code conditions: coherent module ownership, readable operation order, minimal justified abstractions, stable contracts, working regression tests and a reviewable diff. A refactor reducing lines while hiding ownership or trust checks fails acceptance.

## 28. Decision register

| Decision | Status/source | Implementer rule |
|---|---|---|
| Rust modular monolith/native logical tools | Accepted ADR 0001 | Preserve boundaries; no custom dump engine. |
| Hybrid recipient in age stream, backupctl-only recovery | Accepted ADR 0001 | Preserve exact suite/transcript and custody. |
| Signed encrypted v1 in one freeze | Accepted ADR 0002 | No in-place artifact changes or signing tuple edits. |
| Inventory key-free, inside store, one estate | Accepted ADR 0003 | Preserve privacy/provisional keyless limits. |
| DELETE journal/FULL/current 2000 ms timeout | Implemented M5a/spike | Assert effective values; no WAL assumption. |
| M5a observational before M5b destructive | Accepted ADR 0003 | No deletion before recovery acceptance. |
| Per-name-fingerprint scope, marker-first deletion, local ledger only | Accepted ADR 0003 | Preserve limits, protection/tombstones and explicit plans. |
| Shared activity/exclusive maintenance, nonmutating ordinary read | Planned S02 baseline in this revision | Record addendum and test lifecycle before coding cleanup. |
| Clean-code phase before new M5a features | Operator-requested in this revision | Behavior-preserving C1, no dependency/version drift. |
| Exact new CLI/rebuild/event/policy contracts | Planned A/B baselines | Freeze examples/encodings in task docs before code. |
| Production config, API runtime/auth, UI framework | Decision gates H01/P01/U01 | Do not choose silently during earlier tasks. |

If a baseline cannot satisfy a frozen/accepted invariant, state the conflict and alternatives with pros/cons. Resolve the specific decision before dependent work; do not ask the operator to approve already-authorized routine refactoring choices.

## 29. Gate checklist for the next implementing model

Start at S01. Confirm the worktree still has M5a increments 1–3 and the live-cleanup behavior. Read the applicable contract/source files, define the full-CLI failing scene, record the S02 lock/ownership design in ADR 0004, fix and verify safety, then begin C01. Do not jump straight to job commands because they look small.

Before M5a close: S and C1 accepted; job/read-only/keyless modes exposed; discovery differs from adoption; source provenance of keyless rows honest; observations bound to bytes; restore jobs/use locks real; rebuild flags/history losses stated; corruption/secret-content/PG16–18 crash and regression gates pass.

Before M5b close: last-valid/protected/active/dependency exclusions pass; known scope/time/validity mandatory; preview digest/expiry checked; exact set revalidated; marker-first interruption/tombstone recovery demonstrated; no automatic data resurrection/adoption; local ledger explicitly not adversarial replay protection.

Before release: package/service permissions and process descendants tested; config/claims match supported operations; production guard change separately reviewed; benchmark and restore evidence recorded; license/security/recovery docs complete. A future interface does not relax any core gate.

## 30. Risks and reductions

| Risk | Reduction and residual |
|---|---|
| Another model implements historical proposals as current truth | Status labels, stable task IDs, current-code references and frozen contracts. |
| Cleanup deletes live work | S ownership model plus real competing CLI/process tests. |
| Refactor disguises behavior/security change | Small responsibility moves, preserved vectors/contracts, separate bug-fix records. |
| Refresh/rebuild erases lifecycle protection | Merge rules, explicit lost-history confirmation, no deletion while unknown. |
| Retention uses stale/unknown verification | Observation-to-digest binding and execution-time retained-copy checks. |
| Restore runs harmful SQL or leaves partial target | Trusted-origin boundary, fresh target/plan, no silent retry/drop, isolated drills. |
| Key loss/compromise or custom crypto assumption fails | Separate recovery custody, hybrid construction, versioned suite/independent review; no audit claim from passing tests. |
| SQLite copy is inconsistent or silently corrupt | Consistent backup/quiescent copy, integrity check, staged rebuild; local index is not a witness. |
| Host loss deletes all local copies | Explicit limitation; independent-copy subsystem before strong recovery claim. |
| Roadmap overbuilds API/UI before usable CLI | V release before P/U; small concrete ports and no speculative worker framework. |

## 31. Future extensions

Separate designs are required for MySQL/MariaDB/MongoDB/Redis engines; S3/MinIO/SFTP consistency and transport; recipient-only writers/multiple generations/keyring/Vault/KMS; cross-major or cross-server restore; exact TOC/data-only/overwrite modes; age/bucket retention; multi-source/multi-host/tenant support; physical PostgreSQL/WAL/PITR; signed off-host inventory/immutability. None is implied by this CLI roadmap.

Crypto agility means decrypting with a preserved old identity, re-encrypting/re-signing into a new immutable generation under a reviewed suite, validating it, then allowing old generations to age out under safe policy. It is not an in-place rewrap guarantee, and it cannot undo already disclosed data.

## 32. Design and roadmap review — 2026-10-03

Assessment retained from the preceding review: product/architecture direction is sound, current M5a is incomplete, and cleanup safety is the immediate blocker. Reproduction used disposable synthetic staging/scratch directories with a held exclusive scope flock: `backup list` exited successfully, removed both directories, and left the flock held. The existing overlap test calls JobGuard directly and misses LocalStore startup.

This rewrite puts S before C1 before remaining M5a/M5b, makes the clean-code work explicit, reconciles delivered gzip/custom/synthetic/job/SQLite behavior, retains accepted contracts and places unresolved future choices at named gates. It specifies testable behavior rather than promising identical source from every model. Documentation revision alone does not fix the blocker or complete any implementation task.
