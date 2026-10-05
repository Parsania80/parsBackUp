# PostgreSQL Backup Platform — Implementation Roadmap

Revision: 2026-10-05. The operator authorized the review corrections and this detailed roadmap revision; §34 is the current implementation handoff. The 2026-10-03 rewrite was authorized by the operator. It replaces the earlier mixed design/status document with an implementation handoff and adds a dedicated clean-code phase. It changes the work plan; it does not claim that planned behavior is implemented.

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
| Phase S | Same-scope acquisition is tested mid-dump **and** by two real CLI processes | Opening a store removes nothing; work owns `activity.lock` shared, only `backup create` cleans it exclusively. Recovery, job surface and crash matrix remain for phase A. |
| Review corrections R | Consumption-bound signed/encrypted reads; process-group cleanup; overflow refusal; quoted native role exports; restore checks/preparation before mutations | Target/use locks remain A05; captured catalog/TOC output above 64 KiB is refused; service isolation remains H02. |
| Operations/service | None yet | Scheduling, packaging, production hardening, API and UI remain planned. |

Historical review evidence (before the S/C02/R increments): `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` passed; 167 tests passed, zero failed. Existing PostgreSQL 16/17/18 matrices have historical passing records through M4b. They were not rerun in the review or this rewrite. Test counts describe the baseline, not a target future count.

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

The blocker phase S closed was `LocalStore::open` removing all directories below staging/scratch before a job lock was acquired, so a second `backup list` removed live working data while a scope flock remained held. It is fixed in S02/S03 and pinned by `crates/backupctl/tests/store_concurrency.rs`, which runs competing CLI processes rather than calling a guard from one process.

Owned design, as recorded in `docs/architecture/adr-0004-working-directory-ownership.md`: ordinary opening performs no cleanup at all. A stage or a decrypted plaintext view holds `<root>/locks/activity.lock` shared for the entire lifetime of the directory it owns. The only code that removes a working directory is `LocalStore::recover`, invoked by `backup create` before resolution and before any scope claim; it takes that lock exclusive, nonblocking, and skips the whole store — reporting the skip, deleting nothing — while any operation holds it shared. Scope locks still reject duplicate source/profile backups, and because shared claims are compatible with each other, per-profile concurrency is unchanged. The lock file has a fixed name outside immutable artifact directories and is never unlinked. A nonmutating read that uses no working data takes no claim.

If a read-only artifact root requires decrypted scratch, use a separately private writable scratch area only after its configuration/lifetime contract is recorded; never write into the read-only root or silently fall back to a public temp directory. A read-only root is refused with its path named (ADR 0004 Decision 7).

Cleanup treats errors as errors, not as evidence an entry is abandoned. Process age/PID alone is not liveness. Under the exclusive claim only a UUID-named *directory* is removed; a symlink, a regular file, or a name this tool would not write is reported and left alone. Crash recovery preserves published artifacts, reports abandoned staging, and removes only working directories it owns exclusively. Do not reset protected or verified facts during reconciliation.

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

Execution order: authenticate artifact; validate plan/confirmation/current source; check target absence; fully decrypt and bind payload bytes; decrypt/bind globals and recheck DR role conflicts; apply opt-in validated globals; recheck target absence; create fresh database; prepare required schemas; restore native archive; report outcome. Failure may leave cluster roles or target objects partially changed. Leave them for explicit operator repair, report that fact, and never auto-retry or auto-drop them.

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
| 7 | S — M5a cleanup/concurrency correction | ✅ Done | Startup purge removed; ownership proved by two-process scenes and both lock controls. |
| 8R | R — review correctness corrections | ✅ Done | R01–R05 accepted 2026-10-05: 185 workspace tests, fast gates and all six PG16/17/18 matrices pass; evidence and handoff in §34. |
| 8 | C1 — clean code and human readability | 🟡 Started | C01 measured in §33; §33.6 approved as C02's boundaries; C02-1 (`keys.rs`), C02-2/C02-3 (`store.rs`, complete) and C02-4 (`stage.rs`, the sink half of that boundary — `LocalStage`/`LocalJob`/`begin` held back, see §33.6's note) moved; `scratch`/`signed`/`development`/`plans`/`inventory`, `backupctl/src/command/`, C03 and C04 pending. |
| 9 | A — complete M5a inventory/jobs/recovery | ⬜ Todo | Three earlier increments already implemented. |
| 10 | B — M5b retention/protection/deletion | ⬜ Todo | Requires complete M5a and C1. |
| 11 | H — M6 hardened CLI/systemd/Debian | ⬜ Todo | Production configuration and process/permission gates. |
| 12 | V — CLI production validation/release | ⬜ Todo | Original M9 CLI track; precedes API/UI. |
| 13 | P — M7 API/asynchronous service | ⬜ Todo | Requires hardened core and explicit decisions. |
| 14 | U — M8 API-backed UI | ⬜ Todo | Requires stable API. |
| 15 | F — platform validation/release | ⬜ Todo | Original M9 full-platform track. |

### ➡️ Current: #8 - C1 — resume at C02-5 after accepted R corrections
### ⏭️ Next: #9 - A — complete M5a after C1 acceptance

Task IDs below remain stable even if a phase is split into several commits. Complete dependent tasks in listed order. Independent documentation can proceed alongside its owning task; later feature coding waits for the phase prerequisites.

### Completed milestones M0–M4b: preserve this baseline

M0: architecture/ADRs/threat/content/privilege contracts and synthetic fixtures. M1: five initial crates, guarded local backup, bounded tools, publication and inspect/list. M2: opt-in role globals without passwords, DR/portable security policy, plan/run, checksum/archive verification. M3: profile validation, catalog-resolved exact scopes/dependency refusal, TOC digest, section-limited restore and namespace preparation. M4a: `backup-crypto`, custom hybrid recipient, age streaming, safe plaintext view ownership, key lifecycle and rotation/recovery drill. M4b: hybrid origin signature, encrypted manifest/public header, signature-first reads, DR without signing secret and frozen v1.

Historical matrix evidence covers PostgreSQL 16/17/18; archives are [September](archive/SESSION-LOG-2026-09.md) and [October completed M4b](archive/SESSION-LOG-2026-10.md). Active M5 increments remain in session-log.md. Do not reopen these milestones merely to rename types or broaden selection. Their guides and tests define compatibility.

### S — Correct ownership before feature development ✅

Prerequisites: baseline review; read storage/job implementation and ADR 0003. Owners: `backup-local`, application restore/verify resource lifetime, full-CLI integration tests. No artifact version change.

1. **S01 — failing full-startup regression.** Add a controlled mid-dump barrier and launch a second real CLI process opening the same store. Cover duplicate backup, `backup list`, archive verify and restore scratch access. Demonstrate that the baseline loses live working paths; assert the first operation's paths and bytes survive after the fix. Synchronize with a pipe/file barrier owned by the test; avoid timing-only sleeps.
2. **S02 — activity/maintenance ownership.** Implement §10's shared-operation/exclusive-cleanup baseline in a small local guard. Document acquire/release order, reader initialization and descriptor/resource lifetimes first. Ordinary open no longer purges directories. All stage and plaintext-view users retain ownership until their last file access/drop. Cleanup with a busy activity lock preserves every working directory and reports why it skipped/refused. Scope locks remain independent and nonblocking. Validate regular lock files, permissions and no-follow access.
3. **S03 — safe interruption recovery.** On an explicit writable recovery path, take exclusive maintenance ownership, conditionally mark genuinely abandoned jobs interrupted, and clean/report only abandoned work. Reopening the same scope must recover its old rows before the new job makes the scope appear busy. A concurrently completed job cannot be overwritten as interrupted. Add two-process SIGKILL scenes, repeated recovery/idempotence and changed-files/symlink refusals.

Acceptance: active backup/restore/verify survives unrelated reads and refused competing commands; different backup profiles may still run; killed operations release ownership and recover without a complete artifact; no plaintext leak, live directory deletion or silent terminal-state rewrite. Existing negative same-scope acquisition control still fails when exclusivity is removed. Run fast checks and affected M1–M4b matrices. Do not proceed to C1 until these scenes pass.

**Met 2026-10-03.** S01/S02/S03 landed as `crates/backup-inventory/src/activity.rs`, `LocalStore::recover`, `Inventory::open_bound`/`sweep_interrupted` and the `backup create` invocation, designed in [ADR 0004](docs/architecture/adr-0004-working-directory-ownership.md), whose gate section records each scene, both lock controls with the failures they produced, the fast gates and the PostgreSQL 16/17/18 matrices. Workspace tests rose from 167 to 179.

### C1 — Clean code and human readability

Purpose: make routine behavior understandable from named modules and straight-line orchestration. This is a separate phase, not permission to rewrite cryptography or change product behavior. Prerequisites: S and R acceptance (§34). Preserve runtime dependencies and public contracts; the full refactor diff should explain structural moves, not new features.

Current pressure points: the store, application and inventory crate roots mix several responsibilities. Historical line counts below belong to their recorded baselines; remeasure with `wc -l crates/*/src/*.rs` before a new extraction. Counts identify inspection targets, not quality thresholds. Long tests are not a reason to fragment coherent production logic, and a smaller file is not proof of simpler code.

| Task | Ordered changes | Acceptance |
|---|---|---|
| C01 | Capture current exported APIs, CLI examples, JSON/error contracts and passing baseline. Identify repeated logic and mixed ownership with concrete call sites. | Inventory of refactor scope; no speculative abstraction list. |
| C02 | Split local store responsibilities: opening/keys, stage/sinks, signed publication/reader, development reader/writer, scratch/activity, plans, inventory bridge. Move cohesive tests with their subject. | Crate-root reexports preserve callers; no artifact bytes, publication/read ordering, key rules or path behavior changes. |
| C03 | Split application into ports, backup, verify, restore and shared artifact facts; split inventory connection/open/recovery from SQL operations/tests where useful. | Use cases read in operation order; SQL stays in inventory; filesystem/crypto stays in local/crypto. |
| C04 | Simplify names, branches and comments; extract repeated semantic helpers, remove dead/stale prose, consolidate fixture helpers. Review before/after call paths and docs. | A reviewer can trace create/verify/restore/recovery without jumping through unnecessary wrappers; all contracts and regression gates pass. |

**C01 met 2026-10-03.** The inventory is §33: exported surface per crate, the `--output json` and human/error contracts captured from 67 real invocations against three synthetic store shapes, the mixed-ownership and repetition sites with file:line, and the eight hazards that block a naive move. Baseline re-measured at `097ace3` (fmt, clippy `-D warnings`, 179 tests, `git diff --check` — all clean). No source was edited for C01, and §26's stale line counts were recorded as findings in §33 rather than corrected here.

**§33.6 approved as C02's boundary set (2026-10-03), including the `backupctl/src/command/` addition and the two corrections to the diagram** (`activity` stays in `backup-inventory`; `layout.rs` and the recovery operation already exist). C02 is being taken one responsibility move per change, smallest first:

- **C02-1 — `backup-local/src/keys.rs`.** The key-file lifecycle moved out of the store file: `load_pair` (`pub(crate)`, still called by `with_keys` and `with_signing_keys`), the six `pub fn` key commands, and the two file-system rules they own alone (`refuse_occupied`, `ensure_private_parent`). `lib.rs` re-exports the six commands from the crate root, so `backupctl`'s import paths are unchanged — measured, not assumed: commenting the `pub use keys::{…}` line out makes `cargo check -p backupctl` fail with `unresolved imports backup_local::generate_key_pair, …, signing_key_status` at `crates/backupctl/src/main.rs:25`, and restoring it compiles clean. `backup-local/src/lib.rs` went 2297 → 1922 lines; `keys.rs` is 392 including the seven key tests that moved with their subject (`generation_creates_a_private_parent`, `generation_refuses_an_occupied_path_before_writing`, `publishing_refuses_an_occupied_recipient`, `publishing_refuses_an_identity_the_store_would_not_open`, `publishing_writes_the_recipient_of_a_hand_written_identity`, `a_generated_pair_reports_public_facts_and_opens_the_store`, `a_mismatched_key_pair_is_refused_before_the_store_is_created`). Each moved body was diffed against `HEAD` and is identical apart from rustfmt's wrapping and the `pub(crate)` marker; test count is 16 in the lib suite before and after (9 store + 7 keys), and no assertion text changed.
- **One file beyond the diagram: `backup-local/src/fixture.rs` (26 lines, `#[cfg(test)]`).** `temp_keys` and `key_pair` were needed by both the moved key tests and the store tests that keep using them, so copying them into the new module would have added a repetition §33.4 already counts. They are shared through a test-only module instead. `temp_root` moved with them for the same reason. This is the smallest form of §26's "consolidate fixture helpers" (C04); the store-specific helpers (`stage_bytes`, `manifest`) stayed in `lib.rs`'s test module.

**C02-1 gates (2026-10-03).** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `git diff --check` exit 0; `cargo test --workspace` **179 passed, 0 failed** — the same total as the phase S baseline, with the `backup-local` lib suite still 16. All six PostgreSQL 16/17/18 matrices exit 0 (`m1`, `m2`, `m3`, `m4a`, `m4b`, `m4a_key_drill`), the drill again covering rotation, cross-generation refusal, key loss, offline recovery, total-loss inertness, an operator-supplied identity and the signing pair's own loss and recovery on each major. Behavior preservation was measured, not asserted: the §33.2 battery was rerun and produced **the same 67 invocation labels** (`diff` of the two label lists is empty), **0 exit-code differences**, and — after masking only run-specific values (artifact ids, freshly generated key hex, byte counts and timestamps from new dumps, the `/tmp` run directory) — **all 134 stdout/stderr streams byte-identical**. Without masking, 12 streams differ on 22 lines, and every one of those lines is a size or timestamp value; no prose, key name, or error sentence moved.

- **C02-2 — `backup-local/src/store.rs`.** The store's shape decision moved: `new`, `with_keys`, `with_signing_keys`, `for_reading` and the private `open` they all funnel through, including `open`'s root and layout checks (absolute-root refusal, `create_dir_all`, `ensure_real_dir` on the root, the four required directories at mode 0700 with `scratch/` added only for a keyed store, and the "nothing is removed here" comment that records ADR 0004). `lib.rs` went 1922 → 1792 lines, `store.rs` is 148; the crate-root surface is untouched — `LocalStore` and `StoreKeys` stay defined in `lib.rs`, so every caller path including `backupctl/src/main.rs:55–69` is unchanged. This move needed **no visibility change at all**, unlike C02-1: the four constructors were already `pub`, `open` is private and is called only from inside the moved set, and a child module may read crate-root private items, so `store.rs` calls `crate::ensure_real_dir` rather than widening or duplicating it. The only other edits are three imports that became unused in `lib.rs` (`KeyRole`, `use keys::load_pair`, `LOCKS_DIR`) — each now used only through `store.rs`, verified by `cargo clippy -D warnings` rather than by eye.
- **Deliberately not in C02-2.** §33.6 also assigns `Recovery` (`lib.rs:146`), `recover` (`:322`) and `clear_working_dir` (`:355`) to `store.rs`, and the path helpers `encrypted`/`artifact_dir`/`plan_path` (`:390–400`). They stay put until **C02-3**, for two reasons: the maintenance pass is the ADR 0004 safety code and a reviewer should see it in its own diff, not mixed with constructors; and those five items are *private* methods and a `pub struct` field-level type, so moving them out of the crate root requires widening them to `pub(crate)` — a real (if small) change in reach that belongs in a change that is only about that.

**C02-2 gates (2026-10-03).** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `git diff --check` exit 0; `cargo test --workspace` **179 passed, 0 failed**, unchanged, including the four two-process `store_concurrency` scenes that open a store through these constructors. All six PostgreSQL 16/17/18 matrices exit 0 (`m1`, `m2`, `m3`, `m4a`, `m4b`, `m4a_key_drill`), each reporting all three majors. Move purity measured three ways: the removed 130-line block vs `store.rs`'s `impl` body is **0 differences** across 125 non-blank lines (the one blank-inclusive difference is the separator line the block used to end with, which stays in `lib.rs`); the definitions exist in exactly one place each (`store.rs:20/29/54/100/125`) and nowhere in `lib.rs`; and the negative control — disabling the whole `mod store;` item, not one line of it — makes `cargo check --workspace` fail with four `error[E0599]: no associated function or constant named … found for struct LocalStore` at `crates/backupctl/src/main.rs:55/58/61/69` and `could not compile backupctl (bin "backupctl") due to 4 previous errors`, then compiles clean once restored (`grep -rn CONTROL crates/` finds nothing). The §33.2 battery reran to the same **67 invocation labels** with **0 exit-code differences**; 28 of 134 streams differ unmasked and **0 remain after masking artifact ids, key hex, byte counts, timestamps and the harness run directory**. No test, assertion or error sentence was edited: `git diff --numstat` for `lib.rs` is 14 added / 519 removed across C02-1 and C02-2 together, every deletion a relocation.

- **C02-3 — `store.rs` completed.** `Recovery`, `recover`, `clear_working_dir` and the three path helpers `encrypted`/`artifact_dir`/`plan_path` moved in, so §33.6's boundary for this file is now filled: `lib.rs` 1792 → 1688, `store.rs` 261. The only non-move lines are the four the plan predicted — `pub use store::Recovery;` in `lib.rs`, and `pub(crate)` on the three path helpers, whose call sites stay in `lib.rs` until their own modules move (`encrypted` 2, `artifact_dir` 6, `plan_path` 2). `clear_working_dir` needed no marker, because its only caller `recover` moved with it. Both new wirings were controlled rather than asserted: disabling the whole `pub use store::Recovery;` line gives `error[E0432]: unresolved import backup_local::Recovery` at `crates/backupctl/src/report.rs:11`, and dropping `pub(crate)` from `artifact_dir` alone gives **6** `error[E0624]: method 'artifact_dir' is private` at exactly the six surviving call sites (`could not compile backup-local (lib) due to 6 previous errors`), which is what makes the widening set the minimum rather than decoration. Each control was reverted in the same step that ran it. `store.rs`'s module header now names all four responsibilities, including that `recover` is the only code in the crate that deletes anything.

**C02-3 gates (2026-10-03).** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `git diff --check` exit 0; `cargo test --workspace` **179 passed, 0 failed**, with the `backup-local` lib suite still 16 and all four `store_concurrency` scenes green — including `a_killed_backups_leftovers_are_recovered_by_the_next_backup_of_its_scope`, which is ADR 0004's reason for putting this pass under an exclusive claim. All six PostgreSQL 16/17/18 matrices exit 0 on the final tree, each naming 16, 17 and 18 in its own log: `m1`, `m2`, `m3`, `m4a`, `m4b`, `m4a_key_drill`. The §33.2 battery reran to the same **67 invocation labels**, **0 exit-code differences**, and **0 of 134 streams differing after masking** — checked against three baselines at once: the pre-refactor C01 run, the post-C02-2 run, and the intermediate build. Unmasked, 28 streams differ, all on id, size or timestamp values.

**Two mistakes in this step, both corrected and both worth keeping.** The first comparison masked digits before substituting the harness directory, so `/tmp/c02d` became `/tmp/c##d` and never matched its own replacement string — 8 phantom "residual differences". Masking long paths first and adding a dash-joined-hex id pattern brings the real number to 0. The second is the one that could have hidden a defect: restoring the `artifact_dir` control replaced `\n    fn artifact_dir(` with a string missing the newline, leaving `}    pub(crate) fn artifact_dir(&self, …)`. It compiled, clippy passed at `-D warnings`, and all 179 tests passed — only `cargo fmt --all --check` caught it. The first matrix pass had already built that tree, so those six exits are not reported as this increment's evidence; the matrices were re-run on the fixed tree and the numbers above are the rerun.

- **C02-4 — `backup-local/src/stage.rs`, the sink half of §33.6's staging boundary.** `Target`, `Writer` and `StageSink` with their `Write` and `PayloadSink` impls moved, together with `LocalStore::stage_sink`, which opens its own `impl LocalStore` block in the new file: 118 non-blank lines relocated, byte-identical to the text removed from `lib.rs` except the two lines (`impl LocalStore {` and its `}`) that the method needs to stand in a block of its own. `lib.rs` 1688 → 1564, `stage.rs` 148. This is the crate's plaintext-versus-age decision in one place — the thing its own header promises — and the two remaining files no longer have to read each other's internals to state it.
- **The widening set is two markers, and each is one call-site pair.** `pub(crate) enum Target` (named at `lib.rs:573` and `:577`, the trait's `payload_sink`/`globals_sink` shims) and `pub(crate) fn stage_sink` (called from those same two lines). Dropping the first gives `error[E0603]: enum 'Target' is private` at `lib.rs:46`; dropping the second gives **2** `error[E0624]: method 'stage_sink' is private` at `:574` and `:578`; disabling the whole module (`mod stage;` *and* its `use`) gives 4 errors — 2 × `E0599: no method named 'stage_sink'` plus 2 × `E0433: cannot find type 'Target'` — at exactly those sites, then compiles clean when restored. `StageSink`, `Writer` and `Target::name` needed no marker because nothing outside the moved set touches them, and `LocalStage`'s fields needed none either: `stage_sink` and `PayloadSink::finish` read `payload`/`globals`/`sealed_*` as a **descendant** of the crate root, which is the same rule C02-2 used for `crate::ensure_real_dir`. Two imports in `lib.rs` became unused (`StagedBytes`, `io::self`), verified by clippy.
- **Deliberately not in C02-4: `LocalStage`, `LocalJob` and `begin`.** §33.6 also assigns the stage *struct* and the job seam here, and `begin` (which constructs it) is measured, not guessed, to be the obstacle: `begin` is a method of `impl ArtifactStore for LocalStore`, and a trait has exactly one impl block per type per crate, so trait methods cannot be spread across modules — the publish paths, `measure` and `plaintext_staged_payload` are in that same block and belong to `development.rs`/`signed.rs`, which have not moved. Probing the move (relocating the struct alone, then restoring both files byte-for-byte from the verified copies) produced **29** `error[E0616]: field 'X' of struct 'LocalStage' is private` in `lib.rs` — `dir` 10, `payload` 6, `id` 5, `globals` 4, `sealed_payload` 2, `sealed_globals` 2 — i.e. taking the struct now would widen all seven fields including ADR 0004's `_claim`, the field whose privacy is the reason the activity guard outlives the directory removal. That is a safety-relevant reach change, so it belongs with the increment that moves its publishers, not with a sink move.

**C02-4 gates (2026-10-03).** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `git diff --check` exit 0; `cargo test --workspace` **179 passed, 0 failed** — the `backup-local` lib suite is still 16, and **7 of its 9 store tests drive the moved sink** rather than route around it: `publication_requires_marker_and_matching_payload`, `an_unfinished_stream_is_not_publishable`, `an_encrypted_stage_publishes_ciphertext_and_no_plaintext`, `a_keyless_store_writes_the_plaintext_layout`, `a_refused_decryption_leaves_no_scratch_behind`, `globals_file_is_bound_and_tamper_checked` and `undeclared_globals_file_is_rejected`, each through `stage_bytes` or a direct `payload_sink`/`globals_sink` call. All six PostgreSQL 16/17/18 matrices exit 0 (`m1`, `m2`, `m3`, `m4a`, `m4b`, `m4a_key_drill`), each log naming 16, 17 and 18, the drill again covering rotation, cross-generation refusal, key loss, offline recovery, total-loss inertness, an operator-supplied identity and the signing pair's loss and recovery per major. The §33.2 battery reran from `/tmp/c02e`: **67 invocation labels identical** to five baselines at once — the pre-refactor C01 run, C02, C02b, C02c and post-C02-3 — **0 exit-code differences**, and of 134 streams **28 differ unmasked, 0 after masking**. Two harness bugs surfaced while comparing and are recorded because they produced fake findings: the run-directory list must be masked **longest-first** (`/tmp/c02` shadows `/tmp/c02d` otherwise), and labels must be read from `<base>/out/*.exit`, not `<base>/*.exit`; the first pass of this step reported 8 residual diffs from exactly that shadowing. `git diff --numstat HEAD` for `lib.rs` is now **21 added / 754 removed** across all four C02 moves, every deletion a relocation.

Proposed private module destinations, adjusted only when code review shows a clearer cohesion boundary:

```text
backup-application/src/{lib,ports,backup,verify,restore,artifact_facts}.rs
backup-local/src/{lib,layout,store,stage,signed,development,scratch,plans,keys,inventory}.rs
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
2. **H02 — process/filesystem hardening.** Preserve R02’s delivered process-group timeout/exit cleanup; add explicit cancellation only with its real caller. Revalidate wrappers retaining pipes after their parent exits or times out under service permissions. Verify tool provenance/matching versions, permission/ownership/no-follow paths, disk/scratch bounds and stable safe errors. Resolve key-command partial writes by validation before mutation or a documented transactional creation path. Validate true read-only discovery/verification and explicitly configured private scratch where decryption needs writes.
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
| Shared activity/exclusive maintenance, nonmutating ordinary read | Accepted, implemented in S02/S03 | [ADR 0004](docs/architecture/adr-0004-working-directory-ownership.md): acquisition order, skip-when-busy, UUID-directory-only removal, both lock controls measured. |
| C02 boundary set = §33.6, plus `backupctl/src/command/` | Operator-approved 2026-10-03 | Splits follow those named call sites; `activity` stays in `backup-inventory`, `layout`/recovery are not re-created. The `JobLock` `O_NOFOLLOW`/mode gap is a separate documented behavior fix, never inside a move-only change. |
| Clean-code phase before new M5a features | Operator-requested in this revision | Behavior-preserving C1, no dependency/version drift. |
| Exact new CLI/rebuild/event/policy contracts | Planned A/B baselines | Freeze examples/encodings in task docs before code. |
| Production config, API runtime/auth, UI framework | Decision gates H01/P01/U01 | Do not choose silently during earlier tasks. |

If a baseline cannot satisfy a frozen/accepted invariant, state the conflict and alternatives with pros/cons. Resolve the specific decision before dependent work; do not ask the operator to approve already-authorized routine refactoring choices.

## 29. Gate checklist for the next implementing model

Start with §34 and the current-status table. Finish R acceptance before resuming C1; C02-1 through C02-4 are already delivered and must not be repeated. Phase S is accepted: the startup purge is gone, working directories are owned through `locks/activity.lock`, and `crates/backupctl/tests/store_concurrency.rs` runs competing CLI processes rather than one process calling a guard. Read [ADR 0004](docs/architecture/adr-0004-working-directory-ownership.md) for the acquisition order before touching any store or lock code, and keep its two controls (exclusive maintenance, exclusive scope) failing when weakened. C1 is behavior-preserving readability only, using the corrected R behavior as its new baseline; do not jump to the job surface because it looks small.

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

Resolution recorded the same day: phase S ran S01–S03 and closed this blocker. The startup purge is deleted, `backup list` can no longer remove a live backup's or verification's working directory, and the abandoned-entry cleanup happens only under an exclusive activity claim in `backup create`. See [ADR 0004](docs/architecture/adr-0004-working-directory-ownership.md) for the measurements and §26 for the acceptance evidence.

## 33. C01 refactor scope inventory — 2026-10-03

C01 is measurement, not movement: the surface a C02/C03 split must preserve, the CLI contracts a C04 diff must reproduce byte-for-byte, and the sites where ownership is mixed or logic is repeated. Nothing here is an abstraction request.

**Baseline at commit `097ace3` (working tree clean, no source edited for this inventory):** `cargo fmt --all --check` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo test --workspace` 179 passed / 0 failed over 18 test binaries (8 of them non-empty), `git diff --check` clean. §26's pressure-point counts are stale and were not corrected silently: `backup-local/src/lib.rs` is **2297** lines (§26 says 2202), `backup-inventory/src/lib.rs` **1359** (§26 says 1217), `backup-application/src/lib.rs` 1158, `backupctl/src/main.rs` 372, `backupctl/src/report.rs` 414, `backupctl/src/cli.rs` 248.

### 33.1 Exported API surface

| Crate | Exported | Consumers found |
|---|---|---|
| `backup-domain` | 9 `pub use`/`pub mod` lines (`lib.rs:9–32`), `protocol` glob-reexported whole (`:32`) | every other crate |
| `backup-crypto` | `keyid`, `keystore`, `protocol`, `signing`, `stream` as `pub mod`; `kem` and `recipient` private with only `HybridIdentity`/`HybridRecipient` re-exported (`lib.rs:14–26`) | `backup-local`, `backup-postgres` (stream only) |
| `backup-postgres` | **one item**: `pub struct PostgresAdapter` (`lib.rs:47`); all other modules are private plumbing | `backupctl` only |
| `backup-local` | 9 types (`StoreKeys:52`, `LocalStore:77`, `LocalStage:84`, `LocalJob:104`, `SignedArtifact:70`, `LocalArtifact:116`, `LocalPlaintext:127`, `Recovery:137`) + 6 key fns (`key_status:1483`, `generate_key_pair:1531`, `publish_recipient:1556`, `generate_signing_pair:1575`, `publish_verifying:1598`, `signing_key_status:1619`) + 2 re-exports (`:19`, `:23`) | `backupctl` |
| `backup-inventory` | `Estate:116`, `Inventory:135`, re-exports at `:30–34` (`ActivityLock`/`ACTIVITY_FILE`, `ArtifactRow`/`Shape`/`State`, `AuditAction`/`AuditEvent`/`JobGuard`/`JobRow`/`JobScope`/`JobState`, `JobLock`/`LOCK_DIR`, `SCHEMA_VERSION`), `INVENTORY_FILE:45` | `backup-local` |
| `backup-application` | 8 traits (`DatabaseAdapter:26`, `JobHandle:120`, `StageHandle:125`, `PayloadSink:147`, `PlaintextView:157`, `ArtifactHandle:161`, `SignedArtifactHandle:176`, `ArtifactStore:211`) + 15 types + `now_unix_ms:402`, `toc_digest:413`, `PLAN_TTL:17` | `backupctl`, `backup-local` (port impls), `backup-postgres` |
| `backupctl` | none — `cli.rs` is entirely `pub(crate)`, the crate is a binary | — |

The two crates with a real surface are the store and the application ports. A C02 file split therefore has exactly one contract to protect: crate-root re-exports must keep the names in the table reachable from their current paths. `LocalJob` (`backup-local/src/lib.rs:104`) is the legitimate cross-crate adapter the roadmap tells us to keep — it implements `backup-application::JobHandle` over `backup_inventory::JobGuard` because the orphan rule forbids either of those crates implementing the other's type.

### 33.2 CLI contracts, captured from real runs

213 streams from 67 invocations against three synthetic stores (plaintext, `[encryption]`, `[encryption]+[signing]`) on PG 16 through fake client binaries. These are the strings a C04 diff must reproduce.

| Command `--output json` | Plaintext store | `[encryption]` store | Signed store |
|---|---|---|---|
| `config check` | `{valid,mode,encryption,signing,shape}` with `shape:"m1-development-plaintext"` | same keys, `shape:"m4a-development-age"` | same keys, `shape:"signed artifact v1"` |
| `backup create --dry-run` | `{profile,source_major,client_version,selection}` | identical | identical |
| `backup create` | 23-key development manifest | same 23 keys | `{manifest:<29 keys>, public:<10 keys>}` |
| `backup list` | **array** of 23-key manifests | **array** | **`{signed:[…10 keys],unsigned:[…]}`** — not an array |
| `backup inspect` | 23-key manifest | same | **29 keys, and no `id`**: `backup_id`, `source_fingerprint`, `profile_snapshot`(9), `requested_selection`(5), `resolved_selection`(7), `compatibility_notes`, `globals_policy`, `subscription_policy`, `started_at_utc`, `completed_at_utc`, `archive_plaintext_bytes`, `archive_toc_sha256`, `payload_ciphertext_bytes`, `payload_ciphertext_sha256`, `globals_ciphertext_bytes`, `globals_sha256`, `engine`, `format_version`, `application_version`, `archive_format`, `compression`, `dump_client_version`, `recipient_id`, `recipient_suite`, `signature_suite`, `signer_id`, `source_server_major`, `source_server_version`, `verification_level` |
| `backup verify` (all three levels) | `{artifact_id,level,payload_size_bytes,payload_sha256,globals_size_bytes,globals_sha256,origin}` | identical | identical, `origin` populated |
| `key status` | stdout empty, **exit 1** | `{identity:<5 keys>,recipient:<5 keys>}` | those two + `signing:[{mode,path,role,signer,suite}]` |
| `restore plan` | exit 1 (see refusal below) | exit 1 | exit 1 |

`public.json`'s 10 keys are exactly `backup_id,format_version,manifest_ciphertext_bytes,manifest_sha256,payload_ciphertext_bytes,payload_sha256,recipient_id,recipient_suite,signature_suite,signer_id`. JSON is assembled by `serde_json::json!` at 12 sites across `main.rs` and `cli.rs` (`json_created`, `json_inventory`, `json_record`, `selection_json`, `key_json`, `signing_json`) plus one hand-written `println!` format string for `config check` (`main.rs:104–106`); there is no serialized request/response type anywhere, which is why the table above is the contract.

Human-mode wording (also part of the contract): `configuration valid (synthetic-only mode)` + `active blocks: [encryption] + [signing]; this store writes: signed artifact v1`; `created synthetic development backup <uuid>` with `database:`/`bytes:`/`payload: plaintext|encrypted with mlkem768x25519-v0`/`security metadata: none`; the signed form is a different 8-line report (`created signed artifact v1`, `sealed:`, `signed:`, `verification: none; the manifest is signed, so later checks are reported by backup verify rather than written into the artifact`); `backup list` human output is `uuid  database  N bytes` per row.

Refusal sentences captured verbatim, with exit codes: `backup create requires --confirm-synthetic; no format this build writes is trusted for real data until [signing] is configured, and the unsigned development formats stay refused for it` (1); `invalid configuration; expected M3 TOML fields` (1, and also for a config whose `[storage] root` is missing — the TOML error is deliberately never rendered); `unknown profile NO_SUCH_PROFILE; configured profiles: none` (1); `restore plan not found` (1); `restore policy requires roles but the backup contains no globals security file` (1, from `backup-application/src/lib.rs:981`, because the fixture profile sets `export_globals = false`); `refusing to overwrite the existing key file …; a new key orphans every artifact encrypted to the current one` (1); and the documented limit from §3 still standing: `backup inspect` of an unknown id in a plaintext store prints bare `No such file or directory (os error 2)` (1) instead of a sentence naming the artifact. Clap-level failures differ: `invalid value '' for '<ID>': invalid length: found 0` (2) with the `For more information, try '--help'.` trailer.

### 33.3 Mixed-ownership sites

- **`backup-local/src/lib.rs:841–1460` is one `impl ArtifactStore` holding six responsibilities**: unsigned publication (`publish` 950–1009), unsigned read (`list`/`inspect`/`open`/`plaintext_*` 1011–1088), plan rewrite (1089–1115), signed publication (`publish_signed` 1129–1253), signed read (`list_signed`/`verify_signed`/`open_signed`/`payload_plaintext`/`globals_plaintext` 1255–1423), and restore plans (`save_plan`/`load_plan` 1424–1460). The shapes are mutually exclusive per store, enforced at runtime by `is_signed()` guards (`950–960`, `850`) rather than by types, so reading either path requires knowing which guard fires.
- **Store opening vs key CLI in one file**: constructors `new 303`/`with_keys 312`/`with_signing_keys 337`/`for_reading 383` and `open 408` sit 1000+ lines from the six `pub fn` key commands at `1483–1640`, yet share `load_pair` (`1464`, called from `317` and `344`), `refuse_occupied` (`1496`) and `ensure_private_parent` (`1513`). The key writers own a 0600/never-overwrite rule that no artifact writer reuses.
- **Directory layout and directory removal are split by policy, not by module**: `open 408–430` creates `staging/artifacts/plans/locks` and `scratch` and removes nothing; `recover 443–474` and `clear_working_dir 476–509` do the removing under an exclusive claim; `decrypt_to_scratch 612–651` creates and removes scratch entries under a shared claim. Three ADR 0004 ownership rules live in four non-adjacent ranges.
- **The activity claim lives in the wrong crate for its subject.** `backup_inventory::ActivityLock` (`activity.rs`) guards `backup-local`'s directories; the hold sites are `backup-local/src/lib.rs:444` (maintenance), `623` (scratch decrypt) and `878` (stage), while the *scope* flock is taken inside the inventory crate at `job.rs:438` (`JobGuard::begin`) and probed at `lib.rs:487–500` (`sweep_interrupted`). Two claims over one store root, one from each crate, with different construction guarantees (see 33.4).
- **`LocalPlaintext` carries two ownership states in one struct**: a scratch-backed view with `scratch: Some(..)` and `_claim: Some(..)` (`641`) and an alias with both `None` (`1044–1048`, `1062–1066`, `1077–1082`). `Drop` at `184` must do the right thing for both, and the field order at `127` is load-bearing for that.
- **The inventory bridge sits inside the filesystem crate**: `record_published 535–564` opens the inventory and writes an `ArtifactRow` from the publish path, so publication ordering and SQL failure handling are entangled in the same method range as the fsyncs.
- **`backupctl/src/main.rs:74–372` is one `run()` function**: 8 top-level arms, four store opens (`open_store 51–69` called at `188`, `208`, `286`, `318` — so the `verify` arm opens a second store while the enclosing `Backup` arm already holds one), the ADR 0004 recovery call at `213`, service construction at `189`/`219`/`287`/`319`, and 11 `if json { … } else { … }` branch pairs interleaved with the business calls.

### 33.4 Repeated logic, with whether the semantics actually match

| Repetition | Sites | Same semantics? |
|---|---|---|
| private, never-overwrite file open | `backup-local/src/lib.rs:591`, `633`, `695`, `713`, `987`, `1004`, `1109`, `1240`, `1429` (9) | Open yes, **afterwards no**: some `sync_all`, some rename into place, some fsync the parent dir |
| `hash_file` re-measure of digest+size | `931`, `943`, `813`, `820`, `1180`, `1202`, `1311`, `1321`, `1372` (9 calls of `1658`) | Yes, but the *reason* differs (measure a stage vs re-measure published bytes vs authenticate a read) |
| marker create + `sync_all` + dir fsync | dev `1004–1007`, v1 `1240–1243` | Yes — the two publication paths converge here |
| staged-dir rename + overwrite refusal + `artifacts/` fsync | dev `994–999`, v1 `1230–1235` | Yes |
| temp manifest write + rename + dir fsync | dev `983–993`, v1 `1105–1115` | Yes |
| signature tuple build + `try_sign` | v1 publish `1203–1207`, re-sign/publish path `1334–1338` | Yes |
| `load_pair` | `317`, `344` | Yes |
| `LocalPlaintext { scratch: None, _claim: None }` | `1044`, `1062`, `1078` | Yes |
| `Duration::from_secs(config.timeout_seconds)` | `backup-application/src/lib.rs:509`, `550`, `825`, `889`, `974`, `1034` (6) | Yes — a per-config fact recomputed per call |
| `config.validate()` | `backup-application/src/lib.rs:508`, `969` + `backupctl/src/main.rs:83` | Yes, three times per `backup create` |
| `open_store(..)` + `Service::new(..)` | `main.rs:188`/`189`, `208`/`219`, `286`/`287`, `318`/`319` | Roughly; the `verify` arm re-opens a store the enclosing `Backup` arm already opened |
| `if json` / `else` report split | `main.rs` (11) + 6 in `backup-application` | Yes structurally, different content |
| verification-level dispatch | `backup-application/src/lib.rs:813`, `819`, `830` vs `866`, `882`; plus `main.rs:289–291` mapping the clap enum | Yes, and the 3-way match exists twice in the service |
| TOC digest compare | `backup-application/src/lib.rs:838–844` (unsigned) vs `892–899` (signed) | Same intent, **different trust**: the signed path also refuses `None` |
| DR role-conflict refusal | `backup-application/src/lib.rs:1002–1005` (plan) vs `1066–1069` (run) | Same check; **sentences differ** — the plan text ends `; use the portable policy or remove them first`, the run text does not |
| `locks/` dir create + lock-file open + `would_block` + `Drop` | `backup-inventory/src/job_lock.rs:52–63`, `68–75`, `183–185`, `187–194` vs `activity.rs:114–123`, `139–147`, `178–180`, `168–175` | `would_block` and `Drop` are **byte-identical**; the opens are **not** — see 33.5 |
| report strings | `backup-application/src/lib.rs:155`/`188`, `172`/`287` | Yes |

### 33.5 Hazards that block a naive move

1. **The two lock files in `locks/` have different protections.** `ActivityLock::open_claim` (`activity.rs:114–159`) checks the directory is real, checks the file is regular, opens with `O_NOFOLLOW`, and asserts `mode & 0o077 == 0`; `JobLock::acquire` (`job_lock.rs:46–102`) validates the fingerprints (`check_scope :51`) but opens **without** `O_NOFOLLOW` and **never checks the mode**, and its `AlreadyExists`-tolerant `create_dir_all` differs from `activity.rs`'s `exists()` guard. Merging them into one helper would change one path's behavior — a finding for a separate, documented fix with its own test, not a move-only C02 change.
2. **Publication order is the security property.** `publish_signed` (`1129–1253`) writes signature before the rename deliberately (`1132–1138` explains it); extracting a shared "finish" helper across `publish`/`publish_signed` must not reorder any fsync.
3. **Tests assert on exact substrings** at `backup-local/src/lib.rs:1838` (`never finished`), `2007` (`is not the recipient of`), `2228`/`2270`/`2279` (`refusing to overwrite`), and `backup-inventory` tests reach `super::*` internals (`.conn`, `binding`, `mark_interrupted`), so moving a method without moving its test breaks the suite in ways unrelated to behavior.
4. **`impl ArtifactStore`'s 8 GATs** (`backup-application/src/lib.rs:211–301`) plus `Box<dyn PayloadSink + 'a>` (`228`, `230`) mean any split of the store must keep the trait's associated types resolvable from the crate root; `StageSink<'a>` (`backup-local/src/lib.rs:171`, impls at `198`/`220`) double-borrows the stage it writes into.
5. **Field order in `LocalStage`/`LocalPlaintext`** (`84`, `127`) is Drop-order semantics for the claim guard; a derived reorder in a split is a behavior change.
6. **`crypto/protocol.rs` constants and the golden vector test** (`backup-crypto/src/signing.rs:667–681`) are frozen; `backup-local` re-exports key types (`:19`, `:23`) so callers do not name `backup-crypto`. Nothing in this inventory proposes moving a crypto module.
7. **Unix-only APIs** (`libc::flock`, `std::os::unix::fs::PermissionsExt`) already gate the whole store layer; a new module boundary must not pretend to widen portability.
8. **The JSON asymmetry in 33.2 is a live contract**: `backup list` returns an array for the two development shapes and an object for a signed store, and `backup inspect` returns a 23-key object versus a 29-key one with a different id field name. A refactor that "unifies" them is a feature change, out of C1 scope.

### 33.6 C02 module boundaries proposed from these sites

Same destination set as §26's diagram, with four measurements added — three where the diagram names a module whose subject lives in another crate, and one where it omits a crate that has the repetition:

```text
backup-local/src/lib.rs          crate facade + re-exports only (§33.1 names the items it must keep reachable)
backup-local/src/store.rs        open 303–430, Recovery 137 + recover 443–509, paths 511–521
backup-local/src/keys.rs         1462–1640: load_pair, the six pub key fns, refuse_occupied, ensure_private_parent
backup-local/src/stage.rs        LocalStage/LocalJob 84–115, Target/Writer/StageSink and their impls 150–260, sinks 566–606, begin 875–920
backup-local/src/scratch.rs      decrypt_to_scratch 612–651 + LocalPlaintext 127–200 (both ownership states together, with Drop)
backup-local/src/development.rs  publish 950–1009 + read 1011–1088 + rewrite_manifest 1089–1115 + ArtifactHandle impl 283–300, with tests 1714–2297 split by subject
backup-local/src/signed.rs       publish_signed 1129–1253 + signed read 1255–1423 + SignedArtifactHandle impl 262–282
backup-local/src/plans.rs        save_plan/load_plan 1424–1460
backup-local/src/inventory.rs    record_published 535–564 (the only bridge; keeps SQL out of the publish paths)
```

Adjustments the measurements force, each with the failure it prevents:

- **`layout.rs` (`backup-local/src/layout.rs`, 38 lines) already exists and already holds the constants**; adding a second `layout` module to the diagram would be an empty module. Fold it into `store.rs`'s facade or leave it where it is.
- **`activity` cannot live in `backup-local`** as §26's diagram says, because `backup-inventory::Inventory::sweep_interrupted` (`lib.rs:487–500`) is a second consumer of the same claim, and the dependency direction is `backup-local → backup-inventory`, not back. Proposed: keep both claims in the inventory crate, rename nothing, and in C02 only **share the identical plumbing** (`would_block`, `Drop`, the dir/open preamble) behind one `pub(crate)` helper — without touching the `O_NOFOLLOW`/mode asymmetry from 33.5, which is a separate documented behavior fix.
- **`recovery.rs` in the §26 inventory diagram is already satisfied** — `sweep_interrupted` is the recovery operation and it is in `lib.rs:487`; whether it earns its own file is a C03 call, not a move C01 can justify.
- **A trait has one impl block per type per crate, so the remaining `backup-local` boundaries are *body* extractions, not method moves** (measured in C02-4, which this reshapes). `impl ArtifactStore for LocalStore` (`lib.rs:492–1111`, one block for 620 lines of behavior) cannot be spread across `stage.rs`, `development.rs`, `signed.rs`, `plans.rs` and `scratch.rs`; only the inherent `impl LocalStore` blocks can move freely, which is how `stage_sink` got to `stage.rs`. For the trait methods the options are a one-line delegate in the trait block calling an inherent method in the target module (an added indirection, so a documented change rather than a pure move) or leaving them at the crate root. It also means a stage *struct* move would force `pub(crate)` on all seven `LocalStage` fields — **29** `E0616` field-privacy errors measured in the probe — including ADR 0004's `_claim`, whose privacy is what keeps the activity guard alive past the directory removal. So `stage.rs` got the sink machinery only, and `LocalStage`/`LocalJob`/`begin` wait for the increment that moves the publishers.
- **The diagram omits `backupctl`, which has the largest repetition count.** C02 should add `crates/backupctl/src/command/` (one file per `TopCommand` arm, each doing: open → call → report) and leave `cli.rs` as argument types + the five `*_json` builders, so the 11 `if json` pairs move next to the arm they describe. `report.rs` already separates human output; it needs no split. This is the only new-file proposal in this section, and it exists because 372 lines of `main.rs` contain the store-open ordering the ADR 0004 gate depends on.
- **`backup-crypto`, `backup-postgres`, `backup-domain` are not in scope for C02.** `backup-postgres` exports one item, `backup-domain` is already module-per-concern, and the crypto module is frozen by vectors.

Deferred to C03 by rule ("SQL stays in inventory, filesystem/crypto stays in local/crypto", and because these are semantic extractions, not moves): the six `Duration::from_secs` recomputes, the triple `config.validate()`, the duplicated level dispatch, and the plan-vs-run DR refusal wording — the last one changes a CLI error sentence and therefore needs an explicit decision rather than a helper.


## 34. Review corrections and agent execution handoff — 2026-10-05

This section supersedes older instructions to start immediately with C1. The operator requested implementation of the five review findings and a roadmap another agent can execute. R is a behavior-fix phase; C1 remains structural refactoring. Artifact v1 fields, signing tuple, suites, restore-plan format, CLI syntax and synthetic-only guards stay frozen. Existing `libc` and `serde_json` workspace packages are reused by adapters; Cargo.lock changes dependency edges only, not resolved versions.

### 34.1 Start and finish rules

1. Read this section, §§3/10/11/26/27/28, AGENT.md, ADRs 0002–0004, then the current source and every caller of the function to change. Historical file:line references are evidence, not live navigation; use `rg` to locate symbols.
2. Inspect `git status --short` and preserve existing changes. Select the first unfinished task below. Do not redo delivered key/store/stage extractions, reimplement an existing lock, add empty modules, broaden production support, or start retention before A acceptance.
3. For a behavior correction, establish a focused failing case, fix the common boundary and rerun its tests. For a move, preserve API and operation order and compare moved bodies. Never label a logic correction as a move-only refactor.
4. Run affected checks during development and the phase gates after the final source edit. Record commands, exit codes, environment/majors, test totals and limitations in session-log.md. A historical passing matrix or a new unit test is not proof that the current matrix passes.
5. Update the relevant task status, current/next markers and README after verification. A missing prerequisite leaves that acceptance gate pending with its precise reason; never mark the enclosing phase complete because code exists.

### 34.2 R task contracts

| ID | Owner and concrete change | Regression and acceptance |
|---|---|---|
| R01 | `backup-local/src/lib.rs`: `decrypt_to_scratch`, `authenticated_manifest`, `payload_plaintext`, `globals_plaintext`. Hash/count the exact ciphertext stream consumed by decryption; drain remaining bytes within recorded-size-plus-one; compare against the verified header or signed manifest before returning a plaintext view. Open ciphertext with O_NOFOLLOW and inspect the opened file. Construct the scratch owner before fallible file opens so refusal cleans up. | `signed_views_refuse_ciphertext_replaced_after_opening` replaces paths and overwrites inodes for payload/globals using only the public recipient; both are refused and scratch is empty. `manifest_decryption_binds_the_stream_to_the_verified_header` refuses a replaced manifest stream before JSON interpretation. Existing signed reads, plaintext limits and crypto vectors pass. A second hash of a path before decryption is insufficient: it recreates the race. |
| R02 | `backup-postgres/src/tools.rs`: both `run` and `run_streaming`. Use `CommandExt::process_group(0)` and terminate that group on deadline and parent exit so descendants cannot hold inherited stdout/stderr open. Reap the direct child; retain bounded capture, warning refusals and safe errors. Reuse workspace libc. | `deadlines_close_descendant_pipes_in_both_runners` covers a sleeping child with a live parent and a background child after parent exit. Both runners finish within the test bound; streaming remains unbounded for archive bytes. Descendants that deliberately escape their group require later service/cgroup hardening in H02; this does not certify hostile executable supervision. |
| R03 | Shared `read_bounded` in PostgreSQL runner: retain at most 65,536 bytes, continue draining to avoid pipe deadlock, remember overflow and refuse incomplete parsed stdout/stderr. Never echo dropped/captured content. Archive stdout uses streaming and is unaffected. | `capture_overflow_is_drained_and_refused` accepts exactly the limit, refuses overflowing stdout and stderr, and covers streaming stderr. All catalog/TOC callers inherit the refusal. Large catalog/TOC output above the cap is an explicit current limitation; a later supported-size task may introduce typed streaming or a justified larger bound with tests, never silent truncation. |
| R04 | `backup-postgres/src/globals.rs`: replace whitespace/semicolon splitting with a small lexer for native role-export syntax: quoted identifiers, doubled quotes, quoted strings, E-string escapes and line comments. Preserve quoted text when rebuilding statements; reject unterminated quotes. `existing_roles` returns/decodes a JSON array so embedded whitespace/newlines survive lookup. Reuse workspace serde_json. | `quoted_identifiers_and_literals_survive_the_complete_parser` checks spaces, semicolons, embedded/trailing quotes, comment-looking literal text, memberships, existing-role exclusion and malformed input. M2 adds a native export/DR round trip for spaces, semicolons, quotes, newlines, membership and a semicolon/comment-looking role setting on all three majors; M4 matrices independently restore roles. Keep roles-only filtering and password-verifier refusal; arbitrary SQL/dollar-quoted function bodies are outside this parser’s contract. |
| R05 | `RestoreService::run`: repeat target absence before cluster mutation, prepare fully decrypted/bound payload, then check/apply globals. Keep the second absence check immediately before CREATE DATABASE. Retain private payload view until native restore finishes. | `restore_refusals_precede_cluster_mutation` proves a target appearing after planning causes zero globals/CREATE DATABASE calls; a newly signed ciphertext with a corrupt age body passes signature/open checks but fails decryption with zero mutations. Existing successful DR/portable/partial restores pass. A target race after the first check is still possible until A05 target/use locks; failures never trigger automatic rollback/drop/retry. |

R implementation status: **R01–R05 accepted 2026-10-05**. All fast and matrix gates pass; evidence is §34.7. The corrected behavior is the baseline for further C1 work. No planned A/B/H feature is implied by these corrections.

### 34.3 Reproducible gates

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
git diff --check
bash tests/m1_docker_smoke.sh
bash tests/m2_docker_smoke.sh
bash tests/m3_docker_smoke.sh
bash tests/m4a_docker_smoke.sh
bash tests/m4b_docker_smoke.sh
bash tests/m4a_key_drill.sh
```

Prerequisites: working Docker daemon, the scripts’ PostgreSQL 16/17/18 images, writable private temporary storage, available fixture ports and stock rage/rage-keygen (the scripts also check `$HOME/.cargo/bin`). Scripts own their synthetic containers and cleanup. Run matrices sequentially because several reuse ports 54336–54338. Capture each script’s stdout/stderr separately; verify its exit code and evidence for all three majors. Do not modify scripts merely to bypass a failed assertion. The historical 67-invocation CLI comparison harness under /tmp may be absent on another host; never claim that battery passed without reconstructing or retaining a reproducible harness. Focused tests and delivered smoke scripts are the reproducible R gates.

### 34.4 Remaining C1 work, in order

| Task | Starting symbols / implementation boundary | Completion evidence |
|---|---|---|
| C02-5 | Inspect `decrypt_to_scratch`, `authenticated_manifest`, `DigestReader`, `LocalPlaintext` and Drop ownership for a cohesive scratch extraction. Move private inherent helpers and their tests into scratch.rs only if it improves navigation. Keep public type definitions/guard fields at the crate root when moving them would widen ownership. | R01 replacement tests and store_concurrency scratch scenes pass. Plaintext cleanup occurs before activity-claim release on success/refusal/drop. Existing crate-root import paths compile. |
| C02-6 | Inspect signed/development publication and reading, plan save/load, and `record_published`. Extract cohesive inherent bodies where useful; trait methods can remain at the root. Keep marker/fsync/rename/signature/decrypt order explicit and inventory bridge below application. | Signed/development store tests, plan expiry tests and M1–M4b matrices. Do not duplicate the signed binding reader, or add a wrapper per method solely to match a diagram. |
| C02-7 | Inspect backupctl’s TopCommand match: parse/config → open/call → human/JSON report. Move command families only if their independent size warrants it. Reuse `open_store`, report.rs and existing JSON builders. | Same flags, JSON keys, refusal reasons and exit semantics; real CLI concurrency scenes still cover startup. Recovery stays in writable create and never ordinary read/dry-run. |
| C03 | Inspect application ports/use cases/Opened and inventory open/recovery/SQL operations. Preserve `Opened`’s shared signed/development facts and LocalJob’s required orphan-rule bridge. Factor only repeated semantic work, with all callers traced. | Restore R05 order remains visible, no I/O in domain, SQL remains in inventory, no new runtime or trait without an actual adapter/test use. All composed-path and inventory migration tests pass. |
| C04 | Remove demonstrably dead code/stale comments; shorten narration while retaining durability/trust/lock rationale; consolidate duplicate fixtures. Audit exported surface and dependency directions. | Full fast/matrix gates, accurate README/roadmap, no unexplained visibility widening, no mandatory file-count/line-count target. Mark C1 accepted only when the reviewable resulting structure satisfies these conditions. |

Previously recorded JobLock no-follow/mode gap (§33.5.1) remains an explicit separate behavior task before A acceptance: use the opened descriptor’s regular-file/permission checks and O_NOFOLLOW without reversing dependencies or unlinking flock names. Test symlink/world-readable refusal and same-scope contention; preserve ActivityLock’s existing protection and ADR 0004 acquisition order. Do not silently fix it inside a structural move.

### 34.5 Feature continuation and phase exits

After R and C1 acceptance, execute existing §26 task IDs unchanged:

| Phase | Ordered task sequence and prerequisites | Exit decision |
|---|---|---|
| A / M5a | A01 modes/jobs CLI → A02 observational reconciliation → A03 rebuild/recovery → A04 digest-bound events/enrichment → A05 restore target/artifact ownership → A06 PG crash/migration drill → A07 leakage/transaction checks → A08 operating guide and close. Existing backup rows are delivered; implement their missing readers/recovery, not a second inventory. | All unknown/conflict/adoption rules and real ownership/crash/privacy gates pass. No deletion enabled. |
| B / M5b | Only after A: B01 exact policy/plan → B02 protection → B03 saved plans → B04 confirmed marker-first execution → B05 local rollback warning → B06 retention drill and close. | Last-valid/protected/active/job-dependent exclusions, exact-set revalidation, interruption/tombstone tests and recovery prove deletion safety. |
| H / M6 | Only after B: H01 production configuration policy → H02 remaining process/filesystem/service hardening → H03 package/timer → H04 CI/operating guide → H05 readability review. Preserve R fixes; do not reimplement them. | Actual supported package/service environments pass lifecycle, permissions, key custody and recovery checks. Synthetic guard remains until V03. |
| V / CLI release | V01 supported matrix/security/failure review → V02 benchmarks/recovery rehearsal → V03 explicit release/production-source decision. | Release limits, license/security/support docs and measured recovery agree. API/UI are not prerequisites. |
| P → U → F | Explicit API/auth/worker decisions, existing-core adapters, then API-only UI, then full-platform verification. | Interface tests cannot bypass core trust/confirmation/ownership gates; no platform completion before all prerequisites pass. |

Every handoff names the next exact task, affected symbols/files, tests executed and pending gates. Recheck current code/status rather than trusting a dated “done” sentence. A future issue discovered while refactoring becomes its own behavior correction with regression evidence.


### 34.6 Change inventory

| File path | Change type | Description |
|---|---|---|
| crates/backup-application/src/lib.rs | Modified | Target check and payload preparation before cluster mutations; later absence check retained. |
| crates/backup-local/src/lib.rs | Modified | Consumption-bound ciphertext reader, no-follow open, early scratch ownership, manifest regression; encrypted development reads also use their recorded checksum binding. |
| crates/backup-local/Cargo.toml | Modified | Reuse workspace libc for no-follow opens. |
| crates/backup-local/tests/common/mod.rs | Modified | Existing test capture can observe target appearance and globals calls. |
| crates/backup-local/tests/signed_store.rs | Modified | Replacement/in-place overwrite tests for payload and globals, with scratch cleanup. |
| crates/backup-local/tests/signed_write_path.rs | Modified | Target-after-plan and valid-signature/corrupt-age refusals before mutation. |
| crates/backup-postgres/src/tools.rs | Modified | Process-group cleanup and capture-overflow refusal, with regressions. |
| crates/backup-postgres/src/globals.rs | Modified | Native-export quote-aware lexer and complete-parser regression. |
| crates/backup-postgres/src/lib.rs | Modified | JSON role lookup preserves quoted names and keeps decode errors data-free. |
| crates/backup-postgres/Cargo.toml | Modified | Reuse workspace libc/serde_json. |
| Cargo.lock | Modified | Dependency edges only; no package version changes. |
| tests/m2_docker_smoke.sh | Modified | Quoted-role native export/DR assertions on PostgreSQL 16/17/18. |
| docs/backup-format/manifest-v1.md | Modified | Clarify consumption-time binding without changing the frozen format. |
| docs/security/threat-model.md | Modified | Record T02 coverage and remaining filesystem/replay/host limits. |
| project.md | Modified | Correct operation order, phase dependencies, current/next status and executable agent handoff. |
| README.md | Modified | Describe corrections and link to the handoff. |
| session-log.md | Modified | Append implementation and final verification evidence. |


### 34.7 Acceptance evidence and next task

Accepted 2026-10-05 on the working tree based on commit `2303019`:

| Gate | Result |
|---|---|
| Workspace tests | 185 passed, 0 failed; includes six new regressions, existing crypto vectors, composed write/restore paths and four real-CLI concurrency scenes. |
| Formatting / Clippy / diff | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `git diff --check`: exit 0. |
| Shell syntax | `bash -n tests/m2_docker_smoke.sh`: exit 0. |
| M1 / M2 / M3 / M4a / M4b / key drill | All six scripts exit 0 and each reports PostgreSQL 16, 17 and 18. |
| Changes after initial matrix pass | M2 rerun with its new native quoted-role checks; M4a and key drill rerun after adding encrypted-development consumption binding. All three refreshed runs exit 0 on all majors. |
| Compatibility / dependency check | No v1/plan field, signature input, suite, CLI syntax or resolved package version changes. Existing packages reused through three additional adapter dependency edges. |

Local evidence logs: `/tmp/parsbackup-review-tests.log`, `/tmp/parsbackup-review-clippy.log`, `/tmp/parsbackup-review-matrices.txt`, `/tmp/parsbackup-review-refreshed-matrices.txt` and `/tmp/parsbackup-review-<script-name>.log`. These are ephemeral run evidence, not prerequisites for another agent; §34.3 supplies the checked-in commands/scripts to regenerate them. The historical 67-invocation comparison battery was not rerun and is not claimed here. No commit or push was requested.

**Next implementing task: C02-5.** Inspect scratch/decryption helpers and their callers against the accepted consumption-binding and activity-lifetime invariants. If extraction adds delegation/visibility without improving cohesion, retain the current boundary and record that decision; then proceed to C02-6. Do not repeat C02-1 through C02-4 or start A features before C1 acceptance. The separate JobLock no-follow/mode task remains due before A acceptance.
