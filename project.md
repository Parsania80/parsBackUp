# PostgreSQL Backup Platform — Implementation Roadmap

Latest implementation handoff: §54 (V01 signed table-family compatibility verified and review accepted for local checkpoint, 2026-11-17). V01 checkpoint is `5a1834b`; SQLite checkpoint `d90a3b4` is committed and remote push verified. Cryptography checkpoint `c13f593` is committed locally. H05 is committed as `046c22e`; H04 as `6a547e9`, H03 as `cb34f5e` and H02 fixture hardening as `3cc9326`. H fixture foundations are locally accepted; production compatibility/content/security validation and V02/V03 remain required. The historical 2026-10-03 rewrite was operator-authorized; historical results are distinct from current verification.

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
| M5a increment 1 | `backup-inventory`, estate binding, SQLite open rules and scope flock; A08 adds JobLock no-follow/private regular-file checks | Trusted operator-owned root required; hostile ancestor replacement remains H02. |
| M5a increment 2 | Signed publication registers an artifact row after the completion marker | Development artifacts remain unregistered. |
| M5a increment 3 + A01 | Schema v2 jobs/audit; backup creation drives running/staged/complete; read-only job list/inspect and inventory integrity check | Jobs predating operation associations report their operation as unknown. |
| A02–A08 | Accepted M5a: mixed-shape discovery/reconciliation, explicit adoption/keyless rebuild, schema v5 verification events/enrichment, restore ownership and operating guide; full PG16/17/18 regression gates pass | Rebuild loses history/private facts; legacy reader diagnostics and writable scratch limits are documented. Retention, service hardening and off-host recovery remain separate. |
| B02–B06 | Accepted M5b: schema v8 protection, exact retention plans, confirmed marker-first deletion/recovery, local older-snapshot warnings and native destructive/race/crash drill (§40) | Rebuild loses lifecycle/rollback history; local ledger is not independent replay protection. Production hardening remains H/V. |
| Phase S | Same-scope acquisition is tested mid-dump **and** by two real CLI processes | Opening a store removes nothing; work owns `activity.lock` shared, only `backup create` cleans it exclusively. Continuously busy stores may defer abandoned-work cleanup. |
| Review corrections R | Consumption-bound signed/encrypted reads; process-group cleanup; overflow refusal; quoted native role exports; restore checks/preparation before mutations | Captured catalog/TOC output above 64 KiB is refused; service isolation remains H02. |
| Operations/service | H03 fixture .deb and opt-in dedicated-user systemd backup timer accepted on Debian 13/Ubuntu 24.04 userspaces (§48) | Shared host-kernel container evidence; H04 CI/references and H05 readability have local acceptance (§49–§50). Production content/compatibility/release gates remain; API/UI are later. |
| H01 policy / H02 fixture hardening | Configuration/reports, native auth/recovery, custody, filesystem/resources, snapshot reads and cancellation/process ownership (§42–§47) accepted on fixtures | Fixture hardening and H03 service/cgroup/package acceptance are recorded (§47–§48). Production command/plan compatibility remains a release gate; production operations stay gated until V03. |

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
| Inventory | `rusqlite` = 0.41.1, defaults disabled, bundled SQLite 3.54.1 (`libsqlite3-sys` 0.39.1) | DELETE journal, FULL synchronous writes, explicit timeout. |
| Encryption | `age` = 0.11.5, `age-core` = 0.11.0, `hpke` = 0.12.0 alloc-only, existing custom hybrid recipient | Security maintenance pair; frozen v1 compatibility verified in §53. |
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

Implemented commands are defined in [cli.rs](crates/backupctl/src/cli.rs): `config check`, `key generate|publish|status`, `profile list|validate`, `backup create|list|inspect|verify|protect|unprotect`, `restore plan|run`, `job list|inspect`, and `inventory check|list|verification|reconcile|adopt|rebuild|recover`. B03/B04 add `backup prune|delete` previews and digest-confirmed `run`; B05 adds `restore plan --acknowledge-older-snapshot`. Machine output supports legacy bare `json` and the opt-in `json-v1` envelope; human mode is default. Current runtime result convention is success/failure; Clap has its own usage handling. The older proposed 0–6 error taxonomy is not shipped.

Preserve existing command syntax, serialized keys, successful output meaning and asserted refusal text during C1. Correct unsafe behavior in S tasks; improve diagnostics in explicit A/H tasks with matching test/document changes. Avoid raw TOML parser snippets, which may reproduce secret input.

New surface baseline, to be implemented in the named tasks:

```text
backupctl --config CONFIG job list
backupctl --config CONFIG job inspect JOB_UUID
backupctl --config CONFIG inventory check
backupctl --config CONFIG inventory reconcile
backupctl --config CONFIG inventory adopt BACKUP_UUID --source-fingerprint FINGERPRINT
backupctl --config CONFIG inventory rebuild --source-fingerprint FINGERPRINT --dry-run
backupctl --config CONFIG inventory rebuild --source-fingerprint FINGERPRINT --prepare-rebuild
backupctl --config CONFIG inventory rebuild --source-fingerprint FINGERPRINT --confirm-rebuild --plan-id PLAN_UUID
backupctl --config CONFIG backup protect BACKUP_UUID
backupctl --config CONFIG backup unprotect BACKUP_UUID
backupctl --config CONFIG backup prune --keep-last N [--profile PROFILE_NAME]
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

Legacy fixture configuration is one `Source`, one local `Storage`, optional encryption/signing blocks, `export_globals`, timeout and `[[profile]]` entries. Examples under [config](config) retain that schema; versioned deployment config is a separate closed parser. Do not implement the earlier illustrative profile fields such as `schedule`, `retention`, compression or alternate source references as if they already existed.

No key blocks means plaintext development output; encryption only means unsigned age development output; encryption plus signing secret means signed v1 writer. Signing without a signing secret selects the DR reader shape. Normal store constructors eagerly load configured identity/key pairs; A03 discovery, adoption and rebuild use the separate keyless inventory path.

The versioned parser describes H01's local-only connection security and explicit access/read-only custody; actual production operations remain gated until V03. Configuration reload affects only new jobs. Reject unknown fields and incompatible combinations before database or store mutation. Profiles are snapped per job; reusing a name groups retention under the existing name fingerprint, so changed selection must be visible to operators. A content-hash scope redesign is a separate decision.

H01 is defined in [h01-production-policy.md](docs/development/h01-production-policy.md): first-release connections remain local-only; remote TLS is deferred. `config_version=1` explicitly separates fixture/production mode, access custody and read-only snapshots. Existing unversioned examples/parser remain fixture-only. The [H02 first increment](docs/development/h02-config-access-reports.md) implements structural checks, capability gates, limited writable keyless fixture commands and `--output json-v1`; native authentication/recovery, key custody/bootstrap, filesystem/resources, true snapshot reads and signal/process ownership are implemented by later fixture increments (§43–§47). Fixture hardening is closed. H03 owns service/cgroup containment; production command/plan compatibility must be resolved before V03 enablement.

The initial CLI release can remain local-only. Remote access, separate cross-server target connections, data-only restore and writer-without-identity operation are explicit extensions, not incidental outcomes of removing the fixture-name check.

## 16. Inventory schema and migration rules

Implemented schema v8: `meta` estate binding, `artifact` discovery/lifecycle/protection fields, `job` rows and operation/target associations, `audit_event`, provisional artifact provenance, verification observations, exact deletion job/dependency/progress evidence and the per-source/signer completion high-water ledger. Exact existing SQL is [schema.rs](crates/backup-inventory/src/schema.rs). Preserve dense migration history: fresh initialization runs the same steps an older database upgrades through. Never edit an already released migration to express a future schema.

Use `journal_mode=DELETE`, `synchronous=FULL`, current explicit 2000 ms busy timeout; read back required pragmas. Read paths use `SQLITE_OPEN_READ_ONLY`, create/migrate nothing and do not sweep. Reject unknown/newer schema and foreign estate. Do not use `immutable=1` on a live store. Run `integrity_check`; a database answering a query can still be corrupt.

Every column is an opaque ID, fingerprint, digest, bounded algorithm label, byte count, UTC timestamp, state, flag or safe event code. No source/target names, hosts, ports, profile names, resolved selection, SQL, credentials or arbitrary error chains. Nullable profile/completion means unknown. Keyless rebuild cannot invent values from UUID order, directory modification time or untrusted public header fields.

Artifact schema changes, plan formats and wire artifact v1 version independently. Job operation/target associations, digest-bound verification observations, missing/deleting/deleted states, protection and the local ledger have real writers through B05. Add future fields only with the task that writes them. Use one transaction for each state/event pair and for each related protection/verification change.

Current artifact registration merges matching rows while preserving protection, observations and tombstones; a keyless refresh cannot erase authenticated profile/time facts already known for the same bytes. If bytes changed, invalidate dependent observations and report conflict instead of carrying old verification forward.

Rebuild restores discovery, not lost audit/protection/verification/rollback history. Stage a replacement inventory, validate it, take exclusive maintenance ownership, preserve a recoverable copy of the old database, then replace durably. No replacement while live jobs use it. Document the restart/copy and lost-history consequences.

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
| 8 | C1 — clean code and human readability | ✅ Done | Accepted 2026-11-02; module decisions, remaining complexity and final gates are recorded in §34.4. |
| 9 | A — complete M5a inventory/jobs/recovery | ✅ Done | A01–A08 accepted 2026-11-13, including separate JobLock hardening; evidence in §34.7. |
| 10 | B — M5b retention/protection/deletion | ✅ Done | B01–B06 accepted; eight PG16/17/18 matrices and destructive/race/crash gates pass (§40). |
| 11 | H — M6 hardened CLI/systemd/Debian | ✅ Fixture scope | H01–H05 fixture foundations accepted (§41–§50); H05 committed 046c22e. Production compatibility remains a V gate. |
| 12 | V — CLI production validation/release | 🔄 Current | V01 readiness validation/findings in §51; no production enablement. V02/V03 remain. |
| 13 | P — M7 API/asynchronous service | ⬜ Todo | Requires hardened core and explicit decisions. |
| 14 | U — M8 API-backed UI | ⬜ Todo | Requires stable API. |
| 15 | F — platform validation/release | ⬜ Todo | Original M9 full-platform track. |

### ➡️ Current: #12 - V — V01 production readiness validation
### ⏭️ Next: V01 blocker resolution, then V02 measurements and V03 release decision

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

1. **A01 — job/inventory read surface ✅.** `job list`, `job inspect` and `inventory check` use a read-only inventory adapter and application service. They never create, migrate, sweep, load keys or contact PostgreSQL. Jobs sort by timestamp/ID; operation is explicitly unknown because schema v2 does not record it. Structural and job-row checks distinguish missing jobs from damaged data. JSON/error contracts and examples are in [m5a-inventory.md](docs/development/m5a-inventory.md). Five full-CLI tests, all 190 workspace tests, strict Clippy, formatting and all six PG16/17/18 matrices pass; see §34.7.
2. **A02 — unified discovery and reconciliation ✅.** Scan IDs/shapes with bounded validated filenames and report registered/unregistered/missing/incomplete/conflicting entries. Discovery does not authenticate descriptive public claims. Normal reads do not auto-adopt. Writable reconcile updates observed missing/conflict state with audit while preserving protection/verification/tombstones and known private facts. Refuse malformed/symlink entries per entry with understandable diagnostics rather than letting one development shape abort every mixed-store list. See §34.7 for evidence and limits.
3. **A03 — explicit adoption and keyless rebuild ✅.** Add discovery-only construction that does not load identity/signing secrets. `inventory adopt ID` records bounded public discovery facts and estate provenance, with trust level distinct from authenticated verification. Public v1 contains no source fingerprint: bind a keyless rebuild to an explicit expected estate, mark it provisional/unconfirmed where necessary, and refuse foreign source when private authentication later supplies the actual fingerprint. Never claim signature proves estate/profile/time. Rebuild preview reports IDs/shapes/unknowns/lost facts; confirmed execution follows §16's staged replacement and exclusive maintenance rules. Preserve old inventory recoverably.
4. **A04 — authenticated enrichment and verification events ✅.** Record successful/failed verification with level, UTC time, artifact ID and ciphertext digests; no secret-bearing diagnostic text. Authenticated manifest enrichment supplies profile/time only after binding checks. Checksum and signature observations remain distinct from archive validation. Keyless refresh preserves known facts for unchanged bytes; changed bytes invalidate observations and produce conflict. Read-only verification reports that no event was persisted.
5. **A05 — restore jobs and resource associations ✅.** Add operation kind/target fingerprint/artifact-use associations through the next migration. Acquire target/use/activity locks before side effects and retain through native restore/validation. Record running/complete/failure/interrupted and safe events; partial failure leaves target for repair. Do not automatically sweep a live backup or a finished restore. Shared use of an artifact blocks future deletion. Add no worker pool/cancel command.
6. **A06 — recovery and integrity drill ✅.** Implement `tests/m5a_docker_smoke.sh` on PG16/17/18: kill backup/restore mid-operation, duplicate startup, unrelated read, same-scope restart, publication-before-registration failure, db loss/rebuild, wrong-estate refusal, mixed shapes, malformed headers, schema v1->v2->current and newer-schema refusal, populated-db corruption and single-file read-only copy. Tests run through actual CLI initialization. Completed 2026-11-09, including six rebuild filesystem crash boundaries per major; see §34.7 and the development contract for evidence and limits.
7. **A07 — metadata leakage and audit checks ✅.** Grep raw SQLite files/journals and captured machine/human output for fixture database/host/profile/scope, fake credentials and generated seeds. Exercise normal writes, failed writes, enrich/rebuild and restore. Demonstrate the sentinel is detectable in a positive control. Confirm state/event transaction rollback and no event claiming work that failed before it started. Completed 2026-11-13; authenticated detail reports retain their documented metadata while keyless reports omit it and all captured reports omit credentials/private seeds. See §34.7 and the A07 development contract.
8. **A08 — close M5a ✅.** Operator guide with read/write/keyless/DR modes, unknown facts, adoption/rebuild/lost-history rules and interrupted-state behavior. Run all regressions and ADR 0003 M5a gates. Update phase statuses and threat review. Completed 2026-11-13 with the separate JobLock fix and full regression gates; see §34.7, the [operating guide](docs/development/m5a-operations.md) and [acceptance map](docs/development/m5a-inventory.md#a08-operating-guide-and-acceptance-map). No protect/delete/prune command is enabled.

Migration ordering: add only A04/A05 fields when their writers land; preserve old schema steps and use a new numbered step for each durable change. Fresh/upgrade/read-only paths must be tested against real older schema files, not just a database hand-built to match the new schema.

### B — M5b protection, retention and deletion

Prerequisite: M5a accepted. Owners: pure retention policy in domain, application planning/execution, inventory lifecycle, local marker-first deletion, CLI. This is the first irreversible feature phase; review all invariants against a real inventory before enabling execution.

1. **B01 — policy and plan contract ✅.** Start with per-(source fingerprint, profile fingerprint) `keep_last N`, with N >= 1. Defer age limits/buckets until this passes. Known valid means current complete files, authenticated v1 bindings and a matching archive-validation or stronger validated-restore observation. This is the conservative B01 policy baseline introduced by this revision; record it with examples before enabling retention, because ADR 0003 did not freeze a minimum verification level. Unknown profile/time, missing/conflict/development/unregistered/deleted entries never count as valid or candidates. Refuse prune when the requested scope cannot be established. Define deterministic completion-time ordering and tie-break only equal times with ID; UUID alone never means newer. Completed 2026-11-13 in [m5b-retention.md](docs/development/m5b-retention.md): scoped quota/exclusions, unknown protection, exact saved-plan bytes/digest/expiry, reports/errors, acquisition/recovery rules and worked cases. This is a specification, not implemented deletion.
2. **B02 — protection and preservation ✅.** Add nullable protection flag/event via migration, exposing unknown/unprotected/protected as defined by B01; explicit protect/unprotect establishes knowledge and changes only inventory. Update registration/enrichment merge logic first so refresh cannot erase protection. A rebuilt index has lost flags and must state that fact; it does not silently inherit a safe-to-delete assumption. Last valid copy, active/use-held artifacts and job dependencies are exclusions even if unprotected. Completed 2026-11-13: schema v6, keyless commands, atomic/idempotent events and preservation/refusal tests; all 227 workspace tests and seven PG16/17/18 matrices pass. See §36.
3. **B03 — saved deletion plans ✅.** Persist versioned immutable plans under plans/: operation, estate/scope, sorted exact ID set, ciphertext digests, relevant policy/inventory facts, created/expiry times and canonical digest. Use the existing 15-minute expiry as baseline. `delete ID` shares the same planner and future executor with a singleton set. Preview only prints/saves intent, never modifies artifacts. Completed 2026-11-13: exact authenticated previews, private bounded plans and stale checks; all 243 workspace tests and seven PG16/17/18 matrices pass. See §37.
4. **B04 — confirmed execution ✅.** Load plan, require exact digest/estate/expiry, take maintenance/artifact exclusion locks in recorded order, and revalidate all candidates/retained backups. If bytes, protection, validity, active usage or policy facts changed, refuse the whole unstarted plan and require a new preview; do not recompute a broader set. Remove marker/sync before deleting contents. Persist deleting/deleted state and each completed action; errors expose exact completed and remaining IDs. Tombstones/events remain. Completed 2026-11-13: schema v7, durable intent/partial receipts, keyless started-only recovery and lifecycle-aware readers; acceptance in §38.
5. **B05 — local rollback warning ✅.** Maintain per-(source fingerprint, signer ID) authenticated completion high-water mark. Older restore plan/list produces a clear older-snapshot warning; explicit acknowledgement is bound into a new restore plan version without changing v1. This detects accidents when ledger survives, not an attacker who rewrites both files and inventory. Unknown authenticated time cannot advance the mark. Completed 2026-11-14: schema v8 and signed restore-plan v2, 266 workspace tests and all seven PG16/17/18 matrices pass; see §39.
6. **B06 — retention drill and close ✅.** Completed 2026-11-14 in `tests/m5b_retention_drill.sh`: exact prune/delete sets, exclusions, unknown rebuilt history, preserved protection, removed/corrupted witnesses, competing deleters, both restore/delete contention directions and started-only recovery/tombstones pass. Eight syscall crash points per major (24 total), all 266 workspace tests and all eight PG16/17/18 native matrices pass; guide/threat review and acceptance are in §40. Phase B is closed; H01 is next.

Deletion is non-atomic across several directories. Report partial execution honestly; never claim transaction rollback can resurrect removed files. Keep maintenance checks simple and testable before adding age/bucket retention or break-glass overrides.

### H — M6 harden CLI and deploy safely

Prerequisites: B acceptance. Implement in reviewable increments; do not enable production data merely because a package installs.

1. **H01 — configuration/release policy ✅ Defined.** Completed 2026-11-15 in [h01-production-policy.md](docs/development/h01-production-policy.md): future versioned config/modes, local socket peer or loopback SCRAM/passfile, maintenance DB for lost-source recovery, fresh same-endpoint/same-major targets, explicit custody/read-only roles, versioned JSON and stable exits. Remote TLS, independent targets, data-only/overwrite and writer-without-identity remain excluded. Legacy fixtures/frozen bytes and V03 production gate stay intact; definition-only evidence is in §41.
2. **H02 — configuration/access/report and process/filesystem hardening.** Fixture-hardening acceptance is recorded in §47; production writer/command compatibility remains an explicit release gate. The implementation requirements below remain authoritative before any production writer is enabled. First increment implemented 2026-11-15 (§42): separate legacy/versioned configuration, capability checks and safe versioned reports while production operations remain disabled. Native auth/maintenance recovery is implemented in §43. Validated key bootstrap/custody is implemented in §44. Continue with filesystem/resource/service hardening and true snapshot reads in reviewable increments. Record new production plan bytes/context and resource limits before adding their writers. Preserve R02’s delivered process-group timeout/exit cleanup; add explicit cancellation only with its real caller. Revalidate wrappers retaining pipes after their parent exits or times out under service permissions. Verify local auth, lost-source maintenance DB, tool provenance/matching versions, permission/ownership/no-follow paths, disk/scratch bounds and stable safe errors. Resolve key-command partial writes by validation before mutation or a documented transactional creation path. Validate true read-only discovery/verification and explicitly configured private scratch where decryption needs writes. Use H01's acceptance map; do not lift the fixture guard during H02.
3. **H03 — systemd/package ✅ Fixture acceptance.** Implemented and tested on target userspaces in §48; no production enablement or independent guest-kernel certification. The following requirements describe the delivered scope: build .deb targets/units under deploy/, install dedicated user and mode-controlled paths, wire profile invocation and chosen timer semantics, preserve data/keys on upgrade/removal. Verify process locks and SQLite migration under actual service permissions/sandbox. Test package reinstall/purge policy.
4. **H04 — CI and operating guides ✅ Local acceptance.** Delivered in §49 with unrun hosted jobs stated separately. The following requirements describe the implemented scope: add pinned fast/matrix/package workflows; document installation, matching clients, credentials, key backup, inventory-copy consistency, recovery, stale alerts and isolated restore drills. A live SQLite database copy must use a consistent backup/export or quiescent maintenance ownership; DELETE journal does not make arbitrary concurrent raw copying safe.
5. **H05 — clean-code checkpoint ✅ Local acceptance.** Bounded A/B/H review and comment corrections accepted in §50; no justified structural refactor or behavior change. The following requirements define the completed scope: review against C1 rules, remove redundant adapters/branches where justified and update ownership comments. Keep fixes and refactors distinguishable. Run affected regressions and package lifecycle gates; no global rewrite.

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
| C02-5 | Implemented and locally verified 2026-10-25: `scratch.rs` owns `decrypt_to_scratch`, `authenticated_manifest`, private `DigestReader`, `LocalPlaintext`'s Drop/PlaintextView impls and the direct manifest regression. `LocalPlaintext` and all private fields remain at the crate root. | 185 workspace tests, strict Clippy, format and diff checks pass; R01 replacements and real-CLI scratch concurrency pass. Moved blocks are byte-identical except two method visibility markers and boundary whitespace. Native matrices remain unverified here; prerequisites below. |
| C02-6 | Inspect signed/development publication and reading, plan save/load, and `record_published`. Extract cohesive inherent bodies where useful; trait methods can remain at the root. Keep marker/fsync/rename/signature/decrypt order explicit and inventory bridge below application. | Signed/development store tests, plan expiry tests and M1–M4b matrices. Do not duplicate the signed binding reader, or add a wrapper per method solely to match a diagram. |
| C02-7 | Implemented and verified 2026-11-02: moved the backup command family intact to `backupctl/src/backup.rs`; smaller families remain in `main.rs`. | 185 workspace tests, six PostgreSQL 16–18 matrices, strict Clippy, format and diff checks pass; 11 CLI help/refusal cases match byte-for-byte. |
| C03 | Inspected 2026-11-02: application ports/use cases/Opened and inventory open/recovery/SQL operations. No simplification justified a source change; see the inspection below. | Restore R05 order remains visible; prior C02-7 gates include composed-path, inventory migration and recovery tests. |
| C04 | Reviewed and accepted 2026-11-02: corrected two stale instructions, audited fixtures, exports and dependency direction; see the evidence below. | Fast gates, 82 paired CLI cases plus three paired creations, and all six PostgreSQL 16–18 matrices pass. |

**C02-5 boundary and verification (2026-10-25).** Scratch creation, consumption binding, manifest decryption and view cleanup now share one module, with no delegation wrappers. Only `decrypt_to_scratch` and `authenticated_manifest` gained `pub(crate)`: the root's five plaintext-producing trait methods call the first, and `open_signed` calls the second. `LocalPlaintext`'s definition, private fields and field order are unchanged; cleanup still runs in Drop before the activity claim is released. The wrong-key/publication tests remain with their composed store fixtures rather than widening or duplicating test helpers. No caller, error string, artifact/plan encoding, key rule or dependency changed. `lib.rs` is 1531 lines (from 1686); `scratch.rs` is 182, including the relocated manifest regression.

Checks on the final source: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked --offline` (185 passed, 0 failed), and `git diff --check` pass. The initial baseline `backup-local --lib` had 17 passing tests; all 48 local-crate tests pass after extraction. Docker is absent (`docker: command not found`), and neither stock rage nor rage-keygen is installed, so all six native PG16/17/18 matrices and the historical CLI comparison battery were not rerun. C1 is not accepted; its native matrix gates remain pending. No commit/push.

**C02-6 inspection (2026-10-25; no source edits).** Traced signed/development publication and reading, plan persistence, their application callers and composed store tests. The smallest justified next extraction is the existing inherent `record_published` into `backup-local/src/inventory.rs`: one caller (`publish_signed`), one required `pub(crate)` marker, no delegate, no public type/field movement. Move its exclusive `ArtifactRow`/`Estate`/`Shape`/`State` and `INVENTORY_FILE` imports with it; `profile_fingerprint` stays imported at the root for `begin_job`. Keep registration after the completion marker and directory sync; job completion stays in the application after publication. Existing registration/privacy and audit-trail tests in `signed_write_path.rs` cover that integration and should remain there. Compare the moved body and run local/workspace gates; native matrices remain required where prerequisites are available.

**C02-6 extraction (2026-11-02).** Moved `record_published` and its exclusive imports to `inventory.rs`, with one `pub(crate)` visibility change and no wrapper. The method body matches HEAD exactly; rustfmt reflowed its signature. The call remains after marker and directory sync. Formatting and strict offline Clippy passed; 183 workspace tests passed with two excluded, including all eight signed-write integration tests. Two full-suite attempts failed in separate existing replacement tests because the safe error `artifact is not a readable age stream` did not match their assertions. The full gate remains open. Docker and stock rage/rage-keygen are unavailable, so native matrices remain pending. No commit or push.

**C02-6 verification follow-up (2026-11-02).** Random age header padding can cause the ciphertext size bound to truncate a replacement during header parsing, before the two previously expected refusal points. Both replacement tests now also accept the specific unreadable-age-stream error while continuing to require refusal and scratch cleanup. The full offline workspace suite passes (185 tests), as do formatting, strict offline Clippy and diff checks. Native matrices remain pending; C1 is not accepted.

**C02-6 native gates (2026-11-02).** With Docker 29.1.3, stock rage 0.12.1 and PostgreSQL 16/17/18 images, M1, M2, M3, M4a, M4b and the M4a key drill each exited 0 and reported all three majors. M4b first failed because its PostgreSQL 16 source could not be reached on IPv4; a separate diagnostic recorded an IPv4 port bind conflict, and the unmodified matrix passed on retry. Logs are under `/tmp/parsbackup-native-*.log` and are ephemeral. The native gates cover this working tree; C1 remains open for C02-7, C03 and C04.

**C02-7 (2026-11-02).** The 108 nonblank lines of the backup dispatch moved intact to `backupctl/src/backup.rs`, with one call from `main.rs`; the existing `open_store`, JSON builders and reports are reused. Config, key, profile and restore remain at the entry point because their smaller arms do not justify added module boundaries. The recovery pass still occurs only for non-dry-run create, before service use. All 185 workspace tests, strict offline Clippy, formatting and diff checks pass. Eleven CLI help/refusal invocations match their pre-move stdout, stderr and exit codes byte-for-byte. All six PostgreSQL 16/17/18 matrices pass; ephemeral logs are `/tmp/parsbackup-c027-*.log`. The historical 67-invocation battery was not rerun. C1 remains open for C03 and C04.

**C03 inspection (2026-11-02; no source edits).** `Opened` already shares restore facts and plaintext access while retaining distinct signed and development trust rules. Archive verification repeats inspection and digest calculation, but signed manifests require a TOC digest and use distinct refusals; development manifests can omit it, so a shared helper would add indirection for a few lines. Restore plan and run repeat role checks with deliberately different timing and refusal text; run must decrypt and bind payload before mutations and recheck the target. Inventory's three opens intentionally differ in creation, migration and estate binding; recovery sweeps only under the maintenance claim, and each conditional job transition remains transactional. `LocalJob` is the necessary bridge between the application trait and inventory-owned guard. Repeated timeout conversions and configuration validation do not justify wrappers or weakening public service boundaries. No source changes or new tests were warranted; the prior C02-7 full suite, composed-path tests, migration tests and matrices cover the unchanged source. The separate JobLock no-follow/mode fix remains due before A acceptance.

**C04 review and C1 acceptance (2026-11-02).** Corrected the store module's claim that recovery performs all deletion (stage/scratch owners clean up on drop) and the M4b script's stock-rage installation hint. Strict Clippy found no unused private code; public exports remain in place and runtime dependency manifests/lockfile match the post-R baseline. Domain, local and integration fixtures serve different crate/test boundaries; no consolidation warranted additional coupling. Ownership: application ports and use-case sequencing remain in `backup-application`; store opening/recovery, keys, sinks, scratch and the inventory bridge have named `backup-local` modules; SQL and locks remain in `backup-inventory`; CLI backup dispatch is in `backupctl/src/backup.rs` and reporting remains in `report.rs`. Remaining complexity: the local store trait implementation and application use cases remain large; signed/development trust rules, restore ordering and inventory open modes are intentionally explicit, and `LocalJob` is the required orphan-rule bridge.

Final checks: 185 workspace tests, strict offline Clippy, format, shell syntax and diff checks pass; all six PostgreSQL 16/17/18 matrices exit 0, including process concurrency and deterministic crypto vectors in the workspace suite. A reconstructed comparison (`/tmp/parsbackup-c04-compare.py`, ephemeral) checked 82 paired CLI help, human/JSON, success, refusal and portable-plan cases plus three paired successful creations across plaintext, encrypted and signed stores against commit `2f0ad60`; generated plan IDs/times/digests and created-artifact IDs/times/digests/sizes were normalized. Expected success/refusal status was checked. The original 67-case harness was unavailable; this is new comparison evidence, not a rerun of that exact historical battery. Matrix logs are `/tmp/parsbackup-c04-*.log` and ephemeral. C1 is accepted; the separate JobLock no-follow/mode hardening remains required before A acceptance.

`load_artifact` is another viable inherent extraction into `development.rs`, consumed by `list`/`inspect`/`open`; keep `refuse_split_manifest` shared with the signed reader. The compact `save_plan`/`load_plan` pair and full publication/authentication trait methods should stay together for now: a separate file for each would need delegation without a demonstrated navigation benefit. Signed-only helpers (`key_ids`, `seal_to_file`, `write_private_file`, `read_header`) should move with a cohesive signed boundary rather than create helper-only hopping while their main operations stay at the root. Preserve the shared scratch reader and private stage/view guards. C02-6 inspection, the inventory extraction and its gates are complete; C1 is accepted below.

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

**A01 evidence (2026-11-02).** The contract was recorded before implementation. Added a read-only bound inventory open, application reader/service, local adapter and CLI reports; no schema migration or runtime dependency was added. A direct `rusqlite` dev dependency reuses the workspace version for real-SQLite CLI fixtures. Tests cover absent/damaged databases versus absent jobs, copied read-only access without keys or server, orphan rows left unswept, deterministic ordering, NULL backup/operation, schema v1 without migration, newer schema refusal, malformed/foreign job fingerprints and an index corruption detected by SQLite integrity check. All 190 workspace tests and strict offline Clippy/format/diff checks pass. M1, M2, M3, M4a, M4b and the key drill pass on PostgreSQL 16/17/18 on the final source; one M2 source run initially could not start its target on the shared fixture port and passed on retry. Logs `/tmp/parsbackup-a01-{final,retry}-*.log` are ephemeral. Schema v2 does not record operation, and `inventory check` verifies SQLite structure rather than artifact authenticity or estate provenance.

**A02 inspection (2026-11-03; no source edits).** Existing `list` and `list_signed` are shape-specific: they skip incomplete/non-UUID entries, signed listing groups every non-public shape as unsigned, and malformed headers can abort the whole listing. Public headers are untrusted until the signed reader verifies them; development manifests expose different data. A02 needs a per-entry scanner with bounded parsing, canonical IDs, non-following file checks, explicit incomplete/invalid/conflict observations, and a complete-scan rule: an I/O failure must not be converted into a missing row. It must not call an existing authenticated reader just to discover a shape or persist untrusted profile/time facts. Existing `State` only accepts `registered`; `INSERT OR REPLACE` in `artifact::write` can erase existing fields and must not be used to refresh discovery. Artifact read methods parse rows but do not call `ArtifactRow::validate`; validate bound-estate/row facts before acting on them. Add narrowly scoped missing/conflict states and safe audit actions with conditional state/event transactions; no unregistered artifact is adopted. Existing schema uses unconstrained state/action text, so verify whether those changes can preserve v2 rather than adding an unnecessary migration.

For concurrency, publication holds a shared activity claim through marker creation and inventory registration. A writable reconcile must establish a safe snapshot against live publication (the existing nonblocking exclusive maintenance claim is a candidate), retain ownership through its state/event updates and fail or report busy rather than infer missing from a partial scan. Confirm the lock's exact scope and protect against non-cooperating filesystem replacement: current metadata checks followed by `File::open` do not alone close symlink races. Keep paths and diagnostics bounded and key-free; do not add deletion or keyless adoption/rebuild, which belong to later tasks. Before coding, extend [m5a-inventory.md](docs/development/m5a-inventory.md) with explicit A02 status/JSON/error/idempotence and concurrency rules. Tests should cover all three shapes in one root, invalid/symlink/oversized entries beside good ones, missing/incomplete/unregistered/conflict, changed header/bytes without trusted-metadata loss, audit atomicity and repeat runs, I/O failure, and publication concurrency. Existing signed-store, inventory and real-CLI concurrency fixtures provide starting points. No runtime checks rerun for this inspection.

**A02 implementation (2026-11-03).** The contract and its limitations are recorded in [m5a-inventory.md](docs/development/m5a-inventory.md). `inventory list` reports mixed shapes without writes; explicit `inventory reconcile` holds an exclusive activity claim, validates a complete scan and atomically records state changes and audit events without replacing existing facts or adopting files. It rejects symlinked inventory and artifact components, detects alias and malformed entries independently, and refuses unsafe special files. Existing schema-v2 text columns hold the new words without migration; older software may refuse those words. The scanner requires Linux procfs; observations are not signature verification, and the legacy `backup list` remains shape-specific. Focused tests cover mixed shapes, no-follow and incomplete entries, changed content, audit rollback and idempotence, no migration, read-only access, and real-process publication contention. No runtime dependency was added. All 195 workspace tests, strict offline Clippy, formatting and diff checks pass; all six M1/M2/M3/M4a/M4b/key-drill matrices pass on PostgreSQL 16/17/18. An initial M4b run stopped because temporary `rage` was absent; restoring version 0.12.1 from the local Cargo cache resolved it. Logs under `/tmp/parsbackup-a02-confirm-*` are ephemeral.

**A03 started (2026-11-03).** Filesystem observation can now run without opening an inventory, and `inventory rebuild --source-fingerprint ... --dry-run` reports mixed shapes, unconfirmed provenance, unknown facts and lost history without writes, keys or PostgreSQL. The preview remains usable when the database is missing or damaged. The write side remains outstanding: explicit adoption, persistent provisional provenance, foreign-source refusal after authentication, and staged validated durable replacement preserving a recoverable old index. Those require focused crash, concurrency and estate tests before A03 is complete. Preserve delivered backup rows and complete the separate JobLock no-follow/mode hardening before A acceptance.

**A03 implementation (2026-11-03).** Added schema v3 provisional-artifact records, atomic adoption and audit, keyless saved rebuild plans bound to artifact and inventory bytes, and staged validated replacement with a recoverable old database. Signed reads check authenticated source against provisional estate, and backup jobs hold activity ownership for their entire lifecycle to prevent inventory replacement before staging or after publication. Tests cover missing/corrupt inventory, keyless reconstruction, stale plans, wrong estate, audit rollback, old inventory recovery, v2 migration and a live pre-staging job. All 201 workspace tests, strict offline Clippy, formatting and diff checks pass; all six M1/M2/M3/M4a/M4b/key-drill matrices pass on PostgreSQL 16/17/18. One earlier M1 run reported a fixture row-count mismatch after an interrupted run; the final clean rerun passed. A corrupted index makes signed authenticated reads fail closed until repaired; a missing index still permits reads. See the [A03 contract](docs/development/m5a-inventory.md#a03-adoption-and-rebuild) for limitations. Crash injection at each filesystem step remains part of A06, not this evidence.

**Next task: A04.** Add authenticated enrichment and verification events bound to artifact digests. Complete the separate JobLock no-follow/mode hardening before A acceptance.

**A04 implementation (2026-11-05).** Schema v4 adds digest-bound verification history. Signed checksum/archive verification enriches unknown profile/time only after authenticated bindings match; signature-only verification does not enrich. Explicit read-only verification avoids recording. Event reads expose whether a later failure or reconciliation invalidated an observation; `current` remains an inventory observation rather than a fresh filesystem check. Full workspace tests pass (205), as do strict offline Clippy, formatting, shell syntax and diff checks. All six PostgreSQL 16/17/18 matrices pass. The first M4b run reported an accepted tampered signature; its test replaced a random byte with a fixed value, which can leave it unchanged. Changed the test to flip a bit, and the full M4b matrix then passed. True read-only-mount verification remains H02; `--read-only` suppresses inventory writes but still uses the existing store/lock/scratch paths.

**Next task: A05.** Implement restore jobs and resource associations, then complete A06–A08 and the separate JobLock hardening before M5a acceptance. The production CLI still requires phases B, H and V; the API-backed UI follows a stable M7 API. UI/UX research and mockups can proceed earlier.

**A05 implementation (2026-11-05).** Restore jobs take activity, exclusive target and shared artifact-use claims before opening artifacts, record operation/target association in schema v5, and hold claims through completion or failure. Native children inherit those claims, preventing a killed parent from exposing a still-running restore. Tests cover concurrent ownership, symlink/mode refusal, a live child after parent death, interrupted recovery, partial failure, completion-recording failure, missing inventory and v4 migration. All 216 workspace tests, strict offline Clippy, formatting and diff checks pass; all six PostgreSQL 16/17/18 matrices pass. The first M2 run exposed a cross-instance DR mismatch: the restore connection identified the target while the index was bound to the original source. The final code uses the existing inventory binding for the job and records the target separately; the rerun passed. Restore requires an existing inventory rather than guessing an estate from the target connection. Claims coordinate one storage root, not different roots or external clients. No automatic target cleanup or retry is added.

**Next task: A06.** Implement the PostgreSQL recovery and integrity drill, then complete A07–A08 and the separately tracked JobLock hardening before M5a acceptance. The production CLI still requires B, H and V; the API-backed UI follows a stable M7 API.

**A06 completed (2026-11-09).** Added `tests/m5a_docker_smoke.sh` using real matching PostgreSQL 16/17/18 tools and actual CLI startup. The final script passes all three majors: streaming-dump SIGKILL, same-scope duplicate refusal/restart and unrelated reads; native-restore SIGKILL with surviving child claims, interruption recovery, retained partial target and validated subsequent restore; publication-before-registration failure/adoption; mixed shapes, malformed headers, estate/stale-plan/newer-schema refusals; keyless missing/corrupt-index rebuild with honest unknowns and history loss; populated v1/v2 migrations; 512-byte index corruption detected despite working table counts; and exact job preservation in a single-file non-writable copy with absent keys/tools/artifacts. Baseline syscall tracing plus delayed successful calls tests stage creation, staged-file sync, old-index link, directory sync after linking, replacement rename and final directory sync: 18 process-crash checkpoints total, preserving the authoritative/previous index and allowing fresh explicit rebuilds. No production failpoint or runtime change was needed. Process crashes do not simulate power loss or faulty storage.

All 216 workspace tests, strict offline Clippy, formatting, shell/embedded-Python syntax and diff checks pass. Final native evidence is `/tmp/parsbackup-a06-verified-m5a.log`; workspace and Clippy logs are `/tmp/parsbackup-a06-{workspace,clippy}.log`, all ephemeral. Earlier development runs exposed readiness against PostgreSQL's temporary initialization server, redundant recipient publication, and an environment-based test pause defeated by deliberate environment clearing; the final fixtures use TCP readiness, one key-generation command and filesystem pause markers. M1–M4b/key-drill matrices were not repeated for this test-only increment; their A05 results remain historical evidence, with full regression acceptance due at A08.

**Next task: A07.** Check metadata leakage, audit transaction rollback and honest event timing across normal/failed writes, enrichment, rebuild and restore. A08 and separate JobLock hardening remain before M5a acceptance; production CLI/API/UI release boundaries are unchanged.

**A07 completed (2026-11-13).** Extended the existing M5a PG16/17/18 drill with literal-byte scans of raw inventory databases, retained/staged/rebuilt copies, read-only copies and live rollback journals. Real CLI writes pause after journal sync during normal/failed backup startup, restore startup, authenticated enrichment and staged rebuild. Scans reject fixture database/host/private profile/object scope/target, fake password-file credentials, generated identity/signing seeds as hex/binary, and each signing-seed component. A deliberately populated SQLite positive-control copy detects every sentinel; poisoned journal byte buffers detect secret sentinels too. Keyless job/inventory reports are checked in JSON/human modes, and every captured CLI output and spawned-process log is scanned for credentials/seeds. Native failure fixtures emit the test secrets, proving the adapter withholds them. Authenticated create/inspect/restore detail intentionally exposes its existing documented metadata; the contract states this boundary explicitly and checks that create still reports its private profile.

Audit checks compare complete history snapshots around malformed configuration, preflight, confirmation and duplicate/target-lock refusals. Native dump/restore failures record only started/failed job actions, leave no fabricated completion, and retain a partial restore target. Successful restore records started/completed after native work. Two new inventory unit tests inject event-insert failures to roll back job start/associations, job transitions/interruption, registration, reconciliation/current flags, verification invalidation and digest-conflict state/events. The existing enrichment test now compares the complete row plus audit/verification history on failure, covering timestamps and provenance as well as profile facts. No runtime behavior, schema, dependency or artifact format changed.

Final verification: all 218 workspace tests, strict offline Clippy, formatting, shell/embedded-Python syntax and diff checks pass; the expanded M5a drill exits 0 on PostgreSQL 16, 17 and 18, including the prior A06 crash/rebuild/migration/corruption scenes. Logs `/tmp/parsbackup-a07-final-m5a.log`, `/tmp/parsbackup-a07-workspace.log` and `/tmp/parsbackup-a07-clippy.log` are ephemeral. A preliminary native run passed PG16 and was stopped cleanly before adding the final journal/configuration probes; only the final complete matrix is acceptance evidence. Earlier M1–M4b/key-drill matrices were not repeated for these test-only changes; the full regression gate remains A08.

**Next task: A08.** Publish the M5a operating guide and run full regression/acceptance gates. Complete the separate JobLock no-follow/mode hardening before accepting M5a. Production CLI phases B/H/V and the API-before-production-UI boundary remain unchanged.


**A08 / M5a accepted (2026-11-13).** The [operating guide](docs/development/m5a-operations.md) documents keyless/read/write/DR modes, discovery versus adoption, explicit expected-estate rebuild, unknown profile/time and lost history, verification/enrichment, interrupted jobs and manual partial-target inspection. The [ADR gate map](docs/development/m5a-inventory.md#a08-operating-guide-and-acceptance-map) records the A02 revision: mixed-shape IDs/diagnostics are provided by `inventory list`, while legacy `backup list` remains shape-specific and signed readers can retain low-level missing-file errors. Backup-reader opening still loads configured keys; `verify --read-only` suppresses inventory writes but can require writable locks/scratch. Neither limitation is presented as solved. No flow or frozen artifact contract changed.

The separate JobLock blocker (§33.5.1) is closed as a behavior fix: acquisition and recovery probes reject linked/non-directory lock paths, symlinked/special lock files and group/world-accessible files, with no-follow/nonblocking opens and descriptor checks. Two focused tests cover existing/dangling links, unchanged targets, permissions, directories and bounded FIFO refusal. Scope fingerprints, nonblocking contention, lock lifetime/order and the no-unlink rule are preserved. Private trusted roots remain required; hostile ancestor replacement/service ownership remains H02.

Final gates: all **220 workspace tests**, strict locked/offline Clippy, formatting, diff checks, seven shell scripts/43 embedded Python blocks, guide TOML/shell examples and local link targets pass. M1, M2, M3, M4a, M4a key drill, M4b and expanded M5a each exit 0 on PostgreSQL 16/17/18 (21 script/major combinations), including all 18 rebuild crash boundaries and A07 privacy/audit scenes. The first M2 attempt timed out starting its PG16 fixture before application work; the unchanged complete retry passed all three majors. No test containers remain. Three isolated source-copy controls deliberately weakened exclusive scope locking, no-follow acquisition and exclusive maintenance; each failed its corresponding test as required, and the temporary copy was removed. No dependency changed; M1–M4b/key-drill scripts are unchanged. Ephemeral evidence is `/tmp/parsbackup-a08-*.log`, including workspace, Clippy, each named matrix and three control logs.

The threat review retains T03/off-host rollback, timing/fingerprint/size correlation, host compromise and hostile SQL boundaries. Process-crash drills do not simulate power loss. M5a does not supply immutable audit history, protection or deletion. S/C1 and M5a are accepted; no production guard is removed. Earlier pending A07 changes remain intact and uncommitted.

**Next task: B01.** Inspect the actual inventory/verification/lifecycle/locking contracts and define the conservative per-source/profile `keep_last N` policy and exact plan contract with examples before implementing retention. Known authenticated scope/time and matching archive-validation evidence, last-valid/protected/active/job-dependent exclusions, digest/expiry binding and unknown/rebuilt-history refusals must be explicit. Do not enable deletion during this contract step. Production CLI completion still requires B, H and V; the production UI follows a stable API, while UI/UX research can proceed earlier. No commit or push in A08.


## 35. B01 contract and session archive — 2026-11-13

**B01 complete; B02 next.** Inspected schema v5 artifact/provenance/events, registration merges, job associations, resource/activity guards, signed readers, rebuild and restore-plan persistence. The new [retention/deletion contract](docs/development/m5b-retention.md) defines the B02–B06 implementation boundary without changing runtime code, commands, schema, v1 or accepted ADRs. Prune selects one source/profile, defaults to whole-database, and optionally selects an existing configured profile by name fingerprint. Its newest N quota includes only freshly authenticated signed files with known scope/time and a current matching archive observation. Protected older valid copies are retained in addition; explicit delete has the same exclusions and leaves another valid copy in that scope. Restore completion is not a validated-restore observation.

Protection knowledge is explicitly three-valued. Only genuinely new signed publications start unprotected; migration, adoption and rebuild produce unknown until an explicit protect/unprotect action. Authentication cannot restore lost protection history. B02 must preserve these facts across register/enrich/reconcile/rebuild, with atomic audit and idempotent repeated state. No protection sidecar or immutable-artifact edit is permitted.

Plans use a distinct versioned private 64 KiB envelope, 15-minute expiry, canonical fixed-field SHA-256 and exact candidates/retained file snapshots. A whole quiet inventory hash conservatively invalidates even unrelated writes. Preview and execution take exclusive maintenance before sorted candidate-exclusive/retained-shared artifact claims and short SQL transactions. Existing shared-claim authentication helpers must borrow the outer claim to avoid self-contention; signature-only file consumption needs a real use claim before deletion is enabled. B04 must supply durable plan/job dependencies and per-ID deleting/deleted intents, marker-first removal, exact partial results and lifecycle-aware readers. Recovery can finish already-started IDs from confirmed intent but never begin pending IDs using an expired/stale plan. Ordinary opens remain nonmutating.

B01 verification: checked both JSON examples, field ordering, UUID/time/digest encodings, canonical SHA-256 golden vector, plan bound and worked-case quota/protection/tie arithmetic. Checked local documentation targets and whitespace, unchanged source/dependency/test files, and that the built CLI still exposes no protect/unprotect/prune/delete commands. No production tests or PostgreSQL matrices were rerun for this documentation-only task; A08's recorded 220-test/seven-matrix evidence remains historical. B02 acceptance will require implementation-specific migration/rollback/merge/privacy tests; B06 retains the complete native destructive/race/crash gate. No commit or push.

**Completed-history summary for AGENT.md rule 9.** The active log exceeded 500 lines after recording B01, so its entries were preserved byte-for-byte in [the November rotation](archive/SESSION-LOG-2026-11.md). That archive contains the original ADR 0003/M5 scope work, accepted S ownership/concurrency correction, C1 cleanup and R correctness work, then completed A01–A08: keyless inventory/jobs, mixed discovery/reconciliation, adoption/rebuild, digest-bound verification/enrichment, restore claims and PG16–18 recovery/privacy/audit drills. M5a acceptance is recorded in §34.7 and [the acceptance map](docs/development/m5a-inventory.md#a08-operating-guide-and-acceptance-map); A07–A08 were committed as `216042e`. Synthetic-only guards, read-only-mount/service/off-host limits and later B/H/V/P/U/F gates are retained. The refreshed active log links the archive and records B01/B02 handoff; archived claims remain dated historical evidence.


## 36. B02 protection and preservation — 2026-11-13

**B02 complete; B03 next.** Appended the actual v5-to-v6 migration for nullable checked `artifact.protected`. Existing rows remain unknown, with no invented events. Registration sets false only for a previously absent signed publication; its row and audit commit together. Re-registration, enrichment and reconciliation preserve true/false/null. Adoption and staged rebuild leave unknown; a preserved old inventory retains its flags/history. An explicit protect/unprotect establishes a known value with one atomic `artifact_protected`/`artifact_unprotected` event, and repeating the known value adds no event. No deleting/deleted writer or dormant lifecycle enum was introduced.

The application protection port/result uses the existing inventory service. Its key-free local adapter holds exclusive maintenance, validates root/index/integrity/rows/target before upgrading, rejects SQLite sidecars and unsafe claims, and never creates an index or opens artifact/key/client paths. Backup command dispatch now opens the configured key-loading store only in artifact command arms, preserving create's recovery-before-scope order; protection has its own keyless path, and verify no longer opens that store twice. The existing transaction helper now returns its operation's value after a successful commit, preserving rollback behavior for all old callers. JSON uses the B01 four fields; human output shows prior state. Unknown-to-unprotected JSON adds the bounded lost-history stderr notice. Explicit migration can remain committed after a later flag/audit failure; that flag/event transaction rolls back together.

Seven new tests and expanded existing fixtures cover real populated v5 migration (artifact/provenance/jobs/associations/audit/verification preserved), failed migration, explicit upgrade only for a valid request, all protection values, idempotence, audit failure rollback, re-registration, authenticated enrichment, conflict/recovery reconciliation and protected previous-index versus unknown replacement. CLI scenes prove absent keys/tools/artifacts, exact JSON and human transitions, unchanged populated histories/provenance, missing index/root/target, foreign rows, newer/symlinked indexes, unsafe activity claims and sidecar refusal. The M5a PG16/17/18 drill adds raw protection journal probes, immutable-artifact tree comparison, duplicate/no-event checks, busy protection refusal during a live dump, and unknown flags after rebuild and authenticated enrichment.

Final gates: **227 workspace tests**, strict locked/offline Clippy, formatting, diff checks, seven shell scripts/43 embedded Python blocks, guide syntax/local targets and unchanged plan golden vector pass. M1/M2/M3/M4a/key-drill/M4b/expanded M5a each exit zero on PostgreSQL 16/17/18, including 18 rebuild crash boundaries and the A07 metadata/audit controls. All native scripts passed without retry; no test containers remain. Ephemeral evidence: `/tmp/parsbackup-b02-{workspace,clippy,m1_docker_smoke,m2_docker_smoke,m3_docker_smoke,m4a_docker_smoke,m4a_key_drill,m4b_docker_smoke,m5a_docker_smoke}.log`. Two early compile checks exposed the unit-only transaction result and read-only constructor bound; both were corrected before passing gates. A final error-category wrapper and stronger preservation fixtures were checked by the full workspace/Clippy gates; successful native behavior is unchanged. No dependency/configuration/frozen artifact change. The B01 archive is unchanged and prior uncommitted work is preserved. No commit or push.

**Next task: B03.** Implement the B01 pure selection rules and exact bounded saved previews, including claim-aware signed authentication, current archive-observation identity/digest binding, unknown protection refusals, deterministic quota/exclusions, whole-index snapshot, canonical digest/expiry and stale-plan tests. The future `run` execution remains B04; protection alone must never be presented as retention validation or host-loss/rollback protection. Production CLI completion still requires the remaining B/H/V tasks, followed by API and production UI work.


## 37. B03 retention previews and saved plans — 2026-11-13

B03 implements preview-only `backup prune --keep-last N [--profile NAME]` and `backup delete ID` through the application planner port. Domain policy orders authenticated completion descending with canonical UUID ascending ties, keeps newest N plus protected/job-dependent older copies, and requires a same-scope survivor for explicit delete. The default profile is whole-database; configured names group historical contents without live catalog resolution. Registered nonprovisional signed rows require known scope/time/protection and the greatest current exact-digest archive-success SQL event ID. Existing verification-event output is unchanged. Unknown protection in any known scope member blocks planning; unsigned/unregistered/unknown/missing/conflicting entries never count.

The local planner takes exclusive nonblocking maintenance, then candidate-exclusive/retained-shared artifact claims in UUID order, and retains them through save/check. Shared readers keep their existing public ownership behavior; the extracted internal signed reader and manifest scratch path borrow existing ownership, avoiding self-contention without downgrading locks. Read-only inventory facts and complete mixed discovery precede fresh authenticated fixed-file snapshots for every usable scoped copy. Descriptor-based no-follow regular-file reads reject extras, symlinks and special files, and current row/header comparison is shared with discovery. Reader custody loads only identity/trusted verifier; signing and recipient files, native tools and PostgreSQL are unnecessary. Preview never migrates/reconciles/recovers, writes inventory/observations/jobs/audit, or changes immutable artifacts.

Nonempty intent is a strict versioned envelope at private create-new `plans/deletion-UUID.json`, synced with its parent before reporting success. It binds exact sorted candidate/all-retained sets, protection, matching archive event identity, every allowed file, policy/scope, a quiet whole-index SHA-256 and checked 15-minute expiry. Canonical typed encoding pins the B01 golden vector. The complete 64 KiB envelope limit, duplicate/unknown-field rejection, required nullable quota, canonical UUIDs, sorted/disjoint sets, file semantics, no-overwrite and incomplete-save cleanup are enforced. Empty prune has null plan fields and no file. The library can check saved intent/confirmation/expiry against current selection, inventory and files, but does not execute it or hand out live execution authorization after dropping claims.

A read-only SQLite probe confirmed that querying a WAL-mode index can create WAL/SHM sidecars despite READONLY. Inventory read/probe now inspect the fixed SQLite read/write journal-format header before opening SQLite, refusing unsupported formats without mutation. A bundled-SQLite positive control reproduces the sidecars without the guard; library and CLI tests require unchanged index bytes and no sidecars. Normal, zero-byte, foreign, old-schema and corruption diagnostics remain covered by the full regression suite.

Focused coverage includes deterministic quota/protection/ties, explicit last-valid refusal across profiles, current archive event identity/digests and invalidation, unknown rebuild protection, unsigned/unregistered non-substitution, stale open jobs/unknown dependencies, activity/artifact contention, no keys for writing/no native tools, exact JSON/human reports and numeric usage errors. Saved-plan tests cover canonical bytes, mutation, expiry/overflow, wrong operation/ID/digest, private modes, symlinks, bounded FIFO refusal, size/overwrite, extra components, globals/marker corruption, unchanged inventory/artifacts, new observations/protection and unrelated-scope job writes invalidating the whole-index snapshot. The extended M5a drill checks real previews/plans/privacy and changed selections under a reused profile name on every supported major.

B04 remains the execution boundary: exact confirmation, durable deletion jobs/dependencies/intents, marker-first synced removal, terminal tombstones and partial recovery/receipts, plus lifetime artifact-use guards on readers. B03 exposes no `run`, marker removal, deletion writer or receipt. No dependency/configuration/schema/frozen-v1 change or production-source enablement; local intent checks cannot recover lost history or prevent rollback. Native verification completion is recorded below before B03 acceptance.


**B03 accepted; B04 next.** All **243 workspace tests**, strict locked/offline Clippy, formatting/diff checks, seven shell scripts/43 embedded Python blocks, changed-document local targets and the unchanged canonical golden vector pass. The final frozen-code run passed M1, M2, M3, M4a, M4a key drill, M4b and expanded M5a on PostgreSQL 16/17/18 (21 script/major combinations), including all 18 rebuild crash boundaries. No test containers remain. Evidence is `/tmp/parsbackup-b03-*.log` (ephemeral); stock rage 0.12.1 was restored from cached Cargo sources with offline installation under `/tmp/parsbackup-test-tools`, without a network download or project dependency change.

Earlier checks caught unsupported partial/schema-only large-object fixture variants, reader key-load/oversized-header diagnostic drift, and an initial SQLite journal-header offset error. The fixture now uses a supported data-only change under the same profile name; existing reader diagnostics and overflow-sentinel behavior are preserved. The corrected header guard and every affected reader passed the full final gates. No failed attempt is counted as acceptance. The B01 archive remains byte-identical (SHA-256 `47482148de261a3a647e0e580f96e9ac1a2cfb971c4dc0a526cfe2ab86d1048a`). No commit or push.

**Next task: B04.** Implement the contracted explicit digest confirmation, exact-set revalidation under held claims, durable deletion jobs/dependencies and per-artifact intent, marker-first synced removal, terminal tombstones, honest partial receipts and recovery of started IDs only. Add lifecycle/non-resurrection and reader-use guards before enabling execution; retain B06's destructive/race/crash acceptance gate. Eleven planned production CLI tasks remain (B04–B06, H01–H05 and V01–V03), followed by four API, four UI and three platform-release tasks. Counts describe scope, not equal effort or delivery time; the CLI and production UI are not finished.


## 38. B04 confirmed deletion, tombstones and recovery — 2026-11-13

Implemented the application deletion execution port, strict digest-confirmed prune/delete run dispatch and exact JSON/human durable progress. The executor holds exclusive maintenance and sorted candidate-exclusive/retained-shared resource claims from fresh full B03 authentication/snapshot checks through terminal recording or handled failure. No unstarted stale, expired, mismatched or in-use plan starts a job. Schema v7 appends plan-bound deletion jobs and exact dependency/progress rows, preserving v6 facts. Job/start, per-ID deleting intent/event, per-ID deleted state/observation invalidation/event and terminal job events each commit atomically; filesystem hashing/removal never spans a SQL transaction.

Fixed no-follow descriptor-relative file removal unlinks and syncs the completion marker before contents, then syncs the removed artifact's parent before recording completion. Durable partitions distinguish completed, deleting and never-started pending IDs. Completed receipt replay validates bound evidence before old expiry/file checks and records nothing. Failed/interrupted reruns report progress and never resume pending candidates.

The existing maintenance recovery pass is also exposed as keyless/tool-free `inventory recover`. It validates saved intent, operation/estate/digest/exact dependencies, lifecycle/audit and remaining fixed file snapshots; only deleting IDs may finish after expiry. Failed/interrupted jobs stay terminal; abandoned running jobs become interrupted. Missing/corrupt evidence or changed/extra/unsafe components refuse. Rebuild cannot discard readable in-flight deletion evidence. Reader/verification handles and plaintext views retain shared use/activity claims, inherited by native children; planner authentication borrows maintenance. Tombstones block staging, registration, protection, verification, adoption and reconciliation even if complete files reappear. Deletion job inspection exposes exact artifact IDs without changing existing backup/restore or verification-event JSON.

Focused verification covers exact candidate/survivor bytes, CLI usage/confirmation/results, atomic audit failures, expired receipts, five recovery removal boundaries, keyless started-only recovery, terminal-state preservation, reader/view claims, non-resurrection and missing/mutated/unsafe recovery evidence. Native M5a now exercises confirmed removal, live journal/plan privacy, partial JSON and keyless recovery on isolated native-artifact copies. Final fast/native acceptance is recorded below after the frozen run. B03 working-tree changes are preserved and remain uncommitted; no dependency/configuration/frozen-v1/flow change or production-source enablement. B05 local rollback warning remains next, then B06's full crash/race/destructive acceptance drill; CLI/API/UI are not finished.


**B04 accepted; B05 next.** All **256 workspace tests** (13 added for B04), strict locked/offline Clippy, formatting/diff checks, seven shell scripts/43 embedded Python blocks, changed-document local targets, canonical plan vector and unchanged archive hash pass. The final frozen runtime/harness passed all seven native matrices on PostgreSQL 16/17/18 (21 combinations), including confirmed deletion, survivor archive checks, partial JSON, keyless recovery, live SQLite journal/plan/output privacy and all 18 existing rebuild crash boundaries. No test containers remain. Evidence: `/tmp/parsbackup-b04-*.log` (ephemeral).

Review closed one library-level gap before the final frozen run: the shared artifact-row writer now rejects caller-supplied deleting/deleted states through both registration and adoption. A focused test proves rollback leaves no row/event. Early native parallel runs competed for shared host ports, including a later target-18 startup refusal; a standalone PG18 diagnostic passed, and all four host-port matrices were serialized in the successful final run. No runtime/harness edits occurred during that run; only ownership comments and acceptance documents were updated afterward.

**Next task: B05.** Implement the local per-scope rollback-warning ledger described in the B roadmap, keeping warnings separate from retention validity and from adversarial replay protection. Then B06 supplies the dedicated full destructive/race/crash acceptance drill. Ten planned production CLI tasks remain (B05–B06, H01–H05, V01–V03), followed by four API, four UI and three platform-release tasks. Counts are scope, not equal effort. B03–B04 remain uncommitted; the production CLI and UI are not finished.

## 39. B05 local older-snapshot warnings — 2026-11-14

Implementation follows the [B05 contract](docs/development/m5b-retention.md#b05-local-older-snapshot-warning-contract--2026-11-14), recorded before code. Schema v8 appends a key-free per-source/signer completion high-water ledger. Migration leaves it empty; generic registration, adoption and keyless discovery do not authenticate it. Signed publication and successful writable checksum/archive enrichment advance it in their existing state/observation/audit transactions. Restore planning explicitly observes authenticated completion in a short transaction on an existing inventory; missing inventory stays missing. Equal timestamps retain the existing mark. Repeated/older observations do not lower it or add advancement events, and deletion/invalidation/reconciliation do not erase it. Explicit rebuild advertises lost `rollback` history.

Signed discovery keeps its existing arrays and adds sorted local `rollback_warnings`/`rollback_unknown` reports without decryption or writes. Matching inventory/header bindings and known authenticated completion are required to borrow recorded time. New signed restore plans use `m5b-restore-plan-v2`, binding selected source/signer/time/ciphertext digests, nullable observed high-water and acknowledgement in the canonical digest. Explicit `--acknowledge-older-snapshot` is required only for a known older selection and refuses otherwise. Run reauthenticates and compares selected bytes and warning context before cluster mutations; changed/lost/newer history requires a new plan. Legacy development-plan serialization/digests remain unchanged; legacy signed plans cannot authorize an older restore. Native tools retain existing resource ownership, and no SQL transaction spans native work.

Focused coverage includes populated v7 migration and failed-step preservation, timestamp ties/scope/validation, atomic publication/verification/audit failures, read-only/signature-only non-advancement, cross-profile warning, changed public bindings, missing/rebuilt history, deleted newest-copy persistence, exact CLI JSON/human reports, v1 byte/digest compatibility and execution, v2 strict parsing/time/bindings, explicit acknowledgement and refusal before globals/target mutation. The M5a drill adds native list/acknowledgement/stale-plan/rebuilt-history and privacy checks. M4b's deliberate old-copy DR restore now requires the explicit warning acknowledgement while retaining all earlier trust/decryption checks.

B05 is accepted after completion of the final frozen regression run. Runtime and native harness fingerprints are recorded under `/tmp/parsbackup-b05-native-inputs.sha256`; only tests and documents may change during that run. An earlier native driver was interrupted by the operator's turn interruption before completing PG16; its remaining fixture container was removed and the full native sequence restarted. No passing claim is made for the interrupted run. Final fast/native results are recorded below. Artifact v1/transcripts, dependencies/configuration, flows and synthetic-only guards are unchanged. T03 remains open: local completion is an authenticated signer claim and a point-in-time accident warning, not independent replay protection. B06 remains the next implementation task after B05 acceptance; production CLI/API/UI are unfinished.

### B05 file changes

| File path | Change type | Description |
|---|---|---|
| [crates/backup-domain/src/rollback.rs](crates/backup-domain/src/rollback.rs) | Added | Strict completion mark, warning and signed-plan binding types. |
| [crates/backup-domain/src/restore.rs](crates/backup-domain/src/restore.rs) | Modified | Versioned rollback binding, acknowledgement/time validation and compatibility tests. |
| [crates/backup-domain/src/lib.rs](crates/backup-domain/src/lib.rs) | Modified | Export the B05 domain vocabulary. |
| [crates/backup-domain/src/fixture.rs](crates/backup-domain/src/fixture.rs) | Modified | Preserve legacy plan fixture semantics. |
| [crates/backup-application/src/lib.rs](crates/backup-application/src/lib.rs) | Modified | Observation/read ports, listing facts, plan acknowledgement and execution rechecks. |
| [crates/backup-inventory/src/rollback.rs](crates/backup-inventory/src/rollback.rs) | Added | Scoped validated monotone reads/writes and atomic advancement audit. |
| [crates/backup-inventory/src/schema.rs](crates/backup-inventory/src/schema.rs) | Modified | Append v7-to-v8 migration and populated preservation/failure tests. |
| [crates/backup-inventory/src/job.rs](crates/backup-inventory/src/job.rs) | Modified | Safe completion advancement audit action. |
| [crates/backup-inventory/src/lib.rs](crates/backup-inventory/src/lib.rs) | Modified | Atomic publication/verification advancement and validation/rollback tests. |
| [crates/backup-local/src/rollback.rs](crates/backup-local/src/rollback.rs) | Added | Existing-index observation/read bridge and matching-fact discovery warnings. |
| [crates/backup-local/src/inventory.rs](crates/backup-local/src/inventory.rs) | Modified | Use the authenticated publication registration path. |
| [crates/backup-local/src/lib.rs](crates/backup-local/src/lib.rs) | Modified | Implement ports/list fields and retain legacy fixture compatibility. |
| [crates/backup-local/tests/signed_write_path.rs](crates/backup-local/tests/signed_write_path.rs) | Modified | Cross-profile/time, acknowledgement, binding, legacy execution and lost/read-only history checks. |
| [crates/backup-local/tests/retention.rs](crates/backup-local/tests/retention.rs) | Modified | Prove deleted newest-copy history and surviving warnings remain. |
| [crates/backupctl/src/cli.rs](crates/backupctl/src/cli.rs) | Modified | Explicit plan acknowledgement flag and listing JSON fields. |
| [crates/backupctl/src/main.rs](crates/backupctl/src/main.rs) | Modified | Dispatch the explicit acknowledgement to the application. |
| [crates/backupctl/src/report.rs](crates/backupctl/src/report.rs) | Modified | Human older-snapshot/unknown-history/acknowledgement reports. |
| [crates/backupctl/src/inventory.rs](crates/backupctl/src/inventory.rs) | Modified | Report rollback history lost by rebuild in human/JSON modes. |
| [crates/backupctl/tests/inventory_cli.rs](crates/backupctl/tests/inventory_cli.rs) | Modified | Preserve the real v5 migration fixture after adding schema v8. |
| [crates/backupctl/tests/store_concurrency.rs](crates/backupctl/tests/store_concurrency.rs) | Modified | End-to-end exact CLI warning/acknowledgement/lost-context tests. |
| [tests/m5a_docker_smoke.sh](tests/m5a_docker_smoke.sh) | Modified | Native B05 warnings, bound/stale plans, rebuilt history and privacy checks. |
| [tests/m4b_docker_smoke.sh](tests/m4b_docker_smoke.sh) | Modified | Require explicit acknowledgement for the deliberately older DR snapshot. |
| [docs/development/m5b-retention.md](docs/development/m5b-retention.md) | Modified | Record the precise B05 contract before implementation. |
| [docs/development/m5a-operations.md](docs/development/m5a-operations.md) | Modified | Explain warnings, unknowns, explicit plan acknowledgement and compatibility. |
| [docs/security/threat-model.md](docs/security/threat-model.md) | Modified | State B05's local accident-warning boundary and open T03 residuals. |
| [project.md](project.md) | Modified | Record implementation, verification, file inventory and next task. |
| [README.md](README.md) | Modified | Preserve the prior review and explain current B05 operation/status. |
| [session-log.md](session-log.md) | Modified | Preserve the prior review and append implementation/verification evidence. |

**B05 accepted; B06 next.** All **266 workspace tests** (ten added for B05), strict locked/offline Clippy, formatting/diff checks, seven shell scripts/43 embedded Python blocks, changed-document targets and existing canonical vectors pass. The frozen runtime/harness passed M5a, M1, M2, M3, M4a, the M4a key drill and M4b on PostgreSQL 16/17/18: **21 script/major combinations**, including B05's cross-profile local warning, explicit acknowledgement, stale-plan refusal, keyless rebuild history loss, native archive verification/DR operation and all **18** existing rebuild crash boundaries. No runtime/native-harness source changed during the successful run; test-only lifecycle/legacy assertions and documents were strengthened. No test containers remain. Ephemeral evidence is `/tmp/parsbackup-b05-{workspace,clippy,m5a_docker_smoke,m1_docker_smoke,m2_docker_smoke,m3_docker_smoke,m4a_docker_smoke,m4a_key_drill,m4b_docker_smoke}.log` and `/tmp/parsbackup-b05-native-inputs.sha256`. The November archive remains byte-identical with SHA-256 `47482148de261a3a647e0e580f96e9ac1a2cfb971c4dc0a526cfe2ab86d1048a`.

Early development corrections preserved the intended gates: schema table and old-version fixtures now include/drop the appropriate v8 table, adoption fixtures carry unknown private facts, and the R05 corruption case separately proves early v2 binding refusal and legacy payload-decryption refusal before mutation. Local tests use real rebuilds instead of adding a SQLite dependency. The earlier interrupted native run is not counted. B05 leaves T03 open and preserves fixture-only operation; no dependency/configuration/frozen-artifact/flow change, commit or push. Previous review documentation remains intact.

**Next task: B06.** Add `tests/m5b_retention_drill.sh` and complete the dedicated full destructive/race/crash acceptance: exact planned/executed sets and exclusions, unknown/rebuilt history refusal, protection preservation, corrupted/removed retained witnesses, two competing deleters, restore/delete contention, marker-first interruption and started-only recovery, durable tombstones and history. Re-run M5a/M1–M4b/key drill, publish the retention operating/threat acceptance and close phase B only when its complete gate passes. Nine production CLI tasks remain (B06, H01–H05, V01–V03), followed by four API, four UI and three platform-release tasks. Counts describe scope, not equal effort. The production CLI/API/UI are unfinished.

## 40. B06 destructive/race/crash retention drill — 2026-11-14

Started from verified B05 commit `4fbb023` with a clean working tree. The operator authorized B06, and its precise acceptance contract was appended to [m5b-retention.md](docs/development/m5b-retention.md#b06-acceptance-drill-contract--2026-11-14) before code. The new executable [tests/m5b_retention_drill.sh](tests/m5b_retention_drill.sh) uses actual CLI initialization, native signed PostgreSQL 16/17/18 archives, private independent temporary stores and isolated Docker servers without host ports. No runtime hook, schema, dependency, configuration, artifact/transcript or flow change was needed.

The dedicated drill passes all three majors, including **24 real process-crash boundaries**: durable deleting intent before marker removal, marker unlink, marker-directory sync, first content unlink, contents-directory sync, artifact-directory unlink, parent-directory sync and tombstone journal commit. Syscall positions come from an identical successful baseline; each delayed successful syscall/path and persisted lifecycle/event state is asserted before SIGKILL. SQLite's lock at journal commit is handled by inspecting the committed single-file copy before killing, then the original afterward. Complete files with deleting intent cannot be used. Pending IDs and retained bytes remain untouched; explicit keyless/tool-free recovery finalizes only started work, retains interrupted/failed job state and exact dependencies, invalidates observations and preserves durable tombstones. Repeated old-plan execution reports its exact remaining partition without starting pending IDs.

Other scenes cover exact planned/executed sets and receipts, protected/quota/profile/last-copy/job/use exclusions, unknown/unverified/missing/conflicting/unsigned/unregistered entries, preserved protection through reconcile/archive enrichment, unknown history after keyless rebuild, independent missing/corrupt retained witnesses, competing deleter refusal and restore/delete contention in both directions. Handled audit failure reports exact completed/deleting/pending JSON. Missing/changed saved intent and unexpected remaining files refuse recovery. Returned complete bytes cannot undo a tombstone through inspect/reconcile/adopt. Raw ledgers/plans and captured reports are scanned for private fixture metadata or secrets at their permitted boundaries; a populated SQLite positive control detects every sentinel. Existing M5a provides the complementary live-journal privacy and rebuild crash checks.

**B06 accepted; phase B complete.** The final strengthened B06 drill and all seven previous native matrices exited 0 on PostgreSQL 16/17/18: **24 script/major combinations**, including 24 new deletion crash points and M5a's 18 existing rebuild crash points/live-journal privacy. All **266 workspace tests**, strict locked/offline Clippy, formatting/diff, eight shell scripts/44 embedded Python blocks and changed-document checks pass. Accepted runtime/harness fingerprints still match; no backupctl test containers remain. Evidence: `/tmp/parsbackup-b06-{m5b_retention_drill,m5a_docker_smoke,m1_docker_smoke,m2_docker_smoke,m3_docker_smoke,m4a_docker_smoke,m4a_key_drill,m4b_docker_smoke,workspace,clippy}.log`, `/tmp/parsbackup-b06-drill-inputs.sha256` and `/tmp/parsbackup-b06-regression-inputs.sha256` (ephemeral). Development corrections were test-harness setup/expectations: temporary-server readiness, existing creation/adoption report contracts and valid stale-job fixtures. The six-boundary development version also passed all majors before being strengthened and rerun; final review added whole-directory witness loss, explicit marker-sync ordering, changed remaining bytes and successful singleton delete/job dependency checks. No production behavior fix was required. No commit or push was requested; the November archive remains byte-identical.

### B06 file changes

| File path | Change type | Description |
|---|---|---|
| [tests/m5b_retention_drill.sh](tests/m5b_retention_drill.sh) | Added | Native exact-set, exclusion, race, crash, recovery and privacy acceptance. |
| [docs/development/m5b-retention.md](docs/development/m5b-retention.md) | Modified | Precise B06 drill contract and acceptance evidence. |
| [docs/development/m5a-operations.md](docs/development/m5a-operations.md) | Modified | Retention drill coverage and interrupted-operation interpretation. |
| [docs/security/threat-model.md](docs/security/threat-model.md) | Modified | M5b threat review, tested local boundaries and remaining risks. |
| [project.md](project.md) | Modified | B06 implementation, evidence, file inventory and phase handoff. |
| [README.md](README.md) | Modified | Plain-language drill/status update. |
| [session-log.md](session-log.md) | Modified | Append-only inspection, development and acceptance record. |

T03 remains open: the inventory shares the artifact root's failure domain, and local retention does not prevent host loss or an editor replacing files and inventory. These process-kill tests do not establish power-loss behavior or an independent security audit. The trusted operator-owned root and synthetic-only guard remain required. **Next task: H01**, the configuration/release policy decision: record versioned production configuration, allowed source/target topologies, secure credential modes, error/JSON version policy, public-only/read-only custody and explicit restore support limits before implementation. Eight production CLI tasks remain (H01–H05, V01–V03), followed by four API, four UI and three platform-release tasks. Counts describe scope, not equal effort; production CLI, API and UI remain unfinished.

## 41. H01 production configuration/release policy — 2026-11-15

Defined [h01-production-policy.md](docs/development/h01-production-policy.md) against clean B06 checkpoint `c40a953`. This is a policy task, not a parser/security implementation or production release. Inspected current config/profile validation, CLI parse/output/error dispatch, native environment/credentials/preflight, source fingerprint inputs, restore plans, key custody, read-only working paths and H/V gates. Confirmed PostgreSQL documentation for peer, protected passfiles, client-required SCRAM, libpq environment/database-argument expansion, TLS verification and restore trust. The policy cites those primary sources; it is newly chosen H01 policy, not a retroactive ADR claim.

Decisions: first release stays local-only (protected Unix socket/peer or literal loopback/SCRAM/passfile), with one source/local root and fresh same-endpoint/same-major restores. A maintenance DB must support recovery when the original logical source database is absent without changing its frozen fingerprint. Version-1 config explicitly states mode/access/read-only custody, preserves legacy unversioned fixtures and permits no production operation before V03. Writer/reader/public/inventory capabilities and true snapshot reads/private external scratch are defined. First-release writers retain the identity; remote TLS, independent target endpoints, cross-major, data-only-to-existing-schema, overwrite and writer-without-identity are deferred/refused. Future explicit `json-v1` envelopes preserve legacy fixture JSON and 0/1/2 exits. New production restore-plan bindings need their own recorded version before implementation; frozen v1 and existing plan bytes are untouched.

H01 is **defined**, with documentation/example/link and unchanged-boundary checks recorded in the session log. The current binary still rejects the new TOML and output flag. No runtime, fixture configuration, dependency, schema, artifact/transcript, test harness, flow, deployment file or key material was changed. B06's 266 tests/eight matrices remain historical evidence, not rerun by H01. T03 and the production guard stay open. Seven production CLI tasks remain (H02–H05, V01–V03), followed by the unchanged API/UI/platform tracks.

| File path | Change type | Description |
|---|---|---|
| [docs/development/h01-production-policy.md](docs/development/h01-production-policy.md) | Added | Inspected choices, versioned fields, custody/auth/topology/restore/report limits and release acceptance map. |
| [project.md](project.md) | Modified | H01 definition, H02 ownership/sequencing, status and handoff. |
| [README.md](README.md) | Modified | Simple policy/status explanation without implying production enablement. |
| [session-log.md](session-log.md) | Modified | Append-only definition, sources and verification record. |

**Next: H02, first increment.** Implement the legacy/versioned config split, command capability validation and safe report envelope, keeping all production-mode operations except structural config checks gated. Preserve fixture vectors and refuse unsupported combinations before side effects. Then take the native credential/maintenance connection, key bootstrap, filesystem/process, resource-limit and snapshot-read increments with their required synthetic/all-major tests. H01's policy map is authoritative for that work; H03 packaging and V03 release remain separate gates. No commit or push is part of this definition task.


## 42. H02 configuration/access/report increment — 2026-11-15

Operator authorized the first H02 increment after H01 definition. Preserved the uncommitted H01/status documentation and inspected the legacy parser, native dispatch, eager key opening, inventory-only services, native test assertions and H01's exact custody/report contracts. Recorded [h02-config-access-reports.md](docs/development/h02-config-access-reports.md) before its writers: exhaustive command/access boundaries, version selection, safe file reads, result-data ownership, errors/exits and deferred capabilities.

Implemented a separate closed `ConfigV1` with explicit mode/access/read-only, source-independent tools, peer/SCRAM topology rules, literal names, profile/custody/path validation and no production enablement. Selection validation is shared without removing the fixture guard used by legacy config and frozen signed manifests. CLI config input is bounded regular/no-follow; versioned files additionally require an absolute protected service-owned mode-0600 file with descriptor-checked ancestry. Legacy relative config paths/permissions remain supported; final symlinks/special files/over-64-KiB inputs now refuse deliberately. The CLI reuses already locked workspace `libc` for open flags/descriptor traversal: one manifest/lock dependency edge, no new package/version.

Authorization is exhaustive and occurs before command resources. Versioned fixtures deliver config/profile reads, empty inventory-key status and writable keyless job/inventory/protection operations; configured keys/source/tools are not opened for inventory work. Config checks do not certify referenced resources. Policy-permitted native, authenticated backup, key custody/bootstrap and snapshot operations explicitly refuse `CAPABILITY_NOT_ENABLED` until their later H02 increment. True read-only store commands never enter the legacy lock path. Every production operation except structural config check still refuses; production bare JSON is unsupported. Old plans/artifacts cannot authorize production.

`--output json-v1` now wraps existing result data in exactly one versioned envelope, with stable generated errors, no parser/native/debug-chain text, preserved retention/older-snapshot codes and honest durable deletion partial partitions. Legacy successful bare JSON and config-check compact formatting remain compatible. A static phrase catalogue preserves established fixture diagnostics without arbitrary values. Legacy native failure receipts without a structured service result remain an explicit later-H02 limitation; null data does not assert zero side effects. No frozen artifact/transcript/fingerprint, plan bytes, inventory schema, PostgreSQL adapter, crypto implementation, existing config example, native harness, flow or production-source guard changed.

Fast acceptance: all **278 workspace tests**, strict locked/offline Clippy and formatting pass. The new process matrix covers six role/read-only combinations across 31 command variants, production gating, strict fields/local auth/selection, protected file/FIFO/size boundaries, missing resource isolation, keyless maintenance/protection and legacy/v1 result equivalence. Existing process scenes verify exact deletion partial receipts and signed signature/checksum/archive read results. Native compatibility results and the final scope audit are recorded below; H02 itself is not complete.

### H02 increment file changes

| File path | Change type | Description |
|---|---|---|
| [crates/backup-domain/src/config_v1.rs](crates/backup-domain/src/config_v1.rs) | Added | Separate closed deployment schema and pure validation. |
| [crates/backup-domain/src/lib.rs](crates/backup-domain/src/lib.rs) | Modified | Expose deployment config/role types. |
| [crates/backup-domain/src/profile.rs](crates/backup-domain/src/profile.rs) | Modified | Share selection rules while retaining signed/legacy fixture guards. |
| [crates/backupctl/src/configuration.rs](crates/backupctl/src/configuration.rs) | Added | Version routing and bounded/protected configuration reads. |
| [crates/backupctl/src/access.rs](crates/backupctl/src/access.rs) | Added | Canonical operations, role/read-only/production gates and limited fixture dispatch. |
| [crates/backupctl/src/output.rs](crates/backupctl/src/output.rs) | Added | Single report envelope and generated safe diagnostics. |
| [crates/backupctl/src/main.rs](crates/backupctl/src/main.rs) | Modified | Compose parsing, authorization, legacy dispatch and final reporting. |
| [crates/backupctl/src/cli.rs](crates/backupctl/src/cli.rs) | Modified | Add explicit json-v1 output choice. |
| [crates/backupctl/src/backup.rs](crates/backupctl/src/backup.rs) | Modified | Route existing results through reporter; share keyless protection dispatch. |
| [crates/backupctl/src/inventory.rs](crates/backupctl/src/inventory.rs) | Modified | Root-only keyless calls and existing result reporting. |
| [crates/backupctl/Cargo.toml](crates/backupctl/Cargo.toml), [Cargo.lock](Cargo.lock) | Modified | Reuse existing locked libc for Unix descriptor flags. |
| [crates/backupctl/tests/config_reports.rs](crates/backupctl/tests/config_reports.rs) | Added | Full-process configuration/access/file/report tests. |
| [crates/backupctl/tests/store_concurrency.rs](crates/backupctl/tests/store_concurrency.rs) | Modified | Partial receipt and signed read envelope equivalence. |
| [docs/development/h02-config-access-reports.md](docs/development/h02-config-access-reports.md) | Added | Precise increment contract and remaining limitations. |
| [docs/development/h01-production-policy.md](docs/development/h01-production-policy.md) | Updated pending H01 document | Distinguish now implemented parsing/reports from future capabilities. |
| [project.md](project.md), [README.md](README.md), [session-log.md](session-log.md) | Modified/appended | Implementation status, verification and next handoff. |

**Next H02 increment:** native authentication/maintenance connection contracts and tests, with explicit command resource requirements, lost-source recovery, required SCRAM and trusted tools. Record new production restore-plan bytes before any production writer; preserve all current artifact/plan bytes and production gates. Follow with validated key bootstrap/custody, descriptor/resource hardening and true snapshot reads. H03–H05 and V01–V03 remain separate. Seven production CLI task IDs still remain because H02 has only partially advanced; API/UI/platform counts are unchanged. No commit or push was requested.


### H02 increment acceptance

The configuration/access/report increment is accepted on 2026-11-15: **278 workspace tests**, strict locked/offline Clippy, formatting, diff and documentation checks pass. Native compatibility covers all eight existing matrices on PostgreSQL 16/17/18 (**24 script/major combinations**), including M5a's **18 rebuild crash boundaries** and B06's **24 deletion crash boundaries**, authentic native archives, privacy controls, partial results and started-only recovery. No full H02/production release claim follows from these checks.

Evidence sequencing is explicit: M1/M2/M3/M4a/key drill/M4b and full M5a PG16 passed before the final two lifecycle-message categories/direct assertions. Only `crates/backupctl/src/output.rs` differs from that recorded input set; no service, native, crypto, schema, artifact or plan behavior changed. After that correction, all 278 tests/Clippy/formatting and full B06 PG16/17/18 passed. M5a PG17/18 then completed independently using the unchanged Python test body with only the major-loop selection narrowed; both exited 0, including migrations/corruption/read-only-copy and six crash boundaries each. The earlier combined PG17 run was intentionally interrupted and is not acceptance evidence. The per-major completion lines/provenance, not the inherited all-major success banner in each narrowed body, establish what ran.

Logs: `/tmp/parsbackup-h02-config-{workspace,clippy,m1_docker_smoke,m2_docker_smoke,m3_docker_smoke,m4a_docker_smoke,m4a_key_drill,m4b_docker_smoke,m5b_retention_drill}.log`, `/tmp/parsbackup-h02-config-m5a-pg16-before-lifecycle.log`, `/tmp/parsbackup-h02-config-m5a-pg17.log`, `/tmp/parsbackup-h02-config-m5a-pg18.log`. Input provenance: `/tmp/parsbackup-h02-config-before-lifecycle.sha256`, `/tmp/parsbackup-h02-config-inputs.sha256` (84 final runtime/manifest/test inputs), `/tmp/parsbackup-h02-config-m5a-selection.json` (original/selected bodies and executing binary hashes). These are ephemeral local evidence, not shipped artifacts or independent interoperability proof.

Final audit verifies the exact 19-file pending scope (including preserved H01 documentation), original package versions with only the existing-libc dependency edge, unchanged runtime/test fingerprints and executing binary, parseable policy TOML/JSON, protected structural checking of the exact H01 specimen, local document targets/anchors, append-only log, unchanged November archive and test-container cleanup. Pending implementation remains native auth/maintenance DB and plan context, key bootstrap/custody, resource/filesystem/service hardening and true snapshot reads; production operations stay disabled. No commit or push.


## 43. H02 native authentication and maintenance recovery — 2026-11-15

Operator authorized the next H02 increment. The [declarative native contract](docs/development/h02-native-auth-recovery.md) was recorded before implementation. Writable versioned fixture writer/reader configurations now support live profile validation, signed create/dry-run and restore plan/run. Production dispatch remains gated before resource access; this does not complete H02 or authorize real databases.

**Native contract:** root-owned non-writable no-symlink ELF client paths opened/executed by descriptor; protected service-owned passfiles, bounded explicit escaped entries and sealed in-memory child snapshots; no inherited libpq environment or interactive passwords. TCP requires actual SCRAM, with SSL/GSS encryption explicitly disabled within the local-only boundary. Peer requires administered HBA and protected socket ancestry; success alone cannot prove the HBA method. Existing capture, streaming, timeout and process-group behavior is retained. Dry-run/profile resolution open no keys/store; real create retains existing writer custody. Restore opens identity/verifier only, with no recipient or signing-secret resource.

**Recovery/compatibility:** backup connects to the original database; restore version/existence/role/global/create operations connect to explicit maintenance DB, then restore applies schema/archive to the fresh target. Original database/endpoint/major retain the frozen source fingerprint. New signed fixture plan `h02-restore-plan-v3` binds mode, literal endpoint, acting user, maintenance DB, auth choice, tools and passfile paths alongside existing target/security/sections and B05 rollback binding. Canonical bytes/digests are pinned independently for v3 and legacy signed v2. Legacy v1/v2 omit the new field and retain their bytes. Legacy/versioned engine context mismatches and downgrade attempts refuse before native probes/jobs/cluster mutation. A production context is rejected; production writer compatibility remains a separate gate.

**Verification accepted:** **283 workspace tests**, strict locked/offline Clippy and formatting pass. The final frozen sequential native run exits 0 for the new H02 drill and existing M2/M3/M4b on PostgreSQL 16/17/18 (**12 script/major combinations**), preserving all 88 runtime/test/manifest/binary input fingerprints. The dedicated drill uses each image's actual PG16/17/18 clients/libpq, with the host-built CLI loaded through its mounted host runtime (this is test infrastructure, not package/service acceptance). It checks successful escaped SCRAM credentials under poisoned inherited environment; actual trust/MD5/clear-password refusal; peer identity/unsafe sockets; symlink/script tool refusal; no keys/store on live resolution; missing target credentials; changed context/downgrade before jobs/target; and signed portable plus full DR recovery after source loss without recipient/signer files, with row/role/ownership/grant assertions. The existing M2/M3/M4b matrices are rerun for shared service, selection and signed/legacy restore compatibility. Full inventory/retention crash matrices are not rerun by this increment; §40/§42 evidence remains historical.

Development-only harness corrections concerned signed-create result shape, serde report-map ordering versus typed canonical bytes, and replacing a failing auto-removed container restart with socket provisioning at startup. Resource tests resolved this host's `/usr/bin/true` symlink deliberately before testing a trusted ELF descriptor. Review tightened passfile owner-execute-bit refusal to exactly 0600-or-stricter, with a regression assertion. The first final driver was intentionally interrupted during its new PG18 scene for that correction; it is excluded from final evidence. No failed/interrupted run is counted as acceptance.

| File path | Change type in this increment | Description |
|---|---|---|
| [backup-application/src/lib.rs](crates/backup-application/src/lib.rs) | Modified | Store-free scope resolver, maintenance preflight/context port, v3 writer and execution recheck. |
| [backup-domain/src/config_v1.rs](crates/backup-domain/src/config_v1.rs) | Modified pending file | Shared literal connection validation and serializable mode/auth enums. |
| [backup-domain/src/lib.rs](crates/backup-domain/src/lib.rs) | Modified | Exports the native context/connection types and v3 format. |
| [backup-domain/src/restore.rs](crates/backup-domain/src/restore.rs) | Modified | v3 context/validation and frozen v2/v3 canonical tests. |
| [backup-domain/src/fixture.rs](crates/backup-domain/src/fixture.rs) | Modified | Existing test plan explicitly has no native context. |
| [backup-local/src/lib.rs](crates/backup-local/src/lib.rs) | Modified (test only) | Existing plan persistence test explicitly has no context. |
| [backup-postgres/src/lib.rs](crates/backup-postgres/src/lib.rs) | Modified | Configured adapter, maintenance/target routes and explicit globals/create DB selection. |
| [backup-postgres/src/tools.rs](crates/backup-postgres/src/tools.rs) | Modified | Shared version parser; legacy subprocess behavior retained. |
| [backup-postgres/src/native.rs](crates/backup-postgres/src/native.rs) | Added | Protected descriptor resources, SCRAM/peer environment, sealed passfile and safety tests. |
| [backupctl/src/access.rs](crates/backupctl/src/access.rs) | Modified pending file | Enables only the specified writable fixture native operations. |
| [backupctl/src/native.rs](crates/backupctl/src/native.rs) | Added | Explicit required resources and reader/writer custody dispatch. |
| [backupctl/src/main.rs](crates/backupctl/src/main.rs) | Modified | Shared restore dispatcher/report rendering with explicit adapter/store. |
| [backupctl/src/backup.rs](crates/backupctl/src/backup.rs) | Modified | Adapter injection while preserving legacy defaults. |
| [backupctl/src/output.rs](crates/backupctl/src/output.rs) | Modified pending file | Static safe native-context refusal. |
| [backupctl/tests/config_reports.rs](crates/backupctl/tests/config_reports.rs) | Modified pending file | Required-resource refusal within the exhaustive role/mode matrix. |
| [tests/h02_native_auth_recovery.sh](tests/h02_native_auth_recovery.sh) | Added executable | Actual PG16/17/18 authentication and source-loss recovery acceptance. |
| [h02-native-auth-recovery.md](docs/development/h02-native-auth-recovery.md) | Added | Precise native/resource/plan compatibility contract. |
| [h02-config-access-reports.md](docs/development/h02-config-access-reports.md) | Modified pending file | Explicit native follow-up supersedes earlier availability gate. |
| [README.md](README.md) | Modified | Simple delivered behavior, release limit and handoff. |
| [project.md](project.md) | Modified | Current status, evidence, scope and next increment. |
| [session-log.md](session-log.md) | Appended only | Audit and verification outcome. |

**Next logical step:** H02 validated key bootstrap/custody and command-specific key access, followed by descriptor/resource/service hardening and true snapshot reads. H03 packaging, H04 CI/guides, H05 review and V01–V03 remain required. Seven production CLI task IDs still remain because H02 is partial; API/UI/platform counts are unchanged. Production enablement and T03 stay open. All prior H01/H02 uncommitted edits are preserved; no dependency package/version, schema, frozen artifact, flow, config example, deployment file, commit or push change is introduced here.


### H02 native increment acceptance

Final native acceptance completed at 11:02 Asia/Tehran on 2026-11-15. The new drill passes all three majors with successful SCRAM/peer, all three refused fallback methods per major, safe resources/context checks and both portable and full DR source-loss recovery. M2/M3/M4b each pass all three majors with legacy plans, selective/section restore, signed authentication/forgery/source binding and DR without signing custody. The pre-correction/interrupted runs are excluded. Existing `rage` locale warnings remain visible in the M4b log; its complete assertions and exit status pass.

Ephemeral evidence: `/tmp/parsbackup-h02-native-{workspace,clippy,build}.log`, `/tmp/parsbackup-h02-native-h02_native_auth_recovery.log`, `/tmp/parsbackup-h02-native-{m2_docker_smoke,m3_docker_smoke,m4b_docker_smoke}.log` and `/tmp/parsbackup-h02-native-inputs.sha256`. These are local test evidence, not package/service, production or independent interoperability certification. The mounted host loader exists only to run this host-built CLI against real image-native clients; it does not change the product's native environment policy.

The increment touches the 21 files listed above. Combined pending H01/H02 work totals **29 files**, with no staging, commit or push. Final checks cover all input fingerprints, canonical vectors, 201 local document targets/fragments, fenced TOML/JSON, nine shell scripts/45 Python blocks, formatting/diff, append-only log, unchanged November archive/package versions and scoped test cleanup. H02 remains partial; next is validated key bootstrap/custody, followed by filesystem/resource/service hardening and true snapshot reads. Full H/V acceptance is still required before production release.


## 44. H02 validated key bootstrap and custody — 2026-11-15

Started from clean verified checkpoint `34bb8e8`. The operator authorized validated key bootstrap/custody. Recorded the [declarative key contract](docs/development/h02-key-bootstrap-custody.md) before implementation. No existing key lifecycle operating document/flow was modified. This increment enables versioned fixture writer `key generate/publish` and role-specific `key status`; production continues to refuse all operations except structural checks.

**Bootstrap:** all four destinations and existing protected parent directories are checked before entropy generation/publication. Secrets/public files retain the existing crypto encoding and exact 0600/0644 creation modes. New generation order is identity, signing seed, recipient, verifier. Anonymous destination-local staging is fully written, synced and parsed/pair-checked before linking any final name with no-overwrite semantics. No directory auto-creation, existing-file replacement or secret rollback is attempted. Publish validates both seeds and any existing public halves before deriving missing public halves; matching public files are retained, making public recovery idempotent. A crash leaving one secret needs operator inspection; no second secret is silently invented.

**Descriptors/ownership:** no-follow parent traversal, protected root/service ancestry, service-owned private files, trusted public files, bounded key-file reads and dev/inode alias refusal. Unique directory descriptors use sorted nonblocking shared/exclusive advisory locks, creating no lock files or alternate store lock domain. Crypto descriptor entry points share the frozen parser and never re-open validated key pathnames. The local adapter adds one dependency edge to the already locked workspace `zeroize` package for temporary secret encodings; no package/version changes. Linux anonymous-file staging/procfs support is explicit; unsupported filesystems refuse before final names.

**Custody:** status loads exactly writer four/reader two/public one/inventory zero resources; read-only status is allowed without store/scratch/native access. Real versioned create loads validated writer keys before opening the store. Restore loads identity/verifier only, including when invoked with writer configuration; its native setup also removes forbidden writer-only alias probes. Dry-run, profile and keyless inventory boundaries remain key-free. Authenticated offline backup reads and true snapshot storage remain unavailable pending their own hardening. Production plan compatibility, resource limits/service containment, full H02 and V acceptance are still separate gates.

**Failure/report contract:** mutation reports contain public `keys` facts plus exact `created`, `pending` and `durability_confirmed` values. Preflight/anonymous-staging failures have null data and no final publication. A handled linked prefix emits `partial`/`KEY_PARTIAL` and exit 1, preserving every published file; failed directory sync explicitly reports unconfirmed durability. Abrupt SIGKILL may produce no envelope, with recovery based on surviving custody. Public facts contain role/path/suite/mode and existing 16-hex recipient/signer ID, never seed bytes. Legacy bare JSON and key behavior remain compatible.

**Verification accepted:** final fast gates pass **293 workspace tests**, strict locked/offline Clippy and formatting. The final sequential H02 bootstrap, H02 native recovery, M4a key lifecycle and M4b signing runs all exit 0 on unchanged frozen inputs; the three native matrices each cover PG16/17/18 (**nine script/major combinations**) plus the host bootstrap fault/crash drill. Nine custody unit tests cover prevalidation, unsafe/aliased/FIFO/oversized/permission inputs, descriptor replacement, pair mismatch, locks, distinct parents, exact partial prefixes, public recovery and a late occupied destination. A PostgreSQL adapter test checks that restore excludes writer-only native paths without changing bound context. The full-process drill proves role/read-only/production behavior, public facts/privacy, competing CLI writers, actual four link failures, anonymous-stage and directory-sync faults, four SIGKILL boundaries and preserved-seed recovery. The native H02 drill uses new protected bootstrap and tests foreign ownership before store creation. Final H02/native/key-lifecycle/signing matrix acceptance is recorded below when complete.

Development corrections: one missing method name (`HybridRecipient::as_bytes`), a test calling a nonexistent trait method, a multi-directory fixture inheriting the host's group-writable umask, and one shell heredoc delimiter collision were corrected after inspection. The unsafe fixture was correctly refused by the implementation. Earlier exploratory/partial runs do not count as final acceptance. No production, key-format/suite, frozen artifact/plan/fingerprint, inventory-schema, flow, config-example, deployment file, commit or push change is introduced here.

| File path | Change type | Description |
|---|---|---|
| [backup-crypto/src/keystore.rs](crates/backup-crypto/src/keystore.rs) | Modified | Shared parser and bounded descriptor key loader. |
| [backup-crypto/src/signing.rs](crates/backup-crypto/src/signing.rs) | Modified | Descriptor signing/verifying loader using the existing grammar. |
| [backup-local/src/custody.rs](crates/backup-local/src/custody.rs) | Added | Protected role-specific custody, staged bootstrap, locks/receipts and unit tests. |
| [backup-local/src/lib.rs](crates/backup-local/src/lib.rs) | Modified | Export key operation/custody entry points. |
| [backup-local/src/store.rs](crates/backup-local/src/store.rs) | Modified | Allow the local custody module to compose already-loaded keys with the existing store. |
| [backup-local/Cargo.toml](crates/backup-local/Cargo.toml), [Cargo.lock](Cargo.lock) | Modified | Reuse the existing locked zeroize dependency. |
| [backup-postgres/src/lib.rs](crates/backup-postgres/src/lib.rs) | Modified | Restore adapter omits writer-only key paths from native metadata probes. |
| [backup-postgres/src/native.rs](crates/backup-postgres/src/native.rs) | Modified (test only) | Prove exact native restore custody and unchanged context. |
| [backupctl/src/keys.rs](crates/backupctl/src/keys.rs) | Added | Versioned public key facts and partial receipts. |
| [backupctl/src/access.rs](crates/backupctl/src/access.rs) | Modified | Enable protected key commands within existing mode/role/read-only gates. |
| [backupctl/src/main.rs](crates/backupctl/src/main.rs) | Modified | Register the key dispatcher. |
| [backupctl/src/backup.rs](crates/backupctl/src/backup.rs) | Modified | Accept a protected store without reopening key paths. |
| [backupctl/src/native.rs](crates/backupctl/src/native.rs) | Modified | Compose protected writer/reader custody with native operations. |
| [backupctl/src/output.rs](crates/backupctl/src/output.rs) | Modified | Static key safety/invalid/occupied/busy/failure/partial codes. |
| [backupctl/tests/config_reports.rs](crates/backupctl/tests/config_reports.rs) | Modified | Required-resource key refusals in exhaustive capability matrix. |
| [tests/h02_key_bootstrap_drill.sh](tests/h02_key_bootstrap_drill.sh) | Added executable | Actual process contention, syscall faults and four SIGKILL boundaries. |
| [tests/h02_native_auth_recovery.sh](tests/h02_native_auth_recovery.sh) | Modified | Native acceptance now bootstraps protected keys and checks foreign ownership. |
| [h02-key-bootstrap-custody.md](docs/development/h02-key-bootstrap-custody.md) | Added | Exact bootstrap/custody/resource/report/crash contract. |
| [h01-production-policy.md](docs/development/h01-production-policy.md), [h02-config-access-reports.md](docs/development/h02-config-access-reports.md), [h02-native-auth-recovery.md](docs/development/h02-native-auth-recovery.md) | Appended/modified | Link delivered fixture follow-ups without changing historical contracts. |
| [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Modified/appended | Simple behavior, scope/evidence, next handoff and immutable audit. |

**Next logical step:** H02 filesystem/resource/service hardening and true snapshot reads. Record concrete decrypted-size/free-space/scratch/native-output/cancellation limits before their writers; preserve existing process-group and artifact activity ownership. Deliver protected external scratch and source-free authenticated discovery/verification for quiescent read-only stores without store writes/locks/migrations. Full H02/H03–H05/V01–V03 and production plan/writer compatibility remain required; seven production CLI task IDs remain because H02 is partial. T03 stays open. No commit or push requested.


### H02 key increment acceptance

Accepted 2026-11-15 after final frozen verification. All **91 runtime/test/manifest/binary fingerprints** still match. The host drill verifies four actual handled link failures, pre-publication anonymous-stage sync failure, post-link directory-sync failure with honest durability status, competing CLI writers and four actual SIGKILL boundaries. Every surviving linked prefix is preserved; public-half recovery never replaces seeds. New-key native recovery and both legacy lifecycle/signing matrices pass on PostgreSQL 16/17/18. No inventory/retention crash matrices or M1/M2/M3/M4a encryption smoke are rerun by this scoped increment; prior acceptance remains historical. Existing legacy `rage` locale warnings are visible and did not fail the completed assertions.

Ephemeral local evidence: `/tmp/parsbackup-h02-keys-{workspace,clippy,build}.log`, `/tmp/parsbackup-h02-keys-h02_key_bootstrap_drill.log`, `/tmp/parsbackup-h02-keys-h02_native_auth_recovery.log`, `/tmp/parsbackup-h02-keys-m4a_key_drill.log`, `/tmp/parsbackup-h02-keys-m4b_docker_smoke.log`, `/tmp/parsbackup-h02-keys-inputs.sha256`. These are fixture/review evidence, not package/service, production or independent cryptographic certification. Earlier development runs are excluded from final acceptance.

Final scope is exactly **25 unstaged files**, listed above. Documentation checks pass 234 local file targets/fragments and fenced TOML/JSON; ten shell scripts/46 embedded Python blocks pass syntax. Formatting/diff, unchanged package versions with only the local zeroize edge, existing lifecycle operating document and immutable November archive, append-only log below rotation threshold, untouched HEAD `34bb8e8` and scoped process/container/private-directory cleanup are checked. H02 remains partial and seven production CLI task IDs remain. Production and T03 stay gated; no commit or push.


## 45. H02 filesystem and resource hardening — 2026-11-15

The operator authorized this increment while the accepted key-bootstrap work remained pending. Inspected the store's native/stage/scratch/inventory and custody boundaries and recorded the [declarative filesystem/resource contract](docs/development/h02-filesystem-resources.md) before implementation. This increment covers currently enabled writable versioned fixtures; it does not complete H02 or enable production/snapshot commands.

**Filesystem:** descriptor-relative, no-follow/nonblocking traversal validates root/service ancestry without group/other write, service-owned private store/layout directories and single-link private regular inventory/sidecar files. Only native writer opening may create the final root, at 0700 under an existing protected parent. No recursive parent creation or permission repair. Held root descriptors anchor backend paths and survive store/stage/plaintext/job/artifact-use lifetimes. Tests rename/replace the configured root, write/read the original inventory through the held root, run an actual child against the descriptor path and prove contention on the same physical activity lock. Existing activity/scope/artifact lock names and lifecycle remain unchanged. Used key-parent descriptor ancestry cannot enter the store, including aliases, and reader-only custody remains exact. Recovery and rebuild receipts translate internal descriptor paths to usable configured paths; full-process tests check returned files after the CLI exits.

**SQLite compatibility:** new inventories are explicitly created at 0600, then opened without CREATE; existing files are not chmodded/replaced. Ordinary paths retain SQLite's no-follow flag. Exact current-process live directory descriptor parents allow the trusted procfs ancestor only after a separate no-follow/nonblocking final database open. This avoids SQLite rejecting the pinned root itself. SQLite's own database/journal pathname behavior still applies; moving the directory after a connection opens does not promise transaction continuity. Root/service and same-UID namespace mutation remain trusted, as specified by the contract. No VFS, schema, migration or second lock domain is added.

**Resources:** optional closed `[resources]` defaults to 64-GiB payload, 8-MiB globals, 65-GiB + 16-MiB per-stage ciphertext/metadata, 64-GiB + 16-MiB aggregate live plaintext views per store handle and 64-MiB observed free-space reserve. Validation enforces the contract's exact ranges. Plaintext writes, shared ciphertext/metadata stage writes and shared scratch writes reject a whole incoming buffer before any over-limit byte. Scratch charges release after owned cleanup, retain charges if cleanup fails, and refund short/failed writes precisely. Available filesystem bytes are observed before each guarded data write; this is not an OS reservation, cross-process quota or bound on SQLite/PostgreSQL growth. Native store hashing and ciphertext inspection have conservative checked per-file bounds; manifests retain 64 KiB. Existing bounded native capture and per-tool process-group deadlines remain; no whole-job cancellation/service containment claim is added.

**Reports/compatibility:** static `FILESYSTEM_UNSAFE`, `RESOURCE_LIMIT` and `DISK_RESERVE_LOW` codes reveal no raw adapter diagnostics. Age's header serializer flattens writer errors into text, so the resource writer records only its own generated code across that boundary instead of classifying arbitrary text. A regression test covers both encrypted-header limit and reserve refusals. A rebuild crash leaving a hard-linked current index is deliberately refused by versioned preflight for inspection, without unlinking aliases. Legacy constructors retain their limits/error contracts. Artifact/key/plan/fingerprint bytes, canonical vectors, package versions, production gate and existing operating flows remain unchanged. The only pending lockfile edge remains the earlier local `zeroize` dependency. Native jobs still have the existing generic partial-effect limitation; null data never asserts zero side effects.

**Fast verification:** all **304 workspace tests**, strict locked/offline Clippy, formatting and diff checks pass. Added tests cover closed/ranged resources; exact file/shared budgets and whole-buffer refusal; reserve boundaries/overflow and failed-write refunds; encrypted-header error preservation; unsafe ancestry/root/layout/inventory symlinks, FIFO and hard links; missing-parent refusal; root replacement/child access/SQLite/lock identity; key-directory aliases; private inventory creation; job/artifact/view descriptor lifetimes; overlapping scratch quota, release and reduced plaintext limits; bounded sparse ciphertext inspection; CLI structural-only checks and safe filesystem reports. The updated native drill passes PostgreSQL 16/17/18 protected/foreign/symlink store refusals, payload/globals/stage/reserve failures without publication, scratch/reserve failures without target creation or plaintext leftovers and signed portable/full-DR recovery after source loss. Final frozen regression acceptance follows below; preliminary diagnostic runs are excluded.

### Files changed in this increment

This increment changes 21 files (17 runtime/test files plus four documentation/audit files), preserving prior pending key work. The combined working tree has 36 unstaged files; no staging, commit or push is requested.

| File Path | Change Type | Description |
|---|---|---|
| [backup-domain/src/config_v1.rs](crates/backup-domain/src/config_v1.rs), [backup-domain/src/lib.rs](crates/backup-domain/src/lib.rs) | Modified | Closed optional resource configuration and exported limits. |
| [backup-domain/src/resources.rs](crates/backup-domain/src/resources.rs) | Added | Exact defaults/ranges/ciphertext bounds and structural tests. |
| [backup-inventory/src/lib.rs](crates/backup-inventory/src/lib.rs) | Modified | Private new inventories; descriptor-parent SQLite compatibility with ordinary no-follow behavior retained. |
| [backup-local/src/filesystem.rs](crates/backup-local/src/filesystem.rs) | Added | Protected root/layout, anchored handles, key-parent isolation and boundary/lifetime tests. |
| [backup-local/src/resources.rs](crates/backup-local/src/resources.rs) | Added | Checked shared leases, streaming/reserve enforcement and generated error preservation/tests. |
| [backup-local/src/lib.rs](crates/backup-local/src/lib.rs) | Modified | Store/stage/view/job/artifact root lifetime, bounded hashes and metadata publication budgets. |
| [backup-local/src/custody.rs](crates/backup-local/src/custody.rs) | Modified pending file | Compose validated custody with protected writer/reader store opening. |
| [backup-local/src/stage.rs](crates/backup-local/src/stage.rs), [backup-local/src/scratch.rs](crates/backup-local/src/scratch.rs) | Modified | Plaintext/ciphertext quotas, reserve checks and scratch cleanup/accounting. |
| [backup-local/src/store.rs](crates/backup-local/src/store.rs), [backup-local/src/retention.rs](crates/backup-local/src/retention.rs) | Modified | Legacy defaults and configured recovery paths; keyless retention remains compatible. |
| [backupctl/src/access.rs](crates/backupctl/src/access.rs), [backupctl/src/inventory.rs](crates/backupctl/src/inventory.rs) | Modified | Anchor writable versioned keyless operations/recovery after existing authorization gates. |
| [backupctl/src/output.rs](crates/backupctl/src/output.rs) | Modified | Static filesystem/resource/reserve errors. |
| [backupctl/tests/config_reports.rs](crates/backupctl/tests/config_reports.rs) | Modified | Resource schema/refusal controls and explicitly protected writable fixtures. |
| [tests/h02_native_auth_recovery.sh](tests/h02_native_auth_recovery.sh) | Modified | All-major native protected-store, low-budget/reserve and clean-failure controls. |
| [h02-filesystem-resources.md](docs/development/h02-filesystem-resources.md) | Added | Pre-implementation boundary, budgets, limitations and acceptance contract. |
| [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Appended/surgical | Simple behavior, current handoff, complete scope/evidence and append-only audit. |

**Next logical implementation:** H02 true snapshot reads with protected external scratch, bounded source-free discovery and signature/checksum/archive verification on a quiescent read-only store. Store reads must avoid writable locks, migrations, inventory enrichment and store-local scratch. Record the exact snapshot/resource/lock/report contract before enabling commands. Remaining H02 service/process cancellation/containment, structured native failure receipts and production plan/writer compatibility are separate acceptance work; H03–H05/V01–V03 and T03 remain open. Seven production CLI task IDs remain because H02 is partial. No deployment/flow change, commit or push.


### H02 filesystem/resource increment acceptance

Accepted 2026-11-15 after final verification. **304 workspace tests**, strict locked/offline Clippy, formatting and diff checks pass. Final H02, M2, M3, M4a key-lifecycle, M4b signing and B06 retention drivers each exit 0 across PostgreSQL 16/17/18. The M5a driver is run as three independent loop-only selections (one per major); each exits 0 and completes its own major's full assertions. Together these are **21 native script/major combinations plus the host key-bootstrap drill**, with four actual bootstrap SIGKILL boundaries, 18 rebuild filesystem crash boundaries and 24 deletion crash boundaries, alongside native dump/restore ownership races. Versioned source-loss portable/full-DR recovery, all low-limit/reserve controls on a bounded 256-MiB tmpfs, legacy plan/selection/key-loss/signature behavior, migration/corruption/privacy and keyless deletion recovery pass.

Final review also corrected rebuild receipts that would otherwise return an expired procfs path. A complete CLI regression now prepares/confirms a versioned rebuild in separate processes, verifies its saved previous-inventory path still exists after exit, and checks configured recovery paths. The first cleanup fixture correctly refused a non-UUID directory; the final fixture uses the required UUID. The final 304-test/Clippy/native acceptance uses the corrected code. All product/harness/binary inputs remain unchanged during the completed final native runs; the sole early fixture-only correction changed no product binary or native-consumed input. All **94 final runtime/test/manifest/binary fingerprints** and three verified loop-only M5a driver fingerprints match at acceptance. Earlier diagnostic, pre-receipt and intentionally interrupted combined M5a runs are excluded. The three loop drivers differ only in repository selection and major-loop selection; their hard-coded final all-major banner is not counted as additional coverage. Existing legacy `rage` locale warnings remain visible and do not fail the completed assertions.

Ephemeral local evidence: `/tmp/parsbackup-h02-fs-{workspace,clippy,build,config-reports}.log`, `/tmp/parsbackup-h02-fs-{h02_native_auth_recovery,h02_key_bootstrap_drill,m2_docker_smoke,m3_docker_smoke,m4a_key_drill,m4b_docker_smoke,m5b_retention_drill}.log`, `/tmp/parsbackup-h02-fs-m5a-{16,17,18}.log`, `/tmp/parsbackup-h02-fs-inputs.sha256`, `/tmp/parsbackup-h02-fs-variants.sha256`, `/tmp/parsbackup-h02-fs-scope.json` and `/tmp/parsbackup-h02-fs-doc-audit.py`. These are local fixture/review evidence, not production, package/service or independent cryptographic certification.

The final scope is the 21-file increment listed above and **36 combined unstaged files** with preserved key-bootstrap work. Documentation checks pass 258 local targets/fragments, fenced TOML/JSON and ten shell scripts/46 Python blocks. Final audits verify the frozen inputs/drivers, private fixture/container/process cleanup, no diagnostic code in source/binary, unchanged HEAD `34bb8e8`, existing lifecycle operating document and November archive, append-only log below rotation threshold, unchanged inventory schema/artifact/key/plan/fingerprint formats and package versions with only the earlier local `zeroize` edge. The versioned configuration schema is intentionally extended by optional `[resources]`; no configuration example is changed. No staging, commit, push or deployment change. H02 remains partial; review/commit the combined checkpoint before the next implementation, true snapshot reads with external scratch. Production and T03 remain gated.


### Combined key/filesystem checkpoint review — 2026-11-15

The operator requested reviewing and committing the verified checkpoint. Reviewed all 36 pending files across protected descriptor key parsing, role-specific custody, anonymous/no-overwrite publication and partial/durability receipts, native reader-only setup, root/layout/inventory validation, SQLite descriptor compatibility, stage/scratch/free-space limits and cleanup/lock lifetimes, safe reports/configured paths, tests and contracts. No blocking findings. The documented Linux/procfs, same-UID trust, per-handle quota, observed-reserve and hard-linked-rebuild refusal limits match the code; full H02, production/snapshot access, service containment, native failure receipts and T03 remain gated.

All 94 final runtime/test/manifest/binary and three loop-only-driver fingerprints still match the accepted 304-test/strict-Clippy and 21 native script/major evidence, including four bootstrap, 18 rebuild and 24 deletion crash boundaries. Earlier diagnostic/interrupted runs stay excluded. Only README, this handoff and the append-only log are updated for the review/commit request; no runtime/harness change or regression rerun is required. Final formatting/diff, 258 local document targets/fragments, fenced TOML/JSON, ten shell scripts/46 Python blocks, unchanged inventory/artifact/key/plan formats/package versions/lifecycle/archive, scoped cleanup and exact staged blob/36-file commit checks accompany the checkpoint. No push is requested. Next logical implementation is H02 true snapshot reads with protected external scratch.


## 46. H02 true snapshot reads with external scratch — 2026-11-16

Started from clean checkpoint `da35644` after the operator authorized this increment. Inspected authorization, protected root/key custody, artifact authentication, inventory/reconciliation and scratch/native readers; recorded the [snapshot contract](docs/development/h02-snapshot-reads.md) before code. This increment enables only versioned read-only fixture commands. Production and writable offline backup commands retain their gates; H02 remains partial.

**Capability:** reader/public backup list is key-free; signature verification uses only the verifier, even when a reader's identity/scratch is unusable. Reader inspect/checksum/archive uses identity/verifier and explicit protected external scratch. Inventory check/list/verification and job list/inspect are key-free for permitted read-only roles. Configured source/passfile and writer-only keys are never probed by these paths. Existing report shapes and rollback warnings remain; no audit/observation/job enrichment occurs even when command-level `--read-only` is omitted. Copied deletion tombstones override surviving complete files, including signature-only checks.

**Filesystem/limits:** a private snapshot facade keeps the mutable store handle internal, skips activity/artifact locks and retains pinned root/external scratch descriptors through read/view lifetimes. Snapshot store, scratch and used key-parent trees are checked for descriptor ancestry overlap in both directions. Read-only 0500 directories/0400 files are accepted; no creation/repair/migration/recovery occurs in the store. Catalogue reads cap at 4096 canonical UUID entries and eight private single-link regular components per artifact before materialization. Existing public/signature/manifest and configured payload/globals bounds apply; unsafe/extra/special/aliased components refuse. Optional inventory is capped at 64 MiB, 32 user tables and 100000 aggregate rows. All journal/WAL/SHM sidecars and WAL headers refuse. Views/triggers/virtual tables refuse before binding or row queries; user-table filtering treats underscores literally. A separate immutable SQLite URI open avoids even database read locks; URI path bytes are escaped, existing read-only/writable opens remain unchanged, and supported historical schemas are never migrated. Inventory remains local untrusted history. Mount aliases hiding backing ancestry are outside the visible-inode-walk guarantee; operators supply disjoint backing trees. A quiescent operator-supplied copy is required; live-copy consistency is not certified.

**External scratch/native:** authenticated reads require an existing private external root with protected ancestry. Fresh UUID directories/files use 0700/0600 beneath the held descriptor; only owned directories are cleaned on success/error and pre-existing siblings are preserved. Existing per-file/shared-view quota and observed free-space reserve apply. Cleanup failure retains charge; crash leftovers and secure erasure remain explicit limitations. Archive checks authenticate first, validate trusted root-owned ELF `pg_restore` against the signed source major, then decrypt/list the archive and compare the signed TOC digest. The offline native policy rejects all database commands and carries no passfile/key paths; source loss is irrelevant. Native capture/deadline limits are retained; whole-service cancellation/containment is separate work.

### Files changed

Exact 26-file increment; no dependencies, package versions, inventory schema, artifact/key/plan/fingerprint formats, existing operating flows or config examples change. No staging, commit, push or deployment is requested.

| File Path | Change Type | Description |
|---|---|---|
| [backup-local/src/snapshot.rs](crates/backup-local/src/snapshot.rs) | Added | Bounded read-only facade, exact custody, immutable inventory reads and external scratch isolation. |
| [backup-local/src/filesystem.rs](crates/backup-local/src/filesystem.rs) | Modified | Snapshot/external descriptor opening and two-way inode ancestry checks. |
| [backup-local/src/custody.rs](crates/backup-local/src/custody.rs) | Modified | Verifier-only or reader-only snapshot custody without unused resources. |
| [backup-local/src/lib.rs](crates/backup-local/src/lib.rs) | Modified | Lock-free snapshot claims, authenticated layout/lifecycle checks and retained read descriptors. |
| [backup-local/src/scratch.rs](crates/backup-local/src/scratch.rs) | Modified | Pinned external scratch and retained cleanup/quota ownership. |
| [backup-local/src/inventory.rs](crates/backup-local/src/inventory.rs), [backup-local/src/reconcile.rs](crates/backup-local/src/reconcile.rs), [backup-local/src/rollback.rs](crates/backup-local/src/rollback.rs) | Modified | Explicit immutable snapshot inventory/discovery/history paths. |
| [backup-local/src/store.rs](crates/backup-local/src/store.rs), [backup-local/src/retention.rs](crates/backup-local/src/retention.rs) | Modified | Preserve ordinary store defaults and writable activity-claim compatibility. |
| [backup-inventory/src/lib.rs](crates/backup-inventory/src/lib.rs) | Modified | Immutable read-only URI opening, sidecar/header/file/table/row bounds and regression tests. |
| [backup-local/tests/signed_write_path.rs](crates/backup-local/tests/signed_write_path.rs) | Modified | Exact key use, root/scratch replacement, missing inventory, cleanup/quota, unsafe components and catalogue cap tests. |
| [backup-postgres/src/lib.rs](crates/backup-postgres/src/lib.rs), [backup-postgres/src/native.rs](crates/backup-postgres/src/native.rs) | Modified | Trusted source-major offline adapter and connection-refusal tests. |
| [backupctl/src/snapshot.rs](crates/backupctl/src/snapshot.rs) | Added | Source-free versioned snapshot command dispatch and offline archive composition. |
| [backupctl/src/access.rs](crates/backupctl/src/access.rs), [backupctl/src/main.rs](crates/backupctl/src/main.rs) | Modified | Enable permitted read-only fixture dispatch after existing authorization gates. |
| [backupctl/src/backup.rs](crates/backupctl/src/backup.rs), [backupctl/src/inventory.rs](crates/backupctl/src/inventory.rs) | Modified | Shared unchanged report formatting and explicit immutable inventory/job readers. |
| [backupctl/src/output.rs](crates/backupctl/src/output.rs) | Modified | Static snapshot/scratch refusal codes. |
| [backupctl/tests/config_reports.rs](crates/backupctl/tests/config_reports.rs) | Modified | Updated exhaustive capability expectations and key-free read-only inventory/job controls. |
| [tests/h02_snapshot_drill.sh](tests/h02_snapshot_drill.sh) | Added executable | Actual PG16/17/18 source-loss, non-root read-only bind mount and syscall-audited snapshot acceptance. |
| [h02-snapshot-reads.md](docs/development/h02-snapshot-reads.md) | Added | Pre-implementation capability, filesystem, resource, scratch and verification contract. |
| [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Modified/appended | Simple behavior, current handoff, full scope/evidence and append-only audit. |

**Next logical step:** review/commit this verified snapshot increment, then define and implement H02 service/process cancellation/containment and structured native failure receipts. Production writer/plan compatibility and full H02 acceptance remain prerequisites to H03–H05/V01–V03. Seven production CLI task IDs still remain because H02 is partial; T03 stays open. No flow or release gate is changed.

### Snapshot increment acceptance

Accepted 2026-11-16 on the corrected final inputs: **309 workspace tests**, strict locked/offline Clippy, formatting and diff checks pass. Final sequential snapshot, H02-native, M2, M3, M4a-key and M4b drivers each exit 0 on PostgreSQL 16/17/18: **18 native script/major combinations**. Snapshot acceptance destroys the source container, then uses a non-root reader with no PostgreSQL server/network and a read-only root/store bind mount. Kernel write refusal, 0500/0400 store layouts, before/after store byte/metadata equality and syscall traces prove no store writes, activity/artifact/SQLite locks, migrations, credential metadata reads or database/network connections. Reader/public exact custody, key-free inventory/jobs, offline source-major TOC checks, authenticated tamper/tombstone refusals before native execution, explicit scratch, sibling preservation, owned cleanup, quota/reserve failures and trusted-tool refusal pass. Root/scratch replacement, optional missing inventory, hard links/symlinks/FIFOs, bounded catalogues, URI metacharacters, literal-underscore user-table caps, table/row limits, schema-program refusal before binding and old-reader compatibility are covered by unit/full-process checks.

Final review corrected the SQLite user-table filter from wildcard `LIKE` to literal-underscore `GLOB` and rejects views/triggers/virtual table definitions before binding or row queries. The final 309-test/Clippy and all 18 native combinations use those corrected inputs. Earlier diagnostic/fixture attempts, preliminary pre-filter results and the interrupted legacy run that overlapped a rebuild are excluded. After that avoidable overlap, all final builds/checks/drills ran sequentially with **97 runtime/test/manifest/binary fingerprints** unchanged throughout native acceptance. Existing legacy `rage` locale warnings remain visible and do not fail completed assertions. No bootstrap, rebuild or retention crash matrix is rerun by this snapshot increment; their checkpoint evidence remains historical.

Ephemeral evidence: `/tmp/parsbackup-h02-snapshot-{workspace,clippy,build,native,h02_native_auth_recovery,m2_docker_smoke,m3_docker_smoke,m4a_key_drill,m4b_docker_smoke}.log`, `/tmp/parsbackup-h02-snapshot-inputs.sha256`, `/tmp/parsbackup-h02-snapshot-hash-check.log`, `/tmp/parsbackup-h02-snapshot-scope.json` and `/tmp/parsbackup-h02-snapshot-doc-audit.py`. These are local fixture/review evidence, not production, service/package or independent cryptographic certification. The new driver's `native.log` is the snapshot drill; the separate H02-native log covers authentication/maintenance recovery.

Documentation checks pass **287 local file targets/fragments**, fenced TOML/JSON and **11 shell scripts/47 Python blocks**. Final audits check exact 26-file unstaged scope, full handoff file inventory, unchanged HEAD `da35644`, no staged changes/diagnostic marker, 97 fingerprints, scoped private-fixture/container/process cleanup, unchanged dependency manifests/lockfile, inventory schema, operating lifecycle document and immutable November archive, plus append-only log below rotation threshold. No artifact/key/plan/fingerprint/configuration format or package-version change. Production remains disabled, H02 partial and T03 open. Next is checkpoint review/commit, then remaining H02 service/process cancellation/containment, native failure receipts and production writer/plan compatibility before full H acceptance.

### Snapshot checkpoint review — 2026-11-16

The operator requested review and commit of the verified snapshot increment. Reviewed the full 26-file scope: role/production/read-only gates, key-free/verifier-only/reader-only custody, bounded no-follow catalogue/component validation, immutable SQLite URI escaping and sidecar/header/schema-program/table/row refusals, lifecycle/rollback history, lock-free snapshot claims, pinned store/scratch lifetimes and owned cleanup/quota/reserve behavior, source-free trusted-ELF source-major archive checks, safe unchanged report shapes, unit/full-process/native drill coverage and declared limitations. No blocking findings. Quiescent-copy consistency, visible-ancestry mount limits, same-UID/root trust, per-handle budgets and crash plaintext leftovers remain explicit; full H02/service containment/native failure receipts/production compatibility and T03 stay open.

All 97 runtime/test/manifest/binary fingerprints still match the accepted 309 workspace tests, strict locked/offline Clippy and final 18 native script/major combinations on PostgreSQL 16/17/18. Preliminary/interrupted attempts remain excluded. Only README, this handoff and the append-only log are updated for this review request; no runtime/harness changes or regression rerun. Formatting/diff, 287 local document targets/fragments, fenced TOML/JSON, 11 shell scripts/47 Python blocks, full scope inventory, unchanged dependencies/schema/formats/operating lifecycle/archive, append-only log and scoped cleanup pass. Preparing one local checkpoint commit of exactly the reviewed 26 files, with staged scope/blob and post-commit parent/tree/clean-worktree verification. No push requested. Next logical implementation is remaining H02 service/process cancellation/containment and structured native failure receipts, followed by production writer/plan compatibility and full H02 acceptance.

## 47. H02 cancellation and process ownership — 2026-11-16

The operator requested the next H02 step, then directed that H02 stop expanding into repeated small milestones. Started from clean snapshot checkpoint `7f0c79e`. Inspected the H01 acceptance map and existing process-group/deadline/job/drop ownership before recording the [declarative cancellation contract](docs/development/h02-cancellation.md). This is one bounded closing checkpoint: real CLI signal cancellation, process-group ownership and honest create/restore failure facts. Dedicated-user systemd sandboxing, cgroup hard stops, packaging and timers belong to H03. Production remains disabled.

**Cancellation:** CLI SIGINT/SIGTERM handlers only set one sticky lock-free atomic flag after argument parsing. Ordinary control flow checks it at native spawn/wait, read/hash/write and create/restore/retention safe points. Handled cancellation returns exit 1 and `OPERATION_CANCELLED`; repeated signals are idempotent. Normal cleanup uses existing failed jobs; SIGKILL retains existing inherited-claim/recovery/interrupted semantics. No new state/schema, dependency, configuration flag, worker runtime or whole-job deadline. SQLite busy waits, blocking kernel calls and arbitrary caller code retain their stated limits. Durable publication/deletion ordering is not interrupted by signal-handler I/O; an operation past its final safe point may complete.

**Process ownership:** one owned native group guard kills its process group and reaps the direct child before caller claims can drop. Linux `waitid(WNOWAIT)` observes exit while retaining the leader PID through group cleanup, avoiding reuse between reap and signal; EINTR retries polling. Capture stdin/stdout/stderr threads and streaming watchdogs join. A stalled producer is killed promptly when its consumer fails or panics, with the original sink failure preserved. Existing environment/ELF/passfile, output caps and per-tool timeouts remain. This covers trusted clients and their same-group descendants; deliberately escaped sessions, parent SIGKILL and service-wide containment remain H03 cgroup work. PostgreSQL server workers/committed effects are outside the client's process group.

**Failure facts:** application create/restore scopes attach a typed receipt after acquiring the real job. It contains `job_id`, `artifact_id` and `effects`: `preparation_only`, `artifact_may_be_published` or `database_may_be_modified`. These describe conservative attempts, never a fabricated durable outcome or zero filesystem effects. Json-v1 uses error data and error/partial status accordingly; pre-job errors retain null data, existing deletion partitions and all success data remain unchanged. Human failures add safe job references. Job terminal recording can fail; no job-state claim appears in the receipt. Restore error chaining now preserves cancellation codes instead of flattening the cause. No SQL, credentials, database name or native diagnostic is exposed by the receipt.

**Scope and release boundary:** existing fixture v2/v3 canonical plans, mode/context mismatch refusal and the production gate are unchanged. H01's requirement to define a production format/canonical bytes before adding a production writer remains mandatory; no such writer is enabled here. Existing explicitly unavailable versioned writable offline backup/retention dispatch remains unavailable; legacy fixture behavior is preserved. Closing the fixture hardening foundation does not assert full production command availability. V01/V03 must verify/resolve production command compatibility before release; H03 may package and exercise the gated fixture build now.

### Files changed

Exactly 20 files; no staging, commit, push or deployment is requested. Large application diff blocks are closure indentation around existing create/restore bodies, with the semantic additions described above.

| File Path | Change Type | Description |
|---|---|---|
| [backup-application/src/control.rs](crates/backup-application/src/control.rs) | Added | Sticky cancellation, checked reader and typed failure facts. |
| [backup-application/src/lib.rs](crates/backup-application/src/lib.rs) | Modified | Safe points and actual-job create/restore failure scopes; preserved error chains. |
| [backup-inventory/src/job.rs](crates/backup-inventory/src/job.rs) | Modified | Expose the already-created restore job ID without schema/state changes. |
| [backup-local/src/lib.rs](crates/backup-local/src/lib.rs) | Modified | Job IDs and cooperative bounded/hash reads. |
| [backup-local/src/reconcile.rs](crates/backup-local/src/reconcile.rs), [backup-local/src/scratch.rs](crates/backup-local/src/scratch.rs) | Modified | Cooperative catalogue/ciphertext readers. |
| [backup-local/src/resources.rs](crates/backup-local/src/resources.rs) | Modified | Cancellation at data writes, including safe code preservation through age headers. |
| [backup-local/src/retention.rs](crates/backup-local/src/retention.rs) | Modified | Safe checks before intent and between candidates; existing partial partitions retained. |
| [backup-postgres/src/process.rs](crates/backup-postgres/src/process.rs) | Added | Owned child/group cleanup, no-reap exit observation, cancellation/deadline polling. |
| [backup-postgres/src/tools.rs](crates/backup-postgres/src/tools.rs), [backup-postgres/src/lib.rs](crates/backup-postgres/src/lib.rs) | Modified | Joined capture/stream runners, prompt sink-error/panic cleanup and blocked-stdin tests. |
| [backupctl/src/signals.rs](crates/backupctl/src/signals.rs) | Added | Minimal SIGINT/SIGTERM request handlers. |
| [backupctl/src/main.rs](crates/backupctl/src/main.rs), [backupctl/src/output.rs](crates/backupctl/src/output.rs) | Modified | Real signal caller, static codes and safe receipt/status rendering. |
| [backupctl/tests/store_concurrency.rs](crates/backupctl/tests/store_concurrency.rs) | Modified | Actual signal/job/lock/cleanup tests and post-publication terminal-write fault receipt. |
| [tests/h02_cancellation_drill.sh](tests/h02_cancellation_drill.sh) | Added executable | PG16/17/18 captured/dump/partial-restore cancellation and source-loss recovery. |
| [h02-cancellation.md](docs/development/h02-cancellation.md) | Added | Pre-implementation caller, safe-point, ownership, report and finish-line contract. |
| [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Modified/appended | Behavior, bounded closure/handoff, full scope and immutable audit. |

### Cancellation checkpoint acceptance and handoff

**Accepted 2026-11-16:** all **313 workspace tests**, strict locked/offline Clippy, formatting and diff checks pass. Four added tests cover prompt sink-error/panic cleanup, blocked captured stdin, real SIGINT/SIGTERM with failed job/lock/stage cleanup, and a post-publication SQLite terminal-update fault. That fault leaves a published artifact and a staged job; the receipt conservatively reports possible publication without inventing a terminal job state or exposing injected SQL.

Final sequential native verification passes the new cancellation drill, H02 authentication/recovery and H02 snapshot drill on PostgreSQL **16/17/18: nine script/major combinations**. Cancellation is delivered to the actual CLI during a stalled captured preflight, a lock-blocked dump and a restore copying into a deliberately delayed CHECK constraint. Assertions cover exit/code/error-versus-partial receipts, real job IDs/states, reaped direct children, clean scratch/stages, subsequent same-scope acquisition, preserved partial target and signed source-loss recovery with an independently checked row. Authentication/recovery preserves portable/full-DR recovery and custody; snapshot regression preserves non-root read-only-media and syscall-audit guarantees. Native clients are the cached PostgreSQL images' actual matching executables; the mounted host loader remains fixture infrastructure, not package acceptance.

All **101 runtime/test/manifest/binary fingerprints** match after the final sequential build/drill run. No runtime or harness changes occur during those accepted runs. Preliminary fixture-only corrections (minimal-image shell signals, a stoppable non-PID1 postmaster, descriptor-executed client activity matching, saved plan ID, deterministic restore barrier and selection of the newest recovery artifact) are excluded from acceptance. No diagnostic product build was used. Earlier full legacy/native crash matrices remain historical; they are not rerun for this bounded increment. Existing workspace SIGKILL/inherited-lock and retention compatibility tests pass.

Ephemeral local evidence: `/tmp/parsbackup-h02-cancel-{workspace,clippy,build}.log`, `/tmp/parsbackup-h02-cancel-{h02_cancellation_drill,h02_native_auth_recovery,h02_snapshot_drill}.log`, `/tmp/parsbackup-h02-cancel-inputs.sha256`, `/tmp/parsbackup-h02-cancel-hash-check.log`, `/tmp/parsbackup-h02-cancel-scope.json` and `/tmp/parsbackup-h02-cancel-doc-audit.py`. These are local verification records, not production or service certification.

**Finish line:** the requested H02 fixture-hardening foundation is accepted. Next implementation is **H03 systemd/package**, with a dedicated service user, real sandbox/cgroup ownership, timer behavior and package lifecycle checks. Do not create additional speculative H02 hardening increments. This does not waive H01's pre-writer production-plan canonical-byte contract, enable unavailable versioned writable offline/retention commands or certify production compatibility; those explicit outstanding gates must be resolved and tested before production release. H03 can exercise the existing gated fixture build. H04/H05 and V01–V03 remain required; T03 and production enablement stay open. Review/commit this verified checkpoint before H03 coding; no staging, commit or push was requested here.

Final audit passes **310 local document targets/fragments**, fenced TOML/JSON, **12 shell scripts/48 embedded Python blocks**, formatting/diff, exact 20-file inventory and all 101 frozen inputs. HEAD remains `7f0c79e` with no staged changes. Dependencies, inventory schema, lifecycle operating document and immutable November archive remain byte-identical; the session log is append-only below 500 lines. Scoped fixtures/containers and test CLI/strace processes are absent; unrelated containers are preserved. Documentation-only handoff edits require no runtime rebuild.

### Cancellation checkpoint review — 2026-11-16

Operator requested review/commit, then H03. Reviewed all 20 pending files: signal safety/caller placement, cooperative safe points and durable sections, owned process-group lifetime and no-reap exit observation, joined capture/stream workers and panic cleanup, job/lock/drop ownership, conservative typed error receipts and code chains, retained deletion partitions, actual-signal/fault tests, native barriers/recovery and documented containment limits. No blocking findings. All 101 final input fingerprints still match the accepted 313 workspace tests, strict locked/offline Clippy and nine PostgreSQL 16/17/18 script/major combinations. No runtime or harness changes or regression rerun are needed. Final documentation/link/fence/syntax/scope/archive/log/hash checks pass. Only README/project/log are appended for this review; stage and commit exactly the reviewed 20 files, then verify parent/tree/clean checkout. No push requested. H03 systemd/package implementation follows; production command/plan compatibility and H/V release gates remain explicit.

## 48. H03 fixture package and systemd — 2026-11-16

Operator requested review/commit of H02, then H03. H02 was committed as **`3cc9326`**, with the exact reviewed 20-file tree, parent `7f0c79e` and clean checkout verified; no push. Its 313-test/strict-Clippy/nine native combinations remain verified on all 101 unchanged fingerprints. H03 begins from that clean checkpoint. Inspected H01/roadmap, protected config/native/store paths, distro/runtime availability and systemd/Debian primary documentation; recorded the [declarative package contract](docs/development/h03-systemd-package.md) before code. No operating flow is created or changed.

**Implemented scope:** a repeatable dpkg-deb builder for supplied release ELF bytes with derived shared-library dependencies; a static non-login service identity and exact protected directories; opt-in profile-named oneshot/timer templates; literal config/profile arguments into the existing CLI; a private system/filesystem/capability sandbox; bounded whole-service runtime and cgroup hard stops. Install/reconfigure generates no keys/configuration and enables no scheduling. Upgrade preserves scheduling/material and does not restart in-flight work. Removal stops loaded instances and disables persistent/runtime links through the timer template; purge preserves administrator recovery material and identity. Unsafe existing custody refuses without recursive repair. Shipped scheduling is fixture-only; no production bypass is introduced.

The supplied example is a full-database daily profile including large objects. The timer is daily at **02:00 UTC**, randomized up to 15 minutes, persistent catch-up and one-minute accuracy; failure has no automatic retry. Timer/manual work uses existing scope locks. The service grants no cgroup delegation and uses mixed kill semantics: ordinary CLI SIGTERM cleanup, then remaining cgroup processes killed on a bounded stop/deadline, including separate sessions. Persistent writes are confined to the state directory; private temporary/device namespaces remain available. The CLI's descriptor-based execution remains compatible. Explicit service drop-ins own measured deployment-limit changes.

**Known production compatibility blocker discovered here:** Ubuntu PG16.15's dump selected with `--schema=public` emits `CREATE SCHEMA public`; restore into the existing fresh template0 public schema fails and correctly retains/reports a partial target. No core writer/reader is changed by H03. The example/tests now use the full-database profile, whose recovery must independently pass. This observed selective-public case must be resolved or explicitly excluded at V01 before release; passing H03 does not certify all selective content. Other unavailable versioned command/production-plan gates from §47 remain open.

### H03 files changed

Exactly 14 tracked-scope files are intended; no Rust source, dependency, schema, existing test harness, frozen format, operating flow or host deployment changes. H03 changes remain uncommitted pending their own review.

| File Path | Change Type | Description |
|---|---|---|
| [deploy/build-deb.sh](deploy/build-deb.sh) | Added executable | Package supplied release bytes, dependencies, normalized ownership/time. |
| [deploy/debian/postinst](deploy/debian/postinst) | Added executable | Validate/create service identity and protected directories; reload only. |
| [deploy/debian/prerm](deploy/debian/prerm) | Added executable | Stop loaded jobs/timers and disable all persistent/runtime template links. |
| [deploy/debian/postrm](deploy/debian/postrm) | Added executable | Reload manager; preserve recovery material and identity. |
| [deploy/systemd/backupctl-backup@.service](deploy/systemd/backupctl-backup@.service) | Added | Dedicated-user sandbox, direct profile invocation, deadlines/cgroup ownership. |
| [deploy/systemd/backupctl-backup@.timer](deploy/systemd/backupctl-backup@.timer) | Added | Explicit opt-in UTC daily/catch-up schedule. |
| [deploy/writer.example.toml](deploy/writer.example.toml) | Added | Inert complete signed full-database fixture writer example. |
| [tests/h03/Dockerfile](tests/h03/Dockerfile) | Added | Isolated target userspaces/managers and native PostgreSQL; oldest-runtime build tools. |
| [tests/h03/package_drill.py](tests/h03/package_drill.py) | Added | Repeated-byte package, actual manager/cgroup, lifecycle/custody/recovery acceptance. |
| [tests/h03_package_drill.sh](tests/h03_package_drill.sh) | Added executable | Bounded-scope test entry point. |
| [h03-systemd-package.md](docs/development/h03-systemd-package.md) | Added | Pre-implementation contract, limits and observed production blocker. |
| [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Modified/appended | Behavior, evidence, checkpoint handoff and immutable audit. |

**Verification status:** in progress. The Ubuntu-built release uses the oldest supported libc; repeated packaging of identical bytes is checked. Dedicated systemd PID1 containers use private cgroup namespaces on the shared host kernel, with no writable host cgroup bind, host unit installation or unrelated-service mutation. These are target-userspace service tests, not separate guest-kernel/bare-metal certification. Final target versions, full matrix results and exact hashes follow after acceptance. H04 CI/guides and H05 review remain next after H03; production stays disabled through V03.

### H03 acceptance — 2026-11-16

**Accepted on the stated target userspaces.** The final sequential `tests/h03_package_drill.sh --reuse-images` exits 0 with the identical Ubuntu-built package installed and exercised on both systems:

| Target | Actual native/runtime | Accepted behavior |
|---|---|---|
| Ubuntu 24.04 LTS amd64 | systemd 255.4-1ubuntu8.18, glibc 2.39-0ubuntu8.12, PostgreSQL 16.15 | Full package/service drill passed. |
| Debian 13 amd64 | systemd 257.13-1~deb13u1, glibc 2.41-12+deb13u4, PostgreSQL 17.12 | Full package/service drill passed. |

Both systems pass unit verification; dedicated non-root identity/config/key/passfile custody; actual read-only config/key/system paths, hidden home, no capabilities and no-new-privileges; real timer activation; same-instance timer/manual overlap and same-scope CLI refusal; signed full-database publication; v7-to-v8 inventory migration under service permissions; graceful cancellation with a failed job and empty stage/scratch; and three hard-stop scenarios with a TERM-ignoring separate-session child (ordinary stop, main-process SIGKILL and startup deadline). Upgrade during an active probe preserves its main/escaped child until explicit stop. Service recovery plans/runs after source loss work with only identity/verifier, and an independent SQL query verifies the recovered row. Tests use a privileged fixture DB role to exercise recovery, not a claim that scheduled backups require superuser privileges; V01's least-privilege matrix remains required.

Install/reconfigure/reinstall/upgrade/remove/purge preserve exact administrator config/key/credential/store bytes and the service UID. Initial/reinstalled packages activate no scheduler. Upgrade preserves enabled/active timer state without restarting work. Removal disables loaded, unloaded and runtime template instances; reinstall cannot revive them. Unsafe existing mode/symlink controls refuse without automatic repairs. An additional non-systemd container passes offline install/remove/purge and removes its enabled instance link without a manager. Timer time/catch-up semantics are declared and target units verify; accelerated test drop-ins trigger actual activation/overlap. This does not simulate a full reboot or every missed-calendar schedule. Target systemd managers use private PID/cgroup namespaces on this host's kernel; no host unit installation or writable host cgroup bind is used. Separate guest-kernel/bare-metal certification is not claimed.

**Build/artifact evidence:** the final release build is locked/offline using the existing Rust toolchain inside Ubuntu 24.04, with its own GCC/libc and registry read-only. The same supplied binary is packaged three times: two identical fixture.1 outputs match byte-for-byte, and fixture.2 exercises upgrade/reinstall. Package dependencies are `adduser`, `systemd (>= 249)`, `libc6 (>= 2.39)` and `libgcc-s1 (>= 4.2)`. The retained fixture artifact is `target/packages/backupctl_0.1.0~fixture.1_amd64.deb`, SHA-256 **`5a98230e3cc5601d84318c58f1126db0590df661a3ebe80763edd1c31b50b36a`**; `target/packages/SHA256SUMS` records it. It is not a signed production release. `dpkg-shlibdeps` emits Ubuntu merged-usr diversion/unstaged-input warnings; actual dependency resolution/install/native runs on both targets pass. Packaging repeatability covers supplied bytes with fixed SOURCE_DATE_EPOCH, not independent Rust-build reproducibility or pinned upstream apt package availability.

All **112 frozen existing runtime/test/manifest/debug-binary plus new package/test/contract inputs** match after final acceptance. The final host 313-test/strict-Clippy evidence from `3cc9326` is preserved, not rerun for deployment-only changes; the target release build and service matrix above are new evidence. Formatting/diff and documentation audits pass **327 local targets/fragments**, fenced TOML/JSON, **13 top-level shell scripts/48 embedded Python blocks**, the builder/three maintainer scripts, standalone H03 Python and generated sandbox probe. No Rust/dependency/schema/format change is introduced. Preliminary fixture/diagnostic and interrupted-image results are excluded; final tests include the corrected removal implementation and full-database profile. The observed selective-public restore conflict remains an explicit V01 blocker. No claim of full selective content, production command availability or production plan compatibility follows from H03.

Ephemeral evidence: `/tmp/parsbackup-h03-final-drill.log`, `/tmp/parsbackup-h03-image-{ubuntu-final,debian}.log`, `/tmp/parsbackup-h03-inputs.sha256`, `/tmp/parsbackup-h03-hash-check.log`, `/tmp/parsbackup-h03-scope.json` and `/tmp/parsbackup-h03-doc-audit.py`. Final image IDs are Ubuntu `0d38a18968547f980ab50ff8e6a45bd3a69267bcdf7d8b3846507ae9a7059f97` and Debian `630b84fd826ae5a492185efb0d4c4363ecbb98ce4014ec96688ac01e19ea493f`. Scoped fixture containers/private build directories and CLI processes are absent; unrelated containers are preserved. The verified .deb remains in ignored target output; development test images remain cached. HEAD remains `3cc9326`, the index is empty and H03's exact 14-file scope is uncommitted. Immutable archive/lifecycle/dependencies/schema and append-only log are preserved. Review/commit H03, then implement **H04 CI and operating guides**, followed by H05 and V01–V03. Production remains disabled and T03 stays open. No push or host deployment.

### H03 checkpoint review — 2026-11-16

Operator requested review/commit, then H04 CI/guides. Reviewed all 14 files: supplied-byte packaging/dependency/timestamp handling, private staging, service identity/path custody and refusal, idempotent no-activation install/upgrade, loaded/unloaded/runtime instance removal, preserved purge/reinstall material, literal CLI invocation, timer semantics, real sandbox/cgroup ownership and limits, isolated target/hard-stop/recovery tests and evidence limits. No blocking findings. All 112 frozen inputs and retained package SHA-256 still match accepted Ubuntu24.04/PG16 and Debian13/PG17 results. Unchanged core retains historical 313-test/strict-Clippy acceptance; no regression rerun for documentation-only review additions. Final link/fence/syntax/scope/hash/archive/log checks pass. Stage/commit exactly this reviewed 14-file tree and verify parent 3cc9326/tree/clean checkout; no push. H04 follows without production enablement or waiving the selective-public/production compatibility gates.

## 49. H04 CI and operating references — 2026-11-16

Operator requested H03 review/commit, then H04. H03 was committed locally as **`cb34f5e`**: reviewed 14-file staged blobs/tree, parent `3cc9326` and clean checkout verified; no push. All 112 frozen inputs and the retained verified .deb checksum still match both target-system results. No H03 runtime/harness correction was needed during review. Recorded the [H04 declarative contract](docs/development/h04-ci-guides.md) before implementation. Existing controlled operating documents remain unchanged; new documents are behavior/precondition/command references, not new authoritative flows.

**CI scope:** three GitHub-hosted Ubuntu24.04 workflows with read-only token, commit-pinned checkout/upload actions, nonpersisted checkout credentials, bounded jobs and seven-day synthetic evidence retention. Fast runs on PR/main-push/manual; native/package run on main-push/manual only. No self-hosted runner, pull_request_target, repository secret, automatic deployment/release or production authorization. The fixed Rust toolchain is the already-used **1.97.1**; actionlint **v1.7.7** and stock rage **0.12.1** are provisioning tools, not new product dependencies. Actions revisions were checked against official repository tag refs. Digest-pinned PG16/17/18 and Debian13/Ubuntu24.04 base references are recorded in ci/inputs.json. Native provisioning retags exact digest bytes to existing harness names without changing assertions/all-major loops; package provisioning passes digest references through H03's existing build arguments. Apt/hosted-runner patch packages remain upstream-resolved and recorded; no full hermetic/Rust-build reproducibility claim.

The same `ci/run.sh` invokes local/hosted fast/native/package checks, keeps logs/input fingerprints in ignored target output and refuses changed inputs during execution. Native choices are an explicit enumeration: eleven existing all-major suites (33 major combinations) plus the host bootstrap fault/crash drill; each matrix job owns a separate checkout/binary so builds cannot overlap. Package mode preserves the actual H03 two-target drill. Rust dependency fetching is explicit provisioning before locked/offline execution. Lint uses pinned actionlint source via Go's module verification; no application Go dependency is added. Workflow runner isolation, runtime/image assumptions and repeatable commands are recorded in the H04 contract.

**References:** CLI current role/read-only availability, protected config/examples/resources and command-data/report/error meaning; fixture package/service/custody, opt-in scheduling/deadlines/upgrade/removal and external stale-monitor policy; consistent whole-store copying, generation/verifier custody, signature/checksum/archive distinctions, isolated reader-key source-loss recovery and independent data/security validation. Minimal inventory/offline reader TOML and two actual envelope examples are checked. No unavailable versioned writable backup/retention command, live SQLite-copy/export, alert daemon, off-host copy implementation or production enablement is advertised. H03's observed selective-public restore conflict and remaining production writer/command/privilege/release gates stay explicit.

### H04 files changed

Exactly 15 files intended, with no Rust source/dependency lock/schema/artifact/plan byte change and no existing operating-flow modification. H04 remains uncommitted pending its checkpoint review.

| File Path | Change Type | Description |
|---|---|---|
| [rust-toolchain.toml](rust-toolchain.toml) | Added | Pin already-used Rust and formatting/lint components. |
| [.github/workflows/fast.yml](.github/workflows/fast.yml) | Added | Fast source/reference/report/workflow gates. |
| [.github/workflows/native.yml](.github/workflows/native.yml) | Added | Complete existing suite matrix on isolated hosted jobs. |
| [.github/workflows/package.yml](.github/workflows/package.yml) | Added | Identical-package two-target service/lifecycle acceptance. |
| [ci/inputs.json](ci/inputs.json) | Added | Reviewed tool/action/image/suite pins. |
| [ci/prepare.py](ci/prepare.py) | Added | Explicit linter/digest-image/target provisioning. |
| [ci/run.sh](ci/run.sh) | Added executable | Shared locked/offline entry point, logs and unchanged-input checks. |
| [ci/check.py](ci/check.py) | Added | Pins, local links/fragments/fences/examples/syntax and actual CLI envelopes. |
| [h04-ci-guides.md](docs/development/h04-ci-guides.md) | Added | Pre-implementation scope, CI security/evidence and reference acceptance. |
| [cli-reference.md](docs/operations/cli-reference.md) | Added | Current access/config/resources/commands/reports/error meaning. |
| [service-reference.md](docs/operations/service-reference.md) | Added | Fixture installation/custody/scheduling and external stale-monitor policy. |
| [recovery-reference.md](docs/operations/recovery-reference.md) | Added | Consistent copying, generation custody and isolated independent recovery. |
| [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Modified/appended | User reference links, evidence, scope/handoff and immutable audit. |

**Verification status:** local acceptance in progress. Hosted jobs are not pushed/dispatched and have no claimed result. Required local evidence is fast checks, workflow lint, a representative native all-major suite through the new entry point and the package wrapper on both target userspaces, with unchanged inputs and scoped cleanup. Earlier complete native/crash matrices remain historical unless explicitly rerun here. H05 readability review is next after H04 review/commit; production stays disabled and V01–V03/T03 remain open.

### H04 local acceptance — 2026-11-16

**Accepted locally:** `bash ci/run.sh fast` exits 0 with **313 workspace tests**, strict locked/offline Clippy, formatting, source/reference/syntax checks and actionlint **v1.7.7** semantic validation of all three workflows. Both documented actual envelope examples match the real CLI with safe stdout/exit behavior and no referenced store created. The two complete inventory/snapshot TOML specimens and the shipped writer also pass real structural config check; this is not resource/live certification. Primary action tag refs verified the stored checkout/upload commit pins. Go module source installation of the pinned workflow linter succeeds; a preliminary GitHub release-asset TLS timeout is excluded and no mutable binary is substituted. Go/Python/runner patches are prerequisites, not product dependencies or fully frozen hosted inputs.

Provisioning actually pulled all three PG digests, retagged the unchanged harness names, pulled both target base digests and built H03's target fixture images using digest-qualified BASE arguments. `bash ci/run.sh native h02_cancellation_drill` exits 0 on **PG16/17/18 (three native script/major combinations)** with captured/streamed/partial-restore signals, job/child/lock/stage/scratch cleanup and source-loss row recovery. `bash ci/run.sh package` exits 0 after the locked/offline target release build, byte-identical repeat packaging, offline lifecycle and full real-manager drill on **Ubuntu24.04/PG16.15/systemd255/glibc2.39** and **Debian13/PG17.12/systemd257/glibc2.41**. Both targets pass sandbox/custody, timer/manual overlap, v7 migration, graceful and three escaped-session hard-stop scenes, live-probe upgrade, reinstall/remove/purge/unloaded+runtime link cleanup and reader-only signed source-loss recovery with an independent row check. Existing Ubuntu merged-usr/unstaged-input dpkg-shlibdeps warnings remain visible; both target installations/native recoveries pass.

Each executed CI entry point recorded **170 source inputs** and verified them unchanged during its run. Native/package use the final H04 contract including its CI invocation table. Only that declarative table was appended after the fast run; subsequent reference/lint audit passes, without repeating unchanged Rust tests. After runtime acceptance, only README/project/session-log receive evidence/handoff appends. CI/helper/workflow/reference files remain matched to their tested digests. Final source audit preserves exact 15-file scope, clean index/HEAD `cb34f5e`, existing runtime/dependencies/schema/formats/controlled operating documents and immutable November archive, append-only log below rotation threshold, scoped fixture/container/process cleanup and actual example/workflow checks. This increment introduces no new Rust tests or product dependency.

The current retained fixture package is `target/packages/backupctl_0.1.0~fixture.1_amd64.deb`, SHA-256 **`e4cb121b5c3413452c65a119d4cb28c340e2ffd7ba6d2412b55661fae6c93e86`**, with SHA256SUMS. New source-commit timestamp/build context makes this a distinct local artifact from H03's earlier one; the prior accepted H03 package/checksum is preserved under `target/packages/checkpoint-h03/`. The two final package target images are Ubuntu `8dff06cd24b48b285f4de3ecceb791e541acfd44c67a2f5aa87c134050feb110` and Debian `977de98e6b00cf9e459e940b1f02e600fe60b10028bde1e18360f86979a851dc`. Repeatability covers supplied release bytes and fixed timestamps, not independent Rust-build/apt/runner reproducibility. Shared-host-kernel target container limits from H03 remain.

**Not run here:** hosted GitHub workflows (no push/dispatch), the other ten all-major native suites, host bootstrap drill through the new wrapper, stock rage installation through hosted setup and future H05/V gates. Their existing suite/crash evidence remains historical; defining a 12-job suite matrix does not claim all jobs passed. Local verification covers the new wiring plus one representative all-major suite and both package targets. No badge/branch-protection/hosted-green claim is added. H03's selective-public restore conflict, unavailable versioned writable backup/retention commands, pre-writer production plan contract, least-privilege content testing and production enablement remain explicit release work.

Evidence: `target/ci-logs/{fast,native-h02_cancellation_drill,package}.log` and corresponding `*-inputs.json`, `/tmp/parsbackup-h04-{fast,native,package}.log`, `/tmp/parsbackup-h04-{native,package}-provision.log`, `/tmp/parsbackup-h04-actionlint-build.log`, `/tmp/parsbackup-h04-scope.json` and `/tmp/parsbackup-h04-audit.py`. These are local synthetic verification records, not published release/independent security certification. Final reference count/syntax/scope audit follows the last documentation links. H04 remains uncommitted; **review/commit this checkpoint, then H05 clean-code/readability review**. No push, external workflow dispatch, repository-settings change or host deployment. Production remains disabled and V01–V03/T03 remain open.

Final H04 handoff audit passes **374 local targets/fragments**, fenced TOML/JSON, **51 embedded Python blocks** plus standalone/probe/maintainer/Bash syntax, all workflow pins/semantic lint and actual report examples. All CI/workflow/helper/runtime inputs match accepted job records; only the stated post-test reference/handoff appends differ. Exact 15-file scope, package checksum, immutable archive/lifecycle/dependencies/schema, append-only log, empty index/unchanged HEAD cb34f5e and scoped cleanup pass. No additional runtime rebuild or matrix rerun is needed for these documentation-only handoff updates.

### H04 checkpoint review — 2026-11-16

Reviewed the exact 15-file scope: workflow trigger/token/action isolation, digest/tool provisioning, wrapper exit status and source fingerprints, reference checker and actual envelopes, current access/recovery/service limits and append-only evidence. No blocking findings or runtime corrections. Re-audit passes 374 local targets/fragments, 51 embedded Python blocks, standalone/script syntax, workflow lint, actual examples, format/diff, immutable archive/controlled documents and scoped cleanup. The accepted 170-input fast/native/package records match except documented reference/handoff appends; 313 tests, PG16–18 cancellation and both package targets remain valid unchanged-input evidence, not newly rerun suites. Preparing a local checkpoint of these exact files; staged blob/scope and post-commit parent/tree/clean checks follow. No push/hosted dispatch. H05 follows; production and V/T gates remain unchanged.

## 50. H05 readability review — 2026-11-16

H04 reviewed with no blocking findings and committed locally as **6a547e9**. Verified all 15 staged file blobs, parent cb34f5e, exact committed tree and clean checkout; no push/hosted dispatch. H05 applies C1's ownership/readability rules to the A/B/H additions, without a file-size target, global rewrite, behavior fix or new abstraction. Re-measured Rust source sizes: application root 1453, inventory root 3112, local root 1803 lines before comment edits; these include coherent tests and do not by themselves justify extraction.

### Review findings and disposition

| Area inspected | Finding/disposition |
|---|---|
| A inventory/reconciliation/rollback | SQL, migrations and conditional audit transitions remain inventory-owned. Local reconciliation owns no-follow disk observations, adoption/rebuild and maintenance exclusion; domain rollback binding remains pure. Discovery versus authenticated completion/history remains explicit. No adapter removal warranted. |
| B retention and deletion | Domain owns selection/canonical intent; local owns disk snapshots, maintenance/resource lifetimes, exact revalidation and marker-first synced deletion; inventory owns durable intent/progress/tombstones. Saved-plan checks and execution repeat request construction but differ in receipt/expiry/claim timing; a helper would save little while obscuring those boundaries. Recovery only finishes started candidates. No control-order or format change. |
| H access/native/report | Authorization, snapshot safety and availability are distinct checks. Versioned projection into fixture services preserves connection policy in the PostgreSQL adapter and keys in local custody. CLI snapshot's intentionally unused source cannot become a live credential path. Reporter owns the envelope and conservative partial effects. Keep these adapters. Access module's future-tense ownership comment is stale and corrected. |
| H custody/filesystem/resources/snapshot | Exact writer/reader/public custody, protected descriptor lifetimes, shared quota leases and external snapshot scratch are separate responsibilities. Writable/snapshot inventory opens deliberately differ; repeated checks protect public entry points. Local/store/filesystem headers predate versioned/snapshot constructors and are corrected. |
| H cancellation and package/CI | Atomic request and cooperative safe points stay application-owned; PostgreSQL owns group kill/reap and joined workers, systemd owns whole-cgroup containment/deadlines. Package owns supplied bytes/identity/lifecycle; CI reuses existing drills with isolated builds. Thin shell/Python entry points preserve stable invocation contracts. No extra framework or wrapper removal warranted. |
| Artifact lifetime documentation | Authenticated-artifact prose was attached to ArtifactUse after a guard insertion. Replaced it with claim/root lifetime documentation and put authentication meaning on SignedArtifact. StoreKeys prose now states all four writer roles, identity/verifier recovery and separate verifier-only snapshots accurately. |

**Changes are comments only.** Every nonblank non-comment line in all four changed Rust files is byte-identical to H04 HEAD. No symbol, branch, visibility, runtime dependency, schema, serialized key/byte, refusal text, native flag, signal/mutation/publication ordering, test assertion or controlled operating document changes. No redundant adapter/branch found that would improve readability by removal; C1 explicitly permits keeping cohesive use cases and required bridges. This is a completed bounded review, not a claim of an independent security audit or exhaustive proof of every path. No new tests mirror these comments; existing regressions and package gates supply acceptance.

### H05 files changed

| File Path | Change Type | Description |
|---|---|---|
| [crates/backup-local/src/lib.rs](crates/backup-local/src/lib.rs) | Comments corrected | Key/pipe/plaintext ownership, StoreKeys roles, lifetime guard versus authenticated artifact. |
| [crates/backup-local/src/store.rs](crates/backup-local/src/store.rs) | Comments corrected | Distinguish legacy constructors from protected writable/snapshot opening. |
| [crates/backup-local/src/filesystem.rs](crates/backup-local/src/filesystem.rs) | Comments corrected | Cover store/external scratch descriptors and noncreating snapshot opening. |
| [crates/backupctl/src/access.rs](crates/backupctl/src/access.rs) | Comments corrected | State delivered dispatch owners and unavailable writable offline/retention commands. |
| [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Modified/appended | Review, exact seven-file scope, evidence and handoff. |

**Verification pending:** pinned local fast checks and the full identical-package Debian13/Ubuntu24.04 service/lifecycle/recovery drill through ci/run.sh. H04 package and wrapper evidence are preserved under ignored checkpoint-h04 output before canonical paths are reused. No new native behavior, so additional all-major matrices are not required for comment-only edits; their recorded evidence remains historical. H05 remains uncommitted. V01 must address the observed PG16 selective-public restore conflict, unavailable versioned writable backup reads/retention dispatch, production writer plan-byte contract and least-privilege/content/security matrix; V02/V03 and T03 remain open. H05 does not enable production.

### H05 acceptance — 2026-11-16

The bounded review and comment corrections are locally accepted. `bash ci/run.sh fast` passes **313 workspace tests**, strict locked/offline Clippy, format, actual CLI envelopes, semantic workflow lint and the reference/syntax checks. Before handoff appends the reference audit counted 382 local targets/fragments and 51 embedded Python blocks plus standalone/maintainer/shell syntax; the final count follows the last README link. Both fast and package wrapper invocations verify **170 source inputs unchanged** through execution. The four edited Rust files preserve every nonblank non-comment line exactly against H04; no extra runtime feature/refactor/test was introduced to manufacture a readability change.

`bash ci/run.sh package` passes the locked/offline Ubuntu release build, repeat-byte packaging, offline manager-free lifecycle and the same package on **Ubuntu24.04/systemd255/glibc2.39/PG16.15** and **Debian13/systemd257/glibc2.41/PG17.12**. Both targets pass install/reconfigure/reinstall/upgrade/remove/purge, exact recovery-material/identity preservation, non-root custody/sandbox, real timer/manual and scope exclusion, v7 migration, graceful cancellation, three escaped-session cgroup hard stops, live upgrade, reader-only source-loss recovery and independent recovered-row validation. Package SHA256 **0b54ee3e1a6c9942ceea3e402fb6be9df48891b8bacfa4ae3419622e2fee6ab0** and SHA256SUMS are retained under ignored target/packages; the earlier H04 package is preserved in checkpoint-h04. Source comments were unchanged during both gates. Packaging emits the existing visible dpkg-shlibdeps diversion/staging warnings; actual dependency installation and runtime/lifecycle checks pass. Repeat packaging certifies supplied bytes, not independent Rust-build reproducibility.

Evidence: target/ci-logs/{fast,package}.log and corresponding input manifests, /tmp/parsbackup-h05-{fast,package}.log, /tmp/parsbackup-h05-source-scope.json and /tmp/parsbackup-h05-audit.py. Final audit verifies exact seven-file scope, empty index, HEAD 6a547e9, protected contracts/dependencies/schema/controlled documents/November archive, append-only log, package hashes and scoped cleanup. Only README/project/log handoff updates follow the accepted runs. No hosted workflow, new all-major native matrix, independent guest kernel, deployment or production use is claimed. H04 workflow evidence was preserved under target/ci-logs/checkpoint-h04 before reuse; earlier other native/crash suites remain historical.

**Next logical step:** review/commit this seven-file H05 checkpoint, then **V01 production validation**, starting with precise compatibility/content obligations and the observed selective-public restore blocker. H fixture foundations/readability are accepted; full production readiness still requires available versioned writable offline/retention commands, production writer plan-byte/context compatibility, content/least-privilege/security/failure acceptance, V02 measurements and V03 explicit release decision. These are visible release work, not another open-ended H02 readability expansion. Production remains disabled and T03 remains open. No H05 commit or push was requested/performed.

Final H05 handoff audit: **383 local reference targets/fragments**, 51 embedded Python blocks and standalone/script syntax pass. Exact seven-file scope, comment-only source equality, accepted 170-input records (only stated documentation handoff appends differ), immutable archive/controlled contracts, append-only log, empty index/unchanged HEAD, package checksums and scoped cleanup pass.

### H05 checkpoint review — 2026-11-16

Reviewed all seven files: corrected custody/pipe/scratch/lifetime/dispatch comments agree with their implementations; executable lines are unchanged and scope/evidence/release limits are accurate. No blocking findings. The accepted 313-test fast gate and both-target package lifecycle/recovery evidence match unchanged source inputs and retained checksums. Documentation/reference/syntax, source equality, archive/controlled documents, append-only log and scoped cleanup re-audit passes. Preparing the exact seven-file local checkpoint with staged blob/scope and post-commit parent/tree/clean checks; no push. V01 compatibility/content/security/failure validation follows, preserving the production gate.

## 51. V01 production readiness validation — 2026-11-16

H05 review found no blocking issue and was committed as **046c22e**, exact seven-file blobs/tree, parent 6a547e9 and clean checkout verified. Its accepted 313-test/two-target package evidence remains unchanged. Operator requested V01 next. Recorded [validation contract](docs/development/v01-validation.md) before code. Production remains disabled; validation measures synthetic behavior and reports readiness blockers independently of passing test scenes.

Inspection found the existing selective-public collision: template0 supplies public while a schema-selected archive can recreate it. Native restore now reads matching-client TOC and, only for a real public SCHEMA entry with pre-data selected, removes the empty template namespace with static DROP SCHEMA IF EXISTS public RESTRICT. Existing fresh-target checks, conservative partial effects and native refusal remain. No global clean/CASCADE or archive/plan-byte change. A TOC classification unit regression and actual populated-template sentinel scene protect the boundary.

New all-major versioned signed/encrypted CLI content/privilege drill uses protected configs and actual SCRAM tools, separate non-superuser owner/SELECT/pg_read_all_data/CREATEDB-only restorer roles, full and selected content, independent restored SQL/ownership/ACL/sequence/trigger/type assertions, RLS/missing-grant no-publication, target/public-sentinel refusal, extension/publication/subscription/FDW-secret observations and source-loss reader-only recovery. CI enumerates this additional suite and audits both new declarative documents. Initial fixtures exposed native /dev/null fsync and cluster-wide pg_subscription counting mistakes; corrected probes use --no-sync and filter target subdbid. Initial extra rule setup was moved before ownership transfer; these preliminary attempts are excluded from final acceptance.

**Additional compatibility finding:** table-family resolution expands partition children but frozen ArtifactManifest::resolved_selection_validate requires each resolved table to be literally requested. Full-database partitions restore; the signed selective-family writer refuses expanded children even when native dump and profile resolution succeed. The drill records this exact no-publication failure. V01 does not silently relax artifact v1, falsify requested selection or declare this supported. A reviewed compatibility design is needed to close the gap.

**Security findings:** [V01 security review](docs/security/v01-review.md) records frozen transcript/both-leg/consumption/custody review, limits and dependency provenance. Locked bundled libsqlite3-sys 0.38.2 is covered by RUSTSEC-2026-0459 (crafted DB/WAL memory exposure; patched >=0.39.0). Protected snapshot sidecar/WAL refusal reduces exposure but is not a whole-program exemption. Required SQLite update is not performed silently. Full cargo-audit installation failed on registry access, then its isolated retry timed out/aborted; no full-lock advisory verdict or advisory DB revision exists. Targeted primary-source advisory review is recorded separately, not called a clean scan.

### V01 files changed

Exact intended scope: 12 files; no production dependency, schema or artifact/plan byte change.

| File Path | Change Type | Description |
|---|---|---|
| [crates/backup-postgres/src/lib.rs](crates/backup-postgres/src/lib.rs) | Modified | Narrow empty-public preparation, fixture target guard and TOC unit regression. |
| [tests/v01_content_privileges.sh](tests/v01_content_privileges.sh) | Added executable | Actual all-major versioned content/privilege/failure scenes and independent assertions. |
| [.github/workflows/native.yml](.github/workflows/native.yml), [ci/inputs.json](ci/inputs.json) | Modified | Enumerate V01 suite using existing pinned images/toolchain/security policy. |
| [ci/check.py](ci/check.py) | Modified | Audit V01 contract/security reference links and fences; existing syntax audit covers new embedded fixture. |
| [docs/development/v01-validation.md](docs/development/v01-validation.md) | Added | Pre-code acceptance scope, public fix boundary and open release gates. |
| [docs/security/v01-review.md](docs/security/v01-review.md) | Added | Implementation/transcript/custody review, applicable SQLite advisory and incomplete scan. |
| [docs/operations/cli-reference.md](docs/operations/cli-reference.md), [docs/operations/recovery-reference.md](docs/operations/recovery-reference.md) | Modified/appended | Distinguish historical H03 public collision from locally verified V01 correction/evidence. |
| [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Modified/appended | Review/commit, scope, findings and final validation handoff. |

Verification is in progress. The phase cannot be accepted while required compatibility/security/content gates remain open. New native tests do not activate production or certify arbitrary dependencies, security-label providers, database settings/ACL, tablespaces/global parameter grants, host files/WAL or external services. V02/V03 and T03 remain open. No V01 commit/push/host deployment or controlled operating-flow change.

### V01 verified checkpoint and readiness disposition — 2026-11-16

**Locally verified correction:** selective public/schema-only restore now succeeds on **PG16.15, PG17.11 and PG18.6** with actual same-major clients and versioned signed artifacts. The populated-template control refuses DROP RESTRICT, returns a partial receipt and preserves the sentinel. Full/table archives without a public SCHEMA entry preserve the template namespace; occupied targets remain untouched. No saved-format/schema/dependency change.

Final sequential evidence through the existing CI wrapper:

| Gate | New evidence on final inputs |
|---|---|
| fast | **314 workspace tests**, strict locked/offline Clippy, format, actual report envelopes, three workflows semantically linted, TOML/JSON/reference/script syntax. |
| v01_content_privileges | PG16/17/18: non-superuser owner and SELECT backup, CREATEDB-only different-role portable restore, RLS/missing-grant nonpublication, independent rows/constraints/sequence next values/types/generated values/views/materialized data/function/procedure/trigger/rule/comments/collation/text search/RLS/ownership/ACL/default-ACL/large-object assertions; app/aux/public/schema-only; occupied target/nonempty public refusal; hstore; publication/subscription omission; encrypted FDW credential sentinel; untrusted-extension privilege partial failure; signer/recipient removal and source-loss reader-key recovery. Native partition-family success versus signed manifest refusal remains a reproduced blocker. |
| m2_docker_smoke | PG16/17/18 DR/portable security restore, globals tamper/refusal, plan expiry/source binding and verification. |
| m3_docker_smoke | PG16/17/18 legacy profiles, exact resolution/dependencies, section-limited restore and TOC binding; not proof that the signed family gap is fixed. |
| m4a_key_drill | PG16/17/18 rotation, cross-generation refusal, decryption/signing key loss, offline/total-loss/operator-seed recovery. |
| m4b_docker_smoke | PG16/17/18 signed v1 levels/forgery/foreign-recipient/source binding and DR without signer; existing visible rage locale warnings remain, assertions pass. No independent cryptographic assurance claim. |
| h02_native_auth_recovery | PG16/17/18 peer/SCRAM fallback refusal, trusted tools/custody/resource controls, lost-source portable/DR recovery, context/downgrade checks. |
| h02_cancellation_drill | PG16/17/18 actual TERM/INT, native child reap, actual failed jobs, partial DB effects, owned stage/scratch cleanup and subsequent recovery. |
| m5b_retention_drill | PG16/17/18 exact-set/protection/last-copy/dependency/use exclusions, competing deleters and both restore/deletion directions, eight crash boundaries per major, started-only recovery/tombstones and report/ledger/plan privacy. |
| package | Locked/offline Ubuntu release build, repeat-byte package, manager-free lifecycle, identical package on Ubuntu24.04/systemd255/glibc2.39/PG16.15 and Debian13/systemd257/glibc2.41/PG17.12. Both actual managers pass preservation/custody/sandbox/timer/manual/scope/v7-migration/graceful cancellation/three escaped-session hard stops/live upgrade/reader-only source-loss recovery and independent row. |

The **eight native suites / 24 script-major combinations**, fast and package each record and verify **173 unchanged source inputs during execution**. Source/code/harness/contract stayed frozen during these final runs; preliminary diagnostic/fixture/cargo-cache-lock attempts are excluded. Other old suites, host bootstrap, read-only-media snapshot syscall matrix and full original M0 content/privilege obligations are not claimed rerun. Package-manager diversion/staging warnings remain visible; both actual installations and runtime/lifecycle gates pass. Managers share the host kernel in private cgroup namespaces, not independent guests or bare metal.

Final package SHA256 **b44059d3d1d096e7a40a3f0a0922b88f35bafc3c255596c1a3a38b0364097092**, with SHA256SUMS, is retained in ignored target/packages. H05 package/evidence is preserved under target/packages/checkpoint-h05 and target/ci-logs/checkpoint-h05; its checksum remains 0b54ee3e1a6c9942ceea3e402fb6be9df48891b8bacfa4ae3419622e2fee6ab0. Repeat archive bytes do not prove independent Rust build reproducibility. No hosted workflow was pushed/run, deployment performed or production guard relaxed.

| Open readiness gate | Required disposition before acceptance |
|---|---|
| Applicable bundled SQLite advisory | Reviewed compatible dependency update beyond affected libsqlite3-sys 0.38.2, with inventory migration/snapshot/recovery regressions; no ignore entry. |
| Signed partition-family request/resolution mismatch | Contract-compatible design or explicit new-format decision, retaining honest requested scope and old v1 readability; no silent validation relaxation. |
| Versioned writable offline reads/retention dispatch | Implement and verify missing capability owners before claiming the production CLI promise. |
| Production plan bytes/context | Define canonical format and execution-context binding before adding a production writer; no fixture-plan reuse to bypass mode. |
| Full current advisory scan | Run and record actual scanner/advisory DB provenance when registry provisioning works; targeted review is not full coverage. |
| Remaining content/security scope | Complete or explicitly resolve unvalidated matrix cases: security-label providers, absent extension packages/arbitrary dependency/locale environments, database settings/DB ACL, tablespaces/global parameter grants and required privilege combinations. Current exclusions are not silently treated as passing support. |

**V01 is not accepted as a completed phase.** This is a verified correction/validation checkpoint with explicit findings. V02 benchmarks/rehearsal and V03 license/security/support/release decision remain later; production remains disabled and T03 remains open. Next review/commit this exact 12-file checkpoint, then prioritize the SQLite security update and signed-family compatibility decision. No V01 commit/push was requested/performed.

Evidence is target/ci-logs/{fast,native-v01_content_privileges,native-m2_docker_smoke,native-m3_docker_smoke,native-m4a_key_drill,native-m4b_docker_smoke,native-h02_native_auth_recovery,native-h02_cancellation_drill,native-m5b_retention_drill,package}.log and corresponding input manifests, /tmp/parsbackup-v01-{fast,content,m2_docker_smoke,m3_docker_smoke,m4a_key_drill,m4b_docker_smoke,h02_native_auth_recovery,h02_cancellation_drill,m5b_retention_drill,package}.log and /tmp/parsbackup-v01-audit.py. Scanner provisioning failures are in /tmp/parsbackup-v01-audit-install*.log; no successful scan is implied. Only README/project/log handoff additions and two current reference corrections follow final tests; they receive their own link/syntax audit. Exact scope, protected schemas/dependencies/frozen formats/operating flows/archive, append-only audit, empty index/HEAD046c22e, checksums and scoped cleanup pass before those final handoff edits.

Final V01 handoff audit passes **401 local reference targets/fragments**, fenced TOML/JSON, **52 embedded Python blocks** and standalone/shell/maintainer syntax. All 173-input records match except the five explicitly documented post-test handoff/reference files. Exact 12-file scope, unchanged HEAD046c22e/empty index, immutable schemas/dependencies/formats/controlled documents/archive, append-only log, package/H05 hashes and scoped container/fixture/CLI cleanup pass. No additional runtime or test change follows acceptance.

### V01 checkpoint review — 2026-11-16

Reviewed exact 12-file scope: TOC classification and empty-public RESTRICT preparation under existing fresh-target orchestration; target/partial-effect preservation; synthetic isolated actual-role/content/refusal fixtures; pinned CI enumeration; current reference corrections; declarative contracts/security findings and evidence limits. No blocking checkpoint findings or runtime corrections. Re-audit passes 401 local targets/fragments, 52 embedded Python blocks and standalone/script syntax, format/diff, exact scope, all accepted 173-input records except documented handoff/reference edits, immutable schema/dependencies/formats/controlled documents/archive, append-only log, package/H05 checksums and scoped cleanup. Accepted 314-test/eight all-major suite/two-target package evidence is retained unchanged, not rerun for this review. Preparing local exact-scope checkpoint with staged blob and post-commit parent/tree/clean checks; no push. The requested SQLite advisory update follows separately; V01 full acceptance remains open.

## 52. V01 bundled SQLite advisory remediation — 2026-11-16

Operator requested V01 checkpoint review/commit then SQLite advisory fix. V01 committed
as **5a1834b** after review of all 12 files with no blocking checkpoint findings;
verified exact staged blobs/tree, parent 046c22e and clean checkout. All accepted
173-input fast/eight-native/package records and retained package hashes match, except
stated handoff/reference edits; review does not claim those suites rerun. No push.

Recorded the remediation contract in [V01 security review](docs/security/v01-review.md#sqlite-advisory-remediation-contract--2026-11-16)
before dependency edits. Target rusqlite 0.41.1/libsqlite3-sys 0.39.1 (bundled SQLite
3.54.1), retain existing features/toolchain/schema v8 and saved bytes, inspect exact
lock delta and official registry checksums. Direct index/static endpoints timeout;
the existing local SOCKS proxy reaches them without changing global network config.
Earlier V01 artifact/evidence retained under ignored checkpoint-v01 directories.
Final linked-runtime/version, advisory scan, fast/native/package evidence follows.
V01's signed-family/command-plan/content gates remain open; no production enablement.


### SQLite remediation acceptance — 2026-11-16

**Requested advisory fixed:** rusqlite **0.41.1** / libsqlite3-sys **0.39.1**, bundled
SQLite **3.54.1**. Only two of 221 lock records changed; other 219 records, feature
policy, Rust 1.97.1, schema v8/migration SQL, crypto and frozen saved formats remain
unchanged. Official crate checksums and SQLite amalgamation SHA3 agree with upstream;
actual SQL version/source ID and isolated old-engine failing control pass. A real
old-CLI v8 inventory remains byte-identical after a new-CLI read, and a new-CLI rebuild
is readable by the old CLI. No production API adaptation or schema migration.
See [security acceptance and remaining findings](docs/security/v01-review.md#sqlite-advisory-remediation-acceptance--2026-11-16).

| Final gate | Accepted evidence |
|---|---|
| fast | **315 workspace tests**, strict locked/offline Clippy, format, three workflows semantically linted, two actual CLI report envelopes, references and script syntax. |
| m5a_docker_smoke | PG16/17/18 native interruption/adoption/rebuild, six crash boundaries per major, populated v1/v2 upgrades/corruption, newer-schema refusal, read-only copy and raw inventory/journal/report privacy. |
| h02_snapshot_drill | PG16/17/18 non-root true read-only media, signature/checksum/archive, immutable inventory, exact custody, external scratch cleanup/limits and syscall audit. |
| m5b_retention_drill | PG16/17/18 exact sets/exclusions/protection, competing deleters and both restore/delete contention directions, eight crash boundaries per major, keyless started-only recovery/tombstones and ledger/plan/report privacy. |
| v01_content_privileges | PG16/17/18 content/privilege/public-schema/refusal/source-loss controls pass; known signed partition-family refusal explicitly reproduced, not accepted as supported. |
| h02_cancellation_drill | PG16/17/18 captured TERM/streamed INT/partial-restore TERM, child reap, failed jobs, scratch/stage cleanup and source-loss recovery. |
| package | Ubuntu release/repeat archive/manager-free lifecycle, identical package on actual Ubuntu24.04/systemd255/glibc2.39/PG16 and Debian13/systemd257/glibc2.41/PG17; lifecycle/custody/sandbox/timer/manual overlap/v7 migration/cancellation/escaped-session containment/live upgrade/reader-only source-loss recovery pass. |

All seven final wrappers preserve **173 source inputs** during execution: five native
suites / **15 script-major combinations**, fast and package. Only README/project/log
and security-review handoff edits follow. Initial PG17 M5a journal-observation timeout
is retained, excluded from acceptance; PG17-only diagnostic observed the expected
sync after 18.43 seconds and was intentionally stopped afterward. Its result does not
prove the original cause. Recorded a test-only helper adjustment before editing:
allow the existing 150-second command budget for that observation, detect early child
exit with diagnostics, retain every journal/privacy/integrity/crash assertion. Final
full rerun passes; no product timeout or process policy changed.

Current package SHA256 **ae34b0b8095eabe63ca8baa58d81e98c1b27e0cdd436150e661ca67c79c31b02**. V01 package remains under
checkpoint-v01 with SHA256 b44059d3d1d096e7a40a3f0a0922b88f35bafc3c255596c1a3a38b0364097092;
H05 remains under checkpoint-h05 with its recorded checksum. Package warnings remain
visible; containers share the host kernel and repeated archive bytes do not prove
independent Rust-build reproducibility. No hosted CI/push/host-deployment claim.

Full cargo-audit 0.22.2 before/after scans use official RustSec revision
`02e2517f457a359fc6d3440ea4560c8ea188fee8`, no ignores/target/severity filters. SQLite finding is
absent after the update; both scans exit 1 because **crypto-bigint 0.5.5
(RUSTSEC-2026-0387)** and **ctutils 0.4.2 (RUSTSEC-2026-0385)** remain. basic-toml 0.1.10
also has unmaintained warning RUSTSEC-2026-0374. Full scan provisioning gap is closed;
its verdict is not clean. Initial isolated-cache yanked-lookup errors are retained;
accepted project-cache repeats have empty stderr, using cached yanked metadata.
Updated pair's official index checks are fresh. Exact tool/DB/lock/args/exit provenance
and JSON are in target/ci-logs/sqlite-audit-*; details/reachability limits are in the
security review. No cryptographic pins/transcripts or advisory ignores changed.

| File Path | Change Type | Description |
|---|---|---|
| [Cargo.toml](Cargo.toml), [Cargo.lock](Cargo.lock) | Modified | Pin patched bundled pair; exactly two lock entries, same features and other dependencies. |
| [crates/backup-inventory/src/lib.rs](crates/backup-inventory/src/lib.rs) | Test added | Assert actual linked SQL engine meets patched version floor; production lines unchanged. |
| [tests/m5a_docker_smoke.sh](tests/m5a_docker_smoke.sh) | Test helper modified | Journal observation budget/early-exit diagnostics; original security/crash assertions retained. |
| [docs/security/v01-review.md](docs/security/v01-review.md) | Appended/annotated | Pre-edit contract, timeout disposition, source/runtime evidence, full scan and remaining blockers. |
| [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Modified/appended | Current stack, V01 commit/SQLite acceptance, evidence and handoff. |

V01 checkpoint review found no blocking checkpoint issue and committed **5a1834b**
locally, parent046c22e, exact 12-file staged tree/clean checkout verified before this
increment. SQLite's eight-file follow-up is **uncommitted**. Next: review/commit this
verified checkpoint, then resolve the cryptographic findings with explicit compatible
feature/version/reachability decisions. Signed-family, versioned writable offline
commands/retention, canonical production-plan bytes/context and remaining content/
security obligations still block V01; V02/V03/T03 stay open. Production remains
disabled. No controlled flow modified, push, hosted dispatch or host deployment.
Final documentation/scope/fingerprint/checksum/cleanup audit follows.


Final handoff audit passes **412 local reference targets/fragments**, fenced TOML/JSON,
**52 embedded Python blocks** and standalone/shell/maintainer syntax, format/diff,
exact eight-file scope/HEAD5a1834b/empty index, two-entry lock delta, actual linked
engine/old control/upstream checksums, unchanged production inventory lines/schema/
saved formats/controlled documents/archive, append-only log, all seven 173-input
records except the four stated post-test handoff files, new/retained package hashes,
full-scan provenance/results and scoped process/container/fixture cleanup. Evidence:
`/tmp/parsbackup-sqlite-final-audit.py` and matching .log, canonical
`target/ci-logs/{fast,native-*,package}` logs/input manifests, and
`target/ci-logs/sqlite-audit-*`. No runtime or test edit follows acceptance.


### SQLite checkpoint review — 2026-11-16

Operator requested commit/push first, then cryptographic advisory remediation. Reviewed exact eight-file dependency/test-helper/security/evidence scope; no blocking checkpoint finding or runtime correction. Existing 315-test/five all-major native/two-target package evidence remains unchanged, not rerun for review. Re-audit passes exact two-entry lock delta, registry/amalgamation checksums, linked runtime/old control, protected production code/schema/formats/controlled documents/archive, all seven 173-input manifests except stated handoff docs, 412 references/52 embedded Python blocks/syntax/format/diff, retained package hashes, full scan provenance/findings and scoped cleanup. Preparing exact-scope local commit/staged-blob/parent/tree/clean verification and authorized normal push of main; no force push or production enablement. Cryptography investigation and edits follow the push as a separate increment.


## 53. V01 cryptography advisory remediation — 2026-11-16

SQLite review passed without blocking checkpoint findings; committed **d90a3b4**
(parent5a1834b), exact eight staged blobs/tree and clean checkout verified. HTTPS push
failed with absent credentials; SSH first refused an unknown host, then rejected the
agent key after its host fingerprint was verified against official GitHub metadata/docs
in a temporary trust file. No global Git/SSH/network configuration changed or secret
read/exported. Operator now owns the push through GitHub Desktop; no successful push
or hosted-green result is claimed. Work continues separately under that instruction.

Before dependency edits, inspected feature graphs, official registry/release/advisory
metadata and frozen v1/crypto contracts. ctutils0.4.2 has a compatible patched0.4.8;
age0.12.1 requires p2560.13 unconditionally and enables HPKE P-256, retaining affected
crypto-bigint0.5.5 even if our direct defaults are disabled. A direct bigint0.7 update
cannot satisfy the old elliptic-curve constraint. No patched age0.12 release exists in
the current official index. Choose upstream's security-fixed **age0.11.5/core0.11.0**
pair for the age-v1 stream we use, with **hpke0.12.0 defaults disabled/alloc only** and
**ctutils0.4.8**; keep the custom KEM, ML-KEM/X25519, signing implementations, zeroize
features and exact frozen formats. Detailed pre-code boundary/alternatives/acceptance
are appended to the security review. This is a dependency choice, not a new format or
cryptographic primitive; no ignore/backport/fork or contract relaxation. Verify actual
old/new bytes before accepting the choice. SQLite package/CI evidence preserved under
ignored checkpoint-sqlite; old CLI/lock preserved for cross-version checks.


Pre-gate checks pass: old/new multi-chunk crypto helpers preserve exact public and
signature bytes; both-direction actual signed CLI PG16 verify/restore checks preserve
artifact/key hashes and independently restored data. Golden signing vector is
unchanged. 221->215 lock records: 22 removed/16 added identities (required age/core/
parser/localization branch plus ctutils); fresh official index/hash/non-yanked/MSRV/
license checks pass for all16. Same-DB full advisory scan reports two->zero findings,
exit1->0; basic-toml maintenance warning is retained and the final audit also identifies
proc-macro-error2 2.0.1 unmaintained warning RUSTSEC-2026-0173. That macro has a
visible E0365 future-Rust warning; current pinned1.97.1 compiles, future toolchain
upgrades require revisiting that dependency. No suppression/fork/ignore. Detailed
zeroization/feature/lock delta and synthetic fixture provenance are in security review;
final source-frozen fast/native/package gates follow.


### Cryptography remediation acceptance — 2026-11-16

**RUSTSEC-2026-0387 and RUSTSEC-2026-0385 resolved:** crypto-bigint/P-256/elliptic-curve
are absent, ctutils is0.4.8. age0.11.5/core0.11.0 supplies the existing age-v1 stream
without the unused P-256 dependency; unchanged HPKE0.12.0 is alloc-only and calls its
same Base/ChaCha20Poly1305/HkdfSha256/HPKE_INFO/empty-AAD implementation directly.
Custom KEM/seed derivation/combiner/protocol/constants/signing/key IDs/encodings and
stanza refusal policy remain unchanged, with compiled zeroization obligations. No
vendor fork/source override/ignore or suite/format/schema change. Exact221->215 lock
delta (22 removed/16 added identities, six shared dependency-list changes) is reviewed;
all16 new official registry hashes/non-yanked/MSRV/license checks pass. See
[security acceptance and remaining warnings](docs/security/v01-review.md#cryptography-advisory-remediation-acceptance--2026-11-16).

| Gate | Accepted final evidence |
|---|---|
| fast | **316 workspace tests**, strict locked/offline Clippy, format, three workflow semantic lints, reference/syntax/pin checks and two actual report envelopes. |
| Cross-version probes | Baseline age0.12.1 two-chunk ciphertext remains readable; independent old/new helpers read each other's streams and preserve exact recipient/verifier/signature encodings. Existing golden signature unchanged. |
| Actual signed CLI compatibility | Old/new PG16 artifacts verify and restore in both directions, independent row checks, unchanged stored artifact and key hashes; synthetic scene removed. |
| m4a_key_drill | PG16/17/18 key rotation/loss/offline recovery/total-loss controls, operator-supplied test identity and signing/verifying recovery. |
| m4b_docker_smoke | PG16/17/18 signed levels/twelve forgeries/foreign key/source binding/reader-only DR restore; existing rage locale warnings visible. |
| h02_snapshot_drill | PG16/17/18 non-root read-only media, exact custody, immutable inventory, external scratch cleanup/limits and syscall audit. |
| package | Ubuntu release/repeat archive/manager-free lifecycle; same package on actual Ubuntu24.04/systemd255/glibc2.39/PG16 and Debian13/systemd257/glibc2.41/PG17; full lifecycle/custody/sandbox/timer/manual overlap/v7 migration/cancellation/escaped-session containment/live upgrade/reader-only source-loss restore pass. |

All five final wrappers preserve **174 source inputs** during execution: fast, three
native suites (**nine script-major combinations**) and package. Only README/project/log
and security handoff changes follow tests; no runtime/test/fixture edit. Unrelated
SQLite crash suites were retained, not repeated. New package SHA256
**87b09cdafcaa3a9f7071b119c5538ee41cb82f65acbf6394212c9610d7d7f35e**; SQLite package retained in checkpoint-sqlite at
SHA256 ae34b0b8095eabe63ca8baa58d81e98c1b27e0cdd436150e661ca67c79c31b02; V01/H05 remain
in their prior checkpoint directories. Visible package warnings and shared-host-kernel/
repeat-archive reproducibility limits remain as documented.

Full audit uses cargo-audit0.22.2 and official DB revision
`02e2517f457a359fc6d3440ea4560c8ea188fee8`, confirmed still current by fresh remote HEAD.
Before **2 vulnerabilities/exit1**, after **0/exit0**, empty stderr, no ignores or
architecture/OS/severity filters. basic-toml maintenance warning remains; the age0.11
localization branch adds proc-macro-error2 2.0.1 unmaintained warning RUSTSEC-2026-0173
and its visible future-Rust E0365 warning;
current pinned1.97.1/strict Clippy and both-target builds pass, but future toolchain
upgrades must resolve it. The final exact-report audit caught this additional
maintenance advisory; its original warning expectation was incomplete, with the failed
check retained. Crypto vulnerability remediation is complete; release acceptance of
these maintenance findings remains a V03 constraint. No fork or warning/advisory
suppression was added. No independent constant-time/custom
composition certification. Provenance and source/feature/zeroization tradeoffs are
recorded in the security review and target/ci-logs/crypto-*.

| File Path | Change Type | Description |
|---|---|---|
| [Cargo.toml](Cargo.toml), [Cargo.lock](Cargo.lock) | Modified | Security-fixed age/core pair, custom-only HPKE and patched ctutils; justified transitive graph, no bigint/P-256. |
| [crates/backup-crypto/src/recipient.rs](crates/backup-crypto/src/recipient.rs) | Modified | Two equivalent direct HPKE calls; validation, errors and plaintext wiping retained. |
| [crates/backup-crypto/src/stream.rs](crates/backup-crypto/src/stream.rs) | Test added | Old-format multi-chunk ciphertext/key regression; stream production code unchanged. |
| [crates/backup-crypto/tests/fixtures/age-0.12.1-hybrid.age](crates/backup-crypto/tests/fixtures/age-0.12.1-hybrid.age) | Added | Immutable pre-edit synthetic ciphertext, explicitly public test seed; golden bytes not regenerated. |
| [docs/security/v01-review.md](docs/security/v01-review.md) | Appended/annotated | Pre-code decision, exact compatibility/lock/feature/scan evidence and visible warnings. |
| [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Modified/appended | Commit/push status, updated stack, acceptance/evidence and remaining work. |

**SQLite d90a3b4 committed and pushed:** after automated auth failed, operator used
GitHub Desktop; a public remote lookup now confirms origin/main equals that exact
commit. Crypto's nine-file increment is verified and **uncommitted**. Next review/
commit it, then resolve signed-family/request compatibility and missing versioned
command/production-plan contracts. V01 remaining content/security, V02/V03/T03 remain
open; production stays disabled. No controlled flow changed, crypto push, hosted-green
claim or host deployment. Final exact-scope/source/evidence/document/cleanup audit follows.


Final handoff audit passes **423 local reference targets/fragments**, fenced TOML/JSON,
**52 embedded Python blocks** and standalone/shell/maintainer syntax, format/diff,
exact nine-file scope/HEADd90a3b4/empty index, justified lock identities/semantic edges,
equivalent two HPKE calls and otherwise unchanged recipient validation/wiping,
unchanged stream production code/KEM/signing/protocol/schema/formats/controlled
operating documents/archive, immutable baseline ciphertext/exact signature/public
vectors and both-direction CLI restore evidence, all16 registry hashes/licenses,
full audit zero vulnerabilities with **both** maintenance advisories reported, all
five 174-input records except four stated post-test handoff files, retained/new package
hashes and scoped cleanup. The first handoff-audit warning-set assertion omitted
RUSTSEC-2026-0173; that failed check is retained and the documentation/expectation now
reflect the actual unfiltered report. No product test was weakened or source changed.
Evidence: /tmp/parsbackup-crypto-final-audit.py/.log, initial warning-mismatch log,
/tmp/parsbackup-crypto-{cross-probe,cli-compat,future-incompat}.log and canonical
CI/input/audit/registry evidence under target/ci-logs. No runtime/test/fixture changes
follow acceptance. Cryptography findings are resolved; dependency-maintenance release
disposition remains open. Next review/commit this checkpoint and its recorded tradeoff.

### Cryptography checkpoint review — 2026-11-17

Operator requested review/commit of this checkpoint and its maintenance tradeoff.
Reviewed the exact nine-file scope with **no blocking findings**. Direct HPKE calls
match the cached age-core 0.12 helper's parameters, result handling and panic text;
recipient validation/plaintext wiping and stream production code remain unchanged.
The old ciphertext fixture is byte-identical to the preserved pre-edit vector; keys,
signatures and actual signed CLI restore evidence remain compatible in both directions.
The dependency delta removes the affected unused P-256 path and patches ctutils;
registry provenance and the unfiltered advisory report match the reviewed lockfile.

The selected patched age 0.11 branch is accepted for this bounded vulnerability
checkpoint with its recorded maintenance cost: it adds unmaintained proc-macro-error2
2.0.1 and future-Rust E0365, alongside the existing basic-toml maintenance advisory.
Pinned Rust 1.97.1 and both package targets pass. This is not release acceptance of
those maintenance findings: V03 must resolve or explicitly disposition both advisories,
and any toolchain upgrade must address the macro incompatibility. No warning ignore,
fork, contract rewrite or production enablement is added to close this review.

Re-audit passes the five 174-input records with only four documented handoff files
changed, retained 316-test/three PG16–18 native/two-target package results, package and
baseline hashes, protected contracts/controlled documents/archive, append-only log,
423 references/52 embedded Python blocks/syntax/format/diff and scoped cleanup.
Evidence: /tmp/parsbackup-crypto-review-audit-before.log and final review audit.
Preparing exact nine-file local commit with staged-blob/tree/parent/clean verification;
operator retains GitHub Desktop push responsibility. Next is remaining V01
signed-family/request compatibility, then missing versioned command/production-plan
contracts; V01/V02/V03/T03 remain open and production stays disabled.

## 54. V01 signed table-family compatibility — 2026-11-17

Cryptography review checkpoint committed locally as **c13f593**, exact nine blobs/tree,
parent d90a3b4 and clean checkout verified. Operator owns its Desktop push. Requested
next: define signed partition-family compatibility contract, then implement it.
Inspection confirms native family expansion conflicts with frozen v1's literal-request
validation; changing v1 or falsifying the request is rejected. Selected bounded v2
scope semantics with signed direct family edges; v1 remains the output for unchanged
literal scopes. Explicit-child-only v1 profiles are compatible but do not solve the
automatic-family feature. Contract and acceptance recorded before runtime edits in
[signed table-family scope contract](docs/backup-format/manifest-v2-family.md).

Keep cryptographic container/suites/transcripts, schema8, physical inventory shape,
existing restore-plan bytes/context checks and production guard unchanged. New readers
accept v1/v2 with separate scope rules; old readers explicitly refuse v2. Re-resolve
expanded scope before publication to detect observed DDL changes without promising an
atomic catalog/dump transaction. Crypto package and five CI evidence pairs preserved
under ignored checkpoint-crypto, baseline CLI/hash under /tmp/parsbackup-family-*.
Implementation and final fast/all-major legacy/signed/content/snapshot/package gates
follow; no acceptance, commit or push claimed yet. Maintenance warnings remain V03 work.

Implementation now adds optional-on-the-type/omitted-in-v1 family metadata, separate
v2 graph/profile/exclusion validation, one-statement native relation/edge observation,
pending-detach/unsafe-name refusal and post-dump re-resolution before publication.
Only expanded scopes select version2; header/manifest versions must agree. Human
reports show actual versions and expanded dry-run JSON includes direct edges.
Schema8/physical inventory shape and authenticated-manifest-bound restore/deletion
plans retain their existing bytes. Domain graph/refusal and composed publication/
changed-scope/rebuild tests pass; a v2 retention candidate/retained-witness regression
passes under unchanged schema8. Strict locked/offline Clippy preflight passes.

Preliminary native setup failed three times before family writing: writable versioned
offline dispatch is intentionally unavailable, then scratch overlapped the key-parent
tree, then snapshot root overlapped that same key-parent tree. Stopped piecemeal retries,
read actual snapshot custody code and changed the fixture to the established separated
key/store/external-scratch layout, with a config/mode precheck. No product guard or
assertion was weakened. Next run reached actual old/new v1 restore and v2 partition/
schema-only/inheritance recovery, then synthetic extra-table setup lacked CREATE on
the app schema after the security fixture transferred its ownership to Alice. An
explicit fixture-only grant corrects that setup. Failed logs remain under
/tmp/parsbackup-family-v01-{initial,snapshot,external,separated-layout}.log; they are
not acceptance evidence. Unit setup compile omissions and held-reader rebuild refusal
are likewise excluded; the reader is released before testing maintenance exclusion.
Final source freeze and full contracted gates follow after the preliminary matrix.

The preliminary native program subsequently passed all three majors, including both
directions of actual v1 cross-build recovery, explicit old-reader v2 refusal and v2
family/source-loss recovery. Its outer shell then failed because the running script
had been edited during that preliminary run; it is excluded from final acceptance.
No such edits are allowed during the final frozen-input wrappers. Pre-freeze review
also corrected extension dependency probing to include actual membership type e as
well as automatic dependency x (primary pg_depend contract), with a native extension-
owned family no-publication control. No dependency/schema/crypto change is involved.

First frozen fast gate passed322 tests/strict Clippy and V01/M3 passed all majors,
each preserving176 inputs. M4b then stopped at its new unknown-version3 diagnostic
assertion. An external ERR trap (no source edits) identified line733: reader refusal
was correct but the safe-message catalogue still recognized only unknown version2,
so it returned the generic safe refusal. No validation gap. Before changing code,
selected the narrow reporting correction: recognize version3 statically and add the
static public/private format-version disagreement message used by the new tamper
control. Both are literal safe text, not interpolated input. Failed/diagnostic logs
and input record retained under /tmp/parsbackup-family-m4b-*. A fresh freeze and final
gates follow this reporter correction; earlier gate records are superseded.

### Signed table-family compatibility acceptance — 2026-11-17

**The signed-family request/resolution gap is resolved within the new contract.**
Expanded table requests now publish format2 with their original profile/request and
signed direct parent/child links; whole-database, schema and literal table scopes
remain format1, with the old serialization and literal-scope refusal retained. Both
public/private versions must agree. Old binaries explicitly refuse format2; new
readers recover old v1 artifacts. Existing crypto/container transcripts, dependencies,
schema8, physical inventory shape, restore/deletion-plan bytes and production guard
are unchanged. The native extension lookup now includes actual membership e as well
as automatic dependency x, so expanded extension-owned families cannot be silently
omitted by the dump. No advisory ignore or new dependency was added.

| Gate | Accepted final evidence |
|---|---|
| fast | **322 workspace tests**, strict locked/offline Clippy, formatting, all three workflows semantically linted, reference/script syntax and two real CLI report envelopes. Graph invalidity/version/profile/exclusion controls, publication/observed-scope-change refusal, v2 rebuild and authenticated retention candidate/retained-witness behavior pass. |
| v01_content_privileges | PG16.15/17.11/18.6 with matching clients: signed partition and ordinary/multiple inheritance families; overlapping roots; multilevel cross-schema descendants; schema-only recovery; independent rows/parent links/unrelated-table absence; original request/graph inspect; literal v1; child-only/excluded/unsafe/extension-owned no-publication controls; key-free reconcile/inventory and reader-only v2 recovery after source loss. Existing content/privilege/public-schema/refusal tests also pass. |
| Cross-build controls in V01 | Actual preserved c13f593 CLI creates v1 for new-reader recovery; new v1 restores through the old CLI. Inspected v1 facts agree, no family field is added and stored artifact hashes remain identical. Old CLI refuses new v2 signature/inspect paths without changing stored bytes. All three majors pass; baseline CLI SHA256 b6d32ad152654e00b72310d421bb2a23dcf8afbe0e5cc51e40ca958eee49b71a. |
| m3_docker_smoke | PG16/17/18 legacy selective scope, family expansion, dangling/large-object/extension refusals, section-limited and full native restore, TOC binding. |
| m4b_docker_smoke | PG16/17/18 v1 publication/verification boundaries, existing forgery and reader-key DR/source-binding controls, plus supported-header2/private-manifest1 mismatch refusal after signature level and unknown-header3 refusal. Existing rage locale warnings remain visible. |
| h02_snapshot_drill | PG16/17/18 non-root read-only media containing both v1 and v2, source destroyed first; signature/checksum/archive/inspect with reader keys, immutable store/inventory metadata, no network, external scratch cleanup/limits, custody/tamper/tombstone controls and syscall audit. |
| package | Ubuntu-built locked/offline release and identical repeat archive; lifecycle without a system manager; identical package on actual Ubuntu24.04/systemd255/glibc2.39/PG16 and Debian13/systemd257/glibc2.41/PG17. Both managers pass installation/reconfiguration/reinstallation/upgrade/removal/purge, custody/sandbox/timer/manual overlap/v7 migration/graceful cancellation/three escaped-session hard stops and reader-only lost-source recovery. |

These are **four native suites / twelve script-major combinations**, fast and package.
All **six final wrappers preserve the same 176 source inputs**; only the five handoff
documents named below change afterward. No runtime/test/contract change follows final
acceptance. The multi-suite runner ended143 during its last M3 run without an assertion
failure; cause is unconfirmed. Its incomplete log/input record is retained, its exact
container/directory cleaned, and a fresh standalone M3 wrapper passes all majors on
the same frozen inputs. That interruption and all earlier fixture/reporter diagnostic
runs are excluded from acceptance. No assertion or validation was relaxed.

Package SHA256 **af84a634aeee0f147fa948a4522f7c62c80cb2e615c466593b9059d9c237c989**;
the previous crypto package/evidence remains under checkpoint-crypto at SHA256
87b09cdafcaa3a9f7071b119c5538ee41cb82f65acbf6394212c9610d7d7f35e; SQLite/V01/H05
packages/evidence remain retained. Compiler/package-tool warnings are visible. Shared
host kernel and repeat-archive rather than independent Rust-build reproducibility
limits remain. Unrelated SQLite/retention crash matrices were retained, not rerun.
The prior crypto audit still binds the identical lockfile: zero vulnerabilities in
that recorded scan, both unmaintained advisories and future-Rust constraint remain;
no newly fetched advisory scan or independent cryptographic assurance is claimed.

### Signed-family files changed

| File Path | Change Type | Description |
|---|---|---|
| [docs/backup-format/manifest-v2-family.md](docs/backup-format/manifest-v2-family.md) | Added | Pre-code version/scope/container/inventory/plan compatibility contract and acceptance. |
| [artifact_v1.rs](crates/backup-domain/src/artifact_v1.rs), [selection.rs](crates/backup-domain/src/selection.rs), [table_family.rs](crates/backup-domain/src/table_family.rs), [protocol.rs](crates/backup-domain/src/protocol.rs), [domain lib.rs](crates/backup-domain/src/lib.rs) | Modified/added | Separate v1/v2 validation, omitted-in-v1 metadata, bounded DAG/root completeness and additive version/edge constants. |
| [artifact.rs](crates/backup-domain/src/artifact.rs), [fixture.rs](crates/backup-domain/src/fixture.rs) | Test fixtures modified | Existing v1 fixtures explicitly omit new metadata. |
| [application lib.rs](crates/backup-application/src/lib.rs), [PostgreSQL lib.rs](crates/backup-postgres/src/lib.rs) | Modified | Select v2 for expanded scopes, re-resolve before publication, observe native graph and refuse unsupported observations/extension ownership. |
| [cli.rs](crates/backupctl/src/cli.rs), [report.rs](crates/backupctl/src/report.rs), [output.rs](crates/backupctl/src/output.rs) | Modified | Expanded dry-run graph, actual artifact version and safe static unknown/mismatched-version diagnostics. |
| [inventory artifact.rs](crates/backup-inventory/src/artifact.rs) | Comment only | Explain the existing shared physical container shape; stored values and schema remain unchanged. |
| [common/mod.rs](crates/backup-local/tests/common/mod.rs), [retention.rs](crates/backup-local/tests/retention.rs), [signed_store.rs](crates/backup-local/tests/signed_store.rs), [signed_write_path.rs](crates/backup-local/tests/signed_write_path.rs) | Tests modified | V1 fixture compatibility, v2 publication/change/rebuild and authenticated retention behavior. |
| [v01_content_privileges.sh](tests/v01_content_privileges.sh), [m4b_docker_smoke.sh](tests/m4b_docker_smoke.sh), [h02_snapshot_drill.sh](tests/h02_snapshot_drill.sh), [ci/check.py](ci/check.py) | Tests/checks modified | Actual family/cross-build/recovery/refusal and read-only acceptance; new contract link audit. |
| [v01-validation.md](docs/development/v01-validation.md), [cli-reference.md](docs/operations/cli-reference.md), [recovery-reference.md](docs/operations/recovery-reference.md), [security review](docs/security/v01-review.md), [README.md](README.md), [project.md](project.md), [session-log.md](session-log.md) | Appended/surgical edits | Compatibility/support limits, acceptance, exact evidence and handoff. |

Pre-handoff audit passes exact **29-file scope**, unchanged protected v1/crypto/
dependency/schema/plan/access/controlled-document boundaries, all six176-input records,
source/baseline/package/archive hashes, append-only log, syntax/references/format/diff
and scoped cleanup. Evidence: target/ci-logs/family-final-freeze-inputs.json, the six
canonical CI/input pairs, prior records in family-before-report-correction and
checkpoint-crypto, /tmp/parsbackup-family-{fast,m3_docker_smoke,m4b_docker_smoke,
h02_snapshot_drill,v01_content_privileges,package}.log, baseline and final-audit files.
Post-test handoff changes are limited to README/project/log/security review and V01
validation status; final audit follows those edits.

This **verified 29-file increment remains uncommitted** on c13f593 for review. Next
review/commit it, then implement the still-unavailable versioned writable offline
reads/retention dispatch and define production restore-plan bytes/context before
adding a production writer. V01 remaining content/security, V02/V03/T03 remain open;
production stays disabled. No frozen v1/operating-flow rewrite, push, host deployment
or hosted-green claim. The signed graph is a catalog observation, and post-dump
re-resolution is not an atomic or ABA-proof structural DDL freeze.

Final handoff audit passes **463 local reference targets/fragments**, 52 embedded
Python blocks plus standalone/shell/maintainer syntax, format/diff, exact29-file scope/
HEADc13f593/empty index, all six176-input manifests with only the five stated handoff
documents changed, protected v1/crypto/dependency/schema/plan/access/controlled-doc
boundaries, baseline/new/prior package/archive hashes, append-only log and scoped
cleanup. Evidence: /tmp/parsbackup-family-final-audit.py/.log. No runtime/test/contract
change follows acceptance. The signed-family increment is verified/uncommitted for
review; remaining release obligations and the production guard are unchanged.

### Signed-family checkpoint review — 2026-11-17

Operator requested review and local commit of this verified checkpoint. Review
finds no blocking issue in v1 strictness/serialization, v2 graph/profile/exclusion
validation, native catalog bounds/detach/extension refusals, observed post-dump
change handling, authenticated reader/version behavior or unchanged schema/plan/
crypto boundaries. No implementation changes were needed during review. The final
audit was rerun against all 29 paths and retained six 176-input verification records:
322 tests, four PG16/17/18 native suites and both-target package evidence remain
applicable. Heavy gates were not rerun; source/test/contract bytes are unchanged.

This review accepts the increment for the operator-authorized local checkpoint;
Git history supplies its commit identity. Prior uncommitted statements above
describe the implementation handoff. Review updates only README/project/log, then
rechecks documentation, exact staged blobs/tree and clean checkout after commit.
Push remains the operator's GitHub Desktop action. No production enablement or
release assurance: the catalog/DDL limits, two retained dependency maintenance
warnings and remaining V01/V02/V03/T03 obligations still apply. Next logical work
is versioned writable offline reads/retention dispatch, followed by production
restore-plan bytes/context before a production writer.
