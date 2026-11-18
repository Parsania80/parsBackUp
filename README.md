# backupctl

A Rust PostgreSQL backup platform under development. The current CLI creates backups of **synthetic local fixture databases only**, optionally through a named profile whose scope is resolved against the live catalog, verifies them, and restores them fully or section by section, either as a full DR rebuild (roles, memberships, ownership, privileges) or as a contents-only portable restore. A selective backup is refused when the selection would depend on objects `pg_dump` does not write. What a store writes is decided by its configuration and by nothing else: no key blocks gives the plaintext M1 layout, an `[encryption]` block gives an age-encrypted but **unsigned** development artifact, and `[encryption]` plus `[signing]` gives **signed artifact v1** — encrypted payload *and* encrypted manifest, a bounded `public.json` discovery record, and a detached hybrid Ed25519 + ML-DSA-65 origin signature that is checked before anything is decrypted or restored. v1 is the frozen format ([artifact v1 contract](docs/backup-format/manifest-v1.md), [ADR 0002](docs/architecture/adr-0002-artifact-v1-and-signing.md)); the unsigned shape's manifest is still plaintext JSON beside the ciphertext, so the [M4a guide](docs/development/m4a-encryption.md) and the [M4b signed store guide](docs/development/m4b-signing.md) state which shape is which. A host configured with `verifying_key_file` and no `signing_key_file` can list, verify, plan and restore but cannot produce a signature at all, which is the shape a DR box should be given. Scheduling and an API remain planned. Local older-snapshot warnings are described below; they compare authenticated recorded completion times and do not establish archive validity or independent replay protection. The [roadmap](project.md) defines the milestones and release limits.

## Current commands

```text
backupctl --config /absolute/path/to/m4b.toml key generate
backupctl --config /absolute/path/to/m4b.toml key publish
backupctl --config /absolute/path/to/m4b.toml key status
backupctl --config /absolute/path/to/m3.toml config check
backupctl --config /absolute/path/to/m3.toml job list
backupctl --config /absolute/path/to/m3.toml job inspect JOB_UUID
backupctl --config /absolute/path/to/m3.toml inventory check
backupctl --config /absolute/path/to/m3.toml backup protect BACKUP_UUID
backupctl --config /absolute/path/to/m3.toml backup unprotect BACKUP_UUID
backupctl --config /absolute/path/to/m3.toml inventory list
backupctl --config /absolute/path/to/m3.toml inventory reconcile
backupctl --config /absolute/path/to/m3.toml inventory verification BACKUP_UUID
backupctl --config /absolute/path/to/m3.toml inventory rebuild --source-fingerprint FINGERPRINT --dry-run
backupctl --config /absolute/path/to/m3.toml inventory adopt BACKUP_UUID --source-fingerprint FINGERPRINT
backupctl --config /absolute/path/to/m3.toml inventory rebuild --source-fingerprint FINGERPRINT --prepare-rebuild
backupctl --config /absolute/path/to/m3.toml inventory rebuild --source-fingerprint FINGERPRINT --confirm-rebuild --plan-id PLAN_UUID
backupctl --config /absolute/path/to/m3.toml profile list
backupctl --config /absolute/path/to/m3.toml profile validate PROFILE_NAME
backupctl --config /absolute/path/to/m3.toml backup create --confirm-synthetic
backupctl --config /absolute/path/to/m3.toml backup create --profile PROFILE_NAME --dry-run
backupctl --config /absolute/path/to/m3.toml backup create --profile PROFILE_NAME --confirm-synthetic
backupctl --config /absolute/path/to/m3.toml backup list
backupctl --config /absolute/path/to/m4b.toml backup inspect BACKUP_UUID
backupctl --config /absolute/path/to/m4b.toml backup verify BACKUP_UUID --level signature
backupctl --config /absolute/path/to/m4b.toml backup verify BACKUP_UUID --level signature --read-only
backupctl --config /absolute/path/to/m3.toml backup verify BACKUP_UUID --level archive
backupctl --config /absolute/path/to/m3.toml restore plan BACKUP_UUID --target backupctl_fixture_dr --security dr
backupctl --config /absolute/path/to/m3.toml restore plan BACKUP_UUID --target backupctl_fixture_sel --security portable --section pre-data
backupctl --config /absolute/path/to/m3.toml restore run PLAN_UUID --confirm-target backupctl_fixture_dr
```

`key generate`, `key publish` and `key status` act on whichever of the `[encryption]` and `[signing]` blocks the configuration carries, and `key status` reports all four files with their roles, permission bits, suite and public fingerprint. `backup verify --level signature` is the level that needs no decryption: it checks both ciphertext digests and the origin signature and invokes no PostgreSQL tool, and `restore plan` performs the same authentication before it binds a target, so a replaced artifact now fails at planning rather than after a database has been created.

See the [M1 local backup guide](docs/development/m1-local-backup.md), the [M2 restore and verification guide](docs/development/m2-restore-verify.md), the [M3 profiles and selective operations guide](docs/development/m3-profiles-selective.md), the [M4a encrypted store guide](docs/development/m4a-encryption.md), the [M4b signed store guide](docs/development/m4b-signing.md), and the [example configs](config) — [m4a.example.toml](config/m4a.example.toml) documents the `[signing]` block and the read-only host shape alongside `[encryption]`. PostgreSQL 16–18 Docker smoke tests are available at [tests/m1_docker_smoke.sh](tests/m1_docker_smoke.sh), [tests/m2_docker_smoke.sh](tests/m2_docker_smoke.sh), [tests/m3_docker_smoke.sh](tests/m3_docker_smoke.sh), [tests/m4a_docker_smoke.sh](tests/m4a_docker_smoke.sh), and [tests/m4b_docker_smoke.sh](tests/m4b_docker_smoke.sh); they use isolated synthetic databases and check native restore independently of the CLI. The M4a run wraps every PostgreSQL client so each one records the file arguments it was handed and the first bytes of those files, which is how it shows that a tool only ever opens a decrypted archive from the store's transient `scratch/` view and that no plaintext, role name, or key material reaches the encrypted store. The M4b run adds the trust side: writes and signs a v1 artifact on each major, verifies it at all three levels, shows signature level touching no tool and decrypting nothing, DR-restores it into a cluster configured with a verifying key and no signing key, then feeds that store twelve tampered variants — donor ciphertext, a header that lies about the file beside it, another artifact's signature, a short signature, a missing marker, a symlinked payload, a replaced `public.json`, an unknown field, an oversized file, format version 2, a downgraded suite claim, and a byte flip inside the encrypted manifest — and asserts each refusal names the check that caught it. It also parses a freshly written `payload.age` header to show exactly one `mlkem768x25519` recipient stanza plus age's own grease stanza and nothing else, and hands the file to stock `rage`, which refuses it. Rotating keys and recovering from a lost key file is a documented procedure in [key lifecycle](docs/security/key-lifecycle.md), which covers both pairs and explains `key publish`: derive and write the public half of a key you supplied yourself, leaving the secret untouched. That document is executed rather than merely written by [tests/m4a_key_drill.sh](tests/m4a_key_drill.sh), whose signing steps prove that a host with no signing secret can still verify and restore, and that losing the signing key costs publication rather than data.

Architecture, threat, PostgreSQL content, and artifact contracts are linked from [ARCHITECTURE.md](ARCHITECTURE.md). A public license will be selected before a release; no license grant is implied by this development snapshot.


Current progress (2026-10-03): M0–M4b are complete, M5a is underway, and phase S — the concurrency correction that had to come first — is accepted. Opening a store now removes nothing: an operation that uses `staging/` or `scratch/` holds `<root>/locks/activity.lock` shared for as long as its directory exists, and only `backup create` runs a cleanup pass, which takes that lock exclusively and **skips the whole store while any operation is live** (it reports the skip rather than failing the backup). So a `backup list` during a nightly dump no longer deletes the dump's work, a refused duplicate backup leaves the stage it refused alone, and a process killed by `SIGKILL` releases both its scope and its activity claim for the next `backup create` to recover — marking its job `interrupted` and clearing its leftover directory. The limits that come with that design are stated in [ADR 0004](docs/architecture/adr-0004-working-directory-ownership.md): a store that is continuously busy keeps its abandoned entries until a quiet command runs, and a read-only storage root is refused by name rather than falling back to a public temp directory. Evidence is `crates/backupctl/tests/store_concurrency.rs` (two real CLI processes, marker-file synchronization) and the PostgreSQL 16/17/18 matrices. The revised [implementation roadmap](project.md#26-roadmap-and-implementation-tasks) now points at C1, a dedicated clean-code phase to simplify modules and make operation order easier to read, then the remaining inventory/job/recovery work; retention, scheduling and production release follow their own acceptance gates. The [design review](project.md#32-design-and-roadmap-review--2026-10-03) records the blocker this phase closed.

Each roadmap phase is complete only after its stated acceptance checks pass. Phase S passes the fast gates, its own two-process scenes, both lock controls, and the M1–M4b matrices; target/artifact-use locks, retention and deletion remain M5b work and are not implemented. C1 is underway: [§33 of the roadmap](project.md#33-c01-refactor-scope-inventory--2026-10-03) records the measured exported surface of every crate, the `--output json` and error text captured from real runs against all three store shapes, and the mixed-ownership and repetition sites with `file:line`; the operator approved §33.6 as C02's boundary set and four moves have landed under it. **C02-1** extracted the key-file lifecycle into `backup-local/src/keys.rs` (six `pub fn` commands plus `load_pair` and its two file-system rules, with the seven key tests and a shared `#[cfg(test)] fixture.rs`), re-exported from the crate root so no caller changed. **C02-2 and C02-3** filled `backup-local/src/store.rs`: the store's shape decision — `new`, `with_keys`, `with_signing_keys`, `for_reading` and the private `open` that performs the root and layout checks — then the maintenance pass (`Recovery`, `recover`, `clear_working_dir`) and the path joins every other operation uses. Those are now the crate's only places that turn configuration into a store or delete a working directory, and the rest of `backup-local` never loads a key file. **C02-4** took the staging sink machinery into `backup-local/src/stage.rs`: `Target`, `Writer` and `StageSink` with their `Write`/`PayloadSink` impls plus the `stage_sink` that chooses between a plain file and an age stream, so the crate's plaintext-versus-ciphertext decision is one file. The stage *struct* and `begin` stayed at the crate root — moving them would have made ADR 0004's `_claim` field crate-visible, which is a safety-relevant reach change for the increment that moves the publishers. All four are zero-logic moves proven the same three ways: relocated bodies byte-identical against the baseline, each definition present in exactly one place with a whole-construct negative control that names the callers that break, and the 67-invocation CLI battery reproducing identical exit codes and identical streams once run-specific ids, sizes and timestamps are masked — alongside 179 workspace tests, ADR 0004's four two-process scenes, and all six PostgreSQL 16/17/18 matrices.


Review corrections (2026-10-05): signed decryption binds the ciphertext actually consumed to its authenticated digest before releasing plaintext; both PostgreSQL runners terminate their process groups; captured output above 64 KiB is refused rather than silently truncated; native role exports preserve quoted names; and restore checks target absence and decrypts the payload before changing roles. The [agent handoff and regression gates](project.md#34-review-corrections-and-agent-execution-handoff--2026-10-05) describe implementation boundaries, remaining clean-code work, acceptance checks and the order of later milestones. Production use remains gated by the roadmap.

Verification for these corrections: 185 workspace tests and all six PostgreSQL 16/17/18 smoke/recovery matrices pass, including native quoted-role DR checks. Review phase R is accepted; C1 and later feature phases are still unfinished.

Resumption review (2026-10-25): the next step remains C02-5 in roadmap §34.4: inspect scratch/decryption helpers and ownership, extracting a cohesive module only if it improves navigation without weakening ciphertext binding or cleanup/lock lifetimes. The working tree was clean at review start; the recorded test results above were not rerun for this documentation review.

C02-5 implementation (2026-10-25): `backup-local/src/scratch.rs` now groups scratch decryption, consumed-ciphertext hashing, manifest decryption and plaintext-view cleanup, with its direct manifest regression. Public ownership types and private guard fields remain at the crate root. All 185 workspace tests, strict Clippy, formatting and diff checks pass on this extraction. Native PostgreSQL matrices were not rerun because Docker and stock rage tools are absent; C1 acceptance remains pending. The next implementation task is C02-6 in roadmap §34.4.

C02-6 inspection (2026-10-25): the smallest justified next change is to move the existing artifact-to-inventory registration helper into `backup-local/src/inventory.rs`, preserving registration after durable publication. Publication/read sequences and the compact restore-plan methods can stay together. This inspection changed documentation only; C02-6 implementation and C1 acceptance remain pending.

Resumption review (2026-11-02): C02-6 remains the next implementation step. The C02-5 changes are still uncommitted, and C1's native PostgreSQL matrix checks remain pending.

C02-6 extraction (2026-11-02): artifact registration now lives in `backup-local/src/inventory.rs`, with publication order unchanged. The focused signed-write tests and 183 workspace tests passed; two existing replacement tests were excluded after full runs failed on a safe decryption error their assertions did not anticipate. Full-suite and native matrix verification remain pending.

C02-6 verification follow-up (2026-11-02): both replacement tests now accept the safe header-parsing refusal caused when random age padding exceeds the authenticated ciphertext size bound, while still checking scratch cleanup. All 185 workspace tests, formatting and strict Clippy pass. Native matrices remain pending.

Native test prerequisites (2026-11-02): stock `rage` and `rage-keygen` were installed temporarily and passed a round trip; the local V2Ray proxy reached both relevant registries. Docker still requires administrator installation, so the PostgreSQL matrices have not yet run.

Native test results (2026-11-02): Docker is installed and all six PostgreSQL 16/17/18 matrices passed on the current working tree. The signing matrix passed on retry after an initial IPv4 fixture-port conflict. C1 remains open; C02-7 inspection is next.

C02-7 (2026-11-02): the backup command dispatch now lives in `backupctl/src/backup.rs`, keeping recovery and reporting in their existing order; the other command families remain in the entry point. All 185 workspace tests and six PostgreSQL 16/17/18 matrices pass. C03 inspection is next.

C03 inspection (2026-11-02): the shared restore and inventory paths already preserve distinct trust, recovery and transaction rules. No source simplification was justified; the C04 cleanup and acceptance review is next.

C1 acceptance (2026-11-02): the cleanup review, 185 workspace tests, reconstructed CLI comparisons and all six PostgreSQL 16/17/18 matrices pass. Inventory and job command work is next; the separate job-lock permission and symlink hardening remains required before that phase is accepted.

A01: `job list`, `job inspect` and `inventory check` read the existing inventory without loading keys, contacting PostgreSQL, migrating the database or changing job state. Jobs created before schema v5 report their operation as unknown. See the [inventory read contract](docs/development/m5a-inventory.md) for JSON, errors and limitations.

The next implementation step is A02: discovery and reconciliation of inventory entries.

Resumption review (2026-11-03): A01 is committed; A02 remains next.

A02 inspection (2026-11-03): mixed-shape discovery and safe reconciliation need per-entry diagnostics, preservation of existing inventory facts, and coordination with active publication. Implementation remains next.

A02 (2026-11-03): `inventory list` observes mixed backup shapes without changing them; `inventory reconcile` records missing or conflicting registered entries and their recovery when the store is idle. Neither command adopts backups or verifies their signatures. The existing `backup list` keeps its shape-specific behavior. See the [discovery and reconciliation contract](docs/development/m5a-inventory.md#a02-discovery-and-reconciliation-contract) for results and limitations. Explicit adoption and keyless rebuild are the next implementation step.

A02 verification: 195 workspace tests and all six PostgreSQL 16–18 smoke and key-drill matrices passed; formatting and strict Clippy passed too.

A03 has started with a keyless rebuild preview that also works when the inventory is missing or corrupt. It reports unconfirmed source provenance and unrecoverable history; adoption and confirmed rebuild remain under development.

A03 now supports explicit adoption and a saved-plan rebuild. Both record discovered sources as unconfirmed; rebuild preserves the old inventory under a reported recovery name and cannot recover its lost history. A signed read refuses an authenticated source that disagrees with the provisional inventory. See the [A03 contract](docs/development/m5a-inventory.md#a03-adoption-and-rebuild) before replacing an inventory.

A03 verification: 201 workspace tests, formatting, strict Clippy, and all six PostgreSQL 16–18 smoke and key-drill matrices passed. Authenticated enrichment and verification events are next.

The A02 and A03 inventory changes are being committed together; A04 is the next implementation step.

A04 adds verification history and fills unknown inventory facts only after a signed manifest is authenticated. Use `inventory verification` to read the history, or `backup verify --read-only` to verify without recording it. UI/UX exploration can begin before the CLI is released; the planned production UI follows the validated CLI and stable API.

A04 verification passed 205 workspace tests and all six PostgreSQL 16–18 smoke and key-drill matrices. Restore job ownership is next. The CLI still needs inventory completion, retention, hardening and release validation before it is production-ready.

A05 records restore jobs and holds target, artifact-use and store-activity claims throughout a restore. `job list` and `job inspect` show the operation and a target fingerprint; failures leave partial targets for operator inspection. Restore execution requires an existing inventory; rebuild a missing one explicitly before restoring. See the [restore ownership contract](docs/development/m5a-inventory.md#a05-restore-ownership-contract) for recovery and coordination limits.

A05 verification passed 216 workspace tests and all six PostgreSQL 16–18 smoke and key-drill matrices. The next step is the M5a recovery and integrity drill.

Run `bash tests/m5a_docker_smoke.sh` for the M5a PostgreSQL 16–18 recovery and integrity drill. It uses isolated synthetic databases to check interrupted backups/restores, inventory replacement crashes, rebuilds, migrations, corruption and keyless reads. Run as a non-root user with Docker access, Python 3 and Linux `strace`; see the [A06 drill notes](docs/development/m5a-inventory.md#a06-recovery-and-integrity-drill) for scope and limits.

A06 passed on PostgreSQL 16, 17 and 18, including 18 inventory-replacement crash checkpoints. All 216 workspace tests, formatting and strict Clippy pass. A07's metadata leakage and audit checks are next; M5a acceptance and the production CLI remain unfinished, and the production UI follows the stable API milestone.

The A04–A06 changes are being committed together: authenticated verification history, restore job ownership and the PostgreSQL recovery/integrity drill. A07 remains next.

A07 passed on PostgreSQL 16, 17 and 18. The drill now checks raw inventory files and live journals, credentials/private seeds in captured output, metadata-free keyless reports, and audit rollback/refusal behavior. Authenticated detail reports continue to show their documented database/profile/target fields. All 218 workspace tests, formatting and strict Clippy pass; see the [A07 checks](docs/development/m5a-inventory.md#a07-metadata-and-audit-checks).

A08 / M5a accepted (2026-11-13): the operating guide, separate JobLock permission/symlink hardening, all 220 workspace tests and all seven PostgreSQL 16/17/18 regression matrices pass. B01 is next: inspect and define the retention policy/plan contract before implementing deletion. Production CLI completion still requires B, H and V; the production UI follows a stable API.

The [M5a operating guide](docs/development/m5a-operations.md) explains keyless inspection, adoption, saved-plan rebuild, verification, DR restore and interrupted jobs, including unknown facts, lost history and writable-storage limits. Its [acceptance map](docs/development/m5a-inventory.md#a08-operating-guide-and-acceptance-map) distinguishes the delivered inventory CLI from legacy backup-reader behavior and later retention/service work.

The verified A07–A08 changes are being committed together. The remaining production CLI roadmap has 14 tasks: B01–B06 retention/protection/deletion, H01–H05 hardening/deployment, and V01–V03 validation/release. The full platform then adds 11 API, UI and platform-release tasks; these counts describe scope, not equal effort or a delivery date.

B01 contract defined (2026-11-13): the [retention/deletion specification](docs/development/m5b-retention.md) describes per-profile keep-last rules, unknown protection after rebuild, exact confirmed plans and partial-deletion recovery. It adds no commands or deletion behavior. B02 implements protection and preservation next; 13 planned production CLI tasks remain, followed by the API/UI/platform-release work.


B02 adds keyless `backup protect` / `backup unprotect` with atomic audit and idempotent repeated state. Schema v6 preserves unknown protection for migrated, adopted and rebuilt entries; authentication never guesses it. A new signed publication alone starts unprotected. These commands record inventory intent without reading artifacts, loading keys or contacting PostgreSQL. Retention planning and deletion remain future work; see the [B01/B02 contract](docs/development/m5b-retention.md) and [operating guide](docs/development/m5a-operations.md#establish-protection-knowledge).


B02 verification passed 227 workspace tests, strict Clippy/formatting and all seven PostgreSQL 16–18 regression matrices, including live protection-journal checks. B03 retention previews and saved plans are next; 12 planned production CLI tasks remain. Prune/delete execution and production-source enablement are still gated.

The verified B01–B02 changes are being committed together: the retention/deletion specification and keyless protection with migration, audit and preservation coverage. B03 retention previews and saved plans remain next.


B03 adds preview-only `backup prune --keep-last N [--profile NAME]` and `backup delete ID`. They authenticate signed copies using the recovery identity and trusted verifier, require recorded archive evidence and known protection, and save nonempty exact plans privately for 15 minutes. Empty previews save nothing; no artifacts or inventory history change. The default scope is whole-database history. See [retention previews](docs/development/m5a-operations.md#preview-retention-and-review-saved-intent) for exclusions, busy/stale refusals and lost-history limits. Deletion execution remains B04.


B03 verification passed 243 workspace tests, strict Clippy/formatting and all seven PostgreSQL 16–18 native matrices, including plan privacy and 18 rebuild crash checks. Unsupported WAL indexes now refuse before SQLite can create sidecars. B04 confirmed deletion and recovery is next; 11 production CLI roadmap tasks remain, followed by API and UI work. No deletion execution or production-source enablement is included.


B04 adds explicitly digest-confirmed `backup prune run PLAN_UUID --confirm-digest FULL_SHA256` and `backup delete run PLAN_UUID --confirm-digest FULL_SHA256`. They recheck the saved exact set, remove the completion marker before contents and keep durable deletion history. `inventory recover` finishes only already-started confirmed IDs; pending IDs need a new preview. Interrupted/deleted copies cannot be revived by reconciliation. See [confirmed deletion and recovery](docs/development/m5a-operations.md#confirm-deletion-and-recover-started-work). B04 verification passed 256 workspace tests, strict Clippy/formatting and all seven PostgreSQL 16–18 native matrices. B05 rollback warnings and B06's full destructive acceptance remain before retention closes. Ten production CLI tasks remain before API/UI work.


The verified B03–B04 changes are being committed together: retention previews, immutable plans, confirmed deletion, tombstones and started-only recovery. B05 local rollback warnings are next.

Resumption review (2026-11-14): B03–B04 are committed as `ae4f62d`; the working tree was clean at review start. B05 is the next task: remember the newest authenticated completion per source and signer, warn about older snapshots, and bind explicit acknowledgement into a versioned restore plan. This local warning cannot protect against an attacker who also replaces the inventory. B06's destructive/race/crash drill follows before retention acceptance. This review did not rerun implementation tests.

B05 adds local older-snapshot warnings to signed `backup list` and `restore plan`. If you intend to restore an older snapshot, review the warning and create a new plan with `--acknowledge-older-snapshot`. The saved plan binds that exact warning and is refused if the selected bytes or local history change. Migration/rebuild cannot invent lost history, and replacing the inventory can erase it. See [older-snapshot operation](docs/development/m5a-operations.md#review-older-snapshot-warnings) for unknown history, compatibility and recovery. B05 verification passed 266 workspace tests, strict Clippy/formatting and all seven PostgreSQL 16–18 regression matrices. B06's full destructive/race/crash drill is next; nine production CLI roadmap tasks remain before API/UI work.

Checkpoint review (2026-11-14): B05's implementation, compatibility, tests and documentation were reviewed with no blocking findings. The tested runtime and native-harness fingerprints still match; the verified 28-file change is being committed together. B06 remains next.

B05 is committed as `4fbb023`. B06 completes retention acceptance: its dedicated PostgreSQL 16–18 drill checks exact prune/single-copy deletions, exclusions, competing commands and 24 process-crash boundaries with safe recovery. All 266 workspace tests and eight native matrices pass; see [B06 evidence](project.md#40-b06-destructiveracecrash-retention-drill--2026-11-14). H01's production configuration/release policy is next. Eight production CLI tasks remain before API/UI work; synthetic-only operation remains in place.

B06 checkpoint review (2026-11-14): the seven-file drill/documentation change was reviewed with no blocking findings and unchanged tested fingerprints. It is being committed as one verified checkpoint; H01 remains next.

H01 policy is defined (2026-11-15), following B06 commit `c40a953`. The first production release will stay local-only and restore only into fresh databases; remote access, data-only restores into existing databases and overwrite remain excluded. The [production policy](docs/development/h01-production-policy.md) defines versioned configuration, credential/key custody, read-only access and machine reports. These are future contracts, not new working flags or production permission. H02 implements them next; seven production CLI tasks remain and the current CLI stays synthetic-only.

Completion status (2026-11-15): the backup/recovery, encryption/signing, inventory/jobs and retention core is implemented and accepted on synthetic fixtures. Production CLI release still requires seven tasks (H02–H05 and V01–V03); the later API, UI and platform release require eleven more (P01–P04, U01–U04 and F01–F03). Task sizes differ, so these counts are not a completion percentage or delivery estimate. See the [roadmap](project.md#26-roadmap-and-implementation-tasks).


H02's first increment implements versioned configuration checks, command access rules and `--output json-v1` reports. Legacy fixture configurations still work. Versioned fixture configs can use existing writable keyless inventory/job/protection commands without opening keys or PostgreSQL; other new capabilities refuse explicitly until their hardening is implemented. Production remains disabled. See the [increment contract](docs/development/h02-config-access-reports.md) and [current handoff](project.md#42-h02-configurationaccessreport-increment--2026-11-15). H02 native authentication/recovery work is next; seven production CLI tasks remain.

H02 first-increment verification passes 278 workspace tests and native compatibility across PostgreSQL 16–18, including inventory and retention crash/recovery drills. Versioned native/key/snapshot capabilities and production operations remain disabled; the detailed handoff records the scoped diagnostic reruns. Changes are uncommitted.


H02 native authentication/recovery increment (2026-11-15): writable versioned fixture configs now support live profile validation, signed backup create/dry-run and restore plan/run. TCP requires SCRAM with a protected explicit passfile; peer uses a protected local socket. Native tools must be trusted root-owned executables. Recovery probes use the configured maintenance database, so the original database can be missing. New fixture plans bind the acting user and connection settings; legacy plans retain their format. See the [native contract](docs/development/h02-native-auth-recovery.md). Production remains disabled; verification and remaining H02 work are recorded in [the handoff](project.md#43-h02-native-authentication-and-maintenance-recovery--2026-11-15).

H02 native-increment verification passes 283 workspace tests, strict Clippy and the new authentication/recovery plus M2/M3/M4b matrices on PostgreSQL 16–18 (12 script/major combinations). This includes portable and full DR recovery after source loss using only reader keys. Legacy plan vectors remain compatible. H02 key bootstrap/custody and remaining hardening are next; production stays disabled and changes remain uncommitted.

Checkpoint review (2026-11-15): H01 policy and both H02 increments were reviewed together with no blocking findings. The checkpoint retains the verified 283-test result, strict Clippy and 12 native script/major combinations on unchanged tested inputs. Production stays disabled; H02 key bootstrap/custody is next.

H02 validated key bootstrap/custody (2026-11-15): versioned fixture writers can generate a complete four-file key generation or publish missing public halves from existing seeds. All destinations and inputs are validated first; existing files are preserved. Key parent directories must already exist and be protected. Key status works for writer, reader, public and inventory roles without opening a store or PostgreSQL. Create uses all writer keys; restore uses only identity and verifier, even with a writer config. Interrupted publication keeps surviving material and reports known partial effects instead of replacing secrets. See the [key contract](docs/development/h02-key-bootstrap-custody.md) and [current handoff](project.md#44-h02-validated-key-bootstrap-and-custody--2026-11-15). Production remains disabled.

Key-increment verification passes 293 workspace tests, strict Clippy, four real bootstrap crash boundaries and the new-key recovery/legacy key-lifecycle/signing matrices on PostgreSQL 16–18 (nine script/major combinations). H02 filesystem/resource hardening and true snapshot reads remain next; production stays disabled. Changes are uncommitted.


H02 filesystem/resource hardening (2026-11-15): writable versioned fixtures now require protected store ancestry, private layout and safe inventory files. A held directory descriptor keeps operations attached to the opened store. Optional resource settings bound payloads, globals, stages and shared scratch plaintext, with an observed free-space reserve before data writes. Unsafe paths and exhausted limits refuse safely; existing file permissions are not repaired automatically. See the [filesystem/resource contract](docs/development/h02-filesystem-resources.md). Production, true snapshot reads and service containment remain gated. Verification is recorded in the [current handoff](project.md#45-h02-filesystem-and-resource-hardening--2026-11-15).

Filesystem/resource verification passes 304 workspace tests, strict Clippy and 21 native script/major runs on PostgreSQL 16–18, plus the host key-bootstrap crash drill. Inventory rebuild and retention crash recovery remain compatible. Changes are uncommitted; review/commit the checkpoint before implementing H02 true snapshot reads with external scratch. H02 and production release remain gated.

Checkpoint review (2026-11-15): validated key bootstrap/custody and filesystem/resource hardening were reviewed together with no blocking findings. The verified checkpoint retains 304 workspace tests, strict Clippy and 21 native script/major runs on PostgreSQL 16–18. True snapshot reads with external scratch are next; production remains disabled.


H02 true snapshot reads (2026-11-16): versioned read-only fixture configurations can list a copied store, inspect signed backups and verify signatures, checksums or archives without writing locks, history or plaintext into that store. Discovery needs no keys; signature checks need only the verifier. Authenticated reads require explicit protected external scratch. Archive checks run offline with trusted source-major PostgreSQL tools and need no source database or passfile. Use a quiescent copy or read-only medium; the tool cannot certify how the copy was made. Scratch cleanup preserves other operations’ files, but a killed process can leave plaintext behind. See the [snapshot contract](docs/development/h02-snapshot-reads.md) and [handoff](project.md#46-h02-true-snapshot-reads-with-external-scratch--2026-11-16). Production remains disabled and H02 remains partial.

Snapshot-increment verification passes 309 workspace tests, strict Clippy and 18 native script/major runs on PostgreSQL 16–18. The new drill uses a non-root reader on a kernel-enforced read-only mount after destroying the source, with syscall checks for store writes/locks, network and credential access. Legacy recovery, selection, key lifecycle and signing/tamper checks also pass. Changes are uncommitted; review/commit this checkpoint next, then continue H02 service/process/report hardening.

Checkpoint review (2026-11-16): true snapshot reads and external scratch were reviewed with no blocking findings. All 97 verification fingerprints still match the accepted 309-test, strict-Clippy and 18 native script/major results. This checkpoint is approved for a local commit; remaining H02 service/process/report hardening is next. Production remains disabled.

H02 cancellation and failure reporting (2026-11-16): SIGINT/SIGTERM now request cleanup through ordinary CLI control flow. Native process groups stop before their operation locks are released; temporary stage/scratch files are cleaned. Create/restore failures report their actual job/artifact references and whether publication or database changes may have started. A killed connection does not roll back a database restore; partial targets remain for inspection. Successful command output stays compatible. Systemd/cgroup hard stops and deployment sandboxing belong to H03. See the [cancellation contract](docs/development/h02-cancellation.md) and [closing handoff](project.md#47-h02-cancellation-and-process-ownership--2026-11-16).

Cancellation-checkpoint verification passes 313 workspace tests, strict Clippy and nine native script/major combinations on PostgreSQL 16–18, including partial-restore cancellation, source-loss recovery and read-only snapshots. H02 fixture hardening is closed; review/commit this checkpoint, then proceed to H03 systemd/package. Production remains disabled, and production command/plan compatibility remains a release requirement. Changes are uncommitted.

Checkpoint review (2026-11-16): cancellation/process ownership and failure receipts were reviewed with no blocking findings. All 101 tested fingerprints still match the accepted 313-test, strict-Clippy and nine native script/major results. This verified checkpoint is being committed locally; H03 systemd/package follows with production still disabled.

H02 cancellation/process ownership is committed as `3cc9326`. H03 now adds fixture-only Debian packaging and an opt-in systemd backup timer with a dedicated service user and cgroup hard stops. Package installation generates no secrets and enables no scheduling; removal/purge preserve recovery material. Target-system validation is in progress; production remains disabled. See the [H03 contract](docs/development/h03-systemd-package.md).

H03 verification passed on Debian 13 (PG17) and Ubuntu 24.04 (PG16): the same fixture package passes installation/upgrades/removal/purge, dedicated-user sandbox, timer/manual overlap, inventory migration, graceful and cgroup hard stops, and recovery after source loss using only reader keys. The verified `.deb` is in `target/packages/`; installation enables no timer and generates no secrets. H03 is uncommitted; review/commit it, then H04 CI/guides. A selective `public`-schema restore conflict was found and remains a production release blocker; the shipped example uses a verified full-database profile. Production stays disabled. See [acceptance](project.md#h03-acceptance--2026-11-16).

H03 checkpoint review (2026-11-16): all 14 package/service/test/document files were reviewed with no blocking findings. The 112 tested fingerprints and retained package checksum still match both accepted target-system results. This verified checkpoint is being committed locally; H04 CI and operating references follow.

H03 is committed as `cb34f5e`. H04 adds pinned fast/native/package GitHub Actions definitions and matching local CI entry points, plus current [CLI/report](docs/operations/cli-reference.md), [service/monitoring](docs/operations/service-reference.md) and [copy/custody/recovery](docs/operations/recovery-reference.md) references. Local verification is in progress; no hosted Actions result is claimed before push/run, and production remains disabled.

H04 local verification passed 313 tests, strict Clippy, formatting, all three workflow definitions, actual config/report examples, the PG16–18 cancellation matrix and the Debian13/Ubuntu24.04 package/service drill through the new CI entry point. Each run preserved 170 source fingerprints. Hosted workflows are unpushed/unrun; the remaining native suite results are historical. H04 is uncommitted; review/commit it, then H05 readability review. Production stays disabled. See [H04 evidence](project.md#h04-local-acceptance--2026-11-16).

H04 checkpoint review (2026-11-16): all 15 pending files and their recorded local evidence pass review with no blocking findings. Runtime/package inputs remain unchanged; hosted Actions are still unrun. This checkpoint is being committed locally before the bounded H05 readability review.

H04 is committed as `6a547e9`, with the exact reviewed 15-file tree verified and no push. H05 reviewed the A/B/H ownership boundaries and found stale comments rather than a justified structural refactor. Four source files now describe current custody, snapshot scratch, artifact lifetimes and dispatch accurately; executable lines are unchanged. Fast and package lifecycle verification follows; see [H05 review](project.md#50-h05-readability-review--2026-11-16).

H05 readability review is complete: corrected ownership comments in four files, with executable lines unchanged and no justified structural refactor. All 313 tests, strict Clippy/format/reference checks and the full Debian13/Ubuntu24.04 package/service/recovery drill pass; each wrapper run preserved 170 source inputs. H05 is uncommitted. Next: review/commit H05, then V01 production validation and its known compatibility/selective-public blockers. Production stays disabled. See [H05 acceptance](project.md#h05-acceptance--2026-11-16).

H05 checkpoint review: the seven-file comment/document change passes review with no blocking findings. All tested source fingerprints and the verified package checksum still match; this checkpoint is being committed locally before V01 validation.

H05 is committed as `046c22e`. V01 production-readiness validation is underway: a narrow empty-public-schema restore correction and an all-major content/privilege drill are being verified. Inspection found a signed partition-family compatibility gap and an applicable bundled SQLite advisory; full dependency scanning could not run because registry access failed. Production remains disabled. See [V01 findings](project.md#51-v01-production-readiness-validation--2026-11-16).

V01 checkpoint verification passed 314 tests, strict Clippy/format, eight PG16–18 native suites (24 script-major runs) and both package targets, each preserving 173 source inputs. The selective-public restore correction is locally verified, including safe refusal of populated template schemas. V01 remains open: signed partition-family compatibility, bundled SQLite advisory, unavailable versioned commands/production-plan contracts and incomplete advisory/content coverage still block readiness. The 12-file checkpoint is uncommitted; production stays disabled. See [verified results and open gates](project.md#v01-verified-checkpoint-and-readiness-disposition--2026-11-16).

V01 checkpoint review: the 12-file correction/validation change passes review with no blocking checkpoint findings. Its 173-input fast/native/package records and retained checksums still match. The checkpoint is being committed locally, then the bundled SQLite advisory will receive its own dependency update and verification. Production remains disabled.

V01 checkpoint is committed as `5a1834b`. The SQLite advisory fix is now a separate increment: update the bundled rusqlite/SQLite pair, preserve schema/formats, and rerun migration, read-only snapshot, recovery and package gates. Official registry access works through the existing local proxy; verification is pending. Production stays disabled.


V01 is committed as `5a1834b`. Its separate SQLite advisory fix is verified and
uncommitted: bundled SQLite 3.54.1, 315 tests, five PG16–18 native suites and both
Debian/Ubuntu package targets pass. Schema and saved formats are unchanged. The full
dependency scan now runs but still finds two pre-existing cryptography advisories
and an unmaintained dependency warning. Next: review/commit the SQLite checkpoint,
then resolve those security findings. V01 remains open and production stays disabled.
See [SQLite acceptance](project.md#sqlite-remediation-acceptance--2026-11-16).

SQLite checkpoint review passed with no blocking findings. Its dependency/runtime guard, native and package evidence still match. The reviewed eight-file checkpoint is being committed and pushed as requested before cryptography remediation; production remains disabled.

SQLite checkpoint is committed as `d90a3b4`. Automated HTTPS/SSH push attempts could not authenticate; the operator will push it through GitHub Desktop. Cryptography remediation is a separate increment: replace the unused P-256 dependency path, update ctutils, and prove artifact/key compatibility before acceptance. Production stays disabled.


SQLite checkpoint `d90a3b4` is committed and its GitHub Desktop push is verified.
The separate cryptography fix is verified and uncommitted: both advisory findings
are cleared, with 316 tests, three PG16–18 native suites and both package targets
passing. Old/new signed artifacts remain mutually readable/restorable; key and
artifact formats are unchanged. Two dependency maintenance advisories and a future-Rust
warning remain visible; their release disposition remains open. Next: review/commit this checkpoint, then the remaining V01
compatibility work. Production stays disabled. See [cryptography acceptance](project.md#cryptography-remediation-acceptance--2026-11-16).

Cryptography checkpoint review passed on 2026-11-17 with no blocking findings; it is
being committed locally for the operator's GitHub Desktop push. Retained test and
package evidence still matches the code. The maintenance tradeoff is explicit:
the patched age 0.11 branch removes the vulnerable dependency path but introduces
an unmaintained macro dependency and a future-Rust warning. Both maintenance
advisories remain open release obligations; this checkpoint does not accept them
for production. Next: remaining V01 signed-family compatibility work.

Crypto checkpoint is committed locally as `c13f593`. V01 table-family work now has a
[compatibility contract](docs/backup-format/manifest-v2-family.md): preserve v1 and
use version 2 only when a selected table expands to descendants, with the original
request and signed parent/child links retained. Older readers will refuse those new
artifacts explicitly. Implementation and recovery verification follow; production
stays disabled and the maintenance warnings remain open release work.

The signed table-family implementation is ready for final verification. It keeps
literal scopes on v1, uses v2 for expanded families, and refuses invalid graphs,
unsafe/omitted family members and observed scope changes before publication.
Preliminary old/new recovery and family tests passed; final frozen-input native and
package gates are still pending. No production capability is enabled.

Signed table-family compatibility is now verified: expanded families publish and
restore as version 2 while retaining the original request and signed parent/child
links. Whole/schema/literal scopes keep version 1. Old/new binaries recover v1 in
both directions; older readers explicitly refuse v2. **322 tests**, four PG16–18
native suites and the Ubuntu 24.04/Debian 13 package gates pass on frozen inputs.
The 29-file increment is uncommitted for review; production remains disabled and
the other V01/release obligations remain open. See [acceptance](project.md#signed-table-family-compatibility-acceptance--2026-11-17).

Checkpoint review accepts the signed-family increment with no blocking findings.
The exact 29-file scope and frozen acceptance evidence were rechecked; the 322-test,
four all-major native-suite and both-target package results remain applicable.
The operator requested a local commit; Git history records its identity. GitHub
Desktop push remains with the operator. Next: versioned writable offline reads
and retention dispatch. Production remains disabled.

Progress after signed-family checkpoint a0ab1d4 (2026-11-17): the CLI core,
retention and fixture hardening/package foundations are delivered. Three CLI
release tasks remain: finish V01 production command/plan and content/security
acceptance, run V02 measurements/recovery rehearsal, then complete V03 release
policy and separately reviewed production enablement. V01 includes versioned
writable offline reads/retention dispatch and production restore-plan compatibility.
The later full platform still has four API tasks, four UI tasks and three platform
release tasks; API/UI are not required for the first CLI release. Task counts are
not equal effort or a percentage estimate. Production remains disabled.

Why validation precedes API/UI: the current roadmap releases the CLI first,
and the future API/UI reuse its backup/restore/retention services. Core correctness
checks protect every interface; CLI release administration and the full V02/V03
sequence are a product sequencing choice. A web-first direction could defer
CLI-only release work while addressing required shared backend contracts before
dependent API operations. API/UI integration and end-to-end validation still follow
their implementation. No roadmap reordering is authorized by this clarification.

The operator has now approved the **web-first sequence**: close exactly two shared
backend gates (versioned writable offline/retention dispatch, then restore-plan
compatibility contract/fixture proof), build the API, build the UI, and perform
integrated release validation. Full CLI release is no longer a prerequisite for
API work. Existing core tests remain the baseline; broad performance/release work
moves after the UI. API auth/worker decisions and UI framework choices remain their
own recorded implementation tasks. Production stays disabled until reviewed release
acceptance. The bounded gates and handoff criteria are in
[the current roadmap](project.md#55-web-first-delivery-and-bounded-backend-handoff--2026-11-17).

V01-W1 is now in progress. Its [pre-code dispatch contract](docs/development/v01-w1-offline-dispatch.md) specifies key-free discovery, verifier-only signature checks, reader-only private verification and retention on writable versioned fixtures, without contacting the source. Implementation and verification follow; production remains disabled.

V01-W1 is now implemented and verified: writable versioned fixtures can list,
inspect, verify and prepare/execute retention offline. List needs no keys; signature
checks need only the verifier; private operations use identity plus verifier without
signer/recipient/source credentials. Archive checks alone need matching tools.
**323 tests** and V01/B06/snapshot native suites on PG16–18 pass. Existing plan bytes,
schema, retention safeguards and immutable snapshots remain intact. The increment
is uncommitted for review; production stays disabled. **Next: W2 restore-plan
compatibility contract/fixture proof, then API → UI → integrated release validation.**
See [W1 acceptance](project.md#w1-implementation-and-acceptance--2026-11-17).

The operator requested a local checkpoint of all current W1 and web-first roadmap
changes. Git history records the commit identity; pushing remains operator-owned.

W1 is committed as 1b51013. W2 is now defining [restore-plan compatibility](docs/development/v01-w2-restore-plan-compatibility.md): preserve historical fixture plans, specify a distinct future production format, and verify existing fixture context/refusal behavior. No production writer is enabled. After this bounded proof, API design is next.

W2 restore-plan compatibility is now verified. Existing fixture plans and runtime
behavior stay unchanged; a separate future production format is documented and
still refused by this build. **324 tests**, strict Clippy and the actual PG16–18
native context/authentication/recovery drill pass. Both bounded backend gates are
accepted. **Next: P01 API design, then API → UI → integrated release validation.**
The W2 checkpoint is uncommitted; production remains disabled. See
[W2 acceptance](project.md#w2-acceptance-and-api-handoff--2026-11-18).

W2 checkpoint review found no blocking issues; the operator requested its local
commit before P01 API design. Retained 324-test/all-major context-recovery evidence
was rechecked against unchanged test and contract inputs. Git history records the
commit identity; pushing remains operator-owned.

W2 is committed locally as **2f60e33**. [P01 API design](docs/development/p01-api-contract.md)
now defines the first web interface: authenticated requests, saved restore/deletion
confirmations, safe reports and retry-safe background jobs. The [OpenAPI contract](docs/api/openapi-v1.json)
has 20 operations; the server itself is not implemented yet. One isolated worker
will reuse the existing core, with a bounded queue and honest crash/cancellation
results. **Next: P02 worker implementation → API routes/tests → UI → integrated
release validation.** No additional general backend phase; production stays disabled.

P02 now runs background jobs through the existing backup and restore services.
It accepts up to 16 queued jobs and runs one at a time. Retries return the original
job, and a restart reports interrupted work for review. The PostgreSQL 17 and
systemd drill verified backup, restore, confirmed deletion, cancellation and process
cleanup. [P02 implementation and verification](project.md#59-p02-bounded-api-worker--2026-11-18)
records the results. **Next is P03, the HTTP routes and authentication.**

The P01/P02 checkpoint review verified that queued jobs can still be cancelled
when the receipt limit is reached. Backup jobs now report uncertainty if the
recovery pass fails before it can say what changed. Git history records the local
checkpoint.

P03 now serves the fixture API on loopback. It supports bearer tokens and
browser sessions, with permissions for artifact reads, restore planning, job
submission and cancellation. The read-only listener is available for local
development, and the supervised listener runs jobs. See the
[HTTP API guide](docs/operations/http-api.md). **Next is P04 API verification,
then the UI.**

The P03 checkpoint review verified that health reports degraded readiness when
the default profile configuration changes. The HTTP drill confirmed that the
same change blocks new work and that restoring the configuration restores
readiness. Git history records the local checkpoint.

P04 fixture API acceptance passed. The drill checked restore and deletion
confirmations, partial effects, revocation, queue limits and restart without
replay. The [API guide](docs/operations/http-api.md) explains job recovery.
See [P04 acceptance](project.md#61-p04-fixture-api-acceptance--2026-11-18) for
the evidence. **Next is U01, the UI framework and client design.**

The P04 checkpoint review matched the acceptance evidence to the source and
test inputs. Git history records the local checkpoint for the API that U01 uses.
