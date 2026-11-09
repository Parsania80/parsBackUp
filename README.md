# backupctl

A Rust PostgreSQL backup platform under development. The current CLI creates backups of **synthetic local fixture databases only**, optionally through a named profile whose scope is resolved against the live catalog, verifies them, and restores them fully or section by section, either as a full DR rebuild (roles, memberships, ownership, privileges) or as a contents-only portable restore. A selective backup is refused when the selection would depend on objects `pg_dump` does not write. What a store writes is decided by its configuration and by nothing else: no key blocks gives the plaintext M1 layout, an `[encryption]` block gives an age-encrypted but **unsigned** development artifact, and `[encryption]` plus `[signing]` gives **signed artifact v1** — encrypted payload *and* encrypted manifest, a bounded `public.json` discovery record, and a detached hybrid Ed25519 + ML-DSA-65 origin signature that is checked before anything is decrypted or restored. v1 is the frozen format ([artifact v1 contract](docs/backup-format/manifest-v1.md), [ADR 0002](docs/architecture/adr-0002-artifact-v1-and-signing.md)); the unsigned shape's manifest is still plaintext JSON beside the ciphertext, so the [M4a guide](docs/development/m4a-encryption.md) and the [M4b signed store guide](docs/development/m4b-signing.md) state which shape is which. A host configured with `verifying_key_file` and no `signing_key_file` can list, verify, plan and restore but cannot produce a signature at all, which is the shape a DR box should be given. It does not yet provide scheduling, an API, or an inventory that can tell a valid older artifact from a valid newer one. The [roadmap](project.md) defines the milestones and release limits.

## Current commands

```text
backupctl --config /absolute/path/to/m4b.toml key generate
backupctl --config /absolute/path/to/m4b.toml key publish
backupctl --config /absolute/path/to/m4b.toml key status
backupctl --config /absolute/path/to/m3.toml config check
backupctl --config /absolute/path/to/m3.toml job list
backupctl --config /absolute/path/to/m3.toml job inspect JOB_UUID
backupctl --config /absolute/path/to/m3.toml inventory check
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
