# Session log

## 2026-09-26 — M0 research contracts and fixtures

**Request:** Begin milestone M0 from `project.md` and maintain this log.

**Completed:** Created the architecture contract, ADR 0001, PostgreSQL content/privilege matrices, fixture plan, threat model, artifact v1 specification, and synthetic SQL fixtures. Updated `project.md` minimally to link M0 deliverables and make the origin-signature requirement explicit. No Rust application code or production database configuration was added.

**Research and decisions:** Checked official PostgreSQL documentation for versions 16–18, native dump/restore selection, globals, RLS, large objects, partitions, and subscription behavior. Confirmed native archives may contain database-held credentials. Confirmed `age` encryption alone does not establish sender origin: artifact v1 now requires a detached Ed25519 signature verified against an independently trusted key. Documented the residual rollback/deletion risk. Existing backup products informed retention expectations but did not determine logical archive behavior.

**Verification performed:**

- Checked the new documents and fixture files exist and contain no credential values.
- Ran `core.sql` and `assertions.sql` in an isolated, network-disabled PostgreSQL 15 container available locally. Optional extension, publication, and FDW SQL parsed; publication warned that the test server's `wal_level` does not enable logical publishing.
- Found and fixed an assertion that changed baseline source rows. Re-ran a fresh source -> `pg_dump -Fc --no-subscriptions` -> `pg_restore --exit-on-error` -> `assertions.sql` round trip; all steps passed.
- PostgreSQL 15 was a syntax/round-trip smoke test only. The selected PostgreSQL 16–18 support matrix remains an executable M1/M2 gate, not a claim validated by this session.
- Stopped and removed the temporary container. Checked 15 project/M0 files for broken local Markdown links and trailing whitespace; `git diff --check` passed.

**Next implementation gate:** M1 creates the Rust workspace and local synthetic-data backup path. The first real-data artifact cannot be published until M4 implements encrypted and signed artifact v1. M1/M2 must run the fixture/privilege matrix on PostgreSQL 16, 17, and 18 with matching client binaries.

## 2026-09-26 — M1 synthetic local backup

**Request:** Begin M1 Rust workspace and synthetic-data local backup.

**Implemented:** Added a five-crate Rust workspace (`backup-domain`, `backup-application`, `backup-postgres`, `backup-local`, `backupctl`), an explicit synthetic-use configuration guard, version-matched native `pg_dump -Fc --no-subscriptions`, bounded subprocess output and timeout, local staged publication with fsync/checksum/completion marker, and CLI `config check`, `backup create`, `backup list`, and `backup inspect`. Added a reproducible Docker smoke script, example TOML, README, and M1 operator guide. The artifact format is explicitly `m1-development-plaintext`, separate from future encrypted/signed v1.

**Verification:** `cargo fmt --all`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` passed. The Docker script passed on PostgreSQL 16, 17, and 18 with matching native clients: create/list/inspect followed by an independent `pg_restore --exit-on-error` into a fresh database and fixture assertions. On PostgreSQL 16 it also verified rejection of missing synthetic confirmation, simulated write error, empty output, timeout, mismatched client major, and a malformed config containing a runtime-generated sentinel without echoing that value. Failed backup attempts did not publish another artifact or leave an ordinary staged directory.

**Final QA:** Re-ran the PostgreSQL 16–18 Docker matrix after disabling implicit default `.pgpass` use. Checked 18 source/document files for broken local links and trailing whitespace, confirmed `git diff --check`, and confirmed temporary M1 containers were removed.

**Scope remaining:** M1 has no restore command, encryption, signing, SQLite catalog, scheduler, remote storage, or production-data support. An actual full-filesystem disk-exhaustion event was not induced; the write-failure path was simulated. The public repository license is not yet selected, so Cargo does not declare one.
