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

## 2026-09-27 — M2 safe restore, security metadata, and verification

**Request:** Implement M2 so a backup can reconstruct the database security environment (roles, attributes, memberships, ownership, privileges) and not only tables and data, with an explicit restore security policy, safe plan/run separation, and verification levels. Keep exit codes at 0/1, add no SQLite catalog, and document rather than work around any authentication limitation.

**Implemented:** Added `RestoreSecurityPolicy` (`dr` = roles + ownership + privileges, `portable` = contents only) and a `RestorePlan` record whose SHA-256 digest binds the policy, target, and artifact; plans are mode 0600 JSON under `<storage-root>/plans/` with a 15-minute expiry. The domain manifest now records `security_globals`, the globals digest/size, and the verification level, with shape validation that keeps those fields consistent. `backup create` optionally exports globals, `backup verify --level checksum|archive` was added, and `restore plan`/`restore run` execute the DR order: validate plan and digests, apply roles and memberships, re-check the target is absent, `createdb --template=template0`, then `pg_restore` with policy-derived flags. `--no-owner`/`--no-privileges` are never globally forced. A successful DR restore raises the artifact to `restore-tested`.

**Security decisions:** Globals export uses `pg_dumpall --roles-only --no-role-passwords`, so no SCRAM or MD5 verifier can enter an artifact; the adapter independently refuses to apply a file containing a `PASSWORD` clause, and `list`/`inspect`/`verify` re-hash `globals.sql` and reject an undeclared globals file. Restored roles therefore need an operator-assigned password, and database-level `GRANT ... ON DATABASE`, tablespaces, and other cluster globals stay documented prerequisites. Native tool output stays withheld from errors so data cannot leak through the CLI. Tests use only fake, in-container credentials.

**Verification performed:** `cargo fmt --all`, `cargo test --workspace` (23 tests), and `cargo clippy --workspace --all-targets -- -D warnings` pass. `tests/m2_docker_smoke.sh` passes on PostgreSQL 16, 17, and 18 with version-matched clients: sentinel/`PASSWORD`/`SCRAM-SHA-256` leakage checks, both verification levels, the M1 native restore compatibility path, DR refusal while the exported roles exist, clean-cluster DR restore with `assertions.sql` and `security-assertions.sql`, second-DR refusal, portable restore onto a role-less cluster proving ownership and roles are untouched, plan policy binding, expired-plan refusal, mismatched `--confirm-target`, the `export_globals = false` gate, and globals/payload tamper detection. `tests/m1_docker_smoke.sh` also passes again after its wrappers gained `pg_dumpall` and `createdb`, which the widened preflight now requires.

**Defects found and fixed during integration:** the Docker client wrappers omitted `docker exec -i`, so the role script written to psql stdin never reached the container and the DR restore silently applied nothing; the filter also dropped memberships for roles that already existed, and an empty script returned success. The apply step now replays memberships unconditionally, always re-reads `pg_roles` afterwards, and fails if any exported role is still absent. `security-assertions.sql` referenced a nonexistent `rolattr` column and asserted table ownership the fixture never set, so the fixture now owns `app.audit_events` and the attribute check uses real `pg_roles` columns.

**Scope remaining:** no encryption or signing (M4), no retention/deletion, no scheduler or daemon, no SQLite catalog, no profiles or selective restore (M3), no off-host storage, no multi-database or cluster-wide restore, and no automatic cleanup of a partially restored target.
