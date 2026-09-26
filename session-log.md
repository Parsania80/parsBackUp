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
