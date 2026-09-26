# Synthetic PostgreSQL fixtures

These files implement the M0 [fixture plan](../../../docs/postgres/fixture-plan.md). They contain no credentials and must run only in disposable databases. The test harness is responsible for creating databases/roles, choosing matching client binaries, and recording exact server/client versions. `core.sql` and `assertions.sql` are the baseline; optional scripts require the named extension or privilege and must report a skip reason if unavailable.

Suggested test order on each PostgreSQL 16, 17, and 18 image:

1. Create a new source database from `template0`. Apply `core.sql` with `psql -X -v ON_ERROR_STOP=1`.
2. Optionally apply `optional-extensions.sql`, `optional-publication.sql`, and `optional-fdw.sql`. Publication creation can warn when `wal_level` is not `logical`; this is an observation, not evidence that replication works.
3. Run same-major `pg_dump -Fc --no-subscriptions` into a temporary custom archive. Save `pg_restore -l` for object-class checks.
4. Create a second fresh database and run `pg_restore --exit-on-error`. Apply `assertions.sql` there. Its trigger check runs inside a rolled-back transaction, so it does not alter the restored baseline.
5. Repeat the selective, privilege, fault, encrypted-artifact, and target-compatibility cases listed in the fixture plan. An archive parse alone is not a successful restore test.

Do not paste connection passwords into CLI arguments, shell history, fixture SQL, or test logs. Use ephemeral test identities and an isolated password file only when password authentication is part of the case. PostgreSQL 15 was used solely for an M0 SQL syntax/round-trip smoke check; it is not in the supported product matrix and does not satisfy the PostgreSQL 16–18 release gate.
