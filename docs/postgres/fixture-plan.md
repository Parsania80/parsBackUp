# PostgreSQL fixture and assertion plan

Status: M0 executable fixtures plus required observations. The SQL in `tests/fixtures/postgres/` is synthetic and contains no credentials. It has **not** been certified on PostgreSQL 16–18 in M0; M1/M2 must run and adjust version-specific cases before advertising support. Use a disposable database per case; never run fixtures against an existing database.

## Matrix

Run each row on PostgreSQL 16, 17, and 18 with a matching `pg_dump`/`pg_restore` major. Record exact minor versions, archive TOC, command options, exit code, warning class, restored assertions, and whether a clean target or prepared target was used. Each failure must be expected or triaged. Reference [content matrix](content-matrix.md) and [privilege matrix](privilege-matrix.md).

| ID | Source setup | Backup/restore variation | Assertion or expected limitation |
| --- | --- | --- | --- |
| F01 | `core.sql`: table, identity, indexes, PK/unique/check/FK, data, standalone sequence | Full `-Fc`; clean same-major restore | Row counts, FK/index/constraint definitions, next sequence values. |
| F02 | `core.sql` cross-schema FK and sequence | `--schema=app`, `--table=app.accounts`, schema-only, data-only | Filter scope exact; clean-target partial restore may fail; data-only needs prepared schema. |
| F03 | `core.sql`: view, materialized view, enum/domain, comments, text search | Full; schema-only | Definitions and expected data state; no optimizer-statistics equality claim. |
| F04 | `core.sql`: function, procedure, trigger | Full | Trigger still changes rows after restore; source SQL is treated as executable. |
| F05 | `optional-extensions.sql` | Full, target without/with extension package | Preflight blocks unavailable extension; successful case restores when installed. |
| F06 | Ephemeral roles and grants from test harness | Full; preserve owner vs `--no-owner --no-acl` | Target role absence diagnosed; portable mode ownership assigned to restorer. |
| F07 | RLS table with restricted reader | Default dump vs `--enable-row-security` experiment | Default insufficient role fails rather than claiming a complete backup. |
| F08 | Partitioned and inherited tables in `core.sql` | Parent `-t` vs `--table-and-children` | Record exact child TOC; only expanded form claims family coverage. |
| F09 | Security-label provider if available | Full | Provider dependency documented; skip with explicit reason otherwise. |
| F10 | Large object in `core.sql` | Full; `--schema=app`; filtered plus `--large-objects` | Full preserves bytes; filtered default omits; opt-in adds all large objects. |
| F11 | `optional-publication.sql`; ephemeral subscription only in isolated admin test | Full with `--no-subscriptions` | Publication definition restored; subscription absent and omission recorded. |
| F12 | `optional-fdw.sql` with no credential in file; CI-generated ephemeral mapping sentinel | Full encrypted artifact | Definitions/secret-content handling; no sentinel in manifest/logs, no auto-connect. |
| F13 | Optional collation/locale fixture | Full across matching images | Target locale/ICU requirement reported; do not assume cross-host portability. |
| F14 | Database-level settings in ephemeral setup | Full with/without `--create` | Restore plan accurately reports name/settings and refuses unapproved overwrite. |
| F15 | Ephemeral roles/tablespace setup | `pg_dumpall --globals-only --no-role-passwords` observation | Separate artifact only; no auto-restore or role passwords. |
| F16 | Synthetic host-side timer/file/WAL paths | Logical dump only | Confirm none are represented; recovery checklist names prerequisites. |

## Failure and security cases

| ID | Injection | Expected result |
| --- | --- | --- |
| E01 | Kill `pg_dump` mid-write | Staged data quarantined; no complete artifact. |
| E02 | Disk full or write error | Nonzero job; no completion marker. |
| E03 | Missing/mismatched `pg_dump` major | Preflight rejection before dump. |
| E04 | Wrong restore target fingerprint | Plan confirmation rejected. |
| E05 | Truncated/reordered/tampered age payload or manifest | Authentication/binding failure before `pg_restore`. |
| E06 | Missing age identity | Clear key-unavailable error, no plaintext output. |
| E07 | Archive TOC parses but restore SQL fails | Archive verification may pass; restore test fails with partial-target state. |
| E08 | Missing one SELECT grant or RLS bypass | Full dump fails; no partial backup published as complete. |
| E09 | Path traversal, symlink swap, odd identifier | No arbitrary filesystem access or shell execution. |
| E10 | Delete candidate is only valid backup | Retention refuses; dry-run records reason. |

## Fixture execution contract

1. Create an isolated source database from `template0` and a clean target on each supported major. Test setup creates ephemeral roles and optional objects; it never stores credentials in the repo.
2. Run `core.sql` with `psql -X -v ON_ERROR_STOP=1`; run optional SQL only when its named capability exists. Capture the reason for every skip.
3. Use same-major client tools and `pg_dump -Fc --no-subscriptions`. Record `pg_restore -l` TOC and compare expected object classes, not unstable raw TOC numbers.
4. Restore into a fresh target with `pg_restore --exit-on-error`; run `assertions.sql`. For a partial restore, use a separately prepared target when dependencies are expected.
5. After M4, run the same checks through the encrypted artifact reader. Ciphertext checksum, age authentication, TOC parse, and actual restore are distinct result levels.
6. Keep a machine-readable result per major/fixture with `pass`, `expected-failure`, `skip`, or `fail`, reason, client/server versions, and a link to the test run. A support claim requires zero unexplained skips or failures in core cases.

[PostgreSQL `pg_dump`](https://www.postgresql.org/docs/18/app-pgdump.html), [`pg_restore`](https://www.postgresql.org/docs/18/app-pgrestore.html), and [version policy](https://www.postgresql.org/support/versioning/) are the primary references.
