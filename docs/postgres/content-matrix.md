# PostgreSQL logical backup content matrix

Status: M0 contract for PostgreSQL 16–18. `D` means native `pg_dump` archive content, `G` means `pg_dumpall --globals-only`, and `X` means a different backup mechanism. "Full" means an unfiltered single-database dump with adequate privileges; it is not a guarantee that external dependencies exist on the target. The fixture ID identifies a case in [fixture-plan.md](fixture-plan.md). Every row needs a round-trip result on 16, 17, and 18 before a release claim. [16](https://www.postgresql.org/docs/16/app-pgdump.html), [17](https://www.postgresql.org/docs/17/app-pgdump.html), [18](https://www.postgresql.org/docs/18/app-pgdump.html).

| Content | Native scope | Initial policy / selectivity | Restore condition and metadata | Fixture |
| --- | --- | --- | --- | --- |
| Schemas, tables, table data | D, database | Full; named schema/table and schema/data-only later | Other-schema dependencies can be absent; record resolved names and TOC IDs | F01, F02 |
| Indexes | D, post-data | Full with table; no independent guarantee | Rebuild may be slow or fail on inconsistent partial data | F01 |
| Primary, unique, check, foreign-key constraints | D, pre/post-data | Full; selection follows native TOC | Foreign key needs referenced table; record missing dependencies | F01, F02 |
| Views and materialized views | D | Full; selection must be tested | Referenced relations/extensions must exist; validate populated materialized view data/state | F03 |
| Functions, procedures, triggers, rules | D | Full; no arbitrary-object UI in first release | Language/extensions and referenced objects needed; source code can execute on restore | F03, F04 |
| Sequences and values; identity/generated columns | D; values in data section | Full; data-only includes sequence state | Selected table may not imply every associated sequence; assert next value | F01, F02 |
| Enum, composite types, domains | D | Full; selection may omit dependencies | Table restore needs types installed first | F03 |
| Extensions | D, database-level | Full definition; no extension-binary backup | Target must have compatible extension package/version; record list and preflight | F05 |
| Comments and security labels | D where supported | Comments full; security labels need provider-specific fixture | Provider may be absent; do not claim generic support | F03, F09 |
| Ownership, grants, default privileges | D | Full; portable restore may opt out of owner/ACL | Target roles must exist or options must strip owner/ACL; record flags | F06 |
| Row-level security policies | D definitions | Full; RLS is not a row-filtering backup feature | Default dump disables row security; insufficient role can fail; no partial-data claim | F07 |
| Partition hierarchy and child data | D | Selected parent uses `--table-and-children`; child-only is advanced partial | Record expanded child set; check data routing and collations | F08 |
| Table inheritance | D | Same explicit parent/children rule | Parent-only selection can omit child rows | F08 |
| Large objects | D data | Full default; filtered schema/table excludes unless `--large-objects`, which adds all | No native reference-based subset; verify bytes and OID references | F10 |
| Publications | D | Full default; no automatic replication activation | Publication may require special target privileges and owner | F11 |
| Subscriptions | D only under conditions, including superuser visibility | Explicit `--no-subscriptions`; record omission | May contain connection secrets; later restore needs separate activation plan | F11 |
| Foreign-data wrappers, servers, user mappings, foreign tables | D definitions | Full archive is sensitive; foreign table data is not included by default | External endpoint, extension and mapping secrets may be needed; no auto-connect | F12 |
| Collations and text-search objects | D definitions | Full, version/locale-sensitive | Target OS locale/ICU and provider must be compatible | F13 |
| Database creation, database settings, DB privileges | D with `--create`/tool behavior | Full metadata; creation is an explicit restore policy | Check target name, locale, tablespace, privileges; no blind overwrite | F14 |
| Roles, memberships, role attributes/password hashes | G, cluster-global | Out of initial artifact; manual prerequisite; future `--no-role-passwords` | Privileged and can conflict with target; no auto-restore | F15 |
| Tablespaces and global parameter grants | G, cluster-global | Out of initial artifact; manual prerequisite | Target filesystem and privileges required | F15 |
| WAL archives, replication slots, server files | X, cluster/server | Outside logical artifact | Physical/WAL mechanism needed for PITR | F16 |
| OS cron, systemd, application jobs, external files, env, certs, secrets | X, host/application | Outside database backup | Recovery runbook records dependency names, never secret values | F16 |
| `postgresql.conf`, `pg_hba.conf`, `pg_ident.conf` | X, server configuration | Outside logical artifact | Separate privileged config backup and manual review | F16 |

## Selective-backup rules

- Resolve patterns to exact objects before invoking `pg_dump`; reject zero/ambiguous matches. Record requested and resolved scope in the encrypted manifest. A selected schema/table dump does not automatically include dependencies elsewhere. [`pg_dump`](https://www.postgresql.org/docs/18/app-pgdump.html).
- For a partitioned/inherited parent, use `--table-and-children`, available in the selected majors. A parent-only dump is not represented as a full hierarchy. [`pg_dump` 16](https://www.postgresql.org/docs/16/app-pgdump.html).
- A filtered schema/table dump excludes large objects by default. `--large-objects` adds all large objects, not just those referenced by selected tables. It can disclose unrelated objects; require explicit scope acknowledgement. [`pg_dump` 18](https://www.postgresql.org/docs/18/app-pgdump.html).
- `--schema-only` omits data/sequence values/large-object bytes. `--data-only` requires compatible target schema. `pg_restore` TOC filters are selective, not a dependency solver. [`pg_restore`](https://www.postgresql.org/docs/18/app-pgrestore.html).
- Do not enable `--enable-row-security` as a routine partial-data mode. PostgreSQL documents its interaction with `COPY` restore and its departure from full-data backup. [`pg_dump` 16](https://www.postgresql.org/docs/16/app-pgdump.html).
- Normal database dumps are sensitive. User mappings can hold passwords; subscription connection information may contain plaintext passwords. Even with `--no-subscriptions`, assume database-held credentials may be in the archive. [User mappings](https://www.postgresql.org/docs/18/sql-createusermapping.html), [subscription catalog](https://www.postgresql.org/docs/18/catalog-pg-subscription.html).

## Source boundary

`pg_dump` covers a single database; `pg_dumpall` covers globals. `pg_basebackup` covers the entire physical cluster and cannot select a database or table. WAL archiving is a separate continuous-recovery mechanism. [Backup methods](https://www.postgresql.org/docs/18/backup.html), [`pg_dumpall`](https://www.postgresql.org/docs/18/app-pg-dumpall.html), [`pg_basebackup`](https://www.postgresql.org/docs/18/app-pgbasebackup.html).
