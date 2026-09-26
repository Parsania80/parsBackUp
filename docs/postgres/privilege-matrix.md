# PostgreSQL privilege contract

Status: M0 hypothesis to verify with real PostgreSQL 16–18 containers. This is a **minimum-access test plan**, not a promise that one grant recipe works for every schema, extension, or version. The application must preflight and report privilege failures instead of escalating itself.

| Operation | Candidate least privilege | Explicit failure / boundary | Fixture |
| --- | --- | --- | --- |
| Inspect source version and database | CONNECT and readable catalog views | No password or full connection string in diagnostics | P01 |
| Full logical dump | CONNECT; USAGE on schemas; SELECT on tables, sequences, large objects as needed; ownership/visibility for some definitions | `pg_read_all_data` can simplify read grants but does **not** bypass RLS. A full dump can fail when RLS applies. Never silently switch to partial rows. | P02, P03 |
| Filtered dump | Same rights on selected objects, plus catalog visibility to resolve exact scope | Cross-schema dependencies and large-object rights may remain missing | P04 |
| Global roles/tablespaces export | Privileged `pg_dumpall --globals-only`; future only | Not in initial artifact; password hashes excluded with `--no-role-passwords` if later implemented | P05 |
| Create empty target database | CREATEDB or pre-created database owned by restore role | Creating/dropping a production DB is never implicit | P06 |
| Restore into new DB | CREATE on target DB/schema, ownership or suitable privileges to create objects; preinstalled extensions | Preserving source ownership requires target roles and adequate rights. `--no-owner` is the portable default candidate. | P07 |
| Restore data into existing schema | INSERT and related rights, compatible schema, sequence rights | Data-only restore can violate constraints or trigger policies; no automatic trigger disabling | P08 |
| `--disable-triggers` | Elevated privilege for system constraint triggers | Excluded from routine restore; no silent superuser requirement | P09 |
| Create publication | CREATE on DB; ownership of included tables; some publication forms require superuser | Publication remains definition only and is tested separately | P10 |
| Create/activate subscription | Version-specific subscription privileges and publisher connectivity | Excluded by `--no-subscriptions` initially; never auto-activate | P11 |
| Extension/FDW restore | CREATE/USAGE/ownership rights vary by extension and wrapper | May require trusted extension package or superuser; reject unsupported plan | P12 |

[Predefined roles](https://www.postgresql.org/docs/18/predefined-roles.html) document `pg_read_all_data` and its RLS limit. [`pg_dump`](https://www.postgresql.org/docs/18/app-pgdump.html) documents RLS and dump permissions; [`pg_restore`](https://www.postgresql.org/docs/18/app-pgrestore.html) documents ownership and trigger options. [Role attributes](https://www.postgresql.org/docs/18/role-attributes.html), [publication privileges](https://www.postgresql.org/docs/18/sql-createpublication.html), and [subscription privileges](https://www.postgresql.org/docs/18/sql-createsubscription.html) must be checked for every supported major.

## Required role fixtures

- `fixture_owner`: owns source objects; no superuser/CREATEDB/CREATEROLE.
- `fixture_reader`: CONNECT/USAGE/SELECT only, including a run with missing one table grant.
- `fixture_read_all`: granted `pg_read_all_data`, still subject to RLS.
- `fixture_restore`: owns a fresh target database, no superuser; test `--no-owner` and `--no-acl` separately.
- `fixture_admin`: ephemeral test-only elevated role for globals/subscription observations; never the default service identity.

Create these roles in ephemeral test setup, not in repository SQL containing credentials. CI generates random passwords if password auth is needed. Each test records exact server/client major, grants, command options, exit status, and safe diagnostic category. Do not log passwords or raw archive SQL.
