# M3 profiles and selective operations guide

M3 adds **named profiles** and **scope-resolved selective backups** on top of the M2 backup and restore paths. The rule the milestone is built around is in its acceptance criteria: *support explicit scope without false dependency promises*. A selective archive either contains everything it needs to restore into an empty database, or `backupctl` refuses to create it. There is no override flag, because the tool cannot verify what `pg_dump` would silently omit.

## Requirements

- The M2 requirements unchanged: edition-2024 Rust toolchain, PostgreSQL 16/17/18, version-matched `pg_dump`, `pg_dumpall`, `pg_restore`, `psql`, and `createdb` in one absolute `client_bin_dir`, and a source database named `backupctl_fixture_*`.
- Profiles live in the same service TOML as `[[profile]]` blocks ([`config/m3.example.toml`](../../config/m3.example.toml)). Every profile repeats `database`, which must equal `[source].database`; a profile pointing at another database is rejected at load time along with duplicate names and unknown `--profile` values.
- Selection resolution runs `psql` catalog queries, which the M2 preflight already resolves and version-checks.

## Commands

```text
backupctl --config /absolute/path/to/m3.toml profile list
backupctl --config /absolute/path/to/m3.toml profile validate app-schemas
backupctl --config /absolute/path/to/m3.toml backup create --profile app-schemas --dry-run
backupctl --config /absolute/path/to/m3.toml backup create --profile app-schemas --confirm-synthetic
backupctl --config /absolute/path/to/m3.toml backup inspect BACKUP_UUID
backupctl --config /absolute/path/to/m3.toml backup verify BACKUP_UUID --level archive
backupctl --config /absolute/path/to/m3.toml restore plan BACKUP_UUID --target backupctl_fixture_sel --security portable --section pre-data
backupctl --config /absolute/path/to/m3.toml restore run PLAN_UUID --confirm-target backupctl_fixture_sel
```

Without `--profile`, `backup create` emits the byte-identical M2 argv (a profile-less whole-database dump), and without `--section`, `restore plan` replays the whole archive as in M2. `--dry-run` runs the same resolution `backup create` does — preflight, catalog queries, and every refusal — then prints the resolved scope and writes nothing.

## Profile rules, enforced before connecting

`Profile::validate` rejects a profile without touching the cluster:

| Rule | Why |
| --- | --- |
| Names are exact lower-case identifiers; no `*`, `%`, or patterns | `pg_dump` patterns are matched against the catalog by the tool, not by `backupctl`, so a pattern's resolved set cannot be recorded honestly in a manifest |
| `pg_*` and `information_schema` cannot be selected | system catalogs are not backup content |
| `tables` cannot be combined with `schemas`/`exclude_schemas` | `pg_dump` ignores `--schema`/`--exclude-schema` once `--table` is given; selecting both would silently discard half of the intent |
| `mode = "schema-only"` cannot set `large_objects = true` | a schema-only dump carries no object bytes |
| Duplicate inclusions or exclusions are refused | an accidental repeat means the operator did not read the scope |

`mode` accepts `schema-and-data` (default), `schema-only`, and `data-only`.

## What the resolver reads from the catalog

`profile validate` and `--dry-run` resolve a profile against the live source with `psql --tuples-only --no-align` queries and report the exact names `pg_dump` will be given:

- **Zero matches fail.** A schema list that resolves to nothing, or a table list naming relations that do not exist, is refused (`"selects schemas that match nothing: ..."`) rather than producing an empty archive that looks like a success.
- **Partition families expand.** A table selection containing a partitioned parent is expanded through `pg_inherits` to the parent and all descendants, so the manifest and the argv carry every child. This is done deliberately instead of passing `pg_dump --table-and-children`, because the resolved names must be recorded in the artifact before the tool runs, and that flag does not exist before PostgreSQL 16.
- **Nothing is resolved twice with different answers.** The names handed to `pg_dump` are the names put into the manifest `scope` block, so `backup inspect` reports the same set that was archived and `pg_dump`'s own pattern matching never decides scope.
- **More than 512 resolved relations is refused.** An argument list that long is a `pg_dump` invocation nobody can review, and it usually means a schema filter was the real intent.
- **Extension membership is recorded.** Objects belonging to an extension inside the selection are listed in the manifest so a restore operator can see that those members came from an extension rather than from application DDL.
- **Large objects are all-or-nothing.** `pg_dump --large-objects` writes every large object in the database, never the subset belonging to a selection. So a filtered profile is refused while the database holds any large object, and a whole-database profile that leaves them out is refused too, with the count in the message. `--no-large-objects` is not the escape hatch: the refusal states how many would be lost.

## The fail-closed dependency rule

`find_dangling` walks `pg_depend`, `pg_constraint`, `pg_inherits`, `pg_rewrite`, `pg_trigger`, `pg_attrdef`, `pg_attribute`, `pg_type`, and `pg_proc` and reports every reference from an in-scope object to an out-of-scope one. Six kinds are recognized:

| Kind | Reference found |
| --- | --- |
| `foreign key target` | a `pg_constraint` row whose table is in scope and whose referenced table is not |
| `parent relation` | an inheritance or partition child in scope whose parent is not |
| `sequence default` | a column default depending on a sequence outside the selection |
| `column type` | an enum, domain, composite, range, or array-of-those column type outside the selection, including the array element type |
| `view base relation` | a view or materialized view in scope, reached through its `pg_rewrite` rule, whose base relation is not |
| `function` | a trigger function or a default-expression function in scope whose `pg_proc` entry is outside the selection |

`pg_catalog` and `information_schema` are always exempt, since those exist in every database. Any other unresolved reference aborts `profile validate`, `--dry-run`, and `backup create` with a message that names each pair and the way out:

> `profile aux-only is not self-contained: aux.orders depends on app.accounts (foreign key target). pg_dump does not write objects from outside the selection, so this archive could not restore into an empty database on its own; widen the selection or restore into a database that already holds those objects`

The scope predicate is asymmetric on purpose. A schema selection owns the standalone sequences, types, and functions inside that schema, because `pg_dump --schema` writes them; a table selection owns none of them, because `pg_dump --table` does not — which is why selecting only `app.accounts` is refused for its enum and domain even though both live in `app`.

## Recorded scope and the table-of-contents digest

A selective artifact's manifest gains a `scope` block recording the profile name, the mode, the requested names, the **resolved** names after family expansion, the exclusions, the extension members, the large-object choice, and whether the dump was whole-database. Pre-M3 artifacts carry no `scope`, and the format string stays `m1-development-plaintext`, so old artifacts still load and list.

`backup create` also records `toc_sha256`: the SHA-256 of the `pg_restore --list` output for that payload, newline-joined. `backup verify --level archive` recomputes it and fails with `"archive table of contents does not match the manifest; the payload was replaced or re-dumped"` if it differs, so archive-level verification now proves the object list of the archive, not only that it parses.

## Section-limited restores

`restore plan` accepts `--section pre-data|data|post-data` one or more times, and the chosen set is bound into the plan digest, so `restore run` replays exactly the reviewed sections.

Two refusals come from the fact that every M3 restore creates its own target database:

- A set that omits `pre-data` while selecting `data` or `post-data` is refused — there would be no tables to load into.
- `post-data` without `data` is refused — its indexes, constraints, and triggers would apply to rows that were never loaded.
- A section-limited set cannot use `--security dr`: an archive that omits sections cannot reconstruct roles, ownership, or privileges, so the plan fails before any cluster probing and says to use `portable` or restore every section.

For a table-selected archive, `restore run` first issues `CREATE SCHEMA IF NOT EXISTS` for each schema named by the resolved relations, because a `--table` dump contains no `CREATE SCHEMA` statement and `pg_restore` cannot create a schema it never saw. Only manifest-validated exact non-system schema names into a `backupctl_fixture_*` database are accepted.

A partial restore never raises the artifact's verification level: `restore run` reports `verification level: none` (or the level already recorded) and warns `warning: only part of the archive was replayed, so this run does not prove the artifact restores completely`. Only a full restore of the artifact marks it `restore-tested`.

## Known limitations

- **`mode = "data-only"` archives exist but cannot be restored by this CLI.** `pg_dump --data-only` writes COPY data with no DDL, and every M3 restore target is a freshly created database, so such an archive always fails on restore. It is accepted at profile validation because the selection itself is self-contained; treating it as usable would be the false promise this milestone exists to prevent.
- **Object-level selection is not implemented.** Selection stops at schemas, tables, and sections; there is no `pg_restore --use-list` table-of-contents editing yet.
- **`ALTER DEFAULT PRIVILEGES` and database-level `GRANT ... ON DATABASE` stay cluster prerequisites**, as in M2, and no password verifier ever enters an artifact, so restored roles still need an operator-assigned password.
- A trigger function that writes to a table *by name* creates no catalog dependency, so excluding that table from an otherwise-valid selection is not detected; the archive would restore a trigger whose target does not exist.
- Retention, deletion, catalog, scheduling, encryption, and off-host storage remain later milestones (M4+).

## Validation

`tests/m3_docker_smoke.sh` runs the real CLI against PostgreSQL 16, 17, and 18 containers with version-matched clients and no network. Per major it checks: profile listing and validation against the live catalog, all three large-object refusals, the zero-match refusal, each of the five reachable dangling kinds, family expansion to exact names, `--dry-run` publishing nothing, `--exclude-extension` refused on 16 and accepted on 17/18, the recorded `scope` block and `toc_sha256`, archive verification failing against a rewritten TOC digest and passing again once restored, `--section data` refused, DR-plus-partial refused, a pre-data-only restore that leaves zero rows and reports `verification level: none` with the warning, a full selective restore that passes [`selective-assertions.sql`](../../tests/fixtures/postgres/selective-assertions.sql) and marks the artifact `restore-tested`, a schema-only restore holding structure and the cross-schema foreign key but no rows, and a table-selected events restore carrying both partition rows plus the 2026 child. `tests/m1_docker_smoke.sh` and `tests/m2_docker_smoke.sh` still pass unchanged, which is the no-regression evidence for the optional manifest fields.
