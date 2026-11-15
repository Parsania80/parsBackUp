# H02 native authentication and maintenance recovery contract

This increment implements native operations for **writable versioned fixture** writer/reader configurations. Production remains disabled before any resource access. Legacy configurations, artifact v1, source fingerprints and restore-plan v1/v2 serialization retain their existing meaning. This is a declarative contract, not an operating flow.

## Command resources and limits

| Operation | Required resources | Database connection |
|---|---|---|
| `profile validate` | source, tools, configured profile; no store or keys | Original database |
| `backup create` (including dry-run) | source and tools; real create additionally existing writer keys and writable store | Original database; globals explicitly use it too |
| `restore plan/run` | source, tools, identity and verifier, existing writable store; no recipient or signing secret for reader | Maintenance database for probes/roles/creation; fresh target for schema/archive application |

Other versioned capabilities retain their existing gates. Native paths require explicit source/tools; absence refuses `CONFIG_INVALID` before resource access. Real backup still requires `--confirm-synthetic`. Structural config checking never opens referenced resources. Dry-run/profile resolution open no keys/store. Existing bounded 64-KiB stdout/stderr capture, process-group timeout and streaming watchdog remain in force. Passfiles are bounded to 64 KiB and 256 entries; no password or native stderr is emitted.

## Native boundary

Versioned tools must be executable regular ELF files with root ownership, no group/other write, no symlinks and root-owned non-writable ancestry. Fixed executable names only; shell wrappers remain permitted exclusively on the legacy fixture path. Execution pins a validated descriptor through `/proc/self/fd`; Linux is the supported implementation target. All five tools (`pg_dump`, `pg_restore`, `pg_dumpall`, `psql`, `createdb`) are required and version-checked by preflight before live operations, including dry-run/profile validation. This conservative shared toolset requirement is explicit for this increment.

Peer connections require protected no-symlink socket-directory ancestry controlled by root/service UID and no group/other write. Administrator-provisioned peer HBA remains a deployment trust requirement; success does not prove the server selected peer authentication. TCP uses literal loopback, `PGREQUIREAUTH=scram-sha-256`, `PGSSLMODE=disable` and `PGGSSENCMODE=disable`. Every subprocess clears inherited environment, ignores psql startup files and refuses interactive passwords. Libpq's [PGREQUIREAUTH mapping](https://www.postgresql.org/docs/16/libpq-envars.html) and [authentication control](https://www.postgresql.org/docs/16/libpq-connect.html#LIBPQ-CONNECT-REQUIRE-AUTH) define the SCRAM requirement.

Passfiles are opened by protected directory descriptors with no-follow/nonblocking opens, require service UID ownership and mode 0600 or stricter, and are parsed without diagnostics containing contents. Every non-comment entry has five explicit, nonempty libpq-escaped fields; wildcards, duplicates, invalid escapes and missing endpoint/user/database matches refuse. Matching credentials for maintenance and target are checked before restore effects. A private sealed in-memory descriptor snapshots validated bytes for each child; the pathname cannot be swapped between validation and libpq use. Hard links to configured keys refuse by descriptor identity. Files remain outside store/scratch by validated protected ancestry and lexical disjointness; broader store/key/scratch descriptor policy remains a later H02 gate.

## Restore-plan compatibility

New writer format: `h02-restore-plan-v3`, only for authenticated signed fixture artifacts. It uses the exact existing ordered RestorePlan fields, then optional `rollback` (required in v3), then required `native_context`. Canonical bytes are compact serde JSON in that struct order (report objects may reorder fields; deserialize the typed plan before recomputing its digest); digest remains lowercase SHA-256 of those bytes. `native_context` field order is `mode`, `host`, `port`, `user`, `maintenance_database`, `auth`, `client_bin_dir`, `password_file` (explicit null for peer). Values bind the literal endpoint, acting database role, local authentication choice and configured native/credential paths; original database/major, target, security, sections and rollback acknowledgement remain bound in existing fields. No credential contents enter plans. Production context is rejected by this fixture implementation; production plan validation/writer remains a separate compatibility gate.

v1/v2 omit `native_context` entirely and retain frozen bytes/digests. Legacy engines reject v3; versioned engines reject v1/v2 and any changed context before a native probe or job/cluster mutation. Contexts cannot be removed/downgraded to cross modes. v3 requires literal source/target names, synthetic prefixes, the existing exact 15-minute time window and signed rollback binding. Source fingerprint continues to use original database, literal endpoint and major; maintenance/user/tool changes do not rewrite artifact identity. Target names cannot be conninfo/URI strings. Explicit maintenance selection uses [createdb --maintenance-db](https://www.postgresql.org/docs/18/app-createdb.html).

## Verification boundary

Acceptance requires frozen legacy vectors, context drift/downgrade checks, protected resource tests and actual PG16/17/18 native clients: successful SCRAM, refused trust/MD5/clear-password fallback, escaped passfile credentials, inherited-environment isolation, no prompts, and a signed restore after dropping the original database. Verify fresh-target contents and reader custody without signing/recipient files. Failure after cluster mutation retains the target for inspection under existing restore semantics; no automatic cleanup or zero-side-effect claim. Full H02, deployment hardening, production enablement and T03 are not completed here.

Canonical test vectors are pinned in [restore.rs](../../crates/backup-domain/src/restore.rs): v3 SHA-256 `820c8e6f07924e7b107c4df864913fd940b512349fac01c4186e00f69172f854`; legacy signed v2 SHA-256 `9f9361e5ebc80312749acd990e5bdf668b8eac28d374901ba2e8c3c1ce81e8b6`. The v3 vector uses fixed UUIDs/timestamps, literal TCP/SCRAM paths and a non-acknowledged completion binding with unknown high water; these vectors contain no credentials.
