# H01 production configuration and release policy

Status: **policy defined 2026-11-15**, inspected against B06 checkpoint `c40a953`. This is the H01 decision record authorized by the operator, not a shipped parser, production enablement, or operating flow. H02 implements the contracts below in reviewable increments; H03–H05 and V01–V03 supply deployment and release acceptance. The current CLI remains synthetic-only. Authority: [roadmap H/V](../../project.md#h--m6-harden-cli-and-deploy-safely), [frozen artifact v1](../backup-format/manifest-v1.md), [ownership ADR](../architecture/adr-0004-working-directory-ownership.md), [retention contract](m5b-retention.md).

## Decisions and alternatives

| Decision | Selected first-release policy; benefit | Alternative and tradeoff |
|---|---|---|
| Connection topology | Local Unix socket or literal loopback TCP only; bounds the transport and deployment matrix. | Remote TLS would cover more installations but needs independent endpoint/CA/authentication and failure tests; deferred. |
| Restore topology | Fresh database at the configured local endpoint, same PostgreSQL major; a local replacement cluster can reuse that endpoint. | Independent target endpoint or cross-major restore needs new identity/plan bindings and a tested support extension; deferred. |
| Credentials | Administered peer authentication for sockets, SCRAM plus a protected passfile for loopback TCP; no interactive service prompts. | Inline passwords, environment secrets and automatic auth fallback broaden exposure; refused. |
| Configuration | Explicit version/mode/access, preserving the unversioned fixture parser as a separate compatibility path. | Inferring production from a database name or absent confirmation can accidentally lift the guard; refused. |
| Machine reports | Opt-in `--output json-v1` with a versioned envelope; preserve existing fixture `--output json`. | Changing existing JSON in place breaks callers and frozen assertions; refused. |
| Restore contents | Existing supported schema/data and section policies into fresh targets. | Data-only into an existing schema and destructive overwrite require separate safety contracts; excluded. |
| Writer custody | First release retains the decryption identity on a writer, plus recipient/signing/verifying files; matches the authenticated publication path. | Writer without identity is a later explicit extension, not a configuration omission. |

These choices close H01's product decisions. They do not certify an implementation or override an accepted artifact/plan format. No dependency change is authorized by this record.

## Inspected implementation and gaps

| Owner | Current behavior | Required follow-through |
|---|---|---|
| [domain config](../../crates/backup-domain/src/config.rs) / [profile](../../crates/backup-domain/src/profile.rs) | Closed unversioned TOML; one required source; local hosts and fixture-name guards; mandatory identity path inside encryption. | Separate legacy and versioned deserialization, explicit access/transport/auth validation and command-specific requirements. Keep legacy examples/tests unchanged. |
| [CLI entry](../../crates/backupctl/src/main.rs) / [arguments](../../crates/backupctl/src/cli.rs) | Global fixture validation, human/bare JSON reports, full `anyhow` error chain; ordinary store construction loads keys eagerly. | Safe structured failures and lazy custody; parse output selection before configuration I/O. Never print TOML snippets. |
| [native tools](../../crates/backup-postgres/src/tools.rs) / [adapter](../../crates/backup-postgres/src/lib.rs) | Absolute client paths, cleared environment, noninteractive commands, TLS disabled; preflight connects to `source.database`. | Trusted tool/path checks, explicit auth, maintenance-database restore probes and offline archive verification. Lost-source recovery cannot require that database to exist. |
| [artifact identity](../../crates/backup-domain/src/artifact_v1.rs) | Source fingerprint hashes engine, major, literal host, port and original database; excludes database user and maintenance DB. | Preserve those bytes. Fingerprints identify recorded logical location, not a unique physical cluster or authorization principal. |
| [restore plan](../../crates/backup-domain/src/restore.rs) | Fixture guards, 15-minute plans, source/target checks, signed v2 rollback binding. | Production execution needs a new explicitly versioned plan contract; never reinterpret old fixture plans by removing their validation. |
| [local storage](../../crates/backup-local/src/lib.rs) | Live claims/working directories; `--read-only` verification suppresses observations but can need writable scratch/locks. | Implement true snapshot/media read-only access and external private scratch before claiming that capability. Preserve writable-store lock identity/order. |

## Configuration version 1 contract

The schema below is implemented for structural checks and limited fixture operations by the [H02 first increment](h02-config-access-reports.md). Native, custody and snapshot capabilities still require their later H02 increments. No new example under `config/` is installed by H01.

| Surface | Required version-1 meaning |
|---|---|
| Root `config_version` | Integer `1`, mandatory for this schema. Unknown versions refuse before keys, native tools, store creation or migration. Independent of artifact, plan, inventory and report versions. |
| Root `mode` | Mandatory `fixture` or `production`. Fixture always enforces local fixture source/target names and `--confirm-synthetic` for creates. Production never treats that flag as authorization. |
| Root `access` | Mandatory `writer`, `reader`, `public` or `inventory`, as defined below; a capability ceiling, not OS/API authentication. |
| Root `read_only` | Mandatory boolean. True forbids all store writes, including locks, plans, jobs, observations, recovery, protection, retention previews and key publication. |
| Root `export_globals`, `timeout_seconds` | Boolean defaults false; timeout defaults 300 and stays within 1–3600 seconds. Globals export is allowed only for a writer and remains explicit opt-in. |
| `[storage] root` | Required absolute local store root, trusted ownership, existing-root requirement for readers. No remote URI, implicit alternate root or multiple estates. |
| `[source]` | Optional for offline reads. Required for create, live profile validation and restore plan/run. Exact fields: `host`, `port`, `user`, `database`, `maintenance_database`, `auth`, optional `password_file`. Profiles require source and retain the existing selection field names. |
| Names/port | Database and user are literal lower-case ASCII identifiers matching `[a-z_][a-z0-9_$]{0,62}`; target/maintenance DB use the same restriction. Port is integer 1–65535. |
| `[tools] client_bin_dir` | Absolute trusted version-matched PostgreSQL directory. Required only for native-tool operations, including offline archive verification, which needs no `[source]`. No executable names/options supplied by callers. This moves the path out of source in version 1; the legacy field stays unchanged. |
| Source `maintenance_database` | Explicit existing administrator-provisioned DB, normally `postgres`; independent of the original logical source DB. Used for restore version/existence/role probes, globals and database creation, never substituted into the artifact source fingerprint. |
| Source `auth` | `peer` for an absolute Unix socket directory forbids `password_file`; `scram-passfile` for host exactly `127.0.0.1` or `::1` requires it. Other combinations refuse. No DNS alias `localhost`, host lists, abstract sockets or connection-string fields in version 1. |
| `[encryption]` | Optional block with optional `identity_file` and `recipient_file`; role table determines required/forbidden fields. This optionality belongs to the new schema only. |
| `[signing]` | Optional block with optional `signing_key_file` and `verifying_key_file`; role table determines required/forbidden fields. The verifier is installed independently of artifacts. |
| `[scratch] root` | Optional absolute external private directory, allowed only with `read_only=true` and `access="reader"`. Required when that command needs plaintext files. Disjoint from store and key directories; no implicit `/tmp` fallback. Writable operations retain the existing store-owned scratch path and claims. |

Unknown/duplicate fields at every level, incompatible fields, multiple source blocks and extra command-line native options refuse. Config contents are literal TOML: no environment interpolation, includes, connection URIs, shell expansion or password values. An otherwise valid `[source]` may be present in a reader config for later restore, but offline commands never probe it or read its passfile. An inventory/public config forbids source/profiles/tools/scratch/encryption; public requires only a verifier. Writer with `read_only=true` refuses. `export_globals=true` on other access roles refuses.

The config file itself must be an absolute, protected, regular no-follow file, service-owned mode 0600, with a 64-KiB size bound and no untrusted-writable ancestry. Error reporting never includes its contents. Key/passfile/store/scratch alias checks must use resolved descriptor identity and protected ancestry, not just lexical prefix checks. H02 records concrete native-output, decrypted-size/free-space and scratch limits before their enforcement; this policy adds no arbitrary override for them.

An unversioned file remains on the existing fixture-only path, preserving the current fields, defaults, artifact shapes, tests and bare JSON. It cannot become production. `mode` without `config_version`, version 1 missing `mode`, and mixed legacy/new fields refuse rather than guessing. Versioned fixture mode permits testing the new contracts on synthetic data. Configuration is immutable for a running invocation/job; a later file edit affects only a new invocation, and execution revalidates its saved plan context.

Only after V03 enables production may an authorized local writer invoke `backup create` with an explicit production configuration. `--confirm-synthetic` in production refuses as not applicable; there is no production force/bypass flag. Scheduled invocations use that same command/capability path, never a weaker publication path.

Policy specimen for a production writer (structural checks accept it only from a protected versioned config file; production operations remain disabled):

```toml
config_version = 1
mode = "production"
access = "writer"
read_only = false
export_globals = false
timeout_seconds = 300

[source]
host = "/var/run/postgresql"
port = 5432
user = "backup_reader"
database = "application_db"
maintenance_database = "postgres"
auth = "peer"

[tools]
client_bin_dir = "/usr/lib/postgresql/18/bin"

[storage]
root = "/var/lib/backupctl/store"

[encryption]
identity_file = "/etc/backupctl/keys/generation-1/identity.key"
recipient_file = "/etc/backupctl/keys/generation-1/recipient.key"

[signing]
signing_key_file = "/etc/backupctl/keys/generation-1/signing.key"
verifying_key_file = "/etc/backupctl/keys/generation-1/verifying.key"
```

## Local connections, credentials and privileges

Unix sockets require an absolute, protected directory controlled by the trusted PostgreSQL deployment and administrator-configured `peer` HBA rules, including an explicit user map if required. The client cannot prove an HBA rule is peer merely because no password challenge occurred; trust authentication is not an approved production substitute. Peer uses the client's OS identity on local connections. [PostgreSQL peer documentation](https://www.postgresql.org/docs/18/auth-peer.html).

Loopback TCP uses `scram-passfile` with an explicit passfile, `sslmode=disable` and client `require_auth=scram-sha-256`. Failure to complete SCRAM refuses, with no fallback to trust, MD5 or clear-password authentication. This client control exists in the PostgreSQL 16 baseline; H02 tests linked-client behavior on all supported majors. The local network and host administrator remain trusted: this is not transport encryption or remote endpoint authentication. No remote hostname or tunnel deployment is supported by this policy. [Authentication controls](https://www.postgresql.org/docs/16/libpq-connect.html#LIBPQ-CONNECT-REQUIRE-AUTH), [password methods](https://www.postgresql.org/docs/18/auth-password.html).

Passfiles must be absolute, service-owned regular files, no symlinks, with mode 0600 or stricter inside protected directories outside the store/scratch. H02 validates final descriptors/ownership and rejects unsafe parent directories. Each entry uses explicit host/port/database/user fields, with no wildcard matching; include the maintenance and planned target databases where those operations need credentials. Apply libpq's escaping rules without logging file contents. Missing or mismatched credentials fail noninteractively. Keep `PGPASSFILE=/dev/null` when no passfile is permitted. PostgreSQL documents the matching format and rejects group/world-readable Unix passfiles. [Passfile rules](https://www.postgresql.org/docs/18/libpq-pgpass.html).

Retain a cleared native environment and explicit connection parameters for every subprocess. Do not inherit `PGPASSWORD`, `PGSERVICE`, `PGOPTIONS`, `PGHOST`, `PGDATABASE`, `HOME` defaults or authentication/certificate overrides. H02 generates only the approved locale, timeout, passfile and auth/transport settings. `psql` ignores startup files; commands do not prompt. Database arguments must never reach libpq as URIs or conninfo: `pg_restore --dbname` can override connection flags through such a string, which is why literal-name validation is a release requirement. [Environment behavior](https://www.postgresql.org/docs/18/libpq-envars.html), [database argument expansion](https://www.postgresql.org/docs/18/app-pgrestore.html).

Use a dedicated service OS identity and a least-privilege backup database role. Do not grant restore/admin privileges merely to run the timer. Explicit globals export and DR role application may require a separately provisioned privileged role; the program never grants itself rights or rewrites HBA. Restore uses a separately selected reader configuration with a suitable database user at the same endpoint and logical source identity. Username changes do not alter the frozen source fingerprint; production execution context must bind the acting user in the new plan. V01 verifies actual object/RLS/extension permissions; the [privilege matrix](../postgres/privilege-matrix.md) remains a test plan, not a universal grant recipe.

Remote TLS is **deferred**, not an accepted `sslmode` option. A future extension needs explicit endpoint configuration, protected CA/client credential references, `verify-full` hostname validation, no plaintext/downgrade fallback, controlled GSS interaction and all-major tests for wrong/expired/untrusted certificates, unavailable TLS and endpoint/plan drift. It must update this policy before adding fields or relaxing local validation. `require` alone does not express the same hostname-validation policy. [TLS connection controls](https://www.postgresql.org/docs/18/libpq-connect.html#LIBPQ-CONNECT-SSLMODE).

## Access roles and read-only custody

| Access | Configured key material | Permitted operation classes after implementation/release |
|---|---|---|
| `writer` | Identity, recipient, signing secret and independently trusted verifier required. | Signed encrypted create; reader and inventory operations within the selected config/DB privileges. Explicit key generate/publish only through validated writer paths; no overwrite/automatic rotation. |
| `reader` | Identity and trusted verifier required; signing secret and recipient path forbidden. | Inspect authenticated private metadata; checksum/archive verification. With writable access and an explicit source, plan/run restore; with writable access, retention preview/run. Inventory operations as below. No create or key generate/publish. |
| `public` | Trusted verifier only; no secrets/recipient/source. Requires `read_only=true`. | Public discovery, signature-only verification and keyless inventory/job reads. No decryption, archive validation, restore, maintenance or writes. Discovery is not fresh signature verification; signatures do not authenticate every public header claim. |
| `inventory` | No key blocks/source. | Keyless inventory/job reads. With `read_only=false`, existing explicit protect/unprotect, reconcile/adopt/rebuild/recover paths; no authenticated backup operations, create or restore. Recovery finishes started deletions only. |

All roles may check the configuration structurally. `key status` reads only material permitted by that role and omits secrets; it never attempts a forbidden/absent private key. Access is enforced before command-specific resources are opened. Inventory is key-free regardless of role; a reader/writer inventory command does not load its configured keys. Capability flags are not a defense against an OS user who can replace config or keys; service permissions provide that boundary.

In production mode authenticated backup operations require signed artifact v1. Discovery may identify development/unknown files as untrusted/excluded, but cannot silently fall back to a development decrypt/restore path. The legacy fixture path retains its existing shapes.

Profile listing reads only config and is allowed for writer/reader roles with profiles; live profile validation requires a source and writable writer/reader access. Other unlisted operation classes are denied until explicitly specified. A reader with `read_only=true` has only offline authenticated inspection/verification, config/profile listing, key status and keyless inventory/job reads; it cannot plan or execute a database restore.

True `read_only=true` is for a quiescent copied store/read-only medium. It performs no directory creation, migration, sweep, new lock file, plan, observation, job, audit or artifact update. Do not advertise arbitrary live raw SQLite copies as consistent snapshots; H04 supplies the approved copy/maintenance procedure. Decryption that needs files uses only explicit external mode-0700 scratch with operation-owned mode-0600 files and cleanup. H02 must implement and test this snapshot read path without inventing a second lock domain for writable operations; all writable readers retain existing shared activity/use claims. Unsupported concurrent/live read-only scenarios refuse or report observational disappearance, never weaken destructive-operation ownership. Read-only verification reports no persisted observation; archive verification can use matching trusted tools without a database connection.

Secrets, passfiles and public trust files live outside artifact/scratch roots. Secret files are private regular service-owned files; public key files may be 0644 but must not be writable by untrusted users. Protected ancestry, safe opens, bounded files and non-aliasing are H02 gates. A writer retaining an identity remains an accepted first-release custody limitation. Preserve [generation-specific offline recovery](../security/key-lifecycle.md); no multi-generation keyring, automatic key rotation or writer-without-identity promise is introduced.

## Restore and compatibility limits

The first production release supports PostgreSQL 16/17/18 and matching source-major native clients, same-major restores, one original logical database and one local root per config. The target is a fresh, different database at the same configured literal host/port. A replacement local cluster must reuse that endpoint/major; there is no `--force-source`, estate-remap, independent target connection or cross-major bypass. A logical fingerprint does not prove physical server identity. Restore probes use `maintenance_database` so loss of the original database is recoverable; its original name remains an authenticated artifact fact and fingerprint input.

| Request | Release policy |
|---|---|
| Full schema-and-data archive, full restore | Supported subject to native content/privilege gates; portable or explicit DR security policy. |
| Supported selective schema-and-data or schema-only archive | Existing resolver/dependency restrictions remain; no new arbitrary filter or dependency-closure claim. |
| Section-limited restore | Portable only; pre-data, pre-data+data or full contiguous sections. Partial scope is never labeled a full validated recovery. |
| Data-only profile/restore | Legacy fixture parsing stays compatible. Versioned production rejects data-only profiles and data-only restore requests; no pre-existing-schema support is promised. |
| Existing target, overwrite, `--clean`, automatic drop, trigger disabling | Refused. A failed run leaves partial target/roles for explicit repair; no automatic retry/drop/rollback claim. |
| DR roles/ownership/ACL | Explicit opt-in with authenticated exported globals, current validated role-script/conflict semantics and suitable privileges. Password verifiers, tablespaces, external services and excluded replication state remain outside recovery. |
| Unsigned/plaintext production artifact | Publication and authenticated restore/retention refuse. Legacy fixture shapes remain supported on the fixture path, never upgraded into trusted signed bytes. |

Retain restore's explicit plan/run split, exact `--confirm-target`, 15-minute expiry and B05 acknowledgement of a known older selection bound to that plan. Prune/delete execution retains full digest confirmation. None of these confirmations authorizes a broader artifact set, another target or a changed execution context.

Artifact v1, signature transcripts, source/profile fingerprints, existing restore plans and deletion-plan v1 bytes/digests remain unchanged. Before a production restore-plan writer is added, H02 must record its new format/canonical bytes and bind effective production mode, local endpoint/major, acting DB user and selected security/sections in addition to the existing artifact/rollback facts. Run must refuse changed execution context and require a new plan. This is a mandatory implementation gate; old fixture plans cannot authorize production execution. Retention's existing exact digest/expiry/evidence/maintenance rules remain; a report envelope never changes saved intent.

Production enablement must audit fixture checks across config, profiles, signed snapshot validation, plans and native adapters. In particular, the current signed manifest calls `Profile::validate`, which carries a fixture database guard. Separate deployment authorization from artifact semantics deliberately; do not remove name checks by global replacement. Any actual conflict with the frozen reader/format contract needs a separately recorded compatibility decision before that change. H01 does not authorize weakening the freeze or lifting these runtime guards.

Restoring executes source-selected SQL even for partial dumps. Signatures establish origin, not SQL safety; use a trusted source and appropriately isolated restore account/cluster. Native success is restore-completed, not independently restore-tested. [PostgreSQL restore warning](https://www.postgresql.org/docs/18/app-pgrestore.html).

## Reports, errors and compatibility versions

The explicit `--output json-v1` is implemented by the [H02 first increment](h02-config-access-reports.md). It works with legacy fixtures and version-1 configs; existing fixture `--output json` keeps its bare successful result and asserted semantics. Production machine callers must select `json-v1`; legacy `json` refuses with `OUTPUT_FORMAT_UNSUPPORTED`. Human output remains the default with safe error codes. Help/version and Clap syntax errors remain text; syntax failures exit 2 and need not emit JSON.

After successful argument parsing, `json-v1` emits exactly one JSON object on stdout for success, refusal or handled partial failure; no progress/native output is mixed into it. The required top-level fields are `format`, `operation`, `status`, `data`, `error`. Format is `backupctl-cli-report-v1`; operation is the canonical dotted command path, such as `backup.prune.run`. Status is `ok`, `error` or `partial`. Error is null on success, otherwise exactly `{code, message}` with a stable code and bounded safe text. Data is the command's documented result or null when no result exists; deletion partial data retains the exact disjoint completed/deleting/pending partition and job ID. Other started-operation failures must preserve/report known side effects through safe job/result facts, never a fabricated successful outcome. Noninteractive signal termination cannot promise a final envelope; later recovery/job inspection supplies durable evidence.

`status="ok"` requires a null error and exit 0. `status="error"` or `"partial"` requires an error object and exit 1; partial is reserved for known started work with incomplete effects, and its data must describe those known effects. An error message is at most 512 UTF-8 bytes of safe generated text; truncation must preserve valid UTF-8 and cannot expose raw diagnostic fragments. Result-data schemas must be recorded per command before the first new report writer.

Production-operation refusal envelope:

```json
{"format":"backupctl-cli-report-v1","operation":"backup.create","status":"error","data":null,"error":{"code":"PRODUCTION_NOT_ENABLED","message":"Production operations are not enabled in this build."}}
```

Exit codes stay **0** successful completion, **1** runtime refusal/failure/handled partial result, **2** syntax/usage error. A repeated completed deletion receipt is success; an interrupted plan with pending IDs is not. OS signal status remains platform-defined. No new 0–6 taxonomy or automatic retry hint is introduced. Preserve existing named retention/rollback codes in `error.code`. Reserve `CONFIG_VERSION_UNSUPPORTED`, `CONFIG_INVALID`, `ACCESS_DENIED`, `READ_ONLY`, `PRODUCTION_NOT_ENABLED`, `CONNECTION_POLICY`, `CREDENTIAL_UNSAFE`, `TOOL_UNTRUSTED`, `OUTPUT_FORMAT_UNSUPPORTED` and `NATIVE_OPERATION_FAILED` for the corresponding new boundaries; H02 records per-command mappings before changing old diagnostics.

No raw native stderr, SQL, passwords/seeds, connection strings, full config, parser excerpts or arbitrary debug error chains appear in reports. Keyless/public reports expose only their existing safe facts; authenticated detail/plan reports may retain their documented database/profile details. Preserve `audit_recorded=false` where nothing was recorded; an audit write failure cannot be disguised as durable success. Human text may improve without changing code/meaning. Breaking envelope or command-data type/meaning/removal changes require a new report version; additive documented optional fields are permitted, and consumers ignore unknown fields. Saved artifact/plan canonical schemas remain closed independently. H04 publishes command-data examples; H02 tests the envelope before it is advertised.

## Implementation and release gates

| Owner | Required evidence before claiming the capability |
|---|---|
| H02 config/access/report increment | Separate legacy/versioned parsing, closed fields/versions, role/command matrix, safe pre-mutation failures, bootstrap validation before key writes, all fixture CLI/JSON/plan vectors preserved. Production configs may be checked structurally with `production_enabled=false`; every other production-mode command refuses until V03. Exercise new behavior using versioned fixture mode and isolated synthetic data. |
| H02 native/filesystem/read-only increments | Literal-name/conninfo refusal, explicit maintenance DB with the original DB absent, different backup/restore users without estate drift, all-major peer/SCRAM with fallback refusal, cleared hostile environment, trusted tool provenance, no-follow/ownership/ancestor checks, bounded resources and configured scratch on read-only media. Preserve process-group/inherited claims and the existing writable lock order. Define the new production plan format before its writer. |
| H03 | Debian 13 and Ubuntu 24.04 LTS amd64 install/upgrade/remove/purge, dedicated-user sandbox, protected credentials, timer/manual overlap and no automatic timer enablement. These remain project targets until measured; recheck upstream/package availability at release. |
| H04–H05 | Versioned report/config documentation and pinned CI, safe inventory-copy/recovery procedures and custody/operating examples, module ownership/readability review and affected regressions. |
| V01–V02 | All supported-major content/privilege/failure/recovery matrices, signed native round trips, lost-source maintenance-DB recovery, key loss/rotation, deployment limits and measured RPO/RTO in the stated environment. Independent off-host recovery only if an actual copy workflow was tested. |
| V03 | Resolve critical findings, choose license and support/security/update policy, publish SECURITY/CHANGELOG/support matrix and reproducible checksummed artifacts. Enable production operations only in a separate reviewed change after H/V gates. Real writes require hybrid encrypted signed v1; no force flag/environment switch/package install bypass. |

H01 acceptance is this inspected, sourced policy and a complete H02 handoff. It does not rerun or supersede B06's historical 266-test/eight-matrix acceptance. The H02 first increment implements versioned structural checks, capability gates and report envelopes; production operations, native authentication/maintenance-DB recovery, key custody/bootstrap and true snapshot reads remain disabled until their named writers/tests land. T03/off-host replay protection, host compromise, hostile-source SQL and independently reviewed cryptographic assurance remain outside this policy's guarantee.

Implementation follow-up (2026-11-15): [native authentication/maintenance recovery](h02-native-auth-recovery.md) and [validated key bootstrap/custody](h02-key-bootstrap-custody.md) are delivered for versioned fixtures. Their scoped contracts supersede earlier availability notes. Production, broader filesystem/resource/service hardening and true snapshot operations remain gated; H02 is not complete.
