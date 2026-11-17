# Fixture CLI configuration and report reference

This reference describes the delivered H01–H03 CLI. Production is disabled: a production config may pass structural check, while operations refuse `PRODUCTION_NOT_ENABLED`. The [.deb example](../../deploy/writer.example.toml) is a signed full-database fixture writer. H03 observed a selective `schemas=["public"]` restore conflict on PG16; V01 now verifies a narrow empty-schema correction on PG16–18. Other production compatibility/security gates remain open. The [roadmap](../../project.md) records acceptance and remaining gates. These are reference commands and preconditions, not a new controlled operating flow.

## Configuration and access

A versioned config uses `config_version=1`, explicit `mode`, `access`, `read_only` and an absolute local storage root. Unknown fields/versions and mixed legacy fields refuse. Config files are regular no-follow files, invoking-user owned, exactly 0600, under root/user-owned ancestry without group/world writes; `/tmp` is unsuitable. `config check` validates structure/custody of that file, not referenced credentials, source, tools, keys or available disk space. Legacy examples retain fixture-only behavior; do not convert by adding a version field without translating the schema.

| Role/mode | Delivered commands and resources |
|---|---|
| Writable `writer` | Signed create/profile validation/dry-run, key bootstrap/status, restore with reader keys, keyless inventory/job/protection operations. Create needs all four writer files. |
| Writable `reader` | Restore plan/run with identity and verifier, key status and keyless inventory/job/protection within access rules. Existing store required. |
| Read-only `reader` | Snapshot discovery/inspect/checksum/archive plus permitted inventory/job reads. Decryption needs explicit protected external scratch; archive needs matching trusted tools. No source or passfile is opened for these offline reads. |
| Read-only `public` | Key-free signed discovery and verifier-only signature check; no decryption. |
| `inventory` | Key-free inventory/job inspection and permitted writable maintenance/protection. No source/tools/key configuration. |

Versioned writable offline backup reads and retention dispatch are **not enabled**. Command availability is checked before command resources; `CAPABILITY_NOT_ENABLED` is a real limitation. Do not change custody/read_only to bypass a refusal. Legacy retention behavior and exact-confirmation rules remain documented in the [existing inventory/retention guide](../development/m5a-operations.md); that guide's legacy constructors do not describe versioned snapshot custody. Full [config/access rules](../development/h02-config-access-reports.md), [native policy](../development/h02-native-auth-recovery.md), [key custody](../development/h02-key-bootstrap-custody.md), [resource limits](../development/h02-filesystem-resources.md) and [snapshot rules](../development/h02-snapshot-reads.md) remain authoritative.

Complete minimal inventory specimen (paths are examples):

```toml
config_version = 1
mode = "fixture"
access = "inventory"
read_only = true
[storage]
root = "/var/lib/backupctl/store"
```

Complete offline authenticated snapshot specimen; source is intentionally absent:

```toml
config_version = 1
mode = "fixture"
access = "reader"
read_only = true
[storage]
root = "/var/lib/backupctl/copied-store"
[encryption]
identity_file = "/etc/backupctl/keys/identity"
[signing]
verifying_key_file = "/etc/backupctl/keys/verifier"
[scratch]
root = "/var/lib/backupctl/recovery-scratch"
[tools]
client_bin_dir = "/usr/lib/postgresql/17/bin"
```

Snapshot root must already be consistent/quiescent; config/keys/external scratch must have the stated ownership and disjoint protected directories. Signature-only checks need no identity/scratch; a public specimen omits encryption/scratch/tools and retains the verifier. Trusted clients must match the authenticated source major, with no shell wrapper/symlink/untrusted writable ancestry. A tool directory's existence alone does not prove compatibility.

| Concern | Versioned setting/constraint |
|---|---|
| Local peer | Absolute protected Unix socket directory; `auth="peer"`; no password_file. DB role/peer mapping is administrator-provisioned. |
| Local TCP | Host exactly 127.0.0.1 or ::1; `auth="scram-passfile"`; explicit protected passfile. SCRAM required, no trust/MD5/clear-password fallback. This is local authentication, not transport encryption. |
| Maintenance DB | Explicit existing database, usually postgres; used for restore probes/create even if original source is missing. Target stays a fresh different DB at the same configured local endpoint/major. |
| Passfile | Invoking-service owned 0600 or stricter; explicit host/port/database/user entries for source, maintenance and intended targets; no wildcards. Escape colon/backslash per libpq. Passwords are never config values/environment-file contents. |
| Timeout | `timeout_seconds` defaults 300, range 1–3600, per native call; service has its own whole-job deadline. |
| Resource budgets | Optional `[resources]`: max_payload_bytes (default 64 GiB), max_globals_bytes (8 MiB), max_stage_bytes (65 GiB + 16 MiB), max_scratch_bytes (64 GiB + 16 MiB), min_free_bytes (64 MiB). Payload/globals budgets count plaintext; stage budgets account encrypted data. Per-handle scratch limits and observed reserve are not a filesystem reservation. |

## Commands and result ownership

Run the CLI as the config/key/store owner, using an absolute config path. `/etc/backupctl/profiles/daily.toml` denotes a fully provisioned fixture writer; `recovery.toml` denotes a separately reviewed writable reader, and `snapshot.toml` the read-only specimen above. UUID/target placeholders require reviewed actual values. Help exposes exact accepted flags.

| Intent | Reference command suffix after `backupctl --config CONFIG --output json-v1` | Result `data` meaning |
|---|---|---|
| Structure | `config check` | Version/mode/access/read_only with production_enabled=false; no live certification. |
| Custody | `key status` | Validated public facts only; no seeds. `key generate`/`key publish` are writer-only mutations with explicit partial-publication receipts. |
| Scope | `profile list`, `profile validate daily`, `backup create --profile daily --dry-run` | Requested/resolved selection and live major; dry-run publishes nothing. |
| Create | `backup create --profile daily --confirm-synthetic` | `public` header plus decrypted `manifest`; sensitive metadata belongs in protected logs. |
| Snapshot discovery | `backup list` | Public signed/unsigned observations and local rollback warnings/unknown history; not fresh authenticated contents. |
| Snapshot verification | `backup verify BACKUP_UUID --level signature`, `--level checksum`, `--level archive` | Observed level/digests/origin/audit fact, never proof of restored rows. No history update on snapshot. |
| Detail | `backup inspect BACKUP_UUID` | Authenticated private manifest. |
| Restore intent | `restore plan BACKUP_UUID --target backupctl_fixture_recovered --security portable` | Saved private plan plus digest; no target created. Older selection requires explicit acknowledgement bound to a new plan. |
| Execute | `restore run PLAN_UUID --confirm-target backupctl_fixture_recovered` | Executed intent/security/sections/verification facts; independent validation still required. |
| Jobs/index | `job list`, `job inspect JOB_UUID`, `inventory check`, `inventory list`, `inventory verification BACKUP_UUID` | Safe local durable/observed facts. Rebuild loses some history; old/abandoned job facts are not proof of zero effects. |

Exact successful data writers: [CLI composition](../../crates/backupctl/src/main.rs), [backup reports](../../crates/backupctl/src/backup.rs), [inventory reports](../../crates/backupctl/src/inventory.rs), [snapshot adapter](../../crates/backupctl/src/snapshot.rs), [key reports](../../crates/backupctl/src/keys.rs). Data schemas belong to these commands; the envelope never changes saved artifact/plan canonical bytes.

## Machine envelope and safe failures

Use `--output json-v1` for machine callers. After successful argument parsing stdout is one object with `format`, `operation`, `status`, `data`, `error`. Success has status ok/null error/exit 0. Runtime refusal or failure uses error or partial plus `{code,message}` and exit 1. Syntax/help/version are Clap text; syntax is exit 2. Legacy `--output json` preserves bare successful fixture results. SIGKILL/abort/power loss and signals before handler installation cannot promise any final object.

Actual structural inventory-config example (checked against the CLI by CI):

```json
{"format":"backupctl-cli-report-v1","operation":"config.check","status":"ok","data":{"valid":true,"config_version":1,"mode":"fixture","access":"inventory","read_only":true,"production_enabled":false},"error":null}
```

Actual production refusal for `job list` (checked against the CLI by CI):

```json
{"format":"backupctl-cli-report-v1","operation":"job.list","status":"error","data":null,"error":{"code":"PRODUCTION_NOT_ENABLED","message":"Production operations are not enabled in this build."}}
```

Illustrative handled restore cancellation after mutation was attempted (UUIDs are examples):

```json
{"format":"backupctl-cli-report-v1","operation":"restore.run","status":"partial","data":{"job_id":"00000000-0000-4000-8000-000000000001","artifact_id":"00000000-0000-4000-8000-000000000002","effects":"database_may_be_modified"},"error":{"code":"OPERATION_CANCELLED","message":"Cancellation requested; inspect the job and any reported effects before retrying."}}
```

Create/restore receipts carry actual job_id (nullable for alternate library adapters), artifact_id and effects: preparation_only, artifact_may_be_published, database_may_be_modified. They describe conservative attempts; preparation_only does not mean no filesystem writes. The referenced job's terminal recording may itself fail; no terminal state is fabricated. Key partial writes retain exact created/pending roles and durability_confirmed; deletion retains its exact completed/deleting/pending partition. Never translate partial into success or infer automatic rollback/retry. Native output, SQL and seeds are withheld, but authenticated command results still expose database/profile/path metadata: protect logs.

| Codes/category | Operator implication |
|---|---|
| CONFIG_INVALID, CONFIG_VERSION_UNSUPPORTED, CREDENTIAL_UNSAFE | Fix explicit structural/custody issue; do not weaken ownership or disclose config text. |
| ACCESS_DENIED, READ_ONLY, CAPABILITY_NOT_ENABLED, PRODUCTION_NOT_ENABLED | Request exceeds current role/mode/build availability. Production cannot be unlocked with a flag. |
| KEY_*, FILESYSTEM_UNSAFE, RESOURCE_LIMIT, DISK_RESERVE_LOW | Inspect actual custody/partial receipt/resource budget before another mutation. No automatic repair. |
| OPERATION_BUSY, RECONCILE_BUSY, RESTORE_BUSY | Inspect competing ownership; no deletion of lock files to force entry. |
| OPERATION_CANCELLED, NATIVE_OPERATION_FAILED, OPERATION_FAILED | Inspect job/effects, surviving publication/roles/target before retry. A disconnected native client need not stop PostgreSQL server-side effects immediately. |
| Retention/rollback/stale-plan codes | Preserve exact saved intent/digest and history; require a fresh reviewed plan when stale. No broadening through retries. |

Safe generated messages/codes are owned by the [reporter](../../crates/backupctl/src/output.rs); do not parse human phrasing or assume every code above exhausts all operation-specific failures.

V01 follow-up (2026-11-16): the selective-public collision has a narrow TOC-gated empty-schema preparation correction with local PG16–18 acceptance. Its positive and populated-template refusal evidence is recorded in the [V01 handoff](../../project.md#51-v01-production-readiness-validation--2026-11-16); earlier H03 observations above remain historical. Production readiness still has separate compatibility/security blockers.

V01 table-family compatibility (2026-11-17): a signed table request that expands to
partition/inheritance descendants writes [scope format v2](../backup-format/manifest-v2-family.md).
The original request stays intact; inspect/dry-run JSON includes the resolved direct
parent/child links. Literal table, schema and whole-database scopes continue writing
v1. Human create/inspect/list output reports each artifact's actual version. Older
binaries cannot read v2; use the updated binary for that store. Keep structural DDL
quiet during selective backups; an observed family change before publication refuses
the write, without promising an atomic catalog/dump transaction. Versioned offline
reads still use read_only snapshot mode with external scratch; writable offline and
retention dispatch remain separate release work. Verification acceptance is recorded
in the [current handoff](../../project.md#54-v01-signed-table-family-compatibility--2026-11-17).
