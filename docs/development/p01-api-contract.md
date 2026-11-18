# P01 — first API contract

Status: design accepted for P02 implementation, 2026-11-18. No HTTP server, worker,
authentication service or new dependency is implemented by this document. W2 is
committed as `2f60e33430a68b4ffb457bfe784263eaf0c09709`. The two bounded backend
gates are closed; the next implementation task is P02, then P03/P04 and the UI.
Production operations remain disabled throughout these fixture increments.

The machine-readable interface is [OpenAPI 3.1.2](../api/openapi-v1.json). This
document defines the ownership and cross-request rules that schemas cannot express.
It is a design contract, not an operator flow or a change to an accepted ADR.

## Scope and dependency decision

One server owns one configured estate and local store. It exposes existing backup,
inspection, verification, fresh-target restore, retention and protection services.
Server-owned named profiles select existing validated configuration; requests never
supply connection strings, SQL, native flags, paths, credentials or configuration
documents. The original local-only native policy, fixture name/confirmation guard,
same-major tools, frozen artifacts and W2 historical plan formats remain authoritative.
No overwrite, remote database, schedule/configuration/key mutation, rebuild/adoption,
arbitrary command endpoint, event streaming or generic plugin interface is added.

| Option | Advantages | Costs / decision |
|---|---|---|
| Axum 0.8.9 + Tokio 1.54.1 | Typed Rust handlers; Tower middleware model; network/process/signal support in one runtime | Chosen for the new `backup-api` adapter only; async boundary stays outside synchronous core. |
| Actix Web | Established HTTP framework | Another runtime integration model; no concrete need outweighs the selected stack. |
| Direct Hyper / handwritten HTTP | Fewer framework abstractions | More routing, extraction and error plumbing to maintain; declined. |

P02 resolves `tokio = "=1.54.1"` for process, signal, runtime, time and pipe I/O.
P03 adds `axum = "=0.8.9"` (HTTP/1, JSON, Tokio) and Tokio network features when
it implements the listener.
Use existing serde/UUID/SHA-256/randomness/rusqlite and the already locked `subtle`
constant-time comparison primitive. No ORM, external broker, JWT, CORS middleware,
OpenAPI generator or UI dependency is selected. P02 must check the actual locked
graph's Rust 1.97.1 compatibility, licenses and advisories before acceptance; this
design does not claim that an unresolved graph has passed those checks. Add direct
Tower only if an actual middleware/test call needs it. Do not use broad `full` features.

Primary references checked 2026-11-18: [Axum](https://docs.rs/axum/0.8.9/axum/),
[Tokio](https://docs.rs/tokio/1.54.1/tokio/),
[OpenAPI](https://spec.openapis.org/oas/v3.1.2.html),
[HTTP semantics](https://httpwg.org/specs/rfc9110.html) and
[systemd kill ownership](https://www.freedesktop.org/software/systemd/man/255/systemd.kill.html).
OpenAPI is a static reviewed contract, not generated from unimplemented handlers.

## Authentication, actors and target authority

An operator provisions a private, no-follow regular credential registry outside the
artifact store and key root. Each entry has an actor UUID, credential UUID, active
flag, revision, roles and SHA-256 hash of a random 256-bit opaque token. Clear tokens
are shown to the operator once; they never enter logs, inventory, URLs or reports.
Compare fixed-size hashes in constant time. This is token authentication, not human
password authentication. No HTTP credential provisioning or administrator bootstrap
route exists. Missing/unsafe registry fails closed. Token possession never changes
the OS account, PostgreSQL user, protected configuration or key custody.

Machines use `Authorization: Bearer …`. The future same-origin browser exchanges a
token at `POST /api/v1/session`; the token must then be discarded from browser memory.
It is never persisted in local/session storage. An opaque 256-bit session cookie
`__Host-backupctl` is HttpOnly, Secure, SameSite=Strict, Path=/, without Domain.
Only a hash of its value is persisted in the private control database. Sessions
expire eight hours after issuance, with no sliding renewal. Registry revocation or
revision change invalidates derived sessions and queued work. Browser session reads
return a session-bound random CSRF token; all cookie-authenticated POST/DELETE calls
require that token in `X-CSRF-Token` and an exact configured Origin. Login itself
requires the exact Origin to prevent login CSRF. Missing Origin on browser mutations
is refused. Bearer calls need no CSRF token; any supplied Origin must still match.
Mixed cookie and bearer credentials are rejected, even for the same actor.

The default bind is `127.0.0.1:8090`. Remote access requires a same-origin HTTPS
reverse proxy, an explicit public origin/Host allowlist, and a loopback backend.
Ignore forwarded identity/host headers; do not enable CORS. A deliberate local-only
fixture development mode may use HTTP and a separate `backupctl-dev` non-Secure
cookie, with exact loopback origin checks. That exception cannot be enabled with
a non-loopback public origin. All responses use `Cache-Control: no-store`; no secrets
or raw native output are included in request/access logs. TLS termination is external;
the initial adapter does not introduce a TLS certificate dependency.

| Role | Permissions |
|---|---|
| viewer | `session.self`, `artifact.list`, `profile.read`, `job.read_own`, `health.read` |
| backup | viewer plus `backup.create`, `artifact.inspect`, `artifact.verify`, `job.cancel_own` |
| restore | viewer plus `artifact.inspect`, `artifact.verify`, `restore.plan`, `restore.run`, `job.cancel_own` |
| retention | viewer plus `retention.preview`, `retention.run`, `artifact.protect`, `job.cancel_own` |
| admin | Union of these plus `job.read_all`, `job.cancel_all`, `metrics.read` |

Roles can be combined. The OpenAPI `x-permission` is required independently of the
core configuration's access level. Job and intent reads require ownership or admin
and current permission for the associated operation. An unauthorized object ID returns 404. Admin may inspect another actor's intent but
cannot execute it: execution requires its original actor and current permission.
Only explicitly configured profile IDs are accepted. Configuration revision binds
the effective protected config bytes and profile selection, never credential contents;
queued work refuses drift before core invocation. Same-path password rotation remains
allowed under W2. OS/DB privileges and core guards always apply, including to admin.
Profile responses expose only operations allowed by both configuration and the
caller's permissions. Queued work is bound to the admitting credential/actor revision;
revoking that credential cancels its authority even when another actor token remains.

## Routes and representation

All paths below are under `/api/v1`; the OpenAPI gives complete fields and responses.

| Routes | Behavior |
|---|---|
| `POST/GET/DELETE /session` | Exchange token, read current actor/CSRF, revoke current cookie session. |
| `GET /health`, `GET /metrics` | Authenticated readiness and aggregate counters; no database/path/key labels. |
| `GET /profiles` | Server-owned IDs/display names and allowed operations, no connection or key details. |
| `GET /artifacts`, `GET /artifacts/{artifact_id}` | Keyless public discovery; header claims explicitly unverified. |
| `GET /jobs`, `GET /jobs/{job_id}` | API control jobs, nullable associated core job UUID, safe typed results. |
| `POST /jobs/{job_id}/cancel` | Durable cancellation request for the existing job; no second job. |
| `GET /intents/{intent_id}` | Owner/admin read of saved confirmation summary. |
| `POST /backups`, `/inspections`, `/verifications` | Queue core work and return a durable API job. |
| `POST /restore-plans`, `/retention-previews` | Queue core planning; success returns a saved API intent. |
| `POST /restores`, `/retention-runs` | Consume the matching saved intent and queue one execution attempt. |
| `POST /artifact-protections` | Queue existing protect/unprotect service; unprotect requires explicit reason. |

List pagination is UUID-ascending keyset pagination (`after`, default limit 50,
maximum 100), observational rather than a transactionally frozen catalog. Discovery
is bounded to 4096 artifact entries per call; larger stores return 503
`DISCOVERY_LIMIT` instead of silently omitting entries. This limit is checked before
loading header bodies. Profile/job reads are bounded similarly through config/SQL.
No immutable SnapshotReader is opened against a live writer's store. Short public
reads run on a bounded blocking lane with protected existing adapters; decryption,
hashing, native tools and all mutations belong to the operation worker.

An empty retention preview can succeed without producing a core plan; its result
has `intent:null` and exclusions. It cannot be executed. Protection reasons are
required for both protect and unprotect; redact them from general logs.

JSON is UTF-8, closed at every object boundary; duplicate keys, unknown query/body
fields, malformed identifiers, nonfinite numbers and request bodies over 16 KiB are
rejected. No compressed request bodies. Integers fit the JSON safe integer range.
Restore security is `portable` or `dr_full`; sections are `full`, `pre_data` or
`pre_data_data`, mapped to existing core policies. A section-limited request requires
portable security. A fixture write/restore explicitly supplies `confirm_synthetic:true`.
Older-snapshot acknowledgement is an explicit restore-plan input, never automatic.
The core determines scope, rollback binding, target validity and retention eligibility.

Successful responses are `{api_version,request_id,data}`; errors replace `data` with
`error:{code,retryable}`. API version is `backupctl-api-v1`. Request UUIDs are generated
by the server. Raw error chains, stderr, SQL, credentials, paths and debug formatting
never cross this boundary. Only an allowlisted safe code is returned. A job may fail
after HTTP acceptance; poll its URL (initially two seconds, backing off to ten).

| HTTP | Meaning |
|---|---|
| 200 / 201 | Read/cancellation result or created browser session. |
| 202 | Job durably accepted, not operation success; includes `Location` and `Retry-After: 2`. |
| 400 / 413 / 415 | Invalid closed input / body too large / unsupported content encoding or media type. |
| 401 / 403 / 404 | Invalid credentials / denied permission or Origin/CSRF / absent or invisible object. |
| 409 / 410 / 422 | Idempotency/state/digest/config conflict / expired intent / core policy refusal. |
| 429 | Admission/rate limit, `Retry-After: 1`; no job or consumed intent. |
| 503 / 500 | Not ready, containment/capacity/discovery unavailable / safe unexpected failure. |

## Durable admission, idempotency and saved intent

A separate private API control SQLite database holds actors' session hashes, API jobs,
idempotency receipts, immutable intent records and a store-instance UUID. It is outside
the artifact/key roots, mode 0600 with private parent and no-follow checks. Reuse the
existing rusqlite dependency with explicit FULL durability, DELETE journal and a bounded
busy timeout. Never put tokens, actor policy, raw requests or private database names
into the existing key-free artifact inventory or change its schema v8 for HTTP needs.
Control migrations are versioned separately. One exclusive process lock owns this DB.

The new, strict `api-config-v1` TOML configuration is separate from core ConfigV1.
Its server-owned fields are `format`, `listen`, `public_origin`, `development_http`,
`control_database`, `credential_registry` and `profiles` (bounded to 256 entries).
Each profile has `id`, `display_name`, `writer_config` (nullable absolute protected
path), `reader_config` (absolute protected path), `core_profile` (nullable existing
core profile name) and `operations` (the OpenAPI operation enum). Do not use a writer
configuration to bypass reader access checks. One profile with ID `default` and
`core_profile:null` is required; nullable request `profile_id` selects it. Named
profiles select the configured core scope for backups and prune previews. Prune
execution inherits the preview's profile binding. Other reader operations use the
default configuration, and a restore's selection comes from the
authenticated artifact. All configurations must resolve to the same storage root
and source estate when a source is present; validate literal config bindings without
probing source availability on offline reads. None may enable production. An allowed
operation also requires its corresponding usable writer/reader binding.
No request selects a different configuration file. Configuration revision is SHA-256
over `backupctl-api-config-v1`, a NUL byte and compact UTF-8 JSON with ordered fields
`id,display_name,writer_config,reader_config,core_profile,operations,writer_sha256,reader_sha256`.
Paths are their protected absolute UTF-8 strings; operations are sorted and unique;
hashes cover exact config bytes, with null writer/hash if absent. Password/key file
contents are never included. Changes require restart; compare current protected
bytes again before dispatch. Credential registry changes take effect before admission/dispatch,
without silently replacing the profile snapshot. Reject an unreadable registry.
The registry is strict JSON `format:"api-credentials-v1", credentials:[…]`; each
entry requires `actor_id,credential_id,revision,active,roles,token_sha256`, unique
credential IDs/hashes and one consistent role/revision policy per actor. Revision
is a positive safe integer. Increment it for all credentials of the actor when
rotating tokens or changing role policy. File ownership and key/path protections reuse H02's
rules. These are P02/P03 configuration contracts, not currently accepted CLI fields.

Every job submission and cancellation requires `Idempotency-Key`, a UUID v4 scoped to
actor + HTTP method + normalized route. Fingerprint SHA-256 over a compact typed
request with defaults resolved and fixed declaration order plus method/route; reject
duplicate JSON keys before typing. Config revision is stored separately on first
admission, not included in a retry's fingerprint. Authenticate/authorize before lookup.
Same key/body returns the original job (202 while nonterminal, 200 when terminal),
even if configuration subsequently changed; a different body returns 409
`IDEMPOTENCY_CONFLICT`. Retry never reruns core work. A new key is a new deliberate
attempt and must still satisfy all core safety checks. Receipts have no automatic TTL;
at 100000 admissions the server refuses new work with 503 `CONTROL_CAPACITY`.
Cancellation still validates the key. The job's monotonic state makes cancellation
idempotent for its empty request and job-specific route without a new receipt.
Deleting/replacing control state changes the store-instance identity and invalidates
all prior intents; operators must retain it with the service's state. This is durable
deduplication within that state, not a claim of globally exactly-once effects.

Admission commits job + receipt + intent consumption in one transaction before 202.
It reserves bounded queue capacity in that transaction; failure rolls everything back.
All new submissions (including reads requiring a worker) use the same queue. Limit:
one active worker and 16 queued jobs. FIFO order; queued jobs expire after 30 minutes
or their earlier intent expiry. HTTP concurrency is capped at 32; per-actor token
bucket 60 requests/minute, burst 20, login 5/minute per peer, burst 5. Rate/admission
refusals precede intent consumption. Initial rates are explicit fixture defaults,
not performance claims.

Core-generated restore/retention plans remain server-owned bytes. An API intent wraps
the existing core plan ID/canonical SHA-256 digest, creator actor, API planning job ID,
operation kind, store-instance UUID, configuration revision and expiry. Restore intent
also binds target database, security, sections, rollback acknowledgement and artifact;
retention intent binds exact candidate/retained sets through the core digest. It expires
at the earlier of core expiry and 15 minutes from creation. API intent digest is
lowercase SHA-256 over `backupctl-api-intent-v1` followed by a NUL byte and compact
UTF-8 JSON of these typed fields in that declaration order:
`id,actor_id,planning_job_id,kind,store_instance_id,config_revision,core_plan_id,core_plan_digest,created_unix_ms,expires_unix_ms,confirmation`.
`confirmation` has `target_database,artifact_id,security,sections,acknowledge_older_snapshot`
in that order for restore, or `candidates,retained` (UUID-sorted arrays) for retention.
No plan body or core path is accepted over HTTP. The digest is a content identifier,
not a MAC; the private server record and actor authorization establish authority.
The response-only `digest` and mutable `consumed_by_job_id` are excluded from digest
input. OpenAPI includes recomputable restore/retention examples, not placeholder
API digests. Strings use normal serde_json UTF-8 escaping, with no insignificant
whitespace, floating-point values or Unicode normalization. Reject clock regression
before intent creation/start just as the core rejects a plan before its creation time.

Execution supplies the intent UUID and exact API `confirm_digest`; restore also supplies
the exact target and synthetic confirmation. At admission and again before core starts,
check owner/current permission, operation kind, config/store revision, expiry,
typed confirmation and saved core plan's recomputed digest. Admission requires an
unused intent. Dispatch requires it to be consumed by that specific job. Any drift is refused. Consumption is permanent on accepted execution, including later
cancellation/failure; a new attempt requires a new plan. An idempotent retry returns
the existing job instead of trying to consume twice. Existing core preflights, locks,
plan/target checks, artifact binding and retention replay receipts still run. Do not
reinterpret v1/v2/v3 plans, add actor fields to their bytes or implement future v4 in P02.
API binding does not prove physical cluster identity beyond W2's literal endpoint scope.
Retention prune/delete dispatch comes from the authenticated saved core plan's
operation, never from a client-supplied executable operation at execution time.

## Worker, cancellation and restart ownership

The HTTP parent never calls the process-global sticky `control::request_cancel()`.
Each accepted operation runs in a fresh child of the new `backup-api` executable,
using a private worker entry point and typed bounded pipe messages (maximum 1 MiB).
The child directly composes existing application services and protected adapters;
it does not run `backupctl`, parse CLI output or accept executable paths from clients.
Only server-selected job/config identifiers cross IPC. No secrets in argv/environment
or raw native stdout in responses. Extract shared CLI composition only where a second
caller needs it; preserve synchronous domain/crypto APIs. The worker opens protected
configuration/custody and rechecks the persisted admission binding before effects.

API states: `queued`, `running`, `cancel_requested`, `succeeded`, `failed`, `partial`,
`cancelled`, `interrupted`. Persist running before launch; bind worker identity before
execution permission. Missing launch/result acknowledgement is interrupted, never
automatically replayed. A clean typed result determines success/failure; exit zero
alone does not. Nullable core job IDs come from real service receipts, not invented
history (verification/planning may have none). Results distinguish effects `none`,
`preparation_only`, `artifact_may_be_published`, `database_may_be_modified`, `artifacts_may_be_deleted`,
`inventory_may_be_modified`, `unknown`. Do not infer rollback from cancellation.
Preserve the core's first three nonempty effect labels rather than narrowing a
possible database/role mutation to target existence. `none` is used only when work
has not started or is proven observational; preparation can still leave local scratch
or job records. Partial requires possible substantive effects, not preparation alone.

Queued cancellation atomically marks cancelled without launching a child. Running
cancellation persists cancel_requested, sends SIGTERM to the owned child and permits
cooperative cleanup. Its core signal handler sets only that process's cancellation
flag. A completed result racing cancellation wins; terminal states are immutable.
Known effects plus failure/cancellation yield partial; uncertain death yields interrupted.
Cancellation after a terminal result returns that unchanged result. Same cancellation
key returns the current referenced job, even if it subsequently completed.
Backup includes the core's recovery pass. If recovery fails before returning its
report, effects are unknown. If backup later fails, the job preserves known recovery
effects when the backup itself has no larger effects to report.

Job-capable deployment requires the dedicated service cgroup boundary from H03's
model. Graceful stop is bounded to 30 seconds; if the owned child/native descendants
cannot be proven gone, the parent fail-stops the service and supervision kills its
whole cgroup (including escaped process groups) before restart. One worker deliberately
trades availability for this simple containment boundary. PID/process-group kill alone
is insufficient. No next job may launch while previous ownership is uncertain.
P02 exercises KillMode=mixed and final SIGKILL under a real manager. The control DB
is bound to its verified unit cgroup path so a new unit cannot resume it while a
previous unit may own descendants. Unsupervised development can serve
reads but job admissions return 503 `CONTAINMENT_UNAVAILABLE`. Existing H03 units
are not changed by P01. A scheduler/CLI invocation remains separately protected by
the existing core locks; API serialization is not a global lock replacement.

On restart, hold exclusive API control ownership, then mark all nonterminal jobs
interrupted (queued jobs have effects none; launched jobs unknown absent a proven
receipt). Never auto-resume a queued/mutating request or release its consumed intent.
Existing receipt retries return this honest terminal state. Invalidate browser sessions
on startup; operator tokens remain registry-controlled. Reconcile core jobs only via
existing ownership/recovery services, never rewrite core rows to match an API guess.

## Implementation and acceptance boundary

P02 owns control-state migration/real writers, worker IPC, durable admission, restart,
isolation/cancellation and the actual service boundary. P03 adds this OpenAPI's routes,
auth/session/permissions, bounded reads, safe reporting and counters. P04 proves their
composition: revoked actors/foreign intent, digest/config/expiry drift, duplicate and
conflicting retry, queue/rate refusal, crash around each acknowledgement, escaped child
containment, partial effects, redaction and equivalence with existing core services.
Use real writers and deterministic barriers for races, not fake completed job rows.
There is no additional general backend gate before P02.

P01 verification checks the official OpenAPI structural schema, all local references,
closed object schemas, declared permissions, job/idempotency responses and positive
and negative JSON examples. This validates the design, not HTTP behavior or deployment.
The dependency-free CI checker preserves contract structure; full JSON Schema checks
use the available verification environment, without adding Python/runtime dependencies
to the project. Do not rerun native/package/crash matrices for this design-only change.
