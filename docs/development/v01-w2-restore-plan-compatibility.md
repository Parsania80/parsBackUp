# V01-W2 restore-plan compatibility contract

Recorded before test changes on 2026-11-18. This is a format/context contract,
not an operating flow. It closes the second [bounded backend gate](../../project.md#55-web-first-delivery-and-bounded-backend-handoff--2026-11-17)
by defining the production boundary and proving the existing fixture path. No
production writer/validator, new runtime format, actor model or API is added here.

## Version decision

| Option | Benefit | Cost / disposition |
|---|---|---|
| Reinterpret h02-restore-plan-v3 for production | Reuses one format label. | Rejected: v3 means fixture mode and synthetic names; widening it changes historical authorization semantics. |
| Define the future production contract, retain fixture producer/consumer | Closes the design gate and permits API work without a dormant writer. | Selected. Production implementation and enablement remain integrated V01/V03 work. |
| Implement production writing/execution now | Earlier real-source capability. | Deferred: expands W2 beyond the approved fixture proof and bypasses remaining release gates. |

Current formats remain m3-restore-plan (legacy development), m5b-restore-plan-v2
(legacy signed rollback binding), and h02-restore-plan-v3 (versioned signed fixture
plus native context). Their validators, field order, optional-field omission, bytes,
digests, commands and accepted historical read behavior are unchanged. Artifact
scope v1/v2 is independent of restore-plan version; the manifest ciphertext digest
already binds the private format, request and any table-family graph.

Reserve **production-restore-plan-v4** for the future production implementation.
It is a specification identifier only: do not add a constant, parser branch, writer,
new struct or permissive validation just to reserve it. Current readers must refuse
this format, production contexts under v3, and all production operations. Before any
future v4 writer lands, implement its actual producer/consumer with canonical vectors
and all rejection tests on isolated synthetic data; this requirement does not add
unused runtime encoding to W2. Old readers continue to reject v4; v4 cannot be
renamed/downgraded to execute through a fixture or legacy engine.

## Canonical bytes and digest

Future v4 reuses the existing ordered field layout below, with format changed to
production-restore-plan-v4 and native_context.mode fixed to production. It requires
rollback and native_context, never null/absent. Missing required fields, unknown or
duplicate fields and version/context mismatches refuse. No additional field is
implied by this contract. If implementation needs one, record an explicit versioned
contract change before emitting it; do not silently change these bytes.

Canonical bytes are UTF-8 compact JSON using the typed RestorePlan serializer's
fixed declaration order and serde_json string/number encoding, without BOM, spaces
between tokens or a trailing newline. This is not sorted-key JSON or a general
JSON canonicalization standard. SHA-256 of those bytes is the 64 lowercase hex digest.
Disk storage may use the existing private pretty-printed JSON plus newline; parse
the typed record and serialize canonically before hashing. CLI/API report objects
may reorder keys and are not digest inputs. No arbitrary raw request JSON is hashed
as though it were the typed saved plan.

| Record | Fields in exact serialization order |
|---|---|
| Plan | format, id, artifact_id, artifact_database, source_major, client_version, target_database, security, sections, artifact_scope, created_unix_ms, expires_unix_ms, rollback, native_context |
| security | roles, ownership, privileges (booleans) |
| sections | pre_data, data, post_data (booleans) |
| rollback | source_fingerprint, signer_id, completed_at_utc, payload_sha256, manifest_sha256, high_water, acknowledged |
| non-null high_water | artifact_id, completed_at_utc |
| native_context | mode, host, port, user, maintenance_database, auth, client_bin_dir, password_file |

artifact_scope is explicit null or the authenticated profile name; high_water is
explicit null or the existing closed CompletionMark; password_file is explicit null
for peer or the configured protected absolute path for scram-passfile. Legacy
rollback/native_context omission rules remain historical, not aliases for missing
v4 evidence. Names/enums/UUID/path representations use the current typed encodings;
future v4 IDs must be canonical RFC4122 UUIDv4 and match their server-owned saved
handle. Time fields are unsigned integer Unix milliseconds with checked arithmetic:
expires = created + 900000; refuse now < created and now >= expires. Preserve the
existing section/security combinations, full/portable policy and fresh-target default.

The digest is a content identifier, not a MAC or signature on the plan. Plans remain
private, service-owned intent in a trusted store. Editing trusted local plan storage
is not covered by artifact signatures. The existing CLI run accepts plan UUID plus
exact target confirmation; it does not require a supplied restore-plan digest.
Prune/delete's digest confirmation is a separate unchanged protocol.

## Context and fixture mapping

| Promise for future production | Existing fixture proof / boundary |
|---|---|
| Effective production mode is bound; no fixture plan authorizes it. | v3 fixes mode to fixture and refuses production. V4 remains unknown to the current validator and all production commands are gated before resources. |
| Original source identity binds literal host/port, artifact database and PostgreSQL major; target is a distinct literal database at the same endpoint/major. | Artifact source fingerprint plus plan artifact_database/source_major and existing source checks. Maintenance DB is only the probe/create connection; dropping the original source must not break recovery. A replacement cluster using the same endpoint is supported; no immutable cluster-identity or remote TLS guarantee is added. |
| Acting DB user, maintenance database, auth, native-tool directory and passfile path are exact execution context. | v3 native_context equality before restore preflight, job creation or target mutation. No endpoint/path normalization at execution to disguise drift. Auth is peer/local protected socket or scram-passfile/loopback only. |
| Credential contents and backup keys never enter the plan. | Password file path is bound, not password bytes; safe same-path credential rotation is allowed and actual credentials are validated on use. Identity/verifier are revalidated against artifact trust; signer/recipient paths are not needed for restore. |
| Artifact ID, signed source/signer/completion and ciphertext digests, original selection/security/sections and older-snapshot acknowledgement stay bound. | Existing plan fields/rollback; private manifest digest includes family graph and scope version; execution reauthenticates and fully decrypts before cluster mutation. Archive plaintext digest/TOC are in the authenticated manifest, not duplicated in the plan. |
| Tools are protected and matching-major; plan records the observed client version. | v3 binds configured tool directory and source major. The client version string is included in the digest as a planning observation; current execution rechecks major, not exact patch-string equality. Do not claim a binary-content or minor-version pin. |
| Relevant context/time/confirmation/target conflicts refuse before database mutations. | Shape/time/confirmation/source-name/context checks precede native preflight; source-major checks precede restore job; artifact/rollback/target/decryption/role conflicts are rechecked before cluster changes. Some refusals may open protected resources or create locks; no universal zero-filesystem-side-effect claim. |

The future production enablement change must separately resolve signed-manifest
Profile::validate's fixture-name restriction and other documented production guards.
This contract does not relax artifact semantics or silently authorize real database
names. Config access/read_only and resource/timeout policies remain operation gates;
changing a timeout does not redefine the saved database intent. Source profiles are
not re-resolved during restore: authenticated artifact facts are authoritative.
Storage/key/config file paths are not all fields in a plan; trusted server operation
configuration, protected store ownership and artifact/source revalidation supply
those boundaries. Runtime v4 must not infer authorization merely from valid JSON.

## API handoff and deferred release work

P01 must define authenticated actors, permissions, idempotency and confirmation.
P02/P03 must bind a server-owned plan handle and its canonical digest to actor,
request, operation/store/config context and expiry, then recheck authorization before
calling the shared service. Do not accept a client-submitted plan body or let a
client choose filesystem paths or weaken security/sections. A plan UUID or successful
parse is not an authorization token. Actor bindings belong to the API's persisted
operation/confirmation record, not an invented CLI actor or a silent edit to old plan
bytes. Any new transport/intent encoding is a P01 decision before its writer lands.

API development can use the real v3 fixture producer/consumer after W2; production
mode remains disabled. Production v4 implementation/enablement, wider content/security
support, V02/F02 performance/recovery measurements and V03/F03 release disposition
are integrated release work after API/UI. Existing dependency-maintenance and T03
limits stay visible; no extra general backend phase precedes P01.

## Acceptance

Retain literal v1/v2/v3 canonical vectors and digests unchanged. Add composed tests
using the real signed LocalStore and RestoreService producer/consumer: create and
persist v3, round-trip canonical bytes/digest, reject each changed native context,
wrong source/confirmation/time and legacy downgrade before any new native preflight,
restore job or cluster mutation, then execute the unchanged control. Bind security,
sections, artifact/source/rollback/family-manifest facts with the existing digest and
revalidation controls. Prove future v4 and production-in-v3 still refuse. Exercise
changed artifact ciphertext refusal without target mutation and retain historical
legacy acceptance. Run focused cases, locked/offline fast checks and the existing
actual PG16/17/18 native auth/maintenance/context/downgrade/recovery drill. No package,
benchmark, unrelated crash matrix or hosted rerun is needed for test/document-only
changes; retain that evidence and state it was not rerun.
