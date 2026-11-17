# V01-W1 versioned writable offline dispatch contract

Recorded before implementation on 2026-11-17 under the operator-approved
[web-first handoff](../../project.md#55-web-first-delivery-and-bounded-backend-handoff--2026-11-17).
This is a command/acceptance contract, not an operating flow. W2/API/UI and
production enablement are outside this increment.

## Dispatch and custody

Keep the existing closed config parser and access checks. Production operations
still refuse PRODUCTION_NOT_ENABLED before opening any store, keys or tools.
Authorization precedes read-only checks; a denied role returns ACCESS_DENIED.
Config read_only=true keeps the existing snapshot dispatch/external scratch path.

| Command | Writable fixture roles | Material/resources opened |
|---|---|---|
| backup list | writer, reader | Existing protected store only; no keys, source, passfile or tools. Public remains on its existing read-only snapshot path; inventory access refuses. |
| backup verify --level signature | writer, reader | Protected store and trusted verifier only; never identity/recipient/signer/source/passfile/tools. Public uses the existing snapshot path. |
| backup inspect; verify --level checksum | writer, reader | Protected store, identity and verifier only. No writer-only keys or source/passfile/tools. |
| backup verify --level archive | writer, reader | Same reader custody, plus matching protected pg_restore version/list using authenticated artifact major. No source connection/passfile; tools must be explicitly configured. |
| backup prune/delete preview and run | writer, reader | Existing protected store and reader custody; profiles only select prune scope by the existing name fingerprint. No native tool or source/passfile access. Public/inventory access refuses; read-only reader returns READ_ONLY. |

Writable reads/retention do not create a missing storage root. Reader use from a
writer config does not read or stat its recipient/signing files. Discovery does not
validate configured key files. Signature verification cannot decrypt. Keep protected
ancestry/no-follow/owner/link checks and inode overlap checks for keys actually used;
retain descriptor-pinned root, resource limits, activity/artifact/maintenance claims
and ordinary plaintext cleanup throughout the command. No legacy key-path reopening.

Writable verification uses the existing observation writer and reports audit_recorded
honestly; archive verification supplies the current event required by retention.
Command --read-only suppresses verification observation writes, matching the existing
CLI meaning; only config read_only=true promises a true immutable snapshot. Inspect
may record the existing local rollback observation. Opening/reading never invokes
abandoned-work/deletion recovery implicitly; inventory recover remains explicit.

Use existing services and machine/human reports. Retention preview saves an immutable
plan when candidates exist, without deletion/inventory mutation. Run requires the
saved plan UUID, operation and exact digest; revalidates under existing maintenance
and candidate/witness claims; preserves protection/last-valid/active/job exclusions,
marker-first deletion, terminal receipts, partial outcome and explicit recovery.
Saved plan bytes/schema8/policy/TTL and historical fixture dispatch stay unchanged.
An already consumed plan returns its existing receipt; it does not delete again.

## Acceptance and scope

Add full-process authorization/missing-resource controls and actual PG16/17/18 signed
v1/v2 CLI cases. After creating fixtures, stop the source and remove the generated
passfile, recipient and signer. Prove writable reader and writer-config offline
list/inspect/signature/checksum/archive still work; remove identity to prove list and
signature need no decryption key; restore it for private operations. Use source-free
and tools-free configs for applicable operations; archive alone needs matching tools.
Check audit suppression/current archive observations, v1/v2 prune/delete preview/run,
wrong digest, stale plan, protected/last-valid/active exclusions, replay receipt,
read-only/access/production refusals and corrupt/unsafe resource refusal. Independently
inspect artifact/inventory results and absence of leaked plaintext/credentials.

Run locked/offline fast checks, the changed V01 all-major native suite, existing B06
all-major destructive/race/crash regression (shared retention refactor) and H02
all-major snapshot regression (reader key representation). Freeze source inputs during
final gates. Preserve prior signed-family package and evidence; no package/runtime
service/deployment contract changes are intended and no fresh package/hosted result
is claimed without running it. No new dependencies, artifact/plan/schema/crypto/flow
change or production writer. Record any specific blocker and its minimal fix; do not
add a new general hardening phase. W2 follows acceptance.
