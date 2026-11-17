# Consistent copies, custody and isolated recovery reference

This reference covers delivered fixture capabilities and remaining release gates. It is not a new controlled operating flow. The [snapshot contract](../development/h02-snapshot-reads.md), unchanged [inventory/recovery guide](../development/m5a-operations.md) and [key generation operating document](../security/key-lifecycle.md) own their existing contracts; this document distinguishes newer versioned access. Production remains disabled. V01 locally verifies the public-schema correction; other compatibility/security gates remain open. No PITR, overwrite, automatic target drop, cross-major/independent-target bypass or remote copy implementation is provided.

## What a recovery copy must preserve

| Material | Consistency/custody requirement |
|---|---|
| Signed artifact components | Preserve complete public.json/signature.hybrid/payload.age/manifest.age and optional globals together with completion markers. Exact names/bytes follow [artifact v1](../backup-format/manifest-v1.md); do not reconstruct or edit metadata. |
| Inventory and lifecycle history | Preserve inventory.db with the same store's lifecycle/deletion/rollback/job facts. A standalone SQLite backup does not serialize artifact publication or deletion. Never raw-copy a live database merely because journal_mode=DELETE. |
| Locks/plans/tombstones/layout | Preserve the consistent store as a unit; do not prune markers/history/intent to make a copied artifact visible. A deletion tombstone overrides surviving complete bytes. Copied stale intent is not authorization for new deletions. |
| Decryption identity | Every retained generation's complete hybrid seed is essential; losing it makes corresponding artifacts unreadable. Existing older backups are not re-encrypted by generating new keys. |
| Trusted verifier | Install from independently trusted custody, not from the same untrusted artifact bundle. Public IDs help map generations; they do not establish trust by themselves. |
| Signer and recipient | Writer needs both; reader recovery requires neither. Retain signing seed privately for controlled writer continuity; it is not a recovery-host requirement. Never regenerate beside partial bootstrap survivors blindly. |
| Config and DB/host dependencies | Preserve generation/source/profile mapping and compatible config context without embedding passwords. Separately record native versions, grants, extensions/collations/OS dependencies excluded from logical archives. Backups exclude server config/secrets/external services and password verifiers. |

There is no live-store export/copy CLI. A safe ordinary copy requires the entire store to be quiescent: all timer activations and running service/manual operations are stopped, native descendants have released claims, and no writer/deleter/maintenance process can start during the copy. Stopping one timer alone does not prove this. An administrator-owned consistent filesystem snapshot is also usable only if its inventory/artifact/lifecycle state is known consistent; mounting arbitrary copied bytes read-only does not make them consistent. Do not invent a live SQLite `.backup` plus independently timed directory copy as a full-store guarantee. Preserve originals and validate the copy before relying on it. External copy tooling and host-loss/off-host protection remain outside the delivered CLI.

Versioned snapshot readers never migrate, recover, acquire writable locks or enrich history. Their immutable SQLite path refuses incompatible schema/programs and sidecar/WAL states; a refusal is not permission to remove a live journal/WAL. Discovery can work without decrypting or authenticating the copy. Verification on a quiescent copy proves its stated level, not when/how it was copied. Store roots/key parents/scratch must be protected and disjoint; no implicit `/tmp` fallback. Decryption writes plaintext only into explicit private external scratch and removes owned files on normal cleanup, preserving siblings. SIGKILL/machine loss can leave plaintext; restrict storage/copies and inspect before explicit cleanup. Do not recursively wipe another operation's scratch.

## Verification and interpretation

| Level/evidence | Establishes | Does not establish |
|---|---|---|
| Discovery / inventory list | Available public/local observations | Signature, plaintext, restoreability or fresh validity. |
| Signature | Configured dual origin signature over v1 bound components | All public header claims, decryptability or successful native restore. |
| Checksum | Signature/decryption/authenticated manifest and ciphertext binding | Native archive semantics or restored application data. |
| Archive | Checksum plus trusted matching-major native TOC/selection checks, offline | Database recreation, roles/grants, application correctness or measured RTO. |
| Restore run success | Native execution completed into the confirmed fresh target | Independently checked rows/schema/security/sequence state. Signed artifact bytes are not rewritten to claim a restore test. |
| Independently validated recovery | Stated queries/security/application checks in the stated environment | Future host-loss/RPO/RTO, unrelated profiles or excluded content. |

Reference observation commands for a prepared consistent copy and protected snapshot config:

```sh
backupctl --config /etc/backupctl/profiles/snapshot.toml --output json-v1 backup list
backupctl --config /etc/backupctl/profiles/snapshot.toml --output json-v1 backup verify BACKUP_UUID --level signature
backupctl --config /etc/backupctl/profiles/snapshot.toml --output json-v1 backup verify BACKUP_UUID --level checksum
backupctl --config /etc/backupctl/profiles/snapshot.toml --output json-v1 backup verify BACKUP_UUID --level archive
backupctl --config /etc/backupctl/profiles/snapshot.toml --output json-v1 backup inspect BACKUP_UUID
```

A read-only config cannot save restore intent or perform recovery. Restore uses a separately provisioned writable reader config/store with the exact identity/verifier generation, a protected explicit peer/SCRAM connection, matching source-major tools and an existing maintenance database even after source loss. No signing secret/recipient is required or opened. Source logical name/endpoint/major remains bound; an independently isolated test cluster must present the supported configured endpoint. Fixture source/target names are mandatory. Avoid exposing real service endpoints to a rehearsal.

Portable security omits archive roles/ownership/ACL; explicit DR requires authenticated exported globals, conflict/privilege checks and appropriate administrator authority, and may modify cluster roles before target creation. Roles/security metadata already applied can remain after failure. Section-limited restores are portable only and cannot be labeled full recovery. The shipped package example uses full-database selection. Public-schema correction evidence belongs to V01; these commands do not certify other selective content.

| Restore reference command suffix | Condition/result |
|---|---|
| `restore plan BACKUP_UUID --target backupctl_fixture_rehearsal --security portable` | On writable reader config; authenticates/decrypts, checks target absence and saves bounded private plan. Review artifact/source/security/sections and rollback warning. |
| `restore plan BACKUP_UUID --target backupctl_fixture_rehearsal --security portable --acknowledge-older-snapshot` | Only deliberate older selection; acknowledgement binds exact authenticated facts and surviving local high-water history. A replaced/lost inventory can erase local warning protection. |
| `restore run PLAN_UUID --confirm-target backupctl_fixture_rehearsal` | Exact target, unexpired plan and unchanged context/evidence; creates only a fresh target. Error may leave partial target/roles. No automatic retry/drop/rollback. |
| `job inspect JOB_UUID`, `inventory check` | Inspect actual job/effects/inventory before explicit maintenance or another attempt. A job's audit write can fail; no final state is fabricated by an error receipt. |

Independent rehearsal acceptance records chosen artifact/time/generation, full versus selective content, same-major versions/client provenance, source-loss condition, reader-only custody, restored row/count/checksum evidence, object/sequence state, ownership/ACL/RLS/extension checks appropriate to scope, duration/load and exclusions. A row-only fixture demonstrates that row in that environment; use the [content](../postgres/content-matrix.md) and [privilege](../postgres/privilege-matrix.md) matrices for the production validation obligation. Preserve reports with restricted access; do not publish decrypted data or seeds.

## Failed or interrupted operations

Handled SIGINT/SIGTERM uses ordinary cleanup and failed jobs; hard loss can leave interrupted/nonterminal work requiring existing ownership-aware recovery. Activity/artifact/job locks are kernel claims; never unlink lock files to bypass a busy refusal. Startup create and explicit `inventory recover` only clean abandoned owned work after maintenance exclusion, and recovery resumes only deletion work whose durable confirmed intent had already started. A preview/saved unstarted plan is not deletion authorization. Existing exact plan/digest/expiry/partitions remain authoritative in the [retention contract](../development/m5b-retention.md).

Rebuild is explicit and cannot invent lost verification, protection, operation or rollback history. Restoring an older snapshot is distinct from restoring an older inventory; retain original evidence rather than replacing an index to silence a refusal. A partial publication/database receipt describes possible effects, not proven rollback or durable completion. Keep partial target/artifact/roles for inspection and use a newly reviewed plan/target when another attempt is appropriate. No automation in this increment repairs or deletes them.

V01 follow-up (2026-11-16): the selective-public collision has a narrow TOC-gated empty-schema preparation correction with local PG16–18 acceptance. Its positive and populated-template refusal evidence is recorded in the [V01 handoff](../../project.md#51-v01-production-readiness-validation--2026-11-16); earlier H03 observations above remain historical. Production readiness still has separate compatibility/security blockers.

Expanded table-family artifacts use [scope format v2](../backup-format/manifest-v2-family.md)
with the same signed container and key custody. Preserve their complete original
bytes and use a v2-capable binary; an older reader explicitly refuses them. Updated
readers retain v1 recovery. The existing authenticated manifest digest binds the
family graph into restore plans; changing manifest bytes requires a new artifact and
plan. Schema8's historical v1-signed inventory shape describes the shared file layout,
not permission to use an old reader. Production recovery/plan policy remains gated.

V01-W1 (2026-11-17): writable versioned reader custody can now inspect/verify and
prepare/execute retention without a live source, passfile, recipient or signer.
List is key-free; signature checks need only the independent verifier. Private
checks/deletion require identity plus verifier; archive alone also needs matching
protected tools. Keep the existing store root: offline commands never create a
missing root or silently run recovery. Writable reads may create claims/scratch,
verification observations and local history; use the existing snapshot configuration
for a true immutable copied store. Exact deletion intent, current archive evidence,
protection/last-valid/active exclusions, terminal replay receipts and started-only
`inventory recover` remain unchanged. See [W1 dispatch rules](../development/v01-w1-offline-dispatch.md).
