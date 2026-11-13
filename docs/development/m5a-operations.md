# M5a inventory and recovery operating guide

This guide covers the delivered inventory, job, verification and recovery CLI. The exact reports and failure categories are in the [inventory contract](m5a-inventory.md); artifact bytes remain governed by [artifact v1](../backup-format/manifest-v1.md). Current operations are restricted to synthetic local fixture databases. Production-source enablement, retention, scheduling, packaging and API/UI release have later gates in [project.md](../../project.md).

## Choose a configuration and mode

Use absolute paths, source-major PostgreSQL clients, and a private operator-owned storage root. Keep keys outside that root and install the trusted verifying key independently of artifact files. The [M4a example](../../config/m4a.example.toml) includes the signed-writer and DR key blocks; [key lifecycle](../security/key-lifecycle.md) covers custody and loss. Private identity/signing files and password files require mode `0600` or stricter; public recipient/verifying files use `0644`.

| Operation | Keys loaded | PostgreSQL contacted | Writes and meaning |
|---|---|---|---|
| `job list`, `job inspect`, `inventory check`, `inventory verification` | None | No | Existing index opened read-only; no migration, recovery or audit write. Event reads require their table to exist. |
| `inventory list` | None | No | Existing index plus mixed-shape filesystem observations; no adoption or authentication. |
| `inventory reconcile` | None | No | Current index lifecycle/audit updates under exclusive maintenance; no adoption or authentication. |
| `inventory adopt` | None | No | Explicit provisional registration into an existing bound index; supported old schema may migrate. |
| `inventory rebuild --dry-run` | None | No | Filesystem preview; works with missing/corrupt index and changes nothing. |
| `inventory rebuild --prepare-rebuild` / `--confirm-rebuild` | None | No | Saves a bound plan / installs a validated replacement and preserves any old index. |
| `backup create` | Configured writer key files | Yes | Job and configured artifact shape; signed writes register inventory. Requires `--confirm-synthetic`. |
| `backup list`, `backup inspect`, `backup verify` | Configured backup-reader key files | Archive verification invokes native tools; list/inspect/signature/checksum do not contact the server | Legacy store opening can create required directories; successful writable verification may record/enrich an existing row. |
| `restore plan` / `restore run` | DR identity and trusted verifier; signing secret unnecessary | Yes | Private saved plan / restore job and fresh target. Run requires an existing bound index. |

The backup-reader CLI currently loads configured key files during store opening even for signature-only verification or legacy `backup list`. Signature verification itself decrypts nothing. For observation with absent keys, use the `inventory` and `job` commands, not the legacy backup readers.

For keyless inspection, a complete minimal configuration can be:

```toml
[source]
host = "127.0.0.1"
port = 5432
user = "postgres"
database = "backupctl_fixture_m1"
client_bin_dir = "/usr/lib/postgresql/16/bin"

[storage]
root = "/absolute/path/to/copied-store"
```

Adjust paths and fixture identity to the deployment. These fields still undergo configuration validation, but inventory/job commands do not open the client directory or connect to PostgreSQL. Use this configuration for keyless inventory/job operations; use the appropriate signed writer or DR configuration for backup/restore commands.

## Inspect before changing the index

```sh
backupctl --config /absolute/path/to/keyless.toml --output json inventory check
backupctl --config /absolute/path/to/keyless.toml --output json inventory list
backupctl --config /absolute/path/to/keyless.toml --output json job list
backupctl --config /absolute/path/to/keyless.toml --output json job inspect JOB_UUID
backupctl --config /absolute/path/to/keyless.toml --output json inventory verification BACKUP_UUID
```

UUID placeholders are returned artifact/job IDs. `inventory check` checks SQLite structure, not artifact existence, signature, provenance or freshness. Job/event reports have `audit_recorded: false`. Missing, corrupt and newer-schema indexes are errors rather than empty history. Read-only inspection never upgrades an old schema; a schema without a requested table cannot answer that query.

`inventory list` reports all three shapes and per-entry states: registered, unregistered, missing, incomplete, conflict or invalid. A listed entry is a candidate to investigate. Unregistered does not mean invalid, and registered does not mean authenticated. Public headers are untrusted descriptive input. A scan during publication can observe an incomplete entry; repeat when work is quiet before deciding it is abandoned.

When the store is idle, explicit reconciliation can record changed observations:

```sh
backupctl --config /absolute/path/to/keyless.toml --output json inventory reconcile
```

`RECONCILE_BUSY` means live work owns the store; retry after it finishes. Reconciliation preserves known profile/time facts, changes only observed lifecycle state and associated validity/audit, and never adopts new files. A recovered registered state does not revive an invalidated verification event.

## Adopt one artifact deliberately

Obtain the expected 16-character lowercase source fingerprint from an independently retained trusted record or authenticated signed-manifest inspection. An index's own binding is only a local claim. A keyless scan and signature-only verification cannot establish source estate, profile or completion time.

```sh
backupctl --config /absolute/path/to/keyless.toml --output json inventory adopt BACKUP_UUID --source-fingerprint SOURCE_FINGERPRINT
```

Adoption requires a complete, consistent unregistered artifact and an existing index bound to that source. It records unconfirmed provenance and leaves profile/time unknown. A readable foreign estate is refused. Do not change the supplied fingerprint merely to silence that refusal; inspect the source/configuration and artifact provenance.

After installing the matching DR identity and independently trusted verifier, authenticate and enrich:

```sh
backupctl --config /absolute/path/to/dr.toml --output json backup verify BACKUP_UUID --level checksum
backupctl --config /absolute/path/to/dr.toml --output json backup verify BACKUP_UUID --level archive
```

For an existing registered signed row, matching authenticated source/digests allow profile fingerprint and completion time to be filled and provisional provenance to be cleared with the verification event. Signature-only success supplies none of those private facts. Known contradictory facts are refused. Verification never creates an index or adopts an unregistered artifact.

## Rebuild after loss or corruption

Preserve a quiet copy of the original store and any index/SQLite sidecars for investigation. An interrupted SQLite transaction and an incomplete single-file copy are different from a disposable missing index. Confirmation refuses `inventory.db-journal`, `-wal` or `-shm`; recover the original SQLite file set before rebuilding rather than deleting a sidecar to bypass the guard. Newer-schema indexes require a compatible binary, not replacement by this older build.

Run preview, inspect losses, save a plan and then confirm that exact plan:

```sh
backupctl --config /absolute/path/to/keyless.toml --output json inventory rebuild --source-fingerprint SOURCE_FINGERPRINT --dry-run
backupctl --config /absolute/path/to/keyless.toml --output json inventory rebuild --source-fingerprint SOURCE_FINGERPRINT --prepare-rebuild
backupctl --config /absolute/path/to/keyless.toml --output json inventory rebuild --source-fingerprint SOURCE_FINGERPRINT --confirm-rebuild --plan-id PLAN_UUID
backupctl --config /absolute/path/to/keyless.toml --output json inventory check
backupctl --config /absolute/path/to/keyless.toml --output json inventory list
```

`PLAN_UUID` is the prepared result's `plan_id`, not a restore-plan ID. Preparation binds all artifact bytes, the old index and the expected source. A stale plan requires a new preview/preparation after reviewing what changed. An invalid/incomplete/conflicting artifact prevents rebuilding the entire index; repair the copied store deliberately instead of accepting a partial scan as complete.

Confirmation holds exclusive maintenance, builds and checks a private replacement, syncs it, preserves an existing index under the returned `previous_inventory` path, replaces the active file and syncs the directory. A crash can leave a staged database, a plan or a preserved old index. These files are not automatically promoted. Inspect active/previous indexes and the authoritative artifacts before preparing a fresh plan. The drill proves process-crash behavior; it does not simulate power loss or failing storage.

| Fact after keyless rebuild | Meaning |
|---|---|
| Artifact ID/shape and bounded public ciphertext facts | Observed files; not authenticated provenance. |
| Source fingerprint | Operator's expected estate; unconfirmed until authenticated. |
| Profile fingerprint and completion time | Unknown; no ordering/grouping guess from UUID, file time or header. |
| Verification history | Lost; run a new verification to establish a new observation. |
| Jobs, old audit and protection history | Lost from the active replacement; an old readable index may retain historical evidence. |

Rebuild is not an audit-history restore and does not confer protection or retention eligibility. This phase exposes no protect/delete/prune command. Local index and artifacts can both be rewritten by a storage editor; independent off-host/immutable recovery remains outside this guarantee.

## Verification and writable versus read-only media

Use `--level signature` for the signed ID/ciphertext-pair check, `--level checksum` for authenticated manifest/digest consistency, and `--level archive` for native archive/TOC validation. Signature-only success does not authenticate every public-header claim or establish private source/profile/time facts. An event's `current` field describes persisted observations, not a new filesystem check at report time.

To suppress inventory writes/migration for a verification:

```sh
backupctl --config /absolute/path/to/dr.toml --output json backup verify BACKUP_UUID --level archive --read-only
```

This reports `audit_recorded: false`. It does not make the entire operation usable on a read-only mount: store directories/locks and plaintext scratch may need writes. True alternate-scratch/read-only-mount support remains H02. Use a controlled writable working copy for DR. Keyless job/check/event inspection can read a single current `inventory.db` file in a non-writable directory without artifacts, keys, clients or sidecars; preserve a quiet complete database when taking that copy.

Normal writable verification records success or failure for an existing row. A later failure or missing/conflict reconciliation invalidates earlier observations. If the operation succeeds but recording fails, the command reports that distinction; retry after investigating the index rather than treating an absent event as proof the bytes failed validation.

## Restore and interruption

Keep the configured database identity consistent with the artifact, and select a separate fresh fixture target with `--target`. Signed v1 checks the source fingerprint at plan and execution, including engine/major/host/port/database. The signed DR matrix replaces the original cluster at the same endpoint; changing that endpoint can be refused. Separating source and target job fingerprints does not bypass artifact source binding.

```sh
backupctl --config /absolute/path/to/dr.toml --output json restore plan BACKUP_UUID --target backupctl_fixture_recovered --security portable
backupctl --config /absolute/path/to/dr.toml --output json restore run PLAN_UUID --confirm-target backupctl_fixture_recovered
backupctl --config /absolute/path/to/keyless.toml --output json job list
```

Inspect the returned plan's artifact, target, sections, policy and digest. Restore plans expire after 15 minutes. `portable` skips source roles/ownership/privileges; `dr` requires exported globals and a suitable isolated role environment. Full DR, selective/section limits and content assertions are covered by the [restore guide](m2-restore-verify.md), [profile guide](m3-profiles-selective.md) and [signed store guide](m4b-signing.md).

Run takes shared store activity, exclusive target and shared artifact-use claims before artifact work or mutation. Claims coordinate only one storage root, not different roots or external SQL clients. A conflicting restore fails before starting another job. Partial target/role changes are left for operator inspection; no automatic target drop or retry occurs. A completed job means the native restore and required artifact-update work succeeded. Validate required fixture/application content separately before claiming a tested recovery. Signed manifests remain immutable; the historical development-format `restore-tested` field is not an independent content-validation record.

| Job state | Operator interpretation |
|---|---|
| `running` | Resource ownership was recorded; native work may still be active, or a killed job awaits recovery. |
| `staged` | Backup streams finished; publication/job completion still pending. |
| `complete` | Operation completed; inspect/verify artifacts and validate restored content for the required assurance. |
| `failed` | Handled failure was recorded. Publication may already have succeeded even if registration/completion failed. |
| `interrupted` | A later maintenance pass found an open job whose ownership had ended. It is not a claim about why it stopped. |

Only non-dry-run `backup create` invokes abandoned-work recovery. It runs before taking the new backup scope; it skips cleanup while any live activity remains, conditionally marks abandoned jobs and removes only owned UUID-named staging/scratch directories. Ordinary reads never sweep. If a killed restore's native child still holds inherited claims, it stays protected/running until that child exits. Continuously busy stores can defer recovery. There is no separate cleanup/cancel command in M5a.

Do not unlink a lock file to force progress: another process may still hold its inode. Job locks now refuse linked lock directories, symlinks, non-regular files and group/world-accessible files on acquisition and recovery probes. Inspect ownership/path/type first, then repair legitimate permissions to `0600` while work is stopped. Keep the store operator-owned; these checks do not protect against a hostile actor replacing arbitrary ancestor directories.

## Acceptance evidence

M5a's acceptance map is in [the development contract](m5a-inventory.md). The complete native regression set is M1, M2, M3, M4a, M4a key drill, M4b and M5a on PostgreSQL 16/17/18, plus workspace tests, strict Clippy and formatting. M5a retains the frozen v1 bytes and synthetic-only guard. M5b retention/protection/deletion, M6 service hardening, production CLI validation and later API/UI gates remain separate.

From the repository root, with the locked Cargo dependencies cached, run the gates below. Native scripts require a non-root user with Docker access and the PostgreSQL images, Python 3, stock `rage`/`rage-keygen` on `PATH`, and Linux `strace` with delay injection for M5a. Each script manages its isolated fixture containers and temporary stores. Every command must exit zero; a fixture-startup failure is not passing evidence, and a retry must complete the affected script on all three majors.

```sh
set -e
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
for matrix in m1_docker_smoke m2_docker_smoke m3_docker_smoke m4a_docker_smoke m4a_key_drill m4b_docker_smoke m5a_docker_smoke; do
    bash "tests/${matrix}.sh"
done
```
