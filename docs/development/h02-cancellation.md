# H02 CLI cancellation and process ownership contract

Recorded before implementation on 2026-11-16. This is a declarative implementation contract, not an operating flow. It closes H02 at its fixture acceptance boundary; production remains disabled. Systemd/cgroup sandboxing, dedicated-user packaging and timer behavior remain H03. No new worker framework, dependency, configuration field, inventory state/schema or artifact/plan bytes are introduced.

## Caller and safe points

After successful CLI argument parsing, SIGINT and SIGTERM request sticky process-local cancellation. The signal handler only sets a lock-free atomic flag. Repeated signals are idempotent; cleanup is not performed from a signal handler. The application exposes a small std-only check/read wrapper shared by the native and filesystem adapters. Library callers that never request cancellation retain ordinary behavior. This is one CLI invocation's cancellation state; M7 owns reusable worker cancellation.

Cancellation is checked before native spawn, during native wait, at stream/hash/write boundaries and before starting the next create/restore/retention mutation. It does not interrupt SQLite transactions or durable publication/deletion commit sections halfway through their ordering. A command that has passed its last safe point may finish successfully. Blocking kernel filesystem calls, SQLite's existing busy wait and arbitrary caller code are not given a whole-job deadline. Existing per-tool timeouts remain. There is no new whole-job timeout flag.

Handled cancellation returns exit 1 with safe code OPERATION_CANCELLED. Native tool timeout retains its established diagnostic/code mapping. Syntax remains exit 2; successful completion remains exit 0. SIGKILL, abort, machine loss and a signal before handler installation cannot promise a final envelope or cleanup. Existing recovery marks genuinely abandoned jobs interrupted; a handled error/cancellation uses the existing failed state, with no invented cancelled enum value.

## Native ownership

Each native invocation keeps the existing private process group. A single owned child guard kills the group and reaps its direct child before returning or releasing caller-held activity/artifact/job claims. Polling observes child exit without reaping the group leader before group cleanup, avoiding a recycled leader ID. Captured stdin/stdout/stderr worker threads are joined; streaming watchdogs are joined. Cancellation and consumer failure kill promptly instead of waiting for the full tool deadline. A normally exited wrapper's remaining same-group descendants are also killed so inherited pipes and claims close. Captured output bounds, environment policy, protected tools/passfiles and safe diagnostics remain unchanged.

This contains the invoked process group under the existing trusted-client boundary. It does not sandbox a malicious executable, kill descendants that deliberately create a new session/group, manage PostgreSQL server workers, or guarantee parent-SIGKILL cleanup of an entire tree. Inherited claims preserve existing crash ownership; H03's service cgroup will own hard-stop/escaped-descendant containment. Database statements/roles/targets already started may remain modified and require inspection; cancellation is never automatic database rollback or deletion.

## Failure result data

The create and restore services attach a typed failure receipt after obtaining their actual job handle. Its safe public facts are job_id (nullable only for alternate adapters without an ID), artifact_id and effects. effects is preparation_only until publication/database mutation is attempted, then artifact_may_be_published or database_may_be_modified. These facts report attempts, not proven durable success or zero filesystem effects. Job recording can fail; callers inspect the referenced job rather than receiving a fabricated terminal-state claim. Post-publication/late-recording failures preserve the conservative publication fact.

For json-v1 only, the receipt becomes error data with those three fields. Preparation failures use status error; attempted publication/database mutation failures use status partial. Existing deletion partial partitions remain authoritative and are never replaced by this receipt. Pre-job failures retain null data. Success shapes, legacy bare JSON, saved plans and report envelope v1 remain unchanged. Human errors may add a safe job/artifact reference. No raw native output, SQL, database name, connection path or arbitrary diagnostic appears in the receipt. SIGKILL still has no report guarantee.

## H02 finish line and verification

H01's configuration/access/report, local native auth/recovery, custody, filesystem/resource and snapshot gates are already delivered. This increment supplies the real signal caller, process-group cleanup and structured create/restore failure facts. Existing mode/context-bound v3 fixture plans and production refusal prevent old plans authorizing production; any future production plan writer must satisfy H01's format/canonical-byte gate before V03 enables it. H02 does not add that disabled writer or claim H03/V acceptance.

Verify actual SIGINT/SIGTERM during stalled captured and streaming clients, a wrapper that leaves pipes behind, prompt consumer-failure cleanup, cancellation before publication and during restore mutation, safe receipts, failed job recording, scratch/stage cleanup and released same physical locks. Preserve SIGKILL recovery behavior. Run workspace/strict Clippy and a focused PG16/17/18 cancellation/recovery drill plus affected native/snapshot compatibility checks on frozen inputs. The closing handoff must state exact evidence and any remaining unmet gate rather than silently marking an incomplete capability done.
