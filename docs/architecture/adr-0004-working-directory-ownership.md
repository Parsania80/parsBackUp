# ADR 0004: Working-directory ownership and maintenance exclusion (phase S)

Status: **implemented and verified** (2026-10-03). The baseline is not open
for redesign: [project.md §10](../../project.md) states it, and the operator's phase commission
repeats it. What this document adds are the four things §10 left to be decided at the code seam —
which lock carries the claim, who invokes maintenance, what a busy maintenance pass does, and what
it is allowed to delete. Each is marked **Recommendation** and was implemented that way; none of
them changes the baseline. The gates at the end of this document are the evidence, and Decision 4
records the one place the implementation differs from the sketch.

This supplements [ADR 0003](adr-0003-backup-inventory-jobs-retention.md) rather than correcting it.
Its choice 4 is still the scope lock and its gates are unchanged; one sentence of its context is now
history — "the store's startup purge removes it" — because that purge is the defect this document
removes.

## Context

`LocalStore::open` created the store's directories and then emptied `staging/` and `scratch/` of
every entry, on **every** construction of a store. A command line reads the configuration, opens a
store, and does its work, so `backup list` — a command that writes nothing and takes no lock — was
one of the things that emptied those directories. The comment above the loop said why it was ever
reasonable: "single-owner store". That assumption died with M5a's job lock: the tool now supports
two live operations on one root, and a restart is no longer the only way to find an entry there.

The measured failure is `crates/backupctl/tests/store_concurrency.rs`. Three scenes, each with two
real `backupctl` processes and one storage root, synchronized by marker files a fake client tool
writes and the test releases:

| Scene | Second command | Result before this ADR |
|---|---|---|
| Dump mid-write | `backup list` | exit 0, and the running backup's `staging/<id>/payload.dump` was gone; the backup then failed |
| Dump mid-write | `backup create` (same scope) | refused with `already running` — and it had **already** deleted the stage it refused to duplicate |
| Decrypt mid-read | `backup list` | exit 0, and the verification's `scratch/<view>/payload.dump` was gone |

The second row is the order problem in its sharpest form. `BackupService::create` resolves, claims
the scope, and then stages, so the scope lock is taken *inside* the store's own construction
sequence — after the purge. A refusal that destroyed the thing it refused is not a refusal.

Two properties of the existing mechanism make the fix cheap, and both are recorded in ADR 0003's
spike. `flock` locks belong to the open file description, not the pid, so a process that dies —
including by `SIGKILL`, including by a power loss on the way down — stops holding them; nothing has
to decide what a stale lock means because there is no staleness to detect. And a shared lock is
compatible with another shared lock in the same process or in a different one, which is what keeps
per-profile concurrency intact while a maintenance pass is refused.

What is **not** available as evidence is time or identity. A staging directory's age says nothing
about whether a dump is running: a whole-database dump of a large cluster sits in `staging/` for
hours. A pid would have to be written, read, and interpreted against a process table that a
container or a restarted host makes meaningless. The roadmap says the same thing in §10: "Process
age/PID alone is not liveness." So the only witness is a lock the kernel holds on someone's behalf.

## Decision 1 — opening a store does nothing but open it

`LocalStore::open` keeps its directory creation and its `ensure_real_dir` checks, and performs no
removal at all. A construction is what every command does first, including the ones that only read,
so no destructive step belongs there.

Consequence, stated rather than discovered: an abandoned staging or scratch entry now **survives**
until something with a right to remove it runs. That is the point — but it means phase S has to say
who has that right, which is Decision 3, and what it may remove, which is Decision 4.

## Decision 2 — one activity lock, separate from every scope lock

**Recommendation: one fixed lock file, `<root>/locks/activity.lock`, held shared by any operation
that uses a working directory and exclusive by any pass that clears one.** Implemented in
`crates/backup-inventory/src/activity.rs` next to the scope lock, because it is the same kernel
primitive, the same directory, and the same refusal message shape; `backup-local` is still the only
crate that decides when to take it.

The four lock purposes project.md §18 names stay four, and this adds no fifth:

| Lock | File | Mode | Protects | Refuses |
|---|---|---|---|---|
| source/profile scope | `locks/<source>-<profile>.lock` | exclusive, nonblocking | one dump of one scope | a duplicate backup of that scope |
| store activity | `locks/activity.lock` | shared for work, exclusive for maintenance | live staging and scratch directories | a cleanup that would run alongside them |
| target/artifact use | *(M5b)* | — | a restore or deletion in flight | — |
| SQLite transaction | `inventory.db` | `BEGIN IMMEDIATE` | a row and its audit event together | a half-written transition |

The activity lock is *not* a global backup lock, and the difference is the requirement §10 states as
"shared activity ownership must not serialize different profiles". Two `backup create` commands —
of different profiles, or of the same profile through a scope lock one of them loses — both take the
activity lock in shared mode and both proceed. Only maintenance asks for it exclusively, and only
maintenance deletes.

The file is fixed-named and never unlinked, exactly as ADR 0003's spike reasoned for the scope
locks: unlinking a lock file is how two processes end up locking two different inodes and both
believing they won. It is created 0600 in the 0700 `locks/` directory through `OpenOptions`, opened
without following a symlink (`ensure_real_dir` governs the directory, and a non-regular lock file is
a hard error), and released by closing the descriptor — which `Drop` does, and which the kernel does
when the process dies.

## Decision 3 — ownership is attached to the guard that owns the directory

**Recommendation: `LocalStage` and `LocalPlaintext` each hold their own shared claim, and releasing
it is part of removing what it protected.**

The claim has to outlive the helper call that needed it, so it lives in the type whose drop removes
the directory:

- `LocalStore::begin` takes the shared claim and puts it in the stage. The stage is moved into
  `publish`/`publish_signed`, where the rename into `artifacts/` happens, and is dropped after it.
  So the claim covers the created file, every write the sink makes, the re-open that measures it,
  the decrypt used for the table-of-contents digest, and the rename — the whole lifetime the
  resource has, not the window an early helper returned.
- `decrypt_to_scratch` takes the claim and puts it in the view. A view that decrypts nothing (a
  plaintext artifact, whose payload is handed over where it lies) owns no scratch directory and
  takes no claim: Decision 5's non-mutating read rule applies to it as well.
- A stage's own scratch decrypt holds two claims at once. That is correct and harmless: shared
  against shared is compatible, and both drop.

Nothing else needs to know about the claim. The application layer's `StageHandle`/`PlaintextView`
ports do not mention locks, so the ownership stays a store fact rather than a service rule.

**Acquisition order**, which §18 requires be written down before anything combines these:

1. open the store — no lock, no removal;
2. maintenance, if this command runs any: **exclusive activity** → per-row conditional transition
   inside its own transaction → remove the directories it proved abandoned → release;
3. claim the scope: **exclusive scope lock, nonblocking** → inventory open → job row inserted;
4. work: **shared activity**, held by the guard for the resource's lifetime;
5. release the scope guard, whose drop writes the terminal row state.

Steps 2 and 3 never overlap: maintenance releases the exclusive claim before any scope lock is
taken, so no process can hold the activity lock exclusively while waiting for a scope lock, and no
process ever waits at all — every acquisition here is nonblocking. That is what keeps this from
becoming the deadlock §18 warns about. And no SQL transaction is open at any point in step 4, which
is the "do not hold a transaction while streaming" rule.

## Decision 4 — maintenance is an explicit, reported, best-effort pass

**Recommendation: `LocalStore::recover` is the only code that removes a working directory, a busy
store makes it skip everything rather than fail the command, and what it did is reported.**

Implemented invocation, which differs from the first sketch and is the part worth recording:
`recover` is called from the `backup create` command arm in `crates/backupctl/src/main.rs`, before
`BackupService::new` and therefore before resolution and before the scope claim, and only when the
run is not a dry run. The earlier sketch put it inside `BackupService::create`, after resolution;
that ordering is still legal — the requirement is "before the scope claim", not "after the preflight"
— but it would have needed a new method on the `ArtifactStore` port so a service could ask its store
to inspect its own directories. The pass is a store fact and a command policy; `dry_run` is already
known where the command is dispatched, so that is where the decision lives. Reports go to **stderr**,
in human mode only: JSON output keeps its existing shape, and a cleanup notice mixed into it would
be a serialization change this phase does not need.

Why a refusal would be the wrong answer: `backup create` on a *different* profile is perfectly safe
while another dump runs, and the only thing recovery wanted to do is tidy an entry whose owner died
some weeks ago. Failing a valid backup because a housekeeping pass could not run would convert a
cosmetic gap into an outage. So:

- exclusive acquisition returns "busy" → the pass examined nothing and removed nothing, and the
  report says so in those words;
- it is not a lock convoy, and no wait is introduced. A store that is continuously busy is a store
  whose abandoned entries are continuously deferred; the next quiet command collects them. The
  limit is honest and belongs in the operator documentation, not in a timeout nobody can tune.

What it may delete, under the exclusive claim and nowhere else: an entry of `staging/` or `scratch/`
whose name parses as a UUID and whose own `symlink_metadata` says *directory*. Anything else — a
symlink, a regular file, a name this tool would not have written — is **refused and reported**, not
removed and not treated as evidence that the store is dirty. Errors while removing a directory that
did qualify are errors: they propagate, because "the cleanup could not read the directory" is not
proof that its contents are abandoned.

That rule is what makes the deletion safe without a liveness test per entry: the exclusive claim is
itself the proof. If nothing can hold the store shared while it is held exclusive, then any entry
present at that moment belongs to a process that no longer exists.

## Decision 5 — reads that use no working directory take no claim

`config check`, `key generate|publish|status`, `profile list|validate`, `backup list`,
`backup inspect` and `backup verify --level checksum|signature` create nothing under `staging/` or
`scratch/`, so they claim nothing and are never refused by maintenance and never refuse it.
`backup verify --level archive` and `restore run` do decrypt, so they are shared claimants through
the view their guard returns. This is §10's "A nonmutating read can avoid the activity lock when it
uses no working data", made a property of which guards exist rather than of a flag on the call.

## Decision 6 — recovery stops rewriting rows on open, and its transition is conditional

The interrupted sweep was a side effect of `Inventory::open`, which every writable command calls.
That is now wrong twice over: it makes a *reader* of the index into a writer of `interrupted` states
it never earned, and it runs while another process's job is legitimately in `running`.

**Recommendation: `Inventory::open` performs no sweep; `Inventory::sweep_interrupted` is public and
is called only from `LocalStore::recover` inside the exclusive claim; and each row moves with a
conditional update.** The SQL is
`UPDATE job SET state = 'interrupted', … WHERE job_id = ? AND state IN ('running','staged')`, in one
transaction with its `job_interrupted` event, and the pass reports how many rows actually moved. The
`AND state IN (…)` is the whole of §18's requirement that a sweep "must not overwrite a job that
completed after a snapshot read": the snapshot decides *which* rows to attempt, and the write only
lands if the row is still open at the instant it commits. A job that finished in between is left
finished, and the audit trail shows one `job_interrupted` event for the rows that moved and none for
the one that did not.

Same-scope restart is why step 2 of the acquisition order sits before step 3. A dead process's row
for scope S is only recognizable as abandoned while nothing holds S's lock; the moment the new
backup claims S, `JobLock::is_free` says "held" and the old row becomes indistinguishable from the
new one. Recovering first is not an optimization — after it, the scope the new job enters is clean.

## Decision 7 — a read-only root is refused, not worked around

The scratch directory is `<root>/scratch/<view>`, and phase S changes nothing about that location.
Two options were open when a store on read-only media needs a decrypted payload: give the tool a
separate writable scratch root, or fail. **Recommendation: fail, with the root named.** A silent
fallback to `$TMPDIR` or `/tmp` would put decrypted payload and globals into a directory another
user of the host can list, which is the exact exposure `scratch/` was created to avoid; the roadmap
says the same thing in §10. So a DR host that must verify at archive level or restore from a read-only
mount needs a writable root, and that is a documented limitation of this phase rather than a bug in
it. Configuring a separate scratch location is a real feature — its own lifetime, its own ownership
claim, and its own mode rules — and it belongs with the restore-path work that would use it, not
here.

## Validation gates before phase S closes

All nine ran on 2026-10-03 on this host; the runs and their output are the record, and the two
controls are stated with the failure they produced rather than with a claim that they "would" fail.

1. **Pass.** The three S01 scenes hold: a live dump's stage survives `backup list`, survives a
   refused duplicate of its own scope, and a live verification's scratch view survives `backup
   list`, with the bytes compared and not just the paths — `cargo test -p backupctl --test
   store_concurrency` reports 4 passed, 0 failed.
2. **Pass, with both controls run.** Making `ActivityLock::hold_maintenance` take the store in
   shared mode on `EWOULDBLOCK` fails `activity::tests::two_shared_claims_coexist_and_a_maintenance_claim_refuses_them`
   ("a cleanup claimed a store two operations were using"), `recovery.rs:38`, and the CLI scene,
   which panics with "a refused duplicate backup removed the staging directory
   `…/store/staging/fb410c84-…` of the backup it refused" — the original defect, reproduced from the
   lock change. Changing `JobLock::acquire` from `LOCK_EX` to `LOCK_SH` fails
   `signed_write_path.rs:764` ("a second dump of one scope was accepted mid-dump") and removes the
   `already running` refusal the CLI scene asserts. Both edits were reverted and the suites re-run
   green.
3. **Pass.** Two shared claims coexist in one process and across processes, and scope refusals stay
   per-scope; the per-profile concurrency M5a shipped with is unchanged.
4. **Pass.** `a_killed_backups_leftovers_are_recovered_by_the_next_backup_of_its_scope`: real
   `SIGKILL` mid-dump, both claims released by the kernel, the next `backup create` of that scope
   marks the dead row `interrupted`, removes the abandoned stage, and publishes its own artifact with
   a different id.
5. **Pass.** `a_row_that_finished_after_the_snapshot_is_not_written_as_interrupted` — the conditional
   `AND state IN (…)` is what the assertion measures.
6. **Pass.** A second pass on a quiet store moves no rows and removes nothing, and the third backup
   in the `SIGKILL` scene finds one clean scope: three rows, one `interrupted`, two artifacts.
7. **Pass.** `the_pass_removes_leftovers_and_refuses_everything_else_it_finds`: a non-UUID name, a
   UUID-named regular file, and a UUID-named symlink are each reported and left alone, and the
   symlink's target survives.
8. **Pass.** `tests/m1_docker_smoke.sh`, `m2`, `m3`, `m4a`, `m4b` and `m4a_key_drill.sh` each pass on
   PostgreSQL 16, 17 and 18, which is where "no plaintext outside `scratch/`" and "no working
   directory survives its command" are asserted by reading what the client tools were handed. The
   first key-drill run stopped at `target 18 not ready` with the container already gone; the rerun
   passed all three majors, so the stop is recorded as a host race and the rerun as the evidence.
9. **Pass.** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace` and `git diff --check` all exit 0.


## Out of scope for phase S

Target and artifact-use locks, and every deletion of a *published* artifact — those are M5b's, and
nothing here moves a file inside `artifacts/`. Free-space headroom checks, the worker pool, and
scheduler semantics are M6/M7. A separate writable scratch root for read-only media is Decision 7's
limitation, not a task. And the two flock implementations this document leaves in place — the scope
lock's and the activity lock's — are a known duplication for phase C1 to judge, not a design
claim: they are separate now because merging them would move safety code across a crate boundary in
the same change that is supposed to be provable as a safety fix.
