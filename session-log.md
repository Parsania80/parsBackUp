# Session log

Completed-history archives: [September](archive/SESSION-LOG-2026-09.md), [October through M4b](archive/SESSION-LOG-2026-10.md). Archived entries preserve their original bytes and repository-root link context.

## 2026-10-01 — M5 scoped as ADR 0003, written against the code rather than against the roadmap

`docs/architecture/adr-0003-backup-inventory-jobs-retention.md` was drafted as a proposal and
**accepted the same day**: it states the milestone's gaps, the decisions that fork the design, and
the runs a close needs. No M5 code was written. The operator answered all seven decisions exactly
as recommended after the first table form of them came back unreadable, so the questions were
rewritten as the problem each one solves — the roadmap's M5 bullet then gained its status line and
the threat model's T03 row gained its scoped clause.

**What the survey established.** M5 is greenfield: `crates/backup-local/Cargo.toml` carries no SQL
dependency and no crate in the workspace mentions a metadata database, jobs, retention or pruning;
`BackupCommand` is `create|list|inspect|verify` and `RestoreCommand` is `plan|run`, so
`backup protect|delete|prune` from roadmap §12 do not exist and **nothing in the current build can
destroy a backup**. `backup list` is a directory scan returning
`StoreListing { signed, unsigned }`.

**Four findings that shaped the draft, each from a read of the frozen code.** (1) `backup_id` is
UUIDv4 (`backup-application/src/lib.rs:536`, `uuid` features `["v4", "serde"]` in the workspace
manifest), so ids order nothing and "newest" has to come from `completed_at_utc` or from a
sequence M5 assigns. (2) A v1 manifest records `verification_level: none` always and no reader
raises it, so roadmap §10's "count only verified/complete artifacts as valid" **cannot be read
off the artifact** — whether a backup was verified is a fact about a host at a time, which is
inventory state, and it also means "restore-tested" is per-host and does not travel. (3) M4b
sealed the manifest because it names a database, a host's shape and an operator's scope; a
plaintext database holding those same strings would reopen T13 in the one file operators will
casually copy, so the recommended schema is key-free columns only and `backup inspect` keeps
decrypting. (4) "catalog" already means PostgreSQL's catalog — on 74 lines across seven non-test
Rust files — so the new subsystem is named **inventory** to keep two `catalog.rs` files from
meaning different things.

**The seven decisions, accepted as recommended on 2026-10-01.** Increment boundary (M5a
observability, M5b deletion), placement and schema (`<root>/inventory.db`, key-free columns),
which side is authoritative (files for existence, db for lifecycle, unregistered vs missing,
explicit adoption), what a job is in a synchronous CLI (persisted states and a lock, no worker
pool, `job cancel` deferred), retention mechanics (per `source_fingerprint`-and-profile
`keep_last`, protection as a column because a sidecar file would change the frozen v1 shape,
plan-digest confirmation reusing the restore plan mechanism, **marker-first**
deletion so a crashed delete leaves a directory the reader already refuses, rows kept as `deleted`
because the rebuild scan cannot resurrect them anyway), how far a local ledger honestly goes
on T03 (a high-water-mark alarm labeled as one, with the chained signed inventory declared out of
scope for a future ADR), and the naming decision above — which is why the file is
`adr-0003-backup-inventory-jobs-retention.md`.

Two accepted consequences are written as limits rather than left as details: losing `inventory.db`
costs the protection flags, so the M6 guide has to tell an operator to back that file up; and the
rollback ledger is not T03's mitigation, so the threat model row stays open.

**Verification performed:** docs-only change, `cargo fmt --all --check` exit 0, the repository-wide
relative-link check reports no broken links, and every code claim above was taken from a grep or a
read of the file cited rather than from the roadmap's description of it.

## 2026-10-01 — the M5 spike ran, and one of its measurements reversed a recommendation

ADR 0003 deliberately left the SQLite questions to a spike that would measure them. It ran the same
day in `/tmp/m5-catalog` as a probe binary plus ten driver scripts, and the repository gained no
dependency from it.

**The driver, measured.** `rusqlite` 0.40.2 resolves to `libsqlite3-sys` 0.38.2 and reports
`rusqlite=3.53.2 bundled_sqlite=3.53.2`. The system-library variant was not merely worse, it was
impossible here: `rust-lld: error: unable to find library -lsqlite3`, because `libsqlite3-dev` is
not installed — and had it linked, the binary would have been pinned to the distro's
`libsqlite3-0:amd64 3.46.1-9ubuntu0.3` instead of 3.53.2. Cold build ~53 s either way, dominated by
the amalgamation. rusqlite is **+2.2 MB** in the release binary (444,952 B without it, 2,710,408 B
with `features = ["bundled"]`), and `default-features = false` on the *same source* removes 3 crates
(`hashlink`, `foldhash`, `hashbrown` — the `cache` feature) and 5,424 bytes. So the pin is
`rusqlite = { version = "0.40.2", default-features = false, features = ["bundled"] }`, and the size
argument for or against the default features turned out to be noise; the argument is that a
statement cache does nothing for a CLI that opens, runs a few statements, and exits.

**Journal mode: the reversal.** WAL was the assumed answer, on a concurrency argument nobody had
tested. With one process holding an open write transaction, a second reader got
`complete_rows=41 after 1ms` with the held row invisible under **both** WAL and DELETE, and a second
writer was refused at `busy_timeout=200` after 201 ms / 202 ms — identical, because a synchronous CLI
has no reader standing inside the one commit window where a rollback journal blocks. The only place
WAL won is a write shape the inventory will not use: 5,000 autocommit inserts took **128–130 ms**
under WAL and **394–406 ms** under DELETE; batched into one transaction both are 42–56 ms and
`synchronous` is irrelevant (NORMAL 42 ms, FULL 43 ms). What WAL costs is on the disaster-recovery
path, and the probe found it by accident: a WAL database whose `-wal`/`-shm` are absent — which is
what "copy the `.db`" produces — **cannot be opened read-only in a directory the process may not
write to**: `attempt to write a readonly database`, from the plain read-only open *and* from
read-write plus `PRAGMA query_only=ON`, because WAL must create the `-shm` before it can read. A
rollback-journal database in the identical position opens in all three ways. Copy the sidecars too
and WAL works (`journal=wal rows=41`), which is the whole problem: it depends on files nobody
thinks of as part of the store. The inventory is therefore `journal_mode=DELETE`,
`synchronous=FULL` — one file, copyable, readable from read-only media, and durable without
praying over a crash.

**Three rounds had to be thrown away, and why.** Round 3's six read-only scenes all "succeeded"
because the `check` probe run between them had already created the `-shm`; round 4 rebuilt each
scene in its own directory with the sidecars removed immediately before the open and `ls` used to
prove it. Round 6 was written in the same shape as the earlier drivers and its `mk()` printed the
database path *and* the probe output on stdout, so `db=$(mk …)` swallowed everything into the
variable, the subshell inherited `set -u`, and `local j=$1 lbl=$2 d="$W/$lbl"` aborted on the
unbound `lbl` — six scenes ran against the empty string, panicked at
`called Option::unwrap() on a None value`, and reported `no such table: artifact` for databases that
had never been created. The numbers were real but measured against nothing; round 6 was fixed and
re-run, and the fix is why `readnow` now prints the row count it read. Round 7's `corrupt`
subcommand did not corrupt anything — it only reopened a healthy database, which is why its
`integrity=ok` line meant nothing; it is renamed `reopen` and the corruption evidence comes from
round 8, which zeroes 512 bytes into the middle of a populated file.

**What the probes forced into the design** (all of it now in the ADR's dependency section, each with
the measurement attached): rusqlite's default `busy_timeout` is **5000 ms** — a probe that asked for
no timeout waited 5005 ms before refusing, and the same probe printing `PRAGMA busy_timeout` is what
caught it, so every open sets it explicitly or an operator waits five seconds for a lock instead of
getting an answer. `Connection::open` on a missing path **creates** it, and a 0-byte `inventory.db`
is a legal empty database (`integrity=ok`, `user_version=0`, `no such table: artifact`), so
"the inventory exists" has to mean `user_version >= 1` plus the tables, and `PRAGMA user_version` is
the migration lever. `query_only` is **not** a read-only open — it created a nonexistent file — so
read paths use `SQLITE_OPEN_READ_ONLY`. `immutable=1` **silently serves stale rows**: it reported
`journal=delete rows=41` while the same database held 43 including two committed rows sitting in the
`-wal` the flag tells SQLite to ignore; prohibited against a live store. `SIGKILL` mid-transaction
left `integrity=ok` with the committed rows present and the uncommitted one gone, so choice 4A's
"row still in `running` means interrupted" is the whole recovery story and no application-side
journaling is needed. And **a corrupt inventory still answers queries**: after the byte-zeroing,
`integrity_check` reported `Rowid 83 out of order` and `Fragmentation of 303 bytes reported as 0 on
page 16` while `SELECT count(*) FROM artifact` returned `201` under both journal modes — so the
check command must run `integrity_check` itself, and gates 7–9 now assert that rather than trusting
exit status. Scale is not a problem: 5,001 artifacts are 2.06 MB, `VACUUM` 7–9 ms, `page_size` 4096,
`PRAGMA optimize` 0 ms.

**Round 10 answered the lock question choice 4 left open.** A `flock` on a separate file, held by one
process for 3 s: a second invocation is refused in **0 ms**, succeeds the instant the holder exits,
and after a `SIGKILL` of the holder the lock is **free again with a 0-byte file left behind** — the
kernel closes the descriptor, so there is no stale-pid cleanup path to write or get wrong. A blocking
waiter got it after 2588 ms. The decisive scene is the one that ran both at once: while a process
held an open **write transaction**, `locktry` on the lock file reported `lock free`, because SQLite's
lock exists only while rows are being written and a `backup create` spends nearly all its runtime
streaming a dump with no transaction open. The overlap refusal is about the whole run, so the
`flock` is the job lock and the database's own locking stays as what keeps two row-writes from
interleaving — complementary, not alternatives. Read paths take no lock, so a DR host with the store
on read-only media runs `list`, `inspect` and `verify` without creating anything: **writes need a
writable root, reads need nothing but `inventory.db`.**

**Placement was the one question a spike could not measure,** so it is settled by the argument the
ADR already had: `crates/backup-inventory`, its port in `backup-application`, no dependency on
`backup-crypto` — which turns choice 2's key-free schema rule from a code-review note into a crate
boundary, since nothing in that crate can receive a plaintext path.

**Files changed:** `docs/architecture/adr-0003-backup-inventory-jobs-retention.md` (dependency
section rewritten as measured results, status note updated, choice 4's lock question closed, gates
7–9 added, a third consequence added), `project.md` (M5 paragraph's last sentence now records the
settled dependency set instead of deferring it), `session-log.md` (this entry). Crate graph, code,
and tests: unchanged.

**Verification performed:** every number above is copied from a run in `/tmp/m5-catalog`
(`spike.sh`, `spike2.sh` … `spike10.sh`, probe sources in `spike/src/main.rs`), the repo-relative
link check reports 0 broken links, and `cargo fmt --all --check` exits 0. `cargo clippy` and
`cargo test --workspace` were **not** re-run: this change touches no Rust source in this repository,
and the spike's own crate lives outside it. Two things remain unmeasured and are written as limits
rather than resolved: power-loss behaviour, which `SIGKILL` does not simulate, and the `.deb` build
with a C toolchain in `Build-Depends`.

## 2026-10-03 — M5a increment 1: the inventory exists, and the format decided two of its columns

**Request:** Implement M5a's first increment — the `crates/backup-inventory` crate, the `rusqlite`
pin, a key-free schema behind a `user_version` migration, and the `flock` job lock — then write the
two revisions the running code forced back into ADR 0003 and `project.md`, and add this entry.

**Implemented:** `crates/backup-inventory`, depending only on `anyhow`, `backup-domain`, `libc`,
`rusqlite` and `uuid`. `schema.rs` keeps the whole history in a dense, append-only `MIGRATIONS` list
keyed on `PRAGMA user_version`, and creating a file runs the same `0 -> 1` step an upgrade from an
older host's database runs, so there is one code path that produces a schema. v1 is `meta` plus
`artifact` plus the `(source, profile, completed_at_utc)` index. `lib.rs` exposes two opens and no
second way to get one: `open` creates and migrates, `open_read_only` cannot create anything, because
the spike had already measured that `PRAGMA query_only` creates the file it is supposed to spare.
Every pragma this format depends on is set and then **read back** — `busy_timeout` must answer the
2000 ms asked rather than rusqlite's own 5000 ms default, `journal_mode` must answer `delete`, and
`synchronous` must answer 2 on a write path. `Estate` is checked on both opens, so a database left
behind by another source is refused with the sentence the ADR asked for instead of being adopted.
`integrity_problems` exists as a query that returns SQLite's complaints rather than a boolean,
because the spike found a corrupt inventory still answering `SELECT count(*)`. `job_lock.rs` is
`flock(LOCK_EX | LOCK_NB)` on `<root>/locks/<source>-<profile>.lock`, named only by fingerprints,
file mode 0600 like everything else the store writes, and deliberately never unlinked.

**The finding that changed two accepted lines.** Choice 5 counts `keep_last` per
(`source_fingerprint`, profile *name from the manifest snapshot*), and choice 2 forbids a profile
name in a key-free file. Both were accepted; the schema could satisfy only one. The operator chose
the pattern the frozen format already uses — `profile_fingerprint`, a 16-hex domain-prefixed digest
(`PROFILE_FINGERPRINT_DOMAIN`, golden `nightly → 651dd7a74505b176`) — which resolves the
contradiction without disclosing anything. Writing the digest then exposed the half nobody had
looked at: the v1 signature authenticates `backup_id` and two ciphertext digests and **nothing
else**, so a host holding no key can list a `v1-signed` artifact perfectly and still not know which
profile made it or when it finished. `profile_fingerprint` and `completed_at_utc` are therefore
nullable, `NULL` means "this host never read the manifest" and never "oldest" or "whole-database",
and an inventory rebuilt without the identity key is **retention-blind in both directions**: its
rows cannot satisfy a `keep_last` count and must not be pruning candidates. M5b's `backup prune`
has to refuse on such a store rather than fall back to a per-source count, which is the distinction
choice 5 exists to keep. Gate 2's other half went the same way: the binding is the
`source_fingerprint` and not the `[storage] root` path, because choice 2A's argument for keeping the
file inside the root is that a copy of the root is a copy of the index, and a database that also
refused an unfamiliar absolute path would refuse exactly the DR copy it exists to serve.

**Two things the compiler and a failing test taught, not the design.** rusqlite under
`default-features = false` does not implement `ToSql`/`FromSql` for `u64`, so the two ciphertext
sizes cross the boundary as `i64` through helpers that **refuse** out-of-range values rather than
casting them — which is the right shape anyway, since SQLite's INTEGER is signed and a silently
negative byte count is a number no operator could explain. And the test that tried to prove
"an edited row is reported, not defaulted" failed on its first half: `UPDATE artifact SET shape =
'v1-unsigned'` was refused by SQLite itself, by the schema's own `CHECK`. That is better than what
the test was written to check, so the test now asserts the asymmetry instead — `shape` cannot be
edited into a word at all, while `state` is deliberately unconstrained (so that M5b can add
`deleted` and reconcile can add `missing` without rebuilding every row) and does survive to the read,
where it is refused by name. The `flock` turned out to be unit-testable without spawning anything:
two `File` handles to one path are two open file descriptions, which is what `flock` is owned by, so
the refusal is asserted in-process on a thread with a channel timeout — a missing `LOCK_NB` fails
the test instead of hanging the suite. The `SIGKILL` release cannot be reached that way and is not
claimed here; the spike measured it (0 ms, free lock, file left behind) and
`tests/m5a_docker_smoke.sh` has to re-measure it against a real killed `backup create`.

**Deliberately not built:** the `job` and `audit_event` tables, which will arrive as schema v2 so
the migration path is exercised by a real upgrade of a real v1 file rather than by a hand-made
database; `State` therefore ships with one variant, because a vocabulary entry with no writer is a
claim. Nothing calls `register()` yet, `INVENTORY_FILE` and `locks/` are not in `backup-local`'s
layout, and no command reads from the index — increment 1 is the storage and the rules, not the
surface.

**Files changed:** `crates/backup-inventory/` (new crate: `Cargo.toml`, `lib.rs`, `schema.rs`,
`artifact.rs`, `job_lock.rs`), workspace `Cargo.toml` (member, `rusqlite = "=0.40.2"`
`default-features = false, features = ["bundled"]`, `libc = "0.2"` for `flock` alone, already in the
tree via `getrandom`), `crates/backup-domain/src/{protocol,artifact_v1,lib}.rs`
(`PROFILE_FINGERPRINT_DOMAIN`, `profile_fingerprint`, a shared fingerprint helper),
`docs/architecture/adr-0003-backup-inventory-jobs-retention.md` (status now says increment 1
landed; two **Implementation revision** lines — choice 5 and gate 2; a fourth restated consequence),
`project.md` (a new **M5a increment 1 — landed** paragraph, including what is not wired),
`session-log.md` (this entry).

**Verification performed:** `cargo fmt --all --check` exits 0; `cargo clippy --workspace
--all-targets -- -D warnings` is clean; `cargo test --workspace` reports **153 passed, 0 failed**, of
which 24 are the new crate's and 30 are `backup-domain`'s including the frozen profile-fingerprint
golden. Two claims were corrected against measured output before being written down rather than
after: the workspace test count was first written as 133 and is now the summed `test result` lines
(153), and the lock's refusal is documented as "under 500 ms" because that is the bound the test
asserts, with 0 ms attributed to the spike's separate run. The only slow test in the suite is
`a_locked_inventory_answers_instead_of_waiting_five_seconds`, which costs the two seconds of busy
timeout it exists to prove; the read-only-copy and mid-dump `SIGKILL` scenes from gates 7 and 9 are
still Docker-script work and are not claimed by any unit test. Repo-relative Markdown links: 0
broken. `git diff --check` clean. Nothing was committed or pushed.

## 2026-10-03 — M5a increment 2: a real backup now writes an inventory row

**Request:** Do the smallest wiring increment — the two layout names in `backup-local`, `register()`
on the publish path, and the test that a real `backup create` lands a `v1-signed` row. Job rows,
reconcile and `backup list` reading from the index stay out.

**Implemented:** `backup-local` depends on `backup-inventory` (and not the other way round, which is
what keeps the key-free rule a crate boundary rather than a convention). `layout.rs` gains
`INVENTORY_FILE` and `LOCKS_DIR`, each defined as the other crate's constant instead of restating the
string — the store records where an operator finds these, the inventory owns what they are called —
and `locks/` is created beside `staging/`, `artifacts/` and `plans/` on store open.
`LocalStore::record_published` runs at the end of `publish_signed`: it derives the `Estate` from the
manifest's `source_fingerprint`, opens the index, and writes one `v1-signed` / `registered` row whose
eight discovery fields are copied from the `PublicHeader` that was sealed three statements earlier.
Only `profile_fingerprint` and `completed_at_utc` are read from the manifest itself, which is the
precise case the two nullable columns were added for: this host holds the key that just decrypted it,
and the next host to rebuild this index will not.

**The decision worth writing down.** Registration happens *after* `complete`, not before. Either
order leaves a state ADR 0003 already names — files with no row is `unregistered`, a row with no
files is `missing` — but they are not symmetric: the first is reported and can never be a prune
candidate, while the second is a claim about a backup that is not there. Putting the index write
after the marker means the one step that can fail on a healthy filesystem (a locked or corrupt
`inventory.db`) cannot un-publish a dump, and the error says so in the same sentence that names the
fix. Three consequences follow from that and are true of the binary now: `backup create` can exit
non-zero on a backup that succeeded; pointing a second source at one storage root fails at this step,
because the estate binding refuses to merge two indexes rather than making both sources' `keep_last`
answers wrong; and the unsigned `publish` path writes no row at all, so a plaintext development
store holds nothing but unregistered artifacts until reconcile exists. The third is a limit, not an
oversight — a `plaintext-dev` row would have to state a source fingerprint its manifest does not
carry.

**Files changed:** `crates/backup-local/Cargo.toml` (dependency), `crates/backup-local/src/layout.rs`
(two names), `crates/backup-local/src/lib.rs` (`LOCKS_DIR` in the created directories,
`record_published`, its call site), `crates/backup-local/tests/signed_write_path.rs` (one test),
`project.md` (increment 1's stale "not yet wired" sentence corrected, increment 2 paragraph added),
`session-log.md` (this entry).

**Verification performed:** `cargo fmt --all --check` exits 0; `cargo clippy --workspace --all-targets
-- -D warnings` is clean; `cargo test --workspace` reports **154 passed, 0 failed** (5 in
`signed_write_path`, up from 4). The new test is checked against being vacuous by the only method that
proves it: commenting out `self.record_published(…)` makes it fail with "publishing left no inventory
at …/inventory.db", and it passes again when the call is restored. It asserts the row against
`public.json`'s ten fields, the two manifest-only columns, an `open_read_only` of the file the write
path created (so the row must survive the open a DR host can perform), `integrity_problems` empty,
and — the reason the index is its own file with its own threat model — that the bytes of
`inventory.db` contain neither the fixture database's name nor the configured host nor the
`backupctl_fixture` prefix either one appears under.

## 2026-10-03 — M5a increment 3: the job state machine, and the two states nobody writes

**Request:** Job state machine next: schema v2 with `job` + `audit_event`, `backup create`
opening/transitioning a row, `JobLock` acquired on the real path, mid-dump overlap refused
(ADR 0003 gates 1 and 9).

**Implemented:** `SCHEMA_VERSION` is 2 and the dense `MIGRATIONS` list gains a `1 -> 2` step adding
`job` (`job_id` primary key, nullable `backup_id`, two fingerprints, `state`, two timestamps, and a
`(source_fingerprint, profile_fingerprint, started_at_utc)` index) and `audit_event` (`event_id` as
a rowid, `at_utc`, `action`, and the two ids it names). The rowid is the sequence — `backup_id` and
`job_id` are random UUIDv4s that order nothing, so the trail's only honest ordering is insertion.
`job.rs` is the whole state machine: `JobState` with five states and `is_terminal`, `JobRow`,
`AuditAction`, `JobScope`, and `JobGuard`, whose `begin` takes the `flock` **before** it touches any
SQL and whose `move_to` refuses an illegal transition before it writes rather than after. Every
state write and its event go through one `in_transaction` helper shaped like `migrate` — `BEGIN
IMMEDIATE`, the closure, rollback if anything failed including the commit — so a row and its trail
cannot disagree, and `register()`'s artifact row and its `ArtifactRegistered` event now land in one
transaction too. `Inventory::open` runs `sweep_interrupted` after the estate check: for each
non-terminal row it probes that row's own lock and marks `interrupted` only where the lock is free,
which is what the new `JobLock::is_free` exists for (`ENOENT` is free; `EWOULDBLOCK` is not;
nothing is created by asking). `backup-application` gains the `JobRequest`/`JobHandle` pair and a
`begin_job` method on the `ArtifactStore` port; `create` opens the row before the dump, moves it to
`staged` once both sinks are sealed — one call that covers the signed and the development branch —
and to `complete` after publication. `backup-local` adapts the port through a `LocalJob` newtype,
because the orphan rule forbids implementing `backup_application::JobHandle` for
`backup_inventory::JobGuard` from a third crate.

**The decisions worth writing down.** (1) **No `planned`, no `verified`.** The roadmap's sketch names
both and the first cut of ADR 0003's table kept them; neither has a writer. `planned` in a
synchronous CLI is a row that is one statement older than `running`, and `verified` belongs to
`backup verify`, which choice 4 records as an event and not a job. Every state that shipped has a
writer that means something. (2) **`failed` is written by `Drop`, and there is no reason column at
all.** A guard going out of scope with a non-terminal row writes `failed`; a process that dies
without running a destructor leaves `running` and is found as `interrupted` by the next open, which
is the whole distinction. The reason would be an anyhow chain that can name a database, a host or
`127.0.0.1`, and gate 5 greps the raw `.db` bytes for exactly those — so the operator's terminal
gets the sentence and the index gets the state, and `Drop` swallows the write error because a
`Drop` has no return value and panicking while unwinding from the failure it is recording would turn
a handled refusal into an abort. (3) **Every store gets jobs and the lock**, including the plaintext
development one, whose `job` rows may point at ids its `artifact` table has never seen — the
unregistered state increment 2 already documented, and better than a store with no history at all.
(4) **No CLI surface this increment**: `job list`/`job inspect` are the next thing, so the states
are observable through the crate and its tests only.

**Gate 9, asked in the only window where it means anything.** A test that starts a second
`backup create` after the first has written its rows is refused by SQLite's write lock and proves
nothing about overlap, because during a real dump no transaction is open — only the kernel's lock
is. So `Capture` gained `on_dump_read`, a hook fired once from the first byte the stub dump actually
reads, and the test calls `JobGuard::begin` for the same scope from inside it. The hook reports the
lock files present, a read-back of the live rows (`running`, and nothing else — the refusal leaves
no row of its own), the refusal text naming the lock it met, and a second guard for a *different*
profile, which succeeds and whose `Drop` is the real writer of the real `failed` row on the real
path. Stated as a limit in the test and in the ADR: this is one process with two open file
descriptions, which finding 10 measured is the same mechanism two processes get, but the
two-process `SIGKILL` version belongs to `tests/m5a_docker_smoke.sh`.

**Files changed:** `crates/backup-inventory/src/schema.rs` (v2, the two tables, three migration
tests), `crates/backup-inventory/src/job.rs` (new: states, rows, trail, guard, six of the seven new
unit tests), `crates/backup-inventory/src/lib.rs` (`now_utc`, `in_transaction`, `begin_job`,
`set_job_state`, `jobs`/`job`/`audit_events`, `sweep_interrupted`, `register` wrapped in one
transaction, six job tests), `crates/backup-inventory/src/job_lock.rs` (`is_free`, one test),
`crates/backup-application/src/lib.rs` (`JobRequest`, `JobHandle`, `ArtifactStore::begin_job`, the
three calls in `create`), `crates/backup-local/src/lib.rs` (`LocalJob`, `begin_job`),
`crates/backup-local/tests/common/mod.rs` (`on_dump_read`, the `MidDump` reader),
`crates/backup-local/tests/signed_write_path.rs` (two tests, `write_signed_in`),
`crates/backup-local/tests/write_path.rs` (one test),
`docs/architecture/adr-0003-backup-inventory-jobs-retention.md` (choice 4 revised in four parts,
gates 1 and 9 revised, status paragraph counts four revisions), `project.md` (increment 3),
`session-log.md` (this entry).

**Verification performed:** `cargo fmt --all --check` exits 0; `cargo clippy --workspace
--all-targets -- -D warnings` exits 0; `cargo test --workspace` reports **167 passed, 0 failed** —
`backup-inventory` 34 (up from 24), `signed_write_path` 7 (up from 5), `write_path` 4 (up from 3).
Three negative controls, each reverted and diff-checked afterwards: `LOCK_EX` changed to `LOCK_SH`
in `JobLock::acquire` makes the mid-dump test fail with "a second dump of one scope was accepted
mid-dump"; deleting `job.staged()?` from `create` makes the trail test fail with
`[JobStarted, ArtifactRegistered, JobCompleted]` against the expected four events; and a `Drop`
that writes nothing makes the abandoned row read back `Interrupted` where the test expects `Failed`
— which also proves the sweep is the backstop it was designed to be. One earlier assertion was
removed rather than weakened silently: `started_at_utc != updated_at_utc` failed on a green run,
because timestamps carry second resolution and a stub dump finishes inside one second, so the test
now asserts both parse as UTC and that `updated_at_utc >= started_at_utc`, and leaves the ordering
claim to the trail's monotone `event_id`.

[2026-10-03 11:12] [AGENT] Reviewed AGENT.md, project.md and the complete session history against crate dependencies, backup/store/job code and tests. Design direction remains sound; M5a is incomplete. Independently verified cargo fmt --all --check, cargo clippy --workspace --all-targets -- -D warnings and cargo test --workspace (167 passed, 0 failed). Reproduced a live-cleanup blocker in a temporary synthetic store: backup list exited 0 and removed staging and scratch directories while an exclusive scope lock remained held. Existing mid-dump coverage bypasses LocalStore initialization. Recorded safe cleanup as the immediate next action, with job surface/reconciliation/rebuild/crash gates before M5b. Minimally aligned project roadmap and ARCHITECTURE lifecycle/SQLite summaries; appended README status. Archived completed M0–M4b entries verbatim under archive/SESSION-LOG-2026-09.md and archive/SESSION-LOG-2026-10.md under AGENT.md rule 9 (log had 799 lines); retained active M5 entries. No Rust source changes, Docker matrix rerun, commit or push.

[2026-10-03 11:27] [AGENT] Operator explicitly authorized a complete project.md revision and requested a clean-code phase for simpler, human-readable code. Replaced the old roadmap with a 32-section implementation handoff: status/contract authority, locked stack, crate/data/state/artifact/process/inventory contracts, stable ordered tasks and acceptance gates, S cleanup safety before C1 behavior-preserving readability refactors, then remaining M5a/M5b/M6 and separate CLI/API/UI release tracks. Retained accepted v1/ADR decisions and historical evidence; labeled new shared activity/exclusive maintenance and conservative retention choices as planned baselines requiring task design records. Added explicit keyless expected-estate inputs, read-only audit limits, metadata-preserving enrichment and consistent inventory-copy requirements. Updated README roadmap paragraph. No Rust source, dependencies, flow documents, commits or pushes changed. Documentation checks recorded below.

[2026-10-03 11:28] [AGENT] Verified the rewritten roadmap has all 32 ordered sections, one Current/Next pair, every defined task ID, resolving active-document local links/anchors and an active session log below 500 lines. git diff --check passed. No runtime tests rerun for this documentation-only revision; the preceding review's 167-test baseline is labeled separately from future acceptance.

[2026-10-03 11:30] [AGENT] Operator requested a commit of the latest documentation changes. Preparing a documentation-only commit for project.md, README.md, ARCHITECTURE.md, session-log.md and the two completed-history archives, with message "docs: rewrite implementation roadmap and add clean-code phase". Existing M5a implementation, dependency, ADR and operator-protocol changes remain unstaged. Whitespace checks passed; no push requested.

[2026-10-03 11:32] [AGENT] Operator authorized committing all remaining Git changes. Reviewed the remaining M5a signed-artifact registration, schema-v2 jobs/audit, scope-lock probes, application/local wiring, migration/write-path tests and ADR 0003 revisions. Fresh checks passed: cargo fmt --all --check, cargo clippy --workspace --all-targets -- -D warnings, cargo test --workspace (167 passed, 0 failed), git diff --check. Preparing separate commits for M5a implementation and replacement of legacy AGENTS.md with operator-provided AGENT.md. README retains open cleanup/recovery gates. No source fixes, milestone-completion claim, Docker matrix run or push is part of this commit request.

[2026-10-03 12:56] [AGENT] Phase S (S01–S03) implemented and verified; the live-cleanup blocker is closed. **What the fix is:** `LocalStore::open` no longer removes anything (the `staging/`/`scratch/` purge loop is deleted), an operation that uses a working directory holds `locks/activity.lock` **shared** through the guard that owns the directory (`LocalStage._claim`, taken in `begin`; `LocalPlaintext._claim`, taken in `decrypt_to_scratch`; borrowed plaintext views own nothing and claim nothing), and the only code that deletes a working directory is the new `LocalStore::recover`, which takes that lock **exclusive and nonblocking**, and on `EWOULDBLOCK` skips the entire store and reports the skip instead of failing the command. `recover` runs in the `backupctl` `backup create` arm before `BackupService::new` — not inside the service, because reaching the pass from a service would have added a method to the `ArtifactStore` port for a store-and-lock fact, and `dry_run` is already decided at dispatch; reports go to stderr in human mode only, so `--output json` keeps its existing shape. Cleanup order inside the pass is sweep-then-remove, under the same exclusive claim: `Inventory::open` performs no sweep any more (a *reader* of the index was writing `interrupted` states it had not earned), `Inventory::open_bound` exists because the pass cannot recompute a source fingerprint without a live server major to probe, and each row moves through `job::mark_interrupted`'s conditional `UPDATE … WHERE job_id = ? AND state IN ('running','staged')` in one transaction with its `job_interrupted` event, which is §18's "must not overwrite a job that completed after a snapshot read". Only a UUID-named *directory* is removed; a symlink, a regular file, or a name this tool would not write is reported and left alone, and a removal error propagates rather than being read as proof of abandonment. Scope locks are unchanged and remain a separate, per-(`source`,`profile`) concern.

**The defect found while verifying, and why it matters more than the fix:** `cargo test --workspace` failed `a_killed_backups_leftovers_are_recovered_by_the_next_backup_of_its_scope` with the dead row still `Running`, while the same file passed alone. The cause was a **negative control left in the tree**: `if false && matches!(…)` in the `backup create` arm, from the earlier run that proved the invocation point is load-bearing, made `recover` never execute and — because `print_recovery` is silent for a pass that found nothing — fail with no message at all. Deleted the guard; the scene passed. Lesson recorded for the next phase: a control must be reverted in the same step that ran it, and a green-looking skip is not evidence. Both controls were then re-run deliberately for the ADR record and reverted with the suites re-run green: letting `hold_maintenance` fall back to a shared claim on `EWOULDBLOCK` reproduces the original defect from the CLI ("a refused duplicate backup removed the staging directory … of the backup it refused") and fails `activity::tests::two_shared_claims_coexist…` and `recovery.rs:38`; changing `JobLock::acquire` to `LOCK_SH` fails `signed_write_path.rs:764` ("a second dump of one scope was accepted mid-dump") and removes the `already running` refusal the two-process scene asserts.

**Verification performed:** `cargo fmt --all --check` exit 0; `cargo clippy --workspace --all-targets -- -D warnings` exit 0; `cargo test --workspace` **179 passed, 0 failed** (from 167: `backup-inventory` 40, `backup-local` lib 16, `recovery` 2, `store_concurrency` 4); `git diff --check` exit 0. PostgreSQL matrices on Docker with the 16/17/18 `postgres:*-bookworm` images, all exit 0: `m1_docker_smoke.sh`, `m2_docker_smoke.sh`, `m3_docker_smoke.sh`, `m4a_docker_smoke.sh`, `m4b_docker_smoke.sh`, and `m4a_key_drill.sh` — the drill's **first** run stopped at `target 18 not ready` right after the m4b run (host container/port race, no leftover container and no listener on 54338 when checked), and its rerun passed all three majors; the rerun is the evidence and the stop is recorded rather than hidden. No test was weakened to pass, and no smoke script needed changing: their assertions are that working directories are empty *after* a command, which the guards still guarantee, and `open` still creates `scratch/` only for a keyed store, which the m4a keyless-root assertion checks.

**Limits left standing, as limits:** a store that is continuously busy defers cleanup indefinitely, so abandoned entries survive until a quiet `backup create` runs — the pass is best-effort by design and no timeout was introduced; recovery runs only for `backup create`, so a DR box that only verifies and restores never clears an abandoned scratch view; two `flock` implementations (scope and activity) remain, deliberately, because merging them would move safety code across a crate boundary in the same change that is supposed to read as a safety fix. ADR 0004 Decision 7 keeps a read-only storage root refused by name instead of falling back to `$TMPDIR`. No push, no C1 work, and no inventory/retention feature was started.

[2026-10-03 13:41] [AGENT] Operator requested the phase S commit as C1's clean baseline, so that a later behavior-preserving refactor can be measured against a known-good tree. Staged the 19 files of the phase — `crates/backup-inventory/src/activity.rs`, `crates/backup-local/tests/recovery.rs`, `crates/backupctl/tests/store_concurrency.rs` and `docs/architecture/adr-0004-working-directory-ownership.md` as new paths, plus the inventory/job/store/CLI changes, the two `Cargo` entries and the six documents that described the startup purge — and committed them as `50700b3` "fix: own working directories, clean them only under an exclusive claim": 19 files, 1728 insertions, 81 deletions, working tree clean afterwards. No source changed since the recorded gates ran, so no gate was re-run for the commit; nothing was pushed, and roadmap position remains #8 C1 current, #9 A next.

[2026-10-03 15:20] [AGENT] **C01 run — refactor scope measured, no source moved.** Built the CLI at `097ace3` and drove **67 real invocations** against three synthetic stores (plaintext, `[encryption]`, `[encryption]+[signing]`) on PostgreSQL 16 through fake `psql`/`pg_dump`/`pg_restore`/`pg_dumpall`/`createdb` binaries, capturing **213 stdout/stderr streams**; read the six crates' declarations directly for the exported surface. Wrote the result as `project.md` **§33** and marked C01 met under §26's C1 table, and corrected §26 row 8 to "Started". Measured facts worth repeating because they are contracts a refactor must reproduce: `backup list --output json` is an **array** for the two development shapes but **`{signed:[…],unsigned:[…]}`** for a signed store; `backup inspect` returns a **23-key** development manifest versus a **29-key** v1 manifest whose identifier is `backup_id`, not `id`, and whose public record carries exactly 10 keys; `backup verify` returns the same 7-key object at all three levels for every shape; `key status` in a keyless store writes **nothing to stdout and exits 1**; JSON comes from 12 `serde_json::json!` sites plus one hand-written `println!` at `main.rs:104`. Mixed ownership recorded with call sites: one `impl ArtifactStore` (`backup-local/src/lib.rs:841–1460`) holds unsigned publication, unsigned read, plan rewrite, signed publication, signed read and restore plans; the activity claim lives in `backup-inventory::ActivityLock` but is held from `backup-local` (`:444`, `:623`, `:878`) while the scope flock is taken inside the inventory (`job.rs:438`) and probed there (`lib.rs:487`); `main.rs:74–372` is a single `run()` with 8 arms, 4 store opens (`188`, `208`, `286`, `318`) and 11 `if json` pairs. Repetition counted, not guessed: 9 private-file opens, 9 `hash_file` calls, dev/v1 publication converging on marker+fsync, rename+fsync and temp-manifest pairs, `Duration::from_secs(config.timeout_seconds)` 6 times, `config.validate()` 3 times per `backup create`, and the DR role refusal at `1002–1005` versus `1066–1069` whose sentences **differ** by one clause. One finding is a behavior difference, not a tidiness item: `JobLock::acquire` (`job_lock.rs:46–102`) opens the lock file **without** `O_NOFOLLOW` and never checks its mode, while `ActivityLock::open_claim` (`activity.rs:114–159`) does both — recorded as §33.5 item 1 and proposed as a separate documented fix with its own failing test, explicitly **not** folded into a move-only C02 change. Baseline re-measured for the C04 comparison: `cargo fmt --all --check` exit 0, `cargo clippy --workspace --all-targets -- -D warnings` exit 0, `cargo test --workspace` **179 passed, 0 failed** (18 test binaries, 8 non-empty), `git diff --check` exit 0.

**Not claimed:** no C02 module was created or moved, so phase C1 is not complete and §26 row 8 stays open; §33's boundary list is a proposal awaiting the operator, including the one new-file idea (`backupctl/src/command/`), which §26's diagram omits entirely. Documentation-only change set: `project.md` §26 row 8, the C01 acceptance note, new §33, and README's progress sentence.

[2026-10-03 15:15] [AGENT] **C02-1 — §33.6 approved as C02's boundary set; `backup-local/src/keys.rs` moved.** Operator approved the approved-boundary set including the `backupctl/src/command/` addition and both corrections to §26's diagram (`activity` stays in `backup-inventory`; `layout.rs` and the recovery operation already exist), then authorized the smallest move first. **What moved:** `load_pair` (`pub(crate)`, still called by `with_keys` at `lib.rs:326` and `with_signing_keys` at `:353`), the six `pub fn` key commands (`key_status`, `generate_key_pair`, `publish_recipient`, `generate_signing_pair`, `publish_verifying`, `signing_key_status`), and the two file-system rules they own alone (`refuse_occupied`, `ensure_private_parent`) — 171 lines of function body, zero logic change. `lib.rs` re-exports the six commands from the crate root, so `backupctl`'s import paths are unchanged. Seven key tests moved with their subject; `backup-local/src/lib.rs` 2297 → 1922 lines, `keys.rs` 392, and one file beyond the diagram: a 26-line `#[cfg(test)] mod fixture` holding `temp_root`/`temp_keys`/`key_pair`, because the moved key tests and the store tests that stay both need them and §33.4 already counts that duplication (`stage_bytes`/`manifest` are store-specific and stayed put).

**Proof the move is pure, measured in three independent ways.** (1) Byte identity: each relocated body diffed against `HEAD` — 171 old lines vs 171 new, identical after stripping blank-line/rustfmt wrapping and the `pub(crate)` marker; each of the seven tests identical, with no assertion text changed; the lib suite is 16 tests before and after (9 store + 7 keys). (2) Reachability, with a negative control: commenting out the whole `pub use keys::{…}` block makes `cargo check -p backupctl` fail with `error[E0432]: unresolved imports backup_local::generate_key_pair, …, signing_key_status` at `crates/backupctl/src/main.rs:25`; an initial attempt that commented only the opening line proved nothing (it produced `error: unexpected closing delimiter`, a syntax artifact, not a wiring failure). The block was restored and `grep -rn "CONTROL" crates/` returns nothing. (3) Behavior: see the battery numbers below.

**Verification performed:** `cargo fmt --all --check` exit 0; `cargo clippy --workspace --all-targets -- -D warnings` exit 0; `cargo test --workspace` **179 passed, 0 failed** (unchanged from the phase S baseline); `git diff --check` exit 0. PostgreSQL 16/17/18 matrices on Docker, all exit 0: `m1`, `m2`, `m3`, `m4a`, `m4b`, and `m4a_key_drill` (rotation, cross-generation refusal, key loss, offline recovery, total-loss inertness, an operator-supplied identity, and the signing pair's loss and recovery verified per major). The §33.2 CLI battery was rerun against the same three synthetic store shapes: `diff` of the invocation-label lists is empty at **67 = 67**, **0 exit-code differences**, and after masking only run-specific values — artifact ids, freshly generated key hex, byte counts and timestamps from new dumps, the `/tmp/<rundir>` prefix — **all 134 stdout/stderr streams are byte-identical**. Unmasked, 12 streams differ across 22 lines and every one is a size or timestamp value; no prose, key name, or error sentence changed. Two compile fixes were needed and are not behavior changes: the moved test module needed `use backup_application::ArtifactStore` in scope for `.list()` to resolve (a trait method is not reachable through `super::*` from a sibling module), and `fixture.rs` dropped an unused `KeyRole` import.

**Not done, deliberately:** the `JobLock::acquire` gap recorded as §33.5.1 (no `O_NOFOLLOW`, no `mode & 0o077` assertion, unlike `ActivityLock::open_claim`) was **not** touched — it is a separate documented behavior fix with its own failing test, and folding it into a move-only change is exactly what §26's C1 rules forbid. No further C02 module was created (`store`/`stage`/`scratch`/`signed`/`development`/`plans`/`inventory` and `backupctl/src/command/` all remain pending), C03 and C04 have not started, and phase C1 is not complete. Documentation updated: `project.md` §26 row 8 (now "Started" with the C02-1 state), the approval paragraph and the C02-1 bullet plus a gates paragraph, §28's new decision-register row for the approved boundary set, and README's progress paragraph. No commit, no push — the six changed paths (`M README.md`, `M crates/backup-local/src/lib.rs`, `M project.md`, `M session-log.md`, `?? src/fixture.rs`, `?? src/keys.rs`) are left for the operator.

[2026-10-03 15:43] [AGENT] **C02-2 — `backup-local/src/store.rs`.** The store's shape decision moved out of the store file: `new`, `with_keys`, `with_signing_keys`, `for_reading` and the private `open` they all funnel through, with `open`'s root and layout checks (absolute-root refusal, `create_dir_all`, `ensure_real_dir` on the root, the four required directories created at mode 0700 with `scratch/` added only for a keyed store, and the comment recording that ADR 0004 makes `recover` the only code allowed to delete). `LocalStore` and `StoreKeys` stay declared in `lib.rs`, so the crate-root surface is untouched and `backupctl/src/main.rs:55–69` compiles against the same paths. `lib.rs` 1922 → 1792, `store.rs` 148.

**Why this move is cleaner than C02-1, stated as a measurement:** it required **no visibility change**. The four constructors were already `pub`, `open` is private and called only from inside the moved set, and Rust lets a child module read its ancestors' private items — so `store.rs` calls `crate::ensure_real_dir`, which stays at the crate root (`lib.rs:1341`) with its four call sites, three of which live in code that has not moved yet. Duplicating or widening that helper would have been a behavior-adjacent edit in a move-only change. The only other edits are three `lib.rs` imports that became unused after the move (`KeyRole`, `use keys::load_pair`, `LOCKS_DIR`); their removal is verified by `cargo clippy --all-targets -D warnings` rather than by eye, and the same check proves nothing in `store.rs` is dead.

**Three proofs, all run in this step.** (1) Identity: the removed 130-line block compared to `store.rs`'s `impl` body — 125 non-blank lines on each side, **0 differences**; the single blank-inclusive difference is the separator line that stays behind in `lib.rs`. (2) Uniqueness: the definitions exist at exactly `store.rs:20/29/54/100/125` and nowhere else, and the negative control was run on the **whole item** — commenting out `mod store;` produces `error[E0599]: no associated function or constant named 'new' found for struct 'LocalStore'` at `crates/backupctl/src/main.rs:55:28`, plus the same for `with_keys` (:58), `with_signing_keys` (:61) and `for_reading` (:69), ending in `could not compile backupctl (bin "backupctl") due to 4 previous errors`; the item was restored in the same step and `grep -rn "CONTROL" crates/` returns nothing. (3) Behavior: `cargo fmt --all --check` 0, `git diff --check` 0, clippy 0, `cargo test --workspace` **179 passed / 0 failed** including the four two-process `store_concurrency` scenes and the 16-test `backup-local` lib suite (9 store + 7 keys, unchanged), and all six PostgreSQL matrices exit 0 with 16, 17 and 18 each named in their logs (`m1`, `m2`, `m3`, `m4a`, `m4b`, `m4a_key_drill` — rotation, cross-generation refusal, key loss, offline recovery, total-loss inertness, an operator-supplied identity and the signing pair's loss and recovery per major). The §33.2 battery was rerun from the same script with a different harness directory: the invocation-label lists `diff` empty at **67 = 67**, **0 exit-code differences**, and of 134 streams **28 differ unmasked and 0 remain** after masking artifact ids, key hex, byte counts, timestamps and that directory name. An earlier first pass of this comparison reported 8 residual streams that were only `/tmp/c02` vs `/tmp/c02b` path text, because the mask substituted digits before substituting the run directory — order fixed, re-measured, and the corrected numbers are the ones recorded in `project.md`.

**Deliberately left for C02-3:** `Recovery` (`lib.rs:146`), `recover` (`:322`), `clear_working_dir` (`:355`) and the path helpers `encrypted`/`artifact_dir`/`plan_path` (`:390–400`) are §33.6 `store.rs` items that stayed put. The maintenance pass is ADR 0004's safety code and deserves its own reviewable diff, and all five are private-in-crate-root, so relocating them requires `pub(crate)` widenings — a change in reach that should be the only thing a diff does. Phase C1 is not complete: `stage`/`scratch`/`signed`/`development`/`plans`/`inventory` and `backupctl/src/command/` remain, C03 and C04 have not started, and the §33.5.1 `JobLock` `O_NOFOLLOW`/mode gap is still untouched and still owed as a separate documented behavior fix with its own failing test. Documentation: `project.md` §26 row 8, the C02-2 bullets and its gates paragraph, README's progress paragraph. No commit, no push; the tree is `M README.md`, `M crates/backup-local/src/lib.rs`, `M project.md`, `M session-log.md`, and three new files `fixture.rs`, `keys.rs`, `store.rs`.

[2026-10-03 16:14] [AGENT] **C02-3 — `store.rs` is complete: the maintenance pass and the path helpers moved.** `Recovery` (the pass's report struct), `LocalStore::recover`, `clear_working_dir` and the three helpers `encrypted`/`artifact_dir`/`plan_path` left `lib.rs` for `store.rs`, taking the `recover` doc-comment's ADR 0004 reasoning and `clear_working_dir`'s "qualification is by name and by type" rule with them. `lib.rs` 1792 → 1688, `store.rs` 148 → 261; `pub use store::Recovery;` keeps the crate-root path `backup_local::Recovery` intact for `backupctl/src/report.rs:11`. Three imports in `lib.rs` became unused after the move (`Inventory`, reached only by the pass, and `PLAN_SUFFIX`, reached only by `plan_path`), and their removal is verified by clippy rather than by eye; `STAGING_DIR` and `SCRATCH_DIR` stay imported because `lib.rs:399` and `:654` still build those paths for the stage and scratch code that has not moved.

**The widenings are the only non-move lines in the diff, stated literally.** `encrypted`, `artifact_dir` and `plan_path` went from private-in-crate-root to `pub(crate)`, because they are still called from `lib.rs`'s remaining publication/read `impl` blocks and Rust does not let a *parent* module see a child's private item (the reverse direction, used by C02-1 and C02-2, needed nothing). `clear_working_dir` stayed private — its only caller moved with it. Nothing else changed visibility, and no call site, signature, body line or doc sentence was edited. Measured rather than asserted: the moved method block compared to its `HEAD` counterpart is 90 lines vs 90 with **6 differing lines, exactly the three `fn X` → `pub(crate) fn X` pairs**, and `Recovery` is 12 lines vs 12, byte-identical.

**Why the widenings are minimal, with two negative controls.** (1) `pub use store::Recovery;` disabled → `error[E0432]: unresolved import 'backup_local::Recovery'` at `crates/backupctl/src/report.rs:11:31`, i.e. the re-export is load-bearing rather than decorative; restored. (2) `pub(crate)` dropped from `artifact_dir` *alone* → exactly **6** × `error[E0624]: method 'artifact_dir' is private`, matching the six surviving call sites, so the widening grants nothing more than that reach; restored. Both items were reverted in the same step that ran them and `grep -rn "CONTROL" crates/` returns nothing — the lesson from the phase S control that was left in the tree.

**Two mistakes this increment made, recorded because they changed what evidence I trust.** (1) Restoring `artifact_dir` from a string replace used `t.replace("\n    fn artifact_dir(", …)` for one helper and a pattern missing the leading newline for another, producing `}    pub(crate) fn artifact_dir(&self, id: Uuid) -> PathBuf {` — broken formatting that **compiled, passed `cargo clippy --workspace --all-targets -- -D warnings` and passed all 179 tests**; only `cargo fmt --all --check` caught it. So fmt is a real gate here, not a style ritual, and the first matrix pass (`/tmp/c02b-*`, built against that tree) was discarded rather than reported; all six matrices were re-run on the corrected tree. (2) The behavior battery's value mask was wrong twice: masking digits before the run-directory path turned `/tmp/c02b` into `/tmp/c##b` and faked 8 residual differing streams, and `\b[0-9a-f]{8,}\b` left a UUID's 4-character middle segments in place and faked 20. With paths masked first and `\b[0-9a-f]{2,8}(?:-[0-9a-f]{2,8})+\b` before the long-hex rule, the corrected numbers are the ones below — and the rule now recorded for later steps is that a mask difference is a harness bug until proven otherwise, never a finding.

**Verification on the final tree:** `cargo fmt --all --check` exit 0, `git diff --check` exit 0, `cargo clippy --workspace --all-targets -- -D warnings` exit 0, `cargo test --workspace` **179 passed, 0 failed** — `backup-local --lib` still 16 (9 store + 7 keys), the 4 two-process `store_concurrency` scenes ok including `a_killed_backups_leftovers_are_recovered_by_the_next_backup_of_its_scope`, which is the test that actually exercises the moved pass, and `recovery` 2 ok. All six PostgreSQL 16/17/18 matrices exit 0 on the corrected tree (`/tmp/c02d-summary.txt`: `m1=0 m2=0 m3=0 m4a=0 m4b=0 m4a_key_drill=0`, each log naming 16, 17 and 18) — ADR 0004's scenes are the safety net for this move, since the shared/exclusive claim ordering inside `recover` (drop the claim *after* the removals) is exactly what `m4a_key_drill` and the concurrency tests would break. The §33.2 battery reran from `/tmp/c02d-measure.sh`: invocation-label lists `diff` empty at **67 = 67**, **0 exit-code differences**, and of 134 streams **28 differ unmasked, 0 after masking** — byte-identical to the pre-refactor C01 baseline, to post-C02-1/C02-2, and to the intermediate build, so the preservation claim is cumulative across the whole of C02 rather than per-step.

**State after this increment:** `backup-local`'s §33.6 store grouping is done (`keys.rs` 392, `store.rs` 261, `layout.rs` 38, `fixture.rs` 26, `lib.rs` 1688 with the publication/read/plan `impl ArtifactStore` still in place). Phase C1 is **not** complete: `stage`/`scratch`/`signed`/`development`/`plans`/`inventory`, the `backupctl/src/command/` decomposition, C03 and C04 all remain, and the §33.5.1 `JobLock::acquire` `O_NOFOLLOW`/mode gap is still untouched and still owed as its own documented behavior fix with its own failing test. Documentation updated: `project.md` §26 row 8, the C02-3 bullet and its gates paragraph including both mistakes, README's progress paragraph. No commit, no push — the tree is `M README.md`, `M crates/backup-local/src/lib.rs`, `M project.md`, `M session-log.md`, `?? crates/backup-local/src/{fixture,keys,store}.rs`.

[2026-10-03 16:48] [AGENT] **C02-4 — `backup-local/src/stage.rs`, the sink half of §33.6's staging boundary.** `Target`, `Writer` and `StageSink` with their `Write` and `PayloadSink` impls moved, plus `LocalStore::stage_sink` — the one place that decides whether a staged byte lands in a plain file or is authenticated by age into a stream — which opens its own `impl LocalStore` block in the new file. `lib.rs` 1688 → 1564, `stage.rs` 148. Relocation measured: **118 non-blank lines byte-identical** to the text removed from `lib.rs`, the only additions the `impl LocalStore {` line and its `}` that the method needs to stand alone; three blocks deleted (144–173, 194–247, 341–382) and the arithmetic closes exactly (1688 − 126 + 2 = 1564, the two added lines being `mod stage;` and `use stage::Target;`). Two `lib.rs` imports became unused (`StagedBytes`, `io::self`) and their removal is verified by clippy.

**The widening set is two markers and each is one call-site pair — smaller than C02-3's, and for a reason worth stating.** `pub(crate) enum Target` and `pub(crate) fn stage_sink`, both needed only because `payload_sink`/`globals_sink` (`lib.rs:573`, `:577`) are trait shims that stayed behind. Controls: dropping the enum marker gives `error[E0603]: enum 'Target' is private` at `lib.rs:46`; dropping the method marker gives **2** `error[E0624]: method 'stage_sink' is private` at `:574`/`:578`; disabling the whole construct (`mod stage;` *and* its `use`) gives 4 errors — 2 × `E0599: no method named 'stage_sink'` plus 2 × `E0433: cannot find type 'Target'` — at those same sites, and the tree compiles clean when restored. Nothing in `StageSink`/`Writer`/`Target::name` was widened because nothing outside the moved set touches them, and — unlike C02-3 — **no `LocalStage` field needed widening either**: `stage_sink` reads `payload`/`globals` and `finish` writes `sealed_*` as a *descendant* of the crate root, the same one-directional rule C02-2 relied on for `crate::ensure_real_dir`. All controls were reverted in the step that ran them, and `cargo fmt --all --check` ran after each restore (the C02-3 lesson); the final restore was a byte-for-byte `cp` from a pre-probe backup, confirmed by `cmp`, so the battery/matrix evidence below is from the tree that is now in the working copy.

**Why `LocalStage`, `LocalJob` and `begin` did not come, stated as the constraint they expose.** §33.6 assigns them to `stage.rs` too, but `begin` is a method of `impl ArtifactStore for LocalStore` (`lib.rs:492–1111`), and a trait has exactly one impl block per type per crate: trait methods cannot be spread across modules, and its block-mates — `publish`, `measure`, `plaintext_staged_payload`, `publish_signed` — belong to the `development.rs`/`signed.rs` boundaries that have not moved. Probing the struct move (relocate `LocalStage` alone, capture, restore) produced **29** `error[E0616]: field 'X' of struct 'LocalStage' is private` in `lib.rs`: `dir` 10, `payload` 6, `id` 5, `globals` 4, `sealed_payload` 2, `sealed_globals` 2. Taking the struct now would therefore widen all seven fields, including ADR 0004's `_claim` — the field whose privacy is exactly what keeps the activity guard alive past the directory removal. That is a safety-relevant change in reach and belongs with the publishers' increment, not inside a sink move. Recorded as a new §33.6 adjustment bullet, because it reshapes every remaining `backup-local` boundary: they are *body* extractions (delegate + inherent method), which is an added indirection and must be documented as such rather than passed off as a move.

**Verification performed:** `cargo fmt --all --check` exit 0, `git diff --check` exit 0, `cargo clippy --workspace --all-targets -- -D warnings` exit 0, `cargo test --workspace` **179 passed, 0 failed** — `backup-local --lib` still 16, and 7 of its 9 store tests drive the moved sink (`stage_bytes` or a direct `payload_sink`/`globals_sink` call), including `an_unfinished_stream_is_not_publishable` and `an_encrypted_stage_publishes_ciphertext_and_no_plaintext`, which are the two tests that fail if the seal flags or the age/plain choice move wrongly; `store_concurrency` 4 ok and `recovery` 2 ok. All six PostgreSQL 16/17/18 matrices exit 0 (`/tmp/c02e-summary.txt`: `m1` `m2` `m3` `m4a` `m4b` `m4a_key_drill`), each log naming 16, 17 and 18, the drill re-covering rotation, cross-generation refusal, key loss, offline recovery, total-loss inertness, an operator-supplied identity and the signing pair's loss and recovery per major. The §33.2 battery reran from `/tmp/c02e`: **67 invocation labels identical** to five baselines at once (pre-refactor C01, C02, C02b, C02c, post-C02-3), **0 exit-code differences**, 134 streams with **28 differing unmasked and 0 after masking** — so behavior is still identical to the tree before any C02 move. Cumulative `git diff --numstat HEAD` for `lib.rs` is **21 added / 754 removed**.

**Two more harness bugs, both found before the numbers were recorded, both producing fake findings rather than real ones.** The run-directory mask must be applied **longest-first**: with `/tmp/c02` before `/tmp/c02d`, the shorter string shadowed the longer one and 8 streams came back "different" with `<RUNDIR>d/…` in the text. And the label list lives at `<base>/out/*.exit`, not `<base>/*.exit`; pointing the comparison at the harness root first raised a `UnicodeDecodeError` on the copied `backupctl` binary, which is the tell that a comparison is reading the wrong thing, not a finding about the tree. `project.md` now carries both rules in the C02-4 gates paragraph.

**Not done:** phase C1 is not complete — `scratch`/`signed`/`development`/`plans`/`inventory` for `backup-local`, `backupctl/src/command/`, C03 and C04 remain, and the §33.5.1 `JobLock::acquire` `O_NOFOLLOW`/mode gap is still owed as its own documented behavior fix with its own failing test. No commit, no push: `M README.md`, `M crates/backup-local/src/lib.rs`, `M project.md`, `M session-log.md`, and four new files `fixture.rs`, `keys.rs`, `stage.rs`, `store.rs`.
