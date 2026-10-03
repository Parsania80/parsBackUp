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
