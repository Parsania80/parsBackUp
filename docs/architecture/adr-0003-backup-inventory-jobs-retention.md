# ADR 0003: Backup inventory, job state, and safe deletion (M5 scoping)

Status: **accepted** (2026-10-01). This is a scoping document: it states what M5 has to make
true, what the code can do today, and the seven decisions the increment turns on. The operator
accepted all seven **exactly as recommended** on 2026-10-01, so every "Recommendation" line below
is a decision rather than a proposal, and "Choices (accepted)" is their short form. M5a's first
increment has since landed: `crates/backup-inventory`, whose schema v1 sits behind a
`user_version` migration, whose open rules assert the pragmas below, and whose single-instance
lock is the `flock` file finding 9 asked for. Two lines that the running code had to change are
marked **Implementation revision** at the line itself rather than corrected quietly here — one in
choice 5, one in gate 2 — and both are consequences of the freeze, not of a mistake in this
document. The dependency question was deliberately left to a spike; the spike has now run
(`/tmp/m5-catalog`, nine rounds, 2026-10-01) and its measured answers are under
"Implementation dependencies" at the end of this document. One of them changed a recommendation:
the inventory is **not** in WAL mode, and the reason is a read-only directory, not concurrency.

## Context

M4b froze the artifact. Everything about a stored backup is now provable **from the artifact
itself**: existence (`complete`), integrity (digests), origin (`signature.hybrid`), and content
(`manifest.age`). What the format deliberately does not carry is any lifecycle fact: nothing
records who wrote it, whether it was ever verified after publication, whether it is protected,
or whether a newer one exists.

That is the whole of M5, and the code says so. As of this writing:

- There is no metadata database. `crates/backup-local/Cargo.toml` depends on `anyhow`,
  `backup-application`, `backup-crypto`, `backup-domain`, `serde_json`, `sha2` and `uuid` —
  nothing SQL — and no crate in the workspace mentions SQLite, jobs, retention, or pruning.
- `backup list` **is** a directory scan. `ArtifactStore::list_signed` walks `artifacts/`,
  parses each `public.json`, and returns `StoreListing { signed: Vec<PublicHeader>, unsigned:
  Vec<Uuid> }` (`crates/backup-application/src/lib.rs:167`). Discovery needs no key, which is
  what the freeze designed for and what a rebuild would scan.
- There is no deletion. The CLI surface is `config check`, `key generate|publish|status`,
  `profile validate|list`, `backup create|list|inspect|verify`, `restore plan|run`
  (`crates/backupctl/src/cli.rs:34-56`). `backup protect`, `backup delete` and `backup prune`
  from roadmap §12 do not exist, so nothing in the current build can destroy a backup.
- There is no job state. A `backup create` that is killed leaves a staging directory, and the
  store's startup purge removes it. Nothing records that a run happened, still happens, or died
  halfway, and nothing stops two runs of the same profile starting at once.
- One configuration names exactly one `source`, one `[storage] root`, and a list of
  `[[profile]]` blocks (`crates/backup-domain/src/config.rs:9-29`). The catalog's shape depends
  on whether that stays true — see Choice 3.
- Plans already persist. `restore plan` writes a JSON plan under `<root>/plans/` with a
  15-minute expiry, and `restore run` refuses anything whose target does not match
  (`ArtifactStore::save_plan`/`load_plan`). That is the repository's existing, tested answer to
  "preview now, execute later, bound to a digest", and M5 should reuse its shape rather than
  invent a second confirmation mechanism.

Three threat-model rows are open *because* of these gaps, and each names M5 as its gate:
**T03** (storage editor replays an older valid signed artifact — "untested, not claimed"),
**T12** (catalog loss makes backups undiscoverable — "`public.json` already makes discovery
possible with no key material, which is what an M5 rebuild would scan"), and **T15** (backup
overload; per-source limit, bounded workers) — all three in
[the threat model](../security/threat-model.md). The
[M4b signed store guide](../development/m4b-signing.md) adds a fourth: a mixed store —
a v1 artifact beside an unsigned `m4a-development-age` one — names the unsigned entry as
"having no record without keys" and then refuses to read it with a bare `No such file or
directory (os error 2)`, and the threat model records "choosing which configuration opens which
artifact stays M5 catalog work".

## A naming problem to settle first

The word **catalog** is already taken. `crates/backup-postgres/src/catalog.rs` is the
*PostgreSQL* catalog — the `pg_catalog` queries the profile resolver runs — and the word appears
on 74 lines across seven non-test Rust files, in that sense every time. M5's roadmap §16 metadata
database is a different thing entirely, and a file named `catalog.rs` in two crates that both get
read at backup time is how a future reader confuses "what objects exist in the source database"
with "what backups exist on this host". **Decision (accepted): the new subsystem is the
inventory**, in code and in prose; `catalog` keeps meaning PostgreSQL's; and `Catalog` stays a
port name only if roadmap §5's port list is followed literally. The file is named
`adr-0003-backup-inventory-jobs-retention.md` for the same reason, even though the roadmap section
it scopes is still titled "Catalog, jobs, concurrency, retention".

## What M5 has to make true

| Promise (roadmap) | Today | Gap M5 closes |
| --- | --- | --- |
| "no incomplete backup marked complete" (M5 DoD) | True by accident: `complete` is the last file written and the reader checks it first | Needs a persisted job row whose `complete` state cannot be reached without a published artifact, so the claim is about state, not just about files |
| "retention preview matches executed deletion set" (M5 DoD) | No deletion at all | Preview, plan digest, confirmation, ordered delete, audit row |
| "bounded workers and persisted states" (M5 DoD) | One synchronous process, no state | State machine, single-instance lock, interrupted-run reconciliation |
| "catalog can be rebuilt from artifacts" (§27) | Nothing to rebuild | Reconcile scan + migration + a stated source of truth (Choice 3) |
| T12: catalog loss must not make valid artifacts undiscoverable | Not tested | Rebuild-from-scan as a command, tested by deleting the database file |
| T15: no second dump for the same source/profile while one runs | Not enforced | Lock + overlap refusal |
| T03: rollback to an older valid artifact | Undetectable; the signature has no sequence, nonce or timestamp | Choice 6 — and the honest answer may be "not closed by M5" |
| Mixed-store reading (M4b limit 1 of 3) | Bare OS stat error | Per-artifact shape recorded, so the refusal can name what it found |

Two facts constrain every design below, and both are properties of the frozen format rather
than of this milestone's choices:

1. **`backup_id` is UUIDv4** (`crates/backup-application/src/lib.rs:536`; the workspace `uuid`
   dependency has feature `v4` only, `Cargo.toml:23`). It is random, so it orders nothing. Any
   "newest" comparison must come from `completed_at_utc`/`started_at_utc` in the manifest, or
   from a sequence this milestone assigns — never from the id.
2. **A v1 manifest always records `verification_level: none`**, and no reader raises it, because
   raising it would mean re-signing an artifact on a host that has no signing key. So
   roadmap §10's "count only verified/complete artifacts as valid" **cannot** be read off the
   artifact. Whether an artifact was verified is a fact about a *host at a time*, which is
   exactly the kind of fact only the inventory can hold. Getting this wrong would make retention
   decide from a field that is permanently `none`.

## Choice 1 — one increment, or two

| Option | Pros | Cons |
| --- | --- | --- |
| **A. M5 whole** (inventory + jobs + reconcile + retention + delete) in one increment | One schema design, one test matrix run, no half-built lifecycle | Lands the first irreversible destroy operation in the same change as the subsystem that decides what is safe to destroy — the one place in this project where a bug costs backups |
| **B. Split: M5a inventory + jobs + reconciliation, M5b retention + delete/prune** | Deletion gets reviewed against a catalog that already survived crash and rebuild tests; M5a alone cannot destroy anything; matches how M4a/M4b separated "can read" from "can prove" | Two matrices, and the lifecycle stays unfinished between them |
| **C. Inventory only, retention deferred to M6** | Smallest | M5's acceptance bar is exactly the deletion invariant; M6 is packaging. Pushing it leaves §27 unmet while claiming the milestone |

**Recommendation: B.** The split is at the cliff edge: everything before deletion is
observational and reversible, deletion is not.

## Choice 2 — where inventory state lives, and what it is allowed to contain

Placement options:

| Option | Pros | Cons |
| --- | --- | --- |
| **A. `<storage-root>/inventory.db`** | Moves with the store; a copy of the root is a copy of the index; no new configuration key; `/var/lib/backupctl` stays one directory as §22 expects | Anyone who can rewrite artifacts can rewrite the index, so nothing in it can serve as evidence against a storage editor (this is what kills using it for T03) |
| **B. Separate configured path, like the key files** | Survives a store copy; a reader host can point at its own | Two more paths per deployment, and an operator who backs up the store and not the db loses exactly the protection flags that were supposed to guard it |
| **C. `A` plus a required export** (`inventory export` to a signed, off-host file) | Cheap DR answer, honest about the copy problem | More surface; the export's own trust story is a new problem |

**Recommendation: A**, with the residual stated rather than papered over: the inventory shares
the artifact store's failure domain, so it is an index and an audit trail, **not** an
independent witness. That single sentence is what Choice 6 then has to respect.

The second half of this choice is the one that matters most, and it is not about placement.
M4b sealed the manifest into `manifest.age` for a reason recorded in the store's own comment:
"the manifest names a database, a host's shape, and an operator's profile, none of which belongs
in a directory that may be copied off-site for disaster recovery". A plaintext SQLite file that
stores database names, host, port, profile names and resolved scopes would reopen **T13** in the
one artifact of this design that operators will casually copy, attach to tickets, and back up.

| Option | Consequence |
| --- | --- |
| **A. Key-free columns only**: `backup_id`, `source_fingerprint` (already a digest "so binding does not disclose where the source is"), `signer_id`, `recipient_id`, both suites, ciphertext sizes, digests, shape tag, job state, timestamps, verify events, protection flag | `backup list` renders from this; anything descriptive (`backup inspect`) must decrypt `manifest.age`, which is what v1's reader order already does and what the M4b guide documents as the cost of sealing the manifest |
| **B. Store the database name, host, profile name and resolved scope for convenience** | Restores `backup list` without keys to its M4a richness, and hands whoever reads `/var/lib/backupctl` the entire estate map. Contradicts a decision the freeze just made |

**Recommendation: A.** If a real deployment turns out to need names in list output, the fix is
a decrypting `backup list --describe`, not a wider schema — and a schema narrowed later is
compatible, while a schema that leaked is not.

## Choice 3 — which side is authoritative, and what reconciliation reports

The files are immutable and the inventory is derived, so the direction cannot be
"the database is the truth". Options:

| Option | Rule | Cost |
| --- | --- | --- |
| **A. Files authoritative for existence, inventory authoritative for lifecycle**; reconcile at an explicit command and on open | An artifact present with `complete` but unknown to the db is **unregistered** — reported, never auto-adopted, never deleted by retention. A row whose files are gone is **missing** — never counted as a valid backup, so it cannot satisfy `keep_last` | Requires a reconcile pass and a real decision about auto-adoption |
| **B. Inventory authoritative, files only checked at verify time** | Fast | A store copied without its db looks empty, which is T12's failure mode and a lie about the data |
| **C. Files authoritative for everything, inventory caches list output** | Simplest | Retention and protection then have nowhere trustworthy to live |

**Recommendation: A**, with the row-shape decision it forces: `backup list` should report the
shape of every entry (`v1-signed`, `age-unsigned`, `plaintext-dev`) because that is precisely
the information the mixed-store refusal is missing today. Adoption stays explicit: reconciling
into the inventory is an action with an audit row, not a side effect of reading a directory.

The per-host consequence deserves its own line. A verify run on a DR host proves something about
an artifact that the writer host's inventory cannot know. Under A, each host's inventory holds
its own events, which is honest — and means "restore-tested" is a property of a *host +
configuration*, so the invariant "never delete the only known valid backup" is bounded by what
this inventory has seen. That limit should be written as a limit, not resolved by pretending the
database is global.

## Choice 4 — what a job is

Roadmap §6 sketches `planned → running → staged → verified → complete`, or
`failed/cancelled/quarantined`, and §18 sketches a bounded worker pool. There is no daemon yet:
M6 packages a systemd timer and M7 adds the API. So the question is what the state machine is
*for* in a synchronous CLI.

| Option | Pros | Cons |
| --- | --- | --- |
| **A. Persisted state, no worker pool**: every `backup create` and `restore run` opens a job row, transitions it, and a process that dies mid-run leaves a row in `running` that the next open marks `interrupted`; one row per source/profile is the single-instance lock | Delivers §18's crash semantics, T15's overlap refusal, and audit, all of which are testable with a synchronous CLI. No queue, no thread pool, nothing unused | Two concurrent processes need a lock primitive decided and tested (the db's write transaction, or a separate lock file) |
| **B. Full worker pool and `job cancel` now** | Matches §18 literally, and `job list/inspect/cancel` all mean something | Builds a scheduler nothing schedules with yet, in the same milestone as the first destructive command. Cancelling a running `pg_dump` pipeline mid-stream is its own tested contract |
| **C. Audit log only, no state machine** | Minimal | §18's "never infer success from process exit alone" and M5's DoD both want persisted states |

**Recommendation: A**, with the read-only commands (`list`, `inspect`, `verify`) recorded as
audit events rather than jobs — a job should mean "this operation held resources and could be
interrupted", which `backup verify` does not. `job list`/`job inspect` land in M5a; `job cancel`
belongs with B, i.e. with M6/M7, and saying so now stops it being rediscovered as a gap mid-
milestone. The lock mechanism was left as a spike question; the spike ran it (round 10) and the
answer is in finding 9 below — **a separate `flock` file, not the database's write transaction**,
because the two do not cover the same interval.

## Choice 5 — retention, and the shape of a deletion

The invariants are already written (§10) and are not up for re-litigation: never delete the only
known valid backup for a source, an active or restoring backup, a protected backup, or one an
in-progress job needs. What needs deciding is the mechanism.

| Sub-question | Options | Recommendation |
| --- | --- | --- |
| Which "last N" | per `source_fingerprint`; per (`source_fingerprint`, profile); global per store | Per (`source_fingerprint`, profile): a selective dump and a whole-database dump protect different accidents, and §10's "only known valid backup for a source" is a per-scope claim in practice. **Implementation revision (2026-10-03), two parts.** (1) The scope key is not the profile *name* but `backup_domain::profile_fingerprint` — the same 16-hex, domain-prefixed digest pattern `source_fingerprint` already uses — because choice 2 forbids a profile name in a key-free file, and `backup create` with no profile digests the reserved `whole-database` snapshot name like any other. (2) That digest is computable only by a host that has decrypted `manifest.age`, which the v1 signature does not cover (it authenticates `backup_id` and two ciphertext digests and nothing else). So the column is nullable, `NULL` means "this host has never read the manifest", and **a row whose profile is unknown is invisible to retention in both directions**: it cannot satisfy a `keep_last` count, and it must never be a pruning candidate. A store whose inventory was rebuilt without keys has no retention information until a run with keys fills the rows back in. |
| Where `protected` lives | inventory column; a sidecar file in the artifact directory; an operator-maintained file outside the store | **Inventory column**, and state the consequence plainly: a sidecar file inside `artifacts/<id>/` is a change to the frozen v1 shape (six files, or five without globals) and would need its own ADR and version decision, not a quiet edit; writing protection into the manifest would require the signing key and a DR host has none. So catalog loss costs protection flags, which is Choice 2's residual and an operator-checklist line in the M6 guide |
| How deletion is confirmed | immediate with a `--yes` flag; a persisted plan with a digest and expiry, like restore plans | **The existing plan pattern**: `backup prune` computes a candidate set, persists it under `plans/` with an expiry and a digest over the exact id set, prints it, and `backup prune run --confirm-digest …` deletes nothing else. One confirmation mechanism in the CLI, already tested against expiry and target mismatch |
| Delete order | remove files then the marker; remove the marker first | **Marker first.** The reader's first check is `complete`, so a crash partway through a deletion leaves a directory the store already refuses to open rather than a half-deleted artifact that lists fine. It reuses the freeze's own guarantee instead of adding a new one |
| What happens to the row | delete it | **Keep it** as `deleted` with the audit event and the digests it had. T12's rebuild scan cannot resurrect a deleted artifact, and a lifecycle history that vanishes on lifecycle action defeats the audit trail M5 is introducing |

`backup delete <id>` is the same mechanism with a one-element candidate set, and it should share
the plan path rather than having its own flag, so there is exactly one way to destroy a backup.

## Choice 6 — replay protection (T03): how far a local ledger honestly goes

The signature cannot help: it is deterministic, covers only `backup_id` plus two ciphertext
digests, and carries no timestamp, nonce or sequence number, so an older artifact from the same
generation verifies perfectly forever. Anything M5 can do is a record of what the host has seen.

| Option | What it proves | What it does not | Honest label |
| --- | --- | --- | --- |
| **A. Out of scope for M5** — T03 stays "untested, not claimed" until an off-host or immutable inventory exists | Nothing | Everything | Safest framing; leaves §29's "corruption/replay/suite-downgrade tests" gate partly unmet |
| **B. High-water-mark ledger in the inventory**: per (`source_fingerprint`, `signer_id`) keep the newest `completed_at_utc` and the id; `restore plan` of anything older reports a rollback warning and requires an explicit confirmation; `backup list` flags any id whose recorded issuance is older than a previously seen one | Detects an editor who replaces the *artifacts* while leaving the db alone, and detects "restore the old thing by accident" — which is the more common operator failure | Detects nothing against someone who deletes the whole root, nor against a *newer* forgery, nor across hosts. And the db is in the store's failure domain (Choice 2), so it is an index that also notices, not a witness | Worth doing for the accident case; must be written as "an alarm bell, not a control" |
| **C. Append-only, signed inventory** published to a separate path or host, chained by digest | Genuine rollback detection: to hide a newer artifact you must break the chain or hold the signing key | Cannot help a deployment that has only one host, which is every deployment this release ships to | Real T03 mitigation, and a subsystem of its own: chaining, gap detection, key custody, its own drill. This is a milestone, not a feature |

**Recommendation: B in M5b, and C stays out of scope with its own future ADR.** B is cheap
because every field it needs is already in `public.json` or the manifest and the inventory is
new anyway. It should ship with the sentence "an attacker who can remove an artifact can remove
this ledger's row too, so this catches accidents and lazy edits, not targeted attacks" —
otherwise B reads like T03 is closed and it is not. C is the answer to T03 and pretending
otherwise is how a threat register gets quietly satisfied by the wrong control.

## Validation gates before M5 closes

Nothing here is claimed; these are the runs a close needs, in the house style (real PostgreSQL
majors 16/17/18, refusals asserted as exact sentences, secrets grepped for rather than assumed).

1. `tests/m5a_docker_smoke.sh` — inventory written by a real backup; `backup list` from the db
   and from a rebuild agree; kill the process mid-dump and the next command reports `interrupted`
   with no artifact and an empty `scratch/`; start a second `backup create` for the same profile
   while one runs and it is refused; delete `inventory.db` and T12's rebuild finds every artifact
   through `public.json` with no key material.
2. Schema migration: open a db from an older `user_version` and upgrade it transactionally; open
   one from a newer version and refuse; open a db that belongs to a different `source_fingerprint`
   and refuse rather than merge two estates into one index. **Implementation revision (2026-10-03):
   the binding is the `source_fingerprint`, not the `[storage] root` path.** Choice 2A's whole
   argument for keeping the file inside the root is that a copy of the root is a copy of the index,
   and the DR read depends on that; a database which also refused an unfamiliar absolute path would
   refuse exactly the copy it exists to serve. What is refused, and now tested, is an inventory
   whose recorded estate is another database's.
3. Mixed store: the three shapes recorded per id, and the current bare
   `No such file or directory (os error 2)` replaced by a sentence naming the shape — this
   closes an M4b limit and should be asserted, not just demoed.
4. `tests/m5b_retention_drill.sh` — preview and executed set identical byte for byte; the four
   invariants each fire against a real candidate set; `keep_last` counts only what this inventory
   has seen and refuses to delete the last one; a marker-first delete interrupted at a random
   file leaves a directory every read path refuses; the deleted row still reports its history.
5. No secret, database name, host, or resolved scope in the inventory file: the same `grep -f`
   treatment the key drills give command output, run against the raw `.db` bytes, and re-run
   after the rebuild path so a rebuild cannot smuggle decrypted fields into columns.
6. `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`, plus M1–M4b matrices re-run unchanged — the freeze means those
   artifacts must still verify after this milestone touches the store.
7. Pragmas asserted rather than assumed: after an init, `PRAGMA journal_mode` reads back `delete`;
   the effective `busy_timeout` is read back on every open path (rusqlite's own default is 5000 ms,
   so a forgotten call is invisible in the code and obvious in this test); and a store copied as
   `inventory.db` **alone** into a directory the process cannot write to opens read-only and lists
   the same ids as the source — the scene the spike found WAL failing, run as a test rather than
   as a demo.
8. Corruption is reported, not tolerated: zero 512 bytes into the middle of a populated inventory
   and assert that the check command names the damaged page/rowid, while the same database still
   answers `SELECT count(*)` — the test that keeps finding 7 from becoming a surprise in
   production.
9. The overlap refusal is asserted **mid-dump**, with the first process holding no SQL
   transaction open at all. That is the window where the database lock does not exist and only the
   `flock` does (finding 9); a test that starts the second `backup create` after the first has
   written its rows proves nothing about the real clash.

## Implementation dependencies (the spike decided these, 2026-10-01)

The spike ran on 2026-10-01 in `/tmp/m5-catalog`: a probe binary (`spike/src/main.rs`, subcommands
`version init seed hold readnow writechild killmid check user_version sizes opencreate emptyfile
rovariants syncrun reopen lockhold locktry killhold`) driven by `spike.sh` and rounds 2 through 10,
each round a real run whose output is what this section reports. Rounds 3, 7 and the first cut of 6
were thrown away and re-run: round 3's probes created the very sidecar files they were meant to
find missing, round 7's `corrupt` subcommand did not corrupt anything (it is now `reopen`, and the
corruption result comes from round 8's byte-zeroing), and round 6 built its databases inside a
`$(…)` capture that discarded their output. Nothing from the spike touched this repository's crate
graph; the three dependency variants were separate throwaway crates (`spike`, `minimal`, `system`).

### The driver: `rusqlite`, bundled

| Measured | Result |
| --- | --- |
| `rusqlite` version resolved | 0.40.2, `libsqlite3-sys` 0.38.2 |
| SQLite it links | **3.53.2**, from the bundled amalgamation (`bundled_sqlite=3.53.2` from `SELECT sqlite_version()`) |
| System `libsqlite3` variant | **does not build here**: `rust-lld: error: unable to find library -lsqlite3` (needs `libsqlite3-dev`, absent) |
| Ubuntu's runtime library | `libsqlite3-0:amd64 3.46.1-9ubuntu0.3` — seven minor versions older than the bundled one, and the version the binary would then be pinned to |
| Cold build, either variant | ~53 s, dominated by compiling the SQLite amalgamation |
| Binary size, no rusqlite | 444,952 B |
| Binary size, rusqlite default features + bundled | 2,710,408 B (≈ +2.2 MB: that is SQLite's own code, not the driver's) |
| Same source with `default-features = false` | 2,698,728 B — **3 crates fewer** (`hashlink`, `foldhash`, `hashbrown`, i.e. the `cache` feature) and **5,424 B smaller** |

So the pin is `rusqlite = { version = "0.40.2", default-features = false, features = ["bundled"] }`.
Bundled because the alternative does not link on this machine and, once it did, would hand the
inventory's behaviour to whatever SQLite the host distro ships — the same class of decision M4b
settled by pinning `ed25519-dalek`. `default-features = false` because the statement cache buys
nothing for a CLI that opens the database, runs a handful of statements, and exits.

Consequence for packaging (§22, not measured): a bundled C dependency makes a C toolchain a
Build-Depends for the `.deb` and puts vendored C source in the audit surface. `cargo audit` does
not cover that C code, so a SQLite CVE would have to be caught by bumping the pin, not by the
advisory run.

### Journal mode: the measurement reversed the recommendation

WAL is the mode that is usually recommended for "an app with a database", and the reason to
prefer it here was supposed to be concurrent readers — `backup list` while a job writes. That
reason did not survive the run, and a counter-reason appeared that nobody had asked about.

Read-only access to a store on a DR host or a read-only mount (`rovariants` tries plain
`SQLITE_OPEN_READ_ONLY`, then URI `immutable=1&mode=ro`, then read-write with
`PRAGMA query_only=ON`):

| Scene | Journal | Directory | Sidecars present | Plain read-only | `immutable=1` | `query_only` |
| --- | --- | --- | --- | --- | --- | --- |
| N | WAL | read-only | none (clean close) | **fails: `attempt to write a readonly database`** | opens, **stale rows** | fails |
| M | WAL | read-only | yes (after SIGKILL) | opens, current | stale rows | opens |
| O | DELETE | read-only | none | **opens, current** | same | opens |
| I | WAL | writable | none, db file `r--r--r--` | opens | stale | opens |
| J | WAL | writable | none | opens | stale | opens |

I is the row that locates the constraint: it is the **directory**, not the file, that must be
writable, because WAL needs to create the `-shm` index before it can read. A backup of an
`inventory.db` that omits `-wal`/`-shm` — which is what "copy the `.db`" naturally does — produces
scene N: a database the DR host cannot open at all. A rollback-journal database in exactly the
same position opens fine.

And WAL's upside did not appear. With one process holding an open write transaction:

| Journal | Reader during the held txn | Second writer, `busy_timeout=200ms` | Second writer, default |
| --- | --- | --- | --- |
| WAL | `complete_rows=41 after 1ms`, held row invisible | refused after **201 ms**: `database is locked` | took the lock after **2433 ms** |
| DELETE | `complete_rows=41 after 1ms`, held row invisible | refused after **202 ms**: `database is locked` | took the lock after **2435 ms** |

Identical, because a rollback journal blocks readers only during the short commit window, and a
synchronous CLI that opens, writes a few rows in one transaction, and exits never has a reader
standing in it. The only place WAL was measurably cheaper is a write shape this inventory will not
use: 5,000 single-statement autocommit inserts cost **128–130 ms under WAL** and **394–406 ms under
DELETE** (fsync per commit). Batched into one transaction — which is what a job does — the two are
the same within noise: 42–56 ms for 5,000 rows, either journal mode, `synchronous` NORMAL or FULL.

**Decision: `PRAGMA journal_mode=DELETE` and `PRAGMA synchronous=FULL`** for `inventory.db`. The
inventory then behaves like the rest of the store — one file, copyable, readable from read-only
media — and durability does not depend on sidecar files surviving a copy. The cost is that a
future long-running process holding a write transaction could make a CLI invocation answer
`database is locked`; choice 4A's persisted job states already define that as the expected answer,
and finding 2 below keeps it from being *SQLite's* lock.

### What the probes forced into the design

1. **`rusqlite` defaults `busy_timeout` to 5000 ms.** A probe that asked for no timeout waited
   5005 ms before refusing; the same run reporting `PRAGMA busy_timeout` as the effective value is
   what caught it. Every inventory open must set the timeout explicitly (200 ms is enough for a
   CLI), or an operator typing `backup list` waits five seconds on a lock instead of getting an
   answer.
2. **The lock is not SQLite's.** In scene "writer, default timeout" the second process *took the
   write lock* as soon as the first released it and then wrote. Busy timeouts serialize
   invocations; they do not prevent a second `backupctl` from doing work after the first one's
   transaction ends. Choice 4A's single-instance lock must therefore be an OS-level lock on a
   separate file, held for the whole job, not a SQLite transaction boundary.
3. **"The inventory exists" is not a file-exists check.** `Connection::open` on a missing path
   *creates* it (read-write opens succeed and leave a file; read-only opens refuse and create
   nothing). A stray 0-byte `inventory.db` is a legal SQLite database: `integrity_check=ok`,
   `journal=delete`, `user_version=0`, and `SELECT count(*) FROM artifact` fails with `no such
   table: artifact`. So the existence test is `user_version >= 1` **and** the tables present, and
   `PRAGMA user_version` is the migration lever — 0 means "not ours yet", and the schema version
   is what an upgrade compares against.
4. **`PRAGMA query_only` is not a read-only open.** It succeeded against a nonexistent path and
   created the file. Read paths (`list`, `inspect`, `verify`, audit reads) must open with
   `SQLITE_OPEN_READ_ONLY`; `query_only` is a guard for a write-capable connection, not a
   substitute for the flag.
5. **`immutable=1` is prohibited against a live store.** It served 41 rows while the database
   actually held 43, silently, with no error and no `-wal` read. It is legitimate only for a
   verified single-file copy that has no sidecars — which the journal decision above makes the
   normal shape of a backup, so the use case for it mostly disappears.
6. **A crashed delete/upgrade recovers on its own, and the audit trail survives.** SIGKILL
   mid-transaction left `integrity=ok`, the two committed rows present, the uncommitted one gone,
   and sidecar files behind (`inventory.db-wal`, `inventory.db-shm` under WAL; `.db-journal` under
   DELETE). Nothing here argues for application-side journaling: SQLite's own rollback already
   gives choice 4A the rule "a job row in `running` state with no matching commit is stale".
7. **A corrupt inventory still answers queries.** Zeroing 512 bytes in the middle of a 201-row
   database made `integrity_check` report `Rowid 83 out of order` and `Fragmentation of 303 bytes
   reported as 0 on page 16`, while `SELECT count(*) FROM artifact` returned `201` under both
   journal modes, read-only or not. A truncated file is louder: `database disk image is malformed`
   on every open path. Consequence for M5a: `inventory check` (or whichever command the operator
   guide names) must run `PRAGMA integrity_check` itself — "the command produced output" is not
   evidence the database is readable, and silent partial reads are the failure mode to design
   against.
8. **Scale is not a concern.** 5,001 artifacts are 2.06 MB of database; `seed` wrote 5,000 rows in
   43–46 ms; `VACUUM` took 7–9 ms; `page_size` is the 4096 default and `freelist` was 0 after
   vacuum. A year of nightly backups fits comfortably, so no partitioning, archiving, or size
   limit needs designing now, and `PRAGMA optimize` measures 0 ms.
9. **The job lock is a separate `flock`, because the database locks the wrong interval.** Round 10
   ran both candidates against the same clash. A `flock` on a lock file taken by one process: a
   second invocation is refused in **0 ms** (`locktry: refused in 0ms - another process holds
   it`), succeeds the moment the holder exits, and after a **`SIGKILL` of the holder the lock is
   free again with a 0-byte file left behind** — the kernel closes the descriptor, so there is no
   stale-pid cleanup path to write or to get wrong. Meanwhile, in scene 5, a process holding an
   open *write transaction* left the **lock file free**: SQLite's lock exists only while rows are
   being written, and a `backup create` spends almost all of its runtime streaming a dump with no
   transaction open at all. Choice 4A's overlap refusal is about the whole run, so it needs the
   file lock; SQLite's own locking is still what keeps two row-writes from interleaving, and the
   two are complementary rather than alternatives.
10. **Which means the read-only store still works.** The lock file lives in the storage root and
    only write paths take it, so a DR host with the store on read-only media can run `list`,
    `inspect` and `verify` without creating anything — the journal decision above and this one are
    the same decision seen from two sides: **writes need a writable root, reads need nothing but
    `inventory.db`**.

### Placement

`backup-local` is the crypto boundary and already owns the storage root's layout; putting a SQL
engine inside it would make one crate own both key material and lifecycle state. This is the one
question in this section the spike could not measure, so it is settled by the argument and not by
a run: the inventory is a new crate, **`crates/backup-inventory`**, beside the others, its port in
`backup-application` as §5's port list implies, and it gets no dependency on `backup-crypto`. The
key-free schema rule (choice 2) is then enforceable as a crate boundary rather than a code-review
note: nothing in `backup-inventory` can even receive a plaintext path.

`rusqlite` fits because this workspace is synchronous (the only concurrency today is
`thread::spawn` in `backup-postgres/src/tools.rs`); `sqlx` would add an async runtime to every
crate that touches the inventory. That half was reasoned, not measured — the measured half is the
bundled-versus-system table above.

## Out of scope for M5

Scheduling and systemd units (M6); `job cancel` and any worker pool beyond what Choice 4A
needs; API actors, idempotency keys and rate limits (M7); re-encryption or re-signing under a
new generation (crypto agility stays a documented procedure); authenticating `public.json`'s
suite fields (that is the signed tuple in [artifact v1](../backup-format/manifest-v1.md), i.e.
artifact **v2**, and must not be folded in here); checked-in golden v1 fixtures until a
cross-host artifact exists ([ADR 0002](adr-0002-artifact-v1-and-signing.md)'s rule); and
multi-source configurations — one config, one source, one inventory remains true in M5, and
making it not-true is a design change that should be noticed when it happens.

## Choices (accepted)

The operator accepted all seven on 2026-10-01, each exactly as recommended, so these are
decisions, and an implementation that contradicts one of them is a new ADR rather than a detail.

| # | Decision | Accepted |
| --- | --- | --- |
| 1 | One increment, or M5a observability + M5b deletion | Split at the deletion edge (**B**) |
| 2 | Inventory placement, and whether its schema stays key-free | `<root>/inventory.db`, key-free columns only (**A/A**) |
| 3 | Which side is authoritative; unregistered vs missing | Files for existence, db for lifecycle, explicit adoption (**A**) |
| 4 | Job model in a synchronous CLI | Persisted states + lock, no worker pool, reads are audit events (**A**) |
| 5 | Retention mechanics: per-scope `keep_last`, protection column, plan-digest confirmation, marker-first delete, rows kept | All five as written in the table under Choice 5 |
| 6 | T03 | Local high-water-mark ledger, labeled as an accident alarm and not as a control (**B**); the chained signed inventory stays out of scope (**C** deferred, its own ADR) |
| — | Naming: "inventory" for this subsystem, "catalog" reserved for PostgreSQL's | Adopted |

Four consequences of the accepted set are worth restating, because each is a limit an operator can
be bitten by rather than a design detail:

- **Losing `inventory.db` costs the protection flags.** Choice 5 puts them in the database and
  choice 2 keeps that database beside the store. The mitigation is an operator-checklist line in
  the M6 guide, not code.
- **The rollback ledger catches accidents, not attackers** (choice 6B): someone who removes a
  newer artifact can remove its rows too. T03 is *not* closed by M5 and the threat model row keeps
  saying so.
- **A database that answers is not a database that is healthy.** The spike zeroed 512 bytes inside
  a 201-row inventory and `SELECT count(*)` still returned 201 while `integrity_check` reported
  corruption. Whatever command surface M5a ships, at least one path has to run the check itself;
  "the command exited 0" is not evidence about the inventory's state.
- **An inventory rebuilt without the identity key is retention-blind** (choice 5's implementation
  revision, part 2): `profile_fingerprint` and `completed_at_utc` live inside `manifest.age`, which
  no signature covers, so a keyless rebuild records them as unknown and retention cannot group or
  order such a row. M5b's `backup prune` therefore has to refuse on a store whose rows are unknown
  rather than fall back to a per-source count — the fall-back would silently treat a selective dump
  and a whole-database dump as the same accident, which is the distinction choice 5 exists to keep.

Because choice 1 split the increment, gates 1–3, 5 and 7–9 under "Validation gates" run at M5a,
which can therefore close without ever deleting a byte; gate 4 runs at M5b and gate 6 closes both.
The spike that used to sit at the end of this document has run (2026-10-01) and its findings are the
"Implementation dependencies" section; the two open items it left — power-loss behaviour, which a
`SIGKILL` cannot simulate, and the `.deb` packaging build once a C toolchain is in the
Build-Depends — are M6 concerns, not M5 ones.
