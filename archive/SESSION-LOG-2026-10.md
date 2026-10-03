## 2026-10-01 — M4b: artifact v1 is written, signed, and refused before anything is restored

**What landed.** `backup-domain` gained the v1 record types (`ArtifactManifest`,
`PublicHeader`, `RequestedSelection`), `source_fingerprint`, UTC formatting for the two
timestamps, the `whole-database` and fingerprint domain constants, and the optional
`[signing]` block. `backup-local` became the v1 writer and the signature-first reader:
`payload.age`, optional `globals.age`, `manifest.age`, a 3373-byte `signature.hybrid`,
a bounded `public.json`, then `complete`, with discovery, verification and listing all
possible from `public.json` alone. `backup-application` and `backupctl` put that shape in
front of an operator: `key generate|publish|status` now act on `[signing]` as well as
`[encryption]`, `backup verify` takes `--level signature`, `backup inspect` reads a v1
record out of the authenticated ciphertext, and `restore plan` authenticates before it
binds a source.

**Three things only writing the code forced into the open.**
1. `archive_toc_sha256` is recorded when the artifact is written, not when it is verified.
   `docs/artifact-contract.md` §3.2 says a manifest at `verification_level: none` carries no
   table of contents, but a signed manifest cannot gain a fact later without changing what
   its signature covers, so archive level compares against the write-time digest and refuses
   an artifact that recorded none. §3.2 gets the reconciliation when #33 freezes the format.
2. A v1 dump that names no profile still records a scope, under a reserved synthetic name.
   The manifest is the only record of what was selected, and a missing one is
   indistinguishable from a filtered dump that claimed otherwise.
3. `restore run` on a signed artifact reports `recorded_in_artifact: false`. Replaying the
   archive is exactly what `restore-tested` means, but writing it into the artifact needs
   the signing key a DR host does not hold — and re-signing an artifact this host produced
   nothing about would attribute it to a host that did.

**A rule enforced in the wrong type, found by the test that first wrote a v1 artifact.**
`whole-database` was refused by `Profile::validate`, and `ArtifactManifest::validate`
re-validates the snapshot it signs, so `BackupService::create` on a signed store refused its
own manifest: `profile name whole-database is reserved for a dump that names no profile`.
The rule is about *configuration*, so it now sits in `Config::validate`'s profile loop and a
snapshot the writer builds stays a valid `Profile`. `crates/backup-local/tests/signed_write_path.rs`
is what caught it; the four tests it added are the composed v1 path — the six files and the
signed facts a reader cannot forge, all three verification levels passing with signature
level touching no tool and decrypting nothing into `scratch`, one bit flipped in the
ed25519 half refusing every level *and* the plan while `CREATE DATABASE` stays un-called,
and an artifact whose recorded source fingerprint no longer matches the configuration
refused at planning. The control run is in the same test on purpose: the empty list is only
evidence after the same stub demonstrably created a database for an intact artifact.

**Shared fixtures.** `write_path.rs`'s stub adapter, capture and key/config helpers moved to
`tests/common/mod.rs`, which the two composed-path tests share; the capture now also records
every `CREATE DATABASE` it is asked for, and `signed_store.rs` uses the same `Keys`,
`artifact_dir` and `failure` helpers rather than a third copy.

**Verification performed:** `cargo fmt --all --check` clean, `cargo clippy --workspace
--all-targets -- -D warnings` clean, `cargo test --workspace` at **128 passing tests** (up
from the 87 logged at the signing-crypto increment; 24 of them in `backup-local`'s two
signed integration files). No Docker matrix was run for this increment, so nothing here
claims M4b acceptance: the PG 16/17/18 sign/verify/DR runs, the signing half of the key
drill and the stock-`rage` golden CLI assertion are task #32, and artifact v1 is not frozen
until they are green.

## 2026-10-01 — M4b: matrices run, artifact v1 frozen

**What landed.** `tests/m4b_docker_smoke.sh` (new) writes and signs a v1 artifact on
PostgreSQL 16, 17 and 18, verifies it at `signature`/`checksum`/`archive`, DR-restores it into
a cluster whose store is configured with a verifying key and **no** signing key, and then
feeds that store twelve tampered variants. `tests/m4a_key_drill.sh` gained steps 9–11 for the
signing pair. The documentation freeze followed the run: ADR 0002 is **accepted** with its
validation items marked as executed, `docs/backup-format/manifest-v1.md` is **frozen** with
its field list reconciled against `ArtifactManifest`/`PublicHeader`, `docs/security/key-lifecycle.md`
covers both pairs and the writer/reader custody split, and the threat model, ARCHITECTURE,
README, `project.md` and the M4a guide stopped claiming the M4a state.

**Four bugs the run found in the tests, not in the code.**
1. `grep -q "a [signing] block requires an [encryption] block"` is a **BRE bracket class**, so
   the character set matched single characters and the assertion passed vacuously; now
   `grep -qF`.
2. Three assertions grepped a refusal sentence the CLI does not print ("not written by the
   holder of the configured signing key"). The real context string is
   `origin signature of artifact {id} does not verify`, which is what they now match.
3. The `payload.age` stanza parser kept a trailing newline in each stanza token, so
   `endswith(b"-grease")` missed the randomly named grease stanza and a *fresh, valid*
   artifact failed the single-recipient assertion. The parser now reads only the header block
   up to the `\n\n` terminator and splits on whitespace.
4. In the drill, `cat <<SIGNING` without `>> "$out"` wrote a configuration fragment to
   standard output, and a bare `echo` leaked a blank line into the store's plaintext sweep
   target; both now append to the config file.

**Two limits the freeze records instead of smoothing over.** A `public.json` downgraded to
`signature_suite: "ed25519"` still **passes** `--level signature`, because the signed tuple
covers the backup id and the two ciphertext digests and nothing else; the lie is caught one
step later against the authenticated manifest, which `--level checksum`, `--level archive` and
`restore plan` all reach. Case 6.11 asserts the pass as well as the refusal so neither half
can be quietly reinterpreted. And a missing `complete` marker is refused before any crypto
work but reports the bare `No such file or directory (os error 2)` from the stat rather than a
contract sentence naming the marker — case 6.7 pins the position of the refusal, and the doc
now says an absent component speaks in errno.

**What the run also corrected in the written contract.** `signature.hybrid` is not "sized from
the recorded suite": `HybridSignature` is a fixed 3373-byte array, so a foreign suite claim
cannot make the reader accept a shorter signature — stricter than the ADR said, and now
written as implemented. `archive_toc_sha256` is recorded at write time from the staged archive
(the field's doc comment claimed otherwise), which is what lets archive level compare against
something the signer saw while `verification_level` stays pinned to `none`. The M4a plan to
check a golden v1 fixture into the repository was **not** executed and the reason is recorded
in the contract: every v1 byte in existence came from this tree, so the freeze is pinned by
deterministic crypto vectors, `backup-local`'s signed integration tests, and the matrix's
stanza/`rage` assertions, and a fixture should arrive with the first cross-host artifact.
Untested and stated as such: a store holding both a v1 and an unsigned M4a artifact, and
replay of an older valid signed artifact.

**Verification performed:** `cargo fmt --all --check` clean, `cargo clippy --workspace
--all-targets -- -D warnings` clean, `cargo test --workspace` **128 passed, 0 failed**.
`tests/m4b_docker_smoke.sh` and `tests/m4a_key_drill.sh` green on PostgreSQL 16, 17 and 18;
`tests/m1_docker_smoke.sh`, `m2_`, `m3_` and `m4a_` re-run green on all three with the M4a
paths still verifying. The documented `key status` secret check was re-run against a freshly
generated four-file set (`grep -f` on both seeds over the JSON: no match).

## 2026-10-01 — M4b operator guide, written against a live store rather than against the code

`docs/development/m4b-signing.md` is the operator path for a signed store: which configuration
writes which shape, the four-file `key generate`, the six files of one artifact with their real
sizes and modes, what each verification level is permitted to touch, the DR host's two refusals
and its restore, and the refusal text every tampering variant produces. Rather than transcribing
the matrix's assertions, the guide was written from a **run**: a PostgreSQL 16 container, a writer
configuration, a verify-only configuration, and one artifact at a time.

**What the run showed that reading the code had not settled.**

- **A mixed signed/unsigned store is now observed, not assumed.** The earlier entry's
  "untested and stated as such" is closed for the read path. Through a signed configuration an
  unsigned M4a artifact is listed honestly (`unsigned development artifact; no record without
  keys`) and then refuses *every* read — `backup verify`, `backup inspect` — with the bare
  `No such file or directory (os error 2)`, because the signed reader looks for the `public.json`
  that shape never wrote. Through an `[encryption]`-only configuration the same store refuses at
  discovery, with a sentence naming the mismatch (`is a signed v1 artifact; the signed reader
  does, not the manifest.json reader`), and that refusal also stops `backup list`. The asymmetry
  is documented as a limit with both messages quoted; it is still outside the matrix.
- **A verify-only host does not need its recipient file.** Moving it away left
  `backup verify --level signature` and the restore path working, while the identity and the
  verifying key are both loaded before the store is touched and their absence is a refusal.
  `key status` is the one command that reads the recipient, so the guide says which file is
  needed by which command instead of repeating "both age files always".
- **`key generate` on a verify-only host is a half-write.** The refusal that correctly stops a
  signing secret from appearing on a DR box happens *after* the age pair has been created, so the
  directory is left holding an identity and a recipient. Documented as such, because an operator
  who assumed a clean failure would be reasoning about the wrong directory.
- **The `--confirm-synthetic` guard, the DR-role refusal against a cluster that already has those
  roles, and `export_globals = false` producing a five-file artifact** were each reproduced, and
  the guide quotes the real output rather than a paraphrase.
- **The two shipped limits reproduce live**, which is the strongest form either one can take in a
  guide: editing `signature_suite` to `ed25519` in `public.json` prints
  `origin: ed25519 signature by signer …` at signature level with exit 0 and is refused one step
  later at checksum level, and deleting `complete` reports an errno and nothing about the marker.

**Files:** new guide; README, [M4a guide](docs/development/m4a-encryption.md),
[artifact v1](docs/backup-format/manifest-v1.md),
[key lifecycle](docs/security/key-lifecycle.md) and [threat model](docs/security/threat-model.md)
link to it, and the threat model's mixed-store paragraph became the observed behavior above.
`project.md` records the guide in the M4b status bullet.

**Verification performed:** every command block in the guide came from a real run on 2026-10-01
against PostgreSQL 16 (`pg_dump`/`pg_dumpall`/`pg_restore`/`psql` in a container behind wrappers):
four-file `key generate`, `key status` on writer and DR shapes, three writes (signed, signed
without globals, unsigned into the same store), all three levels, `backup list` and `inspect` in
both directions of the mixed store, a portable plan and run from the verify-only host, a
wrong-database plan refused on `source_fingerprint` before its target existed, and ten tamper
variants restored to pristine between cases. Both seeds were grepped out of every captured output
(`grep -f` over `key status --output json`: no match), no `PGDMP` magic and no fixture role name
reached the store, and `staging/` and `scratch/` were empty after every refusal. No Rust source
changed, so `cargo fmt`/`clippy`/`test` results from the freeze stand.

