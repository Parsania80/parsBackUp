# V01 security review — 2026-11-16

Initial checkpoint scope: code/contract review of the existing fixture implementation, current primary
advisories and measured native tests. This is not an independent cryptographic audit,
proof of constant-time compiled code, production approval or a complete advisory scan.

## Transcript and custody boundaries

The frozen mlkem768x25519-v0 recipient combines ML-KEM-768 then X25519 shared secrets
with versioned HKDF salt/domain and HPKE info. Exact encoding lengths, invalid component
rejection, single hybrid recipient policy and accepted grease stanza remain enforced.
The signing tuple binds backup UUID and payload/manifest ciphertext SHA256 digests;
both Ed25519 strict and ML-DSA-65 verification must pass. Public header fields are not
all signed: authenticated manifest/header cross-checks and consumption-time size/digest
binding remain essential. Globals authentication comes from the encrypted manifest.
No transcript, suite, accepted-list or seed derivation changes in V01.

Reviewed owners: backup-crypto protocol/kem/recipient/signing/stream, local custody and
signed/plaintext readers, application restore ordering, native/process execution and
CLI safe reports. Existing deterministic vectors, wrong-key/changed-leg/truncation/
foreign-recipient tests and native key/tamper controls are the regression obligations;
actual rerun results belong to the roadmap. Versioned writers hold four roles;
recovery readers only identity/verifier; public verification has no identity. The
verifier needs independent custody. Decrypted SQL can execute source-chosen code;
signatures do not make that SQL safe. Plaintext crash leftovers, same-UID/root trust,
in-memory copies/compiler side channels and T03 store/history replacement remain risks.

## Dependency findings

The following dependency notes describe checkpoint 5a1834b. The later remediation
acceptance below supersedes its SQLite and incomplete-scan status; other findings
and compatibility/security limits remain.

Cargo.lock has 221 package records (including seven workspace crates). Relevant locks:
age 0.12.1/age-core 0.12.0, hpke 0.12.0, ml-kem 0.2.3, ml-dsa 0.1.1,
ed25519-dalek 2.2.0, curve25519-dalek 4.1.3, x25519-dalek 2.0.1,
rusqlite 0.40.2/libsqlite3-sys 0.38.2, zeroize 1.9.0. Review preserves these bytes;
an upgrade must be a separate verified compatibility/security change.

**Release blocker:** [RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html)
covers bundled libsqlite3-sys 0.38.2. A crafted database/WAL pair can expose process
memory; patched versions start at 0.39.0. Snapshot sidecar/WAL refusals and protected
roots reduce exposure but do not establish that every inventory open is unaffected.
Do not add an ignore entry or call this fixed. A reviewed bundled SQLite update and
migration/snapshot/recovery regression evidence are required before release.

Locked ml-dsa 0.1.1 is beyond the patched threshold for the reported
[decomposition timing issue](https://rustsec.org/advisories/RUSTSEC-2025-0144.html)
and the [duplicate-hint verification issue](https://github.com/advisories/GHSA-5x2r-hc65-25f9).
That version comparison does not certify the custom composition or all code generation.

**Uncompleted scan:** cargo-audit 0.22.2 installation could not fetch the crates.io
index. The initial attempt held the shared Cargo cache; it was interrupted, then an
isolated CARGO_HOME attempt also timed out and the installer aborted. No scanner ran,
no advisory database revision/full-lock verdict exists and no product dependency
changed. Targeted primary advisory review found the SQLite blocker; it is not an
exhaustive substitute. Repeat a full current scan with tool/database provenance before
V01 acceptance. A network failure must remain visible, not become a clean result.

## Compatibility disposition

The signed partition-family scene finds a frozen manifest mismatch: native resolution
expands children while artifact v1 accepts only literally requested table names. Keep
the refusal and report the capability gap until a reviewed contract-compatible writer
change or new artifact format is agreed; do not falsify the requested selection.
Versioned writable offline reads/retention and production restore-plan bytes/context
also remain gates. Database settings/ACL, arbitrary extension/locale/security-label
providers and tablespace/global-parameter restoration are not certified by content
rows. V01 acceptance remains open; V02/V03 and production enablement are separate.


## SQLite advisory remediation contract — 2026-11-16

Authorized after V01 checkpoint 5a1834b. Update the workspace pin from rusqlite 0.40.2
(to patched 0.41.1) and resolve libsqlite3-sys 0.39.1, bundled SQLite 3.54.1. Retain
bundled/default-features=false and the existing Rust toolchain. Confirm downloaded
crates against the official registry checksums and inspect the exact lockfile delta;
no unrelated dependency update or SQLCipher/system-SQLite substitution. Source schema
v8/migration SQL, inventory states, artifact/restore/deletion bytes, crypto and
production gate stay unchanged. The [upstream advisory](https://rustsec.org/advisories/RUSTSEC-2026-0459.html)
identifies libsqlite3-sys >=0.39.0 as patched; rustc compatibility is satisfied by
pinned 1.97.1 and the crates' 1.89/1.88 minimums.

Acceptance: actual linked SQLite version/source ID and bundled-source patch evidence,
locked/offline workspace tests/strict Clippy/format, migration/read-only/program/WAL
refusal and state/transaction regressions, all-major inventory-recovery/snapshot/
retention/content native scenes, and both-target actual package lifecycle/migration/
recovery. Add only necessary API adjustments and a linked-runtime regression, not a
schema migration or broad cleanup. Preserve earlier artifact/evidence under ignored
checkpoint-v01 paths. Attempt the full current advisory scan separately now that the
local proxy reaches official registry endpoints; retain actual tool/DB/lock provenance
and unresolved findings. Closing this specific advisory does not accept all V01 gates.


### Verification-harness adjustment recorded before editing

The first patched-engine M5a run passed PG16 but stopped on PG17 while waiting for
its live rebuild-journal delay (25-second observation deadline). Source inputs
remained unchanged; preserve that failed log rather than treating it as acceptance.
A PG17-only diagnostic copy reached the exact expected journal sync in 18.43 seconds
and completed that rebuild; it does not establish the original timeout's cause.
Stop the diagnostic after that measurement, without claiming a complete suite pass.
Allow this helper the existing 150-second command budget and detect early child
exit with trace/output diagnostics. Keep the exact journal-path/size/privacy and
post-rebuild integrity assertions, the syscall injection and all six crash scenes.
This necessary test-only correction adds tests/m5a_docker_smoke.sh to the increment;
rerun fast and the full native/package acceptance on the final inputs.


## SQLite advisory remediation acceptance — 2026-11-16

**RUSTSEC-2026-0459 is cleared in the current lock/build.** rusqlite is pinned to
0.41.1 with the same bundled/default-features=false policy; libsqlite3-sys is 0.39.1.
Only these two of 221 package records changed (versions/checksums only); the other
219 records and both dependency lists are identical. Official registry index and
downloaded crate SHA256 values agree with Cargo.lock. No API adaptation, schema
migration, system-SQLite/SQLCipher substitution or crypto change was required.

The actual query engine reports **SQLite 3.54.1**, source ID
`2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76`.
The bundled sqlite3.c SHA3-256 is
`e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81`, matching the
[official SQLite release](https://sqlite.org/releaselog/3_54_1.html). The new linked-runtime
regression checks the patched >=3.54.0 floor and fails as expected in an isolated
old-rusqlite 0.40.2 control reporting SQLite 3.53.2. This is version/source and upstream
patch evidence, not a claim to reproduce every malformed-file exploit. Separately,
a real v8 inventory created by the preserved old CLI is readable by the new CLI
without a byte change; new-CLI rebuild remains readable by the old CLI. The private
cross-engine fixture was removed. Schema v8/migration SQL and saved artifact,
restore/deletion/transcript contracts remain unchanged.

Final locked/offline fast gate passes **315 workspace tests**, strict Clippy, format,
semantic lint of all three workflows, two actual CLI report envelopes, references
and standalone/embedded/script syntax. Five native suites pass **PG16/17/18**:
M5a recovery/integrity (v1/v2 upgrades, populated corruption, newer-schema refusal,
read-only copy and six rebuild crash boundaries per major); H02 true read-only
snapshots/external scratch/syscall audit; M5b destructive/race/crash retention;
V01 content/privileges; H02 cancellation/child reap/job state/cleanup/source-loss
recovery. The signed partition-family refusal is still explicitly reproduced on
all three majors. These 15 script-major combinations do not certify the excluded
content/provider cases or missing versioned production commands.

The package gate passes the Ubuntu-built release, repeat-byte archive, manager-free
lifecycle and the identical package on Ubuntu24.04/systemd255/glibc2.39/PG16 and
Debian13/systemd257/glibc2.41/PG17. Both actual managers pass lifecycle/custody/sandbox/
timer overlap/v7 migration/graceful cancellation/three escaped-session hard stops/
live upgrade and reader-only lost-source restore. Package-tool diversion/staging
warnings remain visible. Private cgroup containers share the host kernel; repeated
archive bytes are not independent Rust-build reproducibility. Package SHA256:
`ae34b0b8095eabe63ca8baa58d81e98c1b27e0cdd436150e661ca67c79c31b02`. Previous V01 and H05 packages/evidence remain under
ignored checkpoint-v01/checkpoint-h05 paths. All seven final wrapper invocations
record **173 unchanged source inputs during execution**. Only this review and
README/project/log handoff edits follow the tests; no runtime or harness edit.

The initial PG17 journal-observation timeout is retained in
`/tmp/parsbackup-sqlite-m5a_docker_smoke-initial-timeout.log` and ignored
`target/ci-logs/sqlite-initial-native-m5a_docker_smoke*`. The diagnostic is not an
accepted suite pass. The final full rerun passes with the recorded helper-budget
adjustment and every original journal/crash/integrity assertion retained; the
original timeout's precise cause is not established.

### Full advisory scan and remaining blockers

cargo-audit **0.22.2** ran on the committed and updated locks against the same official
RustSec DB revision `02e2517f457a359fc6d3440ea4560c8ea188fee8` (2026-11-15),
without ignores, target filters or severity filters. Exact binary SHA256, arguments,
lock digests, exits and Git provenance are in ignored
`target/ci-logs/sqlite-audit-provenance.json`; accepted reports are
`sqlite-audit-{before,after}-project-cache.json` in that directory. Both exit **1**:

| Finding | Committed V01 lock | Updated SQLite lock | Disposition |
|---|---|---|---|
| [RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html), libsqlite3-sys | 0.38.2 affected | 0.39.1, finding absent | Requested SQLite remediation verified. |
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html), crypto-bigint | 0.5.5 affected | Same finding/version | Open timing issue; patched threshold >=0.7.6. Requires compatible dependency/feature and reachability review. |
| [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html), ctutils | 0.4.2 affected | Same finding/version | Open constant-time issue; patched threshold >=0.4.4. |
| [RUSTSEC-2026-0374](https://rustsec.org/advisories/RUSTSEC-2026-0374.html), basic-toml | 0.1.10 unmaintained warning | Same warning/version | Retained maintenance finding. |

crypto-bigint is pulled through elliptic-curve/p256 by age/hpke; ctutils through
ml-dsa/hybrid-array/module-lattice. Dependency presence does not establish exact
runtime exploitability, and the selected custom KEM is not proof that every affected
operation is unreachable. No exemption or unrelated cryptographic upgrade is made.
Review frozen vectors/transcripts and compatible feature/version choices before
changing that set. The full advisory scan is now executed, **not clean**.

The first scan used the isolated installer cache and reported missing index entries
for yanked lookups. Those initial JSON/stderr files remain preserved; accepted repeat
scans use the existing project cache and produce empty stderr, with the same advisory
findings. Yanked checks used cached index entries, not a claim of a fresh live-index
review for every historical crate. The two updated crates were also checked against
fresh official registry metadata. Tool installation/proxy use changed no global
network configuration or project feature/security policy.

SQLite remediation is complete and remains uncommitted for review after V01 commit
5a1834b. V01 acceptance is still blocked by the two cryptographic advisory findings,
signed-family/versioned-command/production-plan compatibility and remaining content/
security obligations. V02/V03/T03 remain open; production remains disabled. No push,
hosted workflow dispatch, host deployment or controlled operating-flow change.
