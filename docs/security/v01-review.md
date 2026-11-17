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

The following dependency notes describe checkpoint 5a1834b. Later SQLite and
cryptography acceptance sections below record the current dependency/scan verdict.
Compatibility and broader security-assurance limits remain.

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


## Cryptography advisory remediation contract — 2026-11-16

Authorized after SQLite commit d90a3b4; operator handles its push through GitHub Desktop.
Resolve RUSTSEC-2026-0385 by ctutils0.4.8 (MSRV1.87, official SHA256
261af4dc7a06ea8a527a8717d8cbba3417530d6ea14e1edb3de6b67806be474f), including
upstream's later constant-time hardening. Resolve RUSTSEC-2026-0387 by removing the
unused P-256/elliptic-curve/crypto-bigint path, not by an ignore or a claim that it
cannot be reached. age0.12.1 enables that path unconditionally; no compatible feature
switch or patched0.12 release is available. Upstream age0.11.5/core0.11.0 were released
with the same 2026-07-14 armor security fixes as the0.12 line and retain the age-v1
streaming/custom-recipient API. Pin that pair together, keep HPKE at exact0.12.0 with
defaults disabled and alloc only; replace the age-core convenience wrappers by direct
calls to the SAME HPKE single-shot implementation with Base/ChaCha20Poly1305/
HkdfSha256, unchanged HPKE_INFO and empty AAD. Keep existing error semantics and
plaintext zeroization; do not alter the custom KEM, combiner/seed expansion, suites,
key encodings/IDs, ML-KEM/X25519/signature pins or zeroization features.

| Candidate | Benefit | Cost/disposition |
|---|---|---|
| Patched upstream age0.11 pair + custom-only HPKE | Removes the unneeded vulnerable dependency; no fork or new primitive | Selected; strict old/new artifact compatibility and full audit required. Monitor eventual compatible0.12 security updates before future repinning. |
| Vendor/patch age0.12 dependencies/features | Retains current version/API | Requires maintaining a fork and extra license/update policy; reject for this bounded change. |
| Force bigint0.7 into the old P-256 stack | Would be a patched version | Incompatible semver/API constraint; not a valid lockfile substitution. |
| Ignore/exempt affected dependency | Avoids implementation changes | Does not satisfy remediation; rejected without a reachability/compiled-code assurance claim. |

Acceptance: preserve old CLI/lock/package/evidence before edits; generate a synthetic
multi-chunk age0.12.1 ciphertext with the baseline implementation, pin it as a regression
fixture with an explicitly public test seed, and require new reader byte-exact recovery.
Use independently compiled before/after helpers for both-direction encryption and
exact deterministic public/signature bytes; existing golden signing vector and
malformed/foreign/mixed/duplicate/tampered/truncated/wrong-key/limits/zeroize bounds
must still pass. Execute a real old/new signed CLI artifact verify/restore compatibility
scene, plus final locked/offline fast, all-major M4a key lifecycle/M4b signed artifacts/
H02 read-only snapshot and both-target package lifecycle/recovery gates. Verify official
checksums/MSRVs/licenses, exact justified lock delta and full same-DB before/after audit
without ignores/target/severity filters; affected bigint/P-256 must be absent and
ctutils patched, with unrelated warnings still reported. Freeze source during these
runs. Do not rerun unrelated SQLite crash matrices without an observed regression.

Keep schema8/migration SQL, manifest/header/restore/deletion formats, protocol constants,
reader allowlists, operating flows, storage/custody/production guard and Rust1.97.1
unchanged. No artifact rewrite or suite rename. No new flow document or API/UI work.
A failed cross-version vector or new unresolved security finding blocks acceptance;
never regenerate expected vectors merely to make a changed transcript pass. Production
remains disabled; V01's other compatibility/content/security gates stay open.


### Pre-gate compatibility and dependency disposition

Both independently compiled before/after helpers pass: new reads the old 70,000-byte
multi-chunk ciphertext and exact recipient/verifier/signature bytes; old reads the new
stream and produces identical deterministic bytes. A real PG16 signed v1 artifact from
the preserved old CLI verifies/restores with the new CLI, and the reverse does too,
with independent restored row assertions, immutable artifact hashes and unchanged
key-file hashes. The synthetic scene/container/keys were removed. The baseline
fixture is crates/backup-crypto/tests/fixtures/age-0.12.1-hybrid.age (71,838 bytes),
SHA256 eb086b3454c01f916436a953b5c5619411462328126c4bcc9913a79901023743;
its deliberately public seed is [7;32], never a production key. Old helper/CLI/lock
and provenance remain under /tmp/parsbackup-crypto-*. Existing golden signature
vector also passes unchanged; no expected old bytes were regenerated after the edit.

The 221->215-record lock delta removes 22 old identities and adds 16 identities for
the age/core/parser/localization branch and ctutils patch. All 16 added identities
have fresh official index/non-yanked/archive SHA256 checks, declared MSRVs up to1.87
and MIT/Apache-2.0 licenses; actual pinned Rust1.97.1 compilation passes. Six shared
record dependency lists change: backup-crypto/base64 and i18n-config/thiserror/type-map
version qualification, HPKE's removed built-in KEM edges and generic-array's removed
optional zeroize edge. generic-array's optional feature supplies a trait impl, not
Drop; unchanged HPKE nonce/key/shared-secret Drop implementations still explicitly
zeroize their bytes (slice method resolution without that feature). Signing key
ZeroizeOnDrop compile bounds, ML-DSA/ML-KEM/X25519/direct zeroization features and
private/plaintext cleanup code remain unchanged. No broad dependency updates.

Same-DB full cargo-audit before/after already reports two->zero vulnerabilities,
exit1->0, empty stderr/no ignores/filters. The before report has basic-toml0.1.10
unmaintained warning RUSTSEC-2026-0374; the after report also adds proc-macro-error2
unmaintained warning RUSTSEC-2026-0173 (identified in final handoff audit). Reports/provenance and registry checks are in ignored
 target/ci-logs/crypto-{audit-*,registry-provenance.json}.

The localization branch introduces proc-macro-error2 2.0.1's visible future-Rust
warning E0365 (private proc_macro re-export). Current pinned1.97.1 builds pass;
/tmp/parsbackup-crypto-future-incompat.log records the compiler diagnostic. This is
an explicit future toolchain-upgrade constraint, not a suppressed warning or a
current advisory exemption. Do not add a fork or widen this fix to replace the
localization stack. Revisit it with the eventual compatible upstream age update;
[the upstream maintenance release](https://github.com/str4d/rage/releases/tag/v0.11.4)
is the source for selecting security-fixed age0.11.5. Final fast/native/package gates
follow on frozen inputs. The full audit and these probes alone do not certify
constant-time machine code or accept V01/production.


## Cryptography advisory remediation acceptance — 2026-11-16

**Both requested cryptography findings are resolved in the current lock/build.**
ctutils is 0.4.8; p256, elliptic-curve and crypto-bigint are absent, including from the
full lockfile. age is 0.11.5, age-core 0.11.0, HPKE remains 0.12.0 with alloc only.
The selected upstream security maintenance release supplies age-v1 streaming/custom
recipients without the unused P-256 path. The local calls exactly preserve the
former age-core helper's Base/ChaCha20Poly1305/HkdfSha256/HPKE_INFO/empty-AAD arguments
and error behavior. The custom KEM/combiner/seed expansion, signing implementation,
key IDs/encodings, fixed protocol constants and reader stanza policy are unchanged.
No crate fork, source override or advisory ignore was added.

The accepted lock delta is221->215 package records: 22 old identities removed, 16
new identities added, six shared records with the previously documented edge or
version-qualification changes. All16 added identities match freshly checked official
registry metadata/archive hashes and are non-yanked, with MIT/Apache-2.0 licenses.
Declared MSRVs fit the unchanged1.97.1 toolchain; all code also compiles under it.
Other cryptographic implementations/versions and their selected features are retained;
explicit HPKE Drop zeroization and signing ZeroizeOnDrop bounds remain compiled.
rusqlite 0.41.1/libsqlite3-sys 0.39.1 and schema8/migrations are unchanged from d90a3b4.

The pre-edit 70,000-byte two-chunk ciphertext, exact recipient/verifier/signature
vectors and unchanged existing golden-signature digest pass. The separately compiled
old and new helpers read each other's streams and produce bit-identical deterministic
public/signature encodings. The old CLI's real signed PG16 artifact verifies/restores
under the new CLI, and a new signed artifact verifies/restores under the old CLI,
with independent restored row checks, byte-identical stored artifacts and unchanged
key files. The cross-version fixture scene/container was cleaned. No old fixture or
expected signature was rewritten to accept a changed transcript.

Final CI-wrapper gates pass on frozen source:

| Gate | Accepted evidence |
|---|---|
| fast | **316 workspace tests**, strict locked/offline Clippy, format, all three workflows semantically linted, two actual CLI report envelopes and reference/script/TOML/JSON syntax. |
| m4a_key_drill | PG16/17/18 rotation, cross-generation refusal, encryption/signing/verifying key loss, offline/source-loss recovery, total-loss inertness, operator-supplied test identity and intact signed artifacts. |
| m4b_docker_smoke | PG16/17/18 signed v1 writes, signature/checksum/archive boundaries, twelve forgery cases, wrong recipient/signer and source binding, operator-supplied seed, reader-only DR restore and stock-rage divergence controls. Existing rage locale warnings remain visible; no independent cryptographic certification. |
| h02_snapshot_drill | PG16/17/18 non-root true read-only media, exact custody, signature/checksum/archive, immutable inventory, external scratch cleanup/limits and syscall audit. |
| package | Ubuntu-built locked/offline release, repeat-byte archive, manager-free lifecycle and identical package on Ubuntu24.04/systemd255/glibc2.39/PG16 and Debian13/systemd257/glibc2.41/PG17. Both actual managers pass lifecycle/custody/sandbox/timer/manual overlap/v7 migration/graceful cancellation/three escaped-session hard stops/live upgrade and reader-only source-loss restore. |

These are **three native suites / nine script-major runs**, fast and package. All five
wrappers preserve **174 source inputs** during execution. Only README/project/log and
security-review handoff edits follow the tests. Package SHA256
`87b09cdafcaa3a9f7071b119c5538ee41cb82f65acbf6394212c9610d7d7f35e`; SQLite, V01 and H05 packages/evidence remain under
ignored checkpoint-sqlite/checkpoint-v01/checkpoint-h05. Package-tool warnings remain
visible. Containers share the host kernel; repeated archive bytes are not independent
Rust-build reproducibility. Unrelated SQLite crash matrices were retained, not rerun
for this crypto-only change.

### Current advisory and maintenance verdict

Full cargo-audit0.22.2 uses official RustSec revision
`02e2517f457a359fc6d3440ea4560c8ea188fee8`; a fresh public remote-HEAD lookup confirms
that revision is still latest during this review. Same-DB before/after scans:
**two vulnerabilities/exit1 -> zero vulnerabilities/exit0**, empty stderr, no ignores,
target or severity filters. RUSTSEC-2026-0387 and RUSTSEC-2026-0385 are absent after
remediation, and SQLite RUSTSEC-2026-0459 stays absent. Exact tool/DB/lock/arguments/
exit provenance and JSON are target/ci-logs/crypto-audit-*; all new registry identities
are in crypto-registry-provenance.json. Yanked lookups use cached index metadata,
with fresh official checks for all16 added identities; no live-index claim for every
historical locked crate.

**Remaining warnings:** basic-toml0.1.10 is unmaintained (RUSTSEC-2026-0374).
The selected localization branch also introduces unmaintained proc-macro-error2 2.0.1
([RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173.html)), which emits
future-Rust E0365. The pinned 1.97.1 build and strict Clippy pass; a future toolchain
upgrade requires revisiting this dependency. Neither maintenance advisory nor the
compiler warning is suppressed or represented as fixed. The macro maintenance advisory was caught by the final exact-report audit; its
initial expectation omitted it and is preserved in the initial warning-mismatch log.
Accepting the two cryptography vulnerability fixes does not accept those maintenance
findings for release. Retaining the pinned toolchain is necessary for now; V03 must
resolve or explicitly disposition this dependency-maintenance constraint. A maintained
compatible upstream update is preferable to adding a localization fork to this bounded
security fix. The graph is not described as warning-free. Zero reported vulnerabilities and compatibility
tests do not establish constant-time compiled code or independent assurance of the
custom composition. V01's remaining compatibility/content/security validation and
V02/V03/T03 obligations remain open; production stays disabled.

SQLite checkpoint **d90a3b4** is committed and its GitHub Desktop push is independently
confirmed by public origin/main lookup. The nine-file cryptography increment remains
uncommitted for review. No automated crypto push, hosted-green result, host deployment,
format/flow rewrite, schema change or production enablement is claimed.

### Checkpoint review and maintenance tradeoff — 2026-11-17

The operator requested local review/commit including this tradeoff. No blocking
checkpoint findings: equivalent HPKE calls, unchanged validation/wiping and frozen
contracts, immutable old ciphertext/key/signature vectors, both-direction signed CLI
restore, exact dependency provenance and all retained source-bound gate records pass
review. The nine-file increment is being committed locally; push remains operator-owned.

Accept the patched age 0.11 branch for the two vulnerability remediations with the
maintenance constraint recorded above. It introduces proc-macro-error2's unmaintained
advisory and future-Rust E0365 while retaining basic-toml's maintenance advisory.
Current pinned-toolchain builds pass; an eventual toolchain upgrade must address
the macro incompatibility. Both maintenance advisories still require resolution or
explicit V03 release disposition. This checkpoint adds no exemption or suppression
and does not accept production readiness or independent cryptographic assurance.

## Signed table-family scope boundary — 2026-11-17

The [v2 family contract](../backup-format/manifest-v2-family.md) separates expanded
scope semantics from frozen v1. Both versions use the same encrypted signed container:
the signed manifest ciphertext digest authenticates the private version, original
request and direct-edge graph. Header version remains untrusted until the existing
public/private comparison. A supported header-version edit can pass signature level
and must fail when the sealed manifest disagrees; unknown versions fail discovery.
V1 retains literal-request validation and omits graph metadata; v2 requires bounded
unique safe names, complete root reachability and an acyclic graph, consistent profile
and exclusions. Offline checks establish internal consistency of the signer's catalog
observation, not historical catalog truth or arbitrary dependency closure.

No crypto implementation/suite/transcript/key change, dependency update, schema
migration, restore-plan byte change or production enablement is part of this increment.
Schema8's historical v1-signed label records the shared container facts; graph/version
binding remains through the authenticated manifest digest. Re-resolution detects
observed DDL changes but does not establish an atomic catalog/dump transaction or
ABA-proof structural freeze. Avoid concurrent structural DDL for selective backups.
Prior maintenance advisories/future-Rust constraint and wider V01/V03/T03 assurance
limits remain. Final compatibility/native/package acceptance follows in project §54.

Final signed-family acceptance passes 322 workspace tests/strict Clippy, four PG16–18
native suites and both actual package targets, with all six wrappers preserving the
same 176 inputs. Both-direction old/new v1 recovery, old-reader v2 refusal, invalid/
omitted/unsafe/extension-owned scope controls, v2 rebuild/retention and non-root offline
snapshot/source-loss recovery pass. Header-version claims remain untrusted until the
manifest comparison; the new mismatch control pins that boundary. Package SHA256
af84a634aeee0f147fa948a4522f7c62c80cb2e615c466593b9059d9c237c989. Detailed evidence,
excluded preliminary/diagnostic/interrupted runs and limitations are in
[the acceptance record](../../project.md#signed-table-family-compatibility-acceptance--2026-11-17).
The identical Cargo.lock retains the prior recorded zero-vulnerability verdict and
both maintenance advisories; no fresh advisory scan, suppression or broader release
acceptance is claimed. Production remains disabled and the increment is uncommitted.
