# V01 security review — 2026-11-16

Scope: code/contract review of the existing fixture implementation, current primary
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
