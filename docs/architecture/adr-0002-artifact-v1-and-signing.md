# ADR 0002: Origin signature and the artifact v1 freeze

Status: **accepted** (2026-10-01) — the M4b shape chosen on 2026-09-28, implemented, and
validated against real PostgreSQL 16, 17 and 18. The four choices in "Choices (accepted)"
below were confirmed by the operator on 2026-09-28; what the run then surfaced is recorded in
"Validation" and in the two written limits at the end of it.

## Context

M4a proved integrity: a bit flip, a truncation or a payload from another key pair is refused
before `pg_restore` sees anything. It did not prove origin. age authenticates a stream, not
the sender, and the recipient key is by design public to anyone allowed to write backups. So
a replaced artifact — one re-encrypted to the same recipient, with a rewritten manifest — is
indistinguishable from a real one. That is why no real-data artifact may be published before
M4b, and why [manifest v1](../backup-format/manifest-v1.md) was written as a contract first.

M4a also left two facts on the table that the freeze has to absorb:

- `manifest.json` is **plaintext** next to the ciphertext. Database name, resolved scope,
  timings and client versions are not confidential today, and they are not covered by any
  authentication, because nothing authenticates anything yet.
- The signed tuple in the contract names `SHA256(manifest.age)`, which only exists once the
  manifest is encrypted. Signing over the plaintext file would mean the signature input
  changes at the freeze, and a change to the signature input is a new format version by the
  contract's own migration rule.

The M4b increment therefore cannot be "add a signature" alone. The spike's measured results
and the chosen shape are below.

## Decided by the M4b spike (`/tmp/m4b-hybrid-sign`, 2026-09-28)

| Question | Measured |
|---|---|
| Is `signature.hybrid` the contract's 3373 bytes? | **Yes**: Ed25519 64 + ML-DSA-65 **3309**. `ml-dsa` 0.1.1 implements final FIPS 204, not the older round-3 encoding that would have produced 3293 |
| Can a signing key be a raw seed, like the age identity? | **Yes**: `SigningKey::from_seed` / `to_seed` round-trips a 32-byte seed; the ML-DSA-65 verifying key encodes to **1952** bytes |
| Does signing need entropy? | **No**. `Signer::sign` on both crates is deterministic, and signing the same tuple twice produced identical bytes |
| Is secret material wiped? | **Only with the `zeroize` feature**, which is off by default for `ml-dsa`. The spike asserts `ZeroizeOnDrop` as a compile-time bound on both signing key types, so a future feature removal breaks the build instead of quietly dropping the guarantee |
| Does a mutated signature verify? | **No** — mutations at the first byte, the middle, the last byte and last-minus-eight all refused; a shortened tuple refused; Ed25519 bit flip refused. (Single-bit mutations are evidence, not proof of non-malleability; see *Malleability* below) |
| Dependency cost | `ed25519-dalek` pinned to **2.2** resolves to `curve25519-dalek` **4.1.3**, the version `age`/`x25519-dalek` already lock — one copy of the curve in the binary, and one copy of `zeroize` (1.9). Measured in the workspace lock after `cargo add`: `ml-dsa` 0.1.1's graph is **not** disjoint from age's. It resolves a second `signature` (3.0 next to age's 2.2), a second `sha2` (0.11 next to 0.10.9) and a second `hybrid-array` (0.4 next to 0.2). The cost is binary size, not soundness: `signature` is traits only, and the two `sha2` copies are independent implementations of the same algorithm rather than two versions of a patched one. The `signature` split does shape the code — the two `Signer` traits are distinct types, so each leg is called by qualified path instead of by an import |

Two dependency constraints follow and are non-negotiable in the implementation: `ml-dsa` must
stay `>= 0.1.1` because GHSA-5x2r-hc65-25f9 (moderate, hint-region malleability) is fixed in
`0.1.0-rc.4`, and the `ed25519-dalek` pin must not float to 3.x while age's set is on
curve25519 4.x.

## Decision: one increment, full v1

The chosen option is **A**: `backupctl` writes the frozen v1 shape in a single step —
encrypted manifest, `public.json`, and `signature.hybrid` — and the format is frozen at the
same commit that produces it. Rejected: signing the current M1 directory shape first, because
it would create a signed format that the freeze then invalidates.

### What an artifact becomes

A store with both `[encryption]` and `[signing]` configured writes:

```text
artifacts/<uuid>/
  payload.age        age stream, one mlkem768x25519 recipient stanza + age's grease stanza
  globals.age        same, only when export_globals is on
  manifest.age       age stream; the private manifest, sealed to the SAME recipient
  signature.hybrid   exactly 3373 bytes: Ed25519(64) || ML-DSA-65(3309)
  public.json        bounded discovery record, 4 KiB cap
  complete           written last, as today
```

There is no plaintext manifest in this shape. A store with `[encryption]` only keeps writing
`m4a-development-age` (unchanged, still unsigned, still forbidden for real data), and a
keyless store keeps writing `m1-development-plaintext` (unchanged, so the M1–M3 matrices and
every existing artifact keep working). Encryption and signing are still deployment
properties, not run flags — the operator's standing rule.

### What is signed

The contract's tuple, unchanged and domain-separated:

```text
"backupctl-artifact-v1\0" || UUID_bytes(backup_id)
  || SHA256_bytes(manifest.age) || SHA256_bytes(payload.age)
```

`globals.age` is **not** in the tuple. It is bound one step away: the signed manifest carries
`globals_sha256`, and the store already refuses an artifact whose globals file does not match
that field (`backup-local` checks it when it opens a v1 artifact, as it does today for M4a).
This is called out because it is the one place where "swap a file in the artifact directory"
depends on a second check rather than on the signature itself.

### Reader order, and what it changes for the operator

1. `backup list` reads only `public.json`. Bounded parse, strict field set, unknown critical
   fields refused. Discovery works with no keys at all.
2. `backup inspect`, `backup verify` and `restore plan` recompute both ciphertext digests and
   verify `signature.hybrid` against the configured trusted verifying key **before** any
   decryption. `signature.hybrid` has one fixed 3373-byte length for the suite this build
   writes, so a file of any other size is refused at parse time rather than sized from the
   header's claim.
3. Only then is `manifest.age` decrypted and authenticated as a whole, and its suite fields,
   backup id and payload digest compared against `public.json`. A disagreement is a refusal,
   not a warning.
4. `restore run` additionally decrypts the payload into the existing transient `scratch/`
   view.

Two consequences are improvements rather than costs: a bad signature is now caught at
**plan** time instead of at `run` (M4a could only fail a wrong key after the target database
was created), and restoring needs no signing key at all — only the decryption identity and
the trusted verifying key. One is a real burden: `backup inspect` on a v1 artifact now needs
the identity, because the metadata it prints is inside `manifest.age`.

### New verification level

`backup verify --level signature` means *digests, suite allowlist and origin, with nothing
decrypted and no PostgreSQL tool invoked*. For a v1 artifact the signature is checked at
every level, including `archive` and `restore`; there is no flag that turns authentication
off, because a level an operator can forget is not a control. The existing `checksum` and
`archive` levels keep their meaning for the older development shapes.

### Suites, ids and the downgrade rules

- `signature_suite` for any new write is `ed25519+ml-dsa-65`, recorded in both `public.json`
  and the encrypted manifest. `ed25519` alone is readable-by-name only; the writer has no
  code path that selects it, which is what the contract's "a new write never chooses a
  classical-only suite" requires.
- `recipient_suite` stays `mlkem768x25519-v0`; `x25519` remains readable-only for old
  development output.
- Both ids are derived, never configured: 16 hex characters of `SHA256(domain ‖ key bytes)`
  for the recipient and the verifying key. `public.json` states them so a mis-set
  configuration is visible rather than merely failing later.

### Key custody (mirrors M4a, with one addition)

```toml
[signing]
signing_key_file   = "/var/lib/backupctl-keys/gen1/signing.key"    # 0600, seed, outside the store
verifying_key_file = "/var/lib/backupctl-keys/gen1/verifying.key"  # 0644, public half
```

Same rules the age pair already enforces: absolute paths, outside `[storage] root`, regular
non-symlink, no overwrite, private parent directory, and no secret material in any `Debug`,
error or output. The addition is that the two halves now have genuinely different
distribution: writing needs `signing_key_file`, and reading or restoring must **not** have it
— it needs only the trusted `verifying_key_file` plus the decryption identity. `key generate`
and `key publish` grow to cover whichever blocks the configuration names, so
`key publish` derives the verifying key from a hand-written signing seed exactly the way it
derives a recipient from a hand-written identity, and `key status` reports all four files with
`suite`, `mode`, path and a public fingerprint.

Both files are the same two-line shape as the age pair — marker, then one lowercase hex
line — and the line is a concatenation in the same order everywhere else in this suite:
a signing key file carries **128 hex characters**, the Ed25519 seed and the ML-DSA-65 seed,
and a verifying key file carries **3968**, the 32-byte Ed25519 key and the 1952-byte
ML-DSA-65 key. Two independent seeds rather than one seed and a derivation, so a weakness in
one scheme's key expansion does not automatically reach the other.

### Malleability, and why it does not matter here

An ML-DSA signature is not guaranteed unique for a given message: a different valid hint
encoding can verify too. That is harmless as long as nothing treats signature bytes as an
identifier — the artifact's identity is its UUID, `signature.hybrid` is only ever
accept/reject input, and `signer_id` is derived from the verifying key rather than from a
signature. This is recorded because the rule is easy to break later by accident.

The classical leg is where malleability *is* stopped: verification uses
`VerifyingKey::verify_strict`, which rejects a non-canonical signature encoding and a
small-order `R`, so an attacker cannot rewrite one valid Ed25519 half into a second valid
one. That check also covers the one weakness the implementing pass found in the crates:
`VerifyingKey::from_bytes` accepts any encoding that decompresses to a point, including a
small-order key, and `ml-dsa`'s `pkDecode` accepts **every** 1952-byte string, so a
verifying key file cannot be malformed on the post-quantum side at all. A weak classical
half is therefore refused when the file is loaded (`is_weak`), not discovered later as an
artifact that mysteriously verifies — or, on the reading side, as one that never does.

### What the freeze commits to

`docs/backup-format/manifest-v1.md` moves from proposal to **frozen**, with its field list
reconciled against what the writer actually emits.

The golden-fixture plan written here on 2026-09-28 was **not** what landed, and the
difference is intentional. A checked-in v1 fixture is a byte-for-byte artifact whose reader
rules a future change must keep accepting; it is the right test once an artifact from another
host can arrive at a store. At this milestone every v1 byte in existence was produced by this
same repository, so the freeze is instead pinned by three cheaper assertions that do not
require publishing a secret-bearing file into git:

- deterministic golden signature and key-encoding vectors in `backup-crypto`'s crate tests,
  which is where a signature-format change has to be noticed;
- `tests/m4b_docker_smoke.sh` reading a freshly written `payload.age` header and asserting
  exactly one `mlkem768x25519` recipient stanza, no other stanza but age's own `*-grease`,
  and a `signature.hybrid` of exactly 3373 bytes;
- the same run feeding that artifact to stock `rage`, which refuses it — the deferred M4a
  "our stream is not a plain X25519 age file" assertion, now at CLI level.

Add the checked-in fixture when the first real cross-host artifact exists, not before.

## Validation

Items 1–2 ran with the implementation; items 3–4 ran with `tests/m4b_docker_smoke.sh` on
2026-10-01. Recorded as executed, with the two limits the runs surfaced written as limits
rather than smoothed over.

1. Crate tests in `backup-crypto`: exact 3373-byte length with ±1-byte refusal, both halves
   verified independently, one-half-only refused, deterministic golden vector, seed
   round-trip through the key-file format, `ZeroizeOnDrop` compile-time assertions, key-file
   mode/symlink/ownership rules reused for the new roles. **Ran**: `cargo test --workspace`
   on 2026-10-01 — 128 passed, 0 failed.
2. Store tests in `backup-local`: writer order (no `complete` without a signature), refusing
   an unsigned or single-leg `signature.hybrid`, refusing a `public.json` over its cap or with
   an unknown critical field, refusing suite disagreement between header and manifest,
   detecting a swapped `globals.age` through the signed manifest, and refusing a signature
   made by a key that is not the trusted one. **Ran** in the same suite.
3. CLI: `key status` over all four files, `--output json` carrying no secret, and the
   stock-`rage` golden assertion. **Ran**, in `tests/m4b_docker_smoke.sh` rather than as a
   checked-in fixture: `key status` rows are compared against the files they describe (roles,
   `0600`/`0644` modes, suite, derived ids) and the assertion "no command printed a seed"
   greps the JSON for both the 64-character identity seed and the 128-character signing seed.
4. Docker: a new `tests/m4b_docker_smoke.sh` writes, signs, verifies at all three levels and
   DR-restores on PostgreSQL 16, 17 and 18; `tests/m4a_key_drill.sh` gains a signing half to
   the lifecycle drill (offline copy, rotation, loss, and a restore with no signing key
   present). **Ran on all three majors** for both scripts, and `tests/m1_docker_smoke.sh`,
   `m2_`, `m3_` and `m4a_` were re-run on all three with the M4a artifact paths still
   verifying.

### Two limits this freeze ships with

- **A suite downgrade in `public.json` is not caught at `--level signature`.** The signed
  tuple covers `backup_id`, `SHA256(manifest.age)` and `SHA256(payload.age)` only; it does
  not cover `signature_suite`, `recipient_suite`, `signer_id` or `recipient_id`. So an editor
  who rewrites `public.json` to claim `ed25519` passes signature-level verification while the
  report echoes the false claim, and the refusal arrives one step later, when the header is
  compared against the authenticated manifest ("public header and manifest disagree on
  signature_suite"). `--level checksum` and `--level archive` reach that comparison, and
  `restore plan` does too, so no restore path relies on the header's word — but a reader that
  trusts `public.json`'s suite fields *because* a signature verified has misread what the
  signature authenticated. Pinned as matrix case 6.11 so the behavior cannot silently change.
- **A missing file is reported as an I/O error, not as a contract refusal.** Remove
  `complete` and the store refuses, as it must, but the message is the bare
  `No such file or directory (os error 2)` from the stat rather than the contract sentence
  naming the completion marker. Same shape for a missing key file. The refusal and its
  position in the reader order are what the tests assert; a reader triaging a stored
  artifact has to know that an absent component speaks in errno. Matrix case 6.7.

## Choices (accepted)

The operator accepted all four defaults on 2026-09-28, so these are decisions rather than
recommendations.

| # | Choice | Accepted default | Why |
|---|---|---|---|
| 1 | `[signing]` without `[encryption]` | refused at config load | signing a plaintext artifact buys origin over bytes anyone can read, and the v1 writer has no unsigned shape to fall back to |
| 2 | Custody layout | the single `[signing]` block above | matches the `[encryption]` split an operator already knows; a verify-only host provably needs no secret |
| 3 | `signer_id` / `recipient_id` | derived from key bytes, not configurable | an id the operator sets is an id that can lie about which key opened this artifact |
| 4 | Reading unsigned `m4a-development-age` artifacts after M4b | allowed, with the existing trust warning; never written once `[signing]` is configured | refusing would orphan the very artifacts the M4a drill produced, and they are development-only anyway |

## Out of scope for M4b

Automatic rotation, one configuration spanning several generations, rollback protection
against a valid older signed artifact (needs the M5 inventory), an external or HSM signer,
scheduling, and any MySQL/MongoDB surface.
