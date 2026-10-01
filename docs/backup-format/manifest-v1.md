# Published artifact v1 contract

Status: M0 wire-format proposal; freeze only after the M4a encryption tests and the M4b signature and interoperability tests. The M4b implementation shape, the measured signature and key lengths, and the one step by which `globals.age` is bound are in [ADR 0002](../architecture/adr-0002-artifact-v1-and-signing.md). Development-only M1 plaintext output is **not** v1. This document defines field and validation requirements, not Rust serialization code.

## Layout

```text
artifacts/<opaque-uuid>/
  public.json
  manifest.age
  payload.age
  signature.hybrid
  complete
```

`payload.age` is a binary `age-encryption.org/v1` file whose plaintext is one PostgreSQL `pg_dump -Fc` archive. `manifest.age` is a separate such file whose plaintext is a UTF-8 JSON manifest. Both encrypt to the configured recipient. Age's Rust implementation supports streaming and requires finishing the stream writer to make a complete decryptable file. [Age crate](https://docs.rs/age/latest/age/), [stream writer](https://docs.rs/age/latest/age/struct.Encryptor.html).

**The M4a development artifact is this same stream carried by the M1 directory shape.** Its `format` tag is `m4a-development-age`, its manifest stays a plaintext JSON file, and only the two payload names change: `payload.age`, plus `globals.age` when `export_globals` is on. A store configured without an `[encryption]` block keeps writing `payload.dump` and `globals.sql` under `m1-development-plaintext`, so encryption is a property of the deployment rather than of the format. Two manifest fields carry what a ciphertext cannot reveal:

- `recipient_suite` names the suite the payload was sealed under, and a reader must refuse a suite it is not allowed to open *before* handing anything to `pg_restore`.
- `payload_plaintext_bytes` records the size the payload decrypts to, which is the bound the decrypt itself runs under; a payload that inflates past its own manifest is refused while streaming. It is recorded because the published size no longer tells anyone how much plaintext to expect.

Decrypted bytes exist only transiently, in a mode-0700 `scratch/` directory under the storage root that the operation which needed them owns and removes; like `staging/`, it is purged at startup. An artifact directory holding both `payload.dump` and `payload.age` is refused rather than resolved by guesswork: the manifest's `format` names the files it binds, so a stray sibling means either a tampered manifest or a dump that leaked plaintext.

The recipient stanza is ours and the authenticated stream is age's; this is the container decision recorded in [ADR 0001](../architecture/adr-0001-foundations.md). A v1 artifact carries exactly one recipient stanza:

```text
-> mlkem768x25519 <base64(1120-byte encapsulated key
   = ML-KEM-768 ciphertext (1088) || X25519 ephemeral public key (32))>
<base64(HPKE ChaCha20-Poly1305 ciphertext wrapping the 16-byte age file key)>
```

The 32-byte HPKE shared secret is `HKDF-SHA256-Extract(salt = "backupctl-MLKEM768-X25519-v0", ikm = ss_ml-kem-768 || ss_x25519 || ct_x25519 || pk_x25519)`: the component secrets in that order per [RFC 10024](https://www.rfc-editor.org/info/rfc10024/), with both X25519 public keys additionally bound into the input. HPKE `info` is the fixed string `backupctl-artifact-v1`. That transcript binding is a deliberate deviation from RFC 9180's bare `Extract(salt = 0, ss_1 || ss_2)`; it belongs to this suite's identity, so changing it introduces a new suite rather than reinterpreting old bytes. Keys are lowercase hex (a 1216-byte public key, a 32-byte seed as the identity), not Bech32, so **stock `rage` cannot read a v1 artifact in either direction** — encrypting, decrypting, or accepting our key files. Only `backupctl` does, and that is the contract, not a gap.

Writer and reader must enforce **exactly one `mlkem768x25519` recipient stanza per artifact and no other recipient stanza for the same file key**. Our recipient claims no age `postquantum` label, so age happily accepts a mixed `[x25519, mlkem768x25519]` header in which either identity alone decrypts; a classical-only recovery recipient added for convenience silently cancels the harvest-now-decrypt-later protection. The rule is about recipient stanzas, not stanza count: `HeaderV1::new` appends one random `*-grease` stanza to every age header it writes, so a rule of "exactly one stanza in total" would reject every artifact age itself produces. That grease stanza is the only foreign stanza a v1 header may contain — its tag and arguments are random printable strings that no identity, ours or age's, can read as a key — and the reader rejects any header carrying another tag. Lost-key recovery is handled by protecting the hybrid identity, never by a parallel classical stanza.

**The suite fields are mandatory even though the signature values are still being chosen at M4b.** Every artifact states the algorithm suite it was written with, so a reader can tell a hybrid artifact from a classical-only one instead of assuming, and a reader can never infer a suite from key sizes or stanza counts.

`suite` is a fixed set of fields, not a free-form string:

| Field | Values | Meaning |
| --- | --- | --- |
| `recipient_suite` | `x25519`, `mlkem768x25519-v0` | How the payload key was agreed. `-v0` covers the exact combiner above (salt, ordering, HPKE `info`); changing any of them requires a new version suffix. `x25519` is readable-only for development output and never written for a real artifact. |
| `signature_suite` | `ed25519`, `ed25519+ml-dsa-65` | How the artifact was signed |
| `implementation` | version strings | Crate/version that wrote the bytes |

`public.json` is bounded to 4 KiB, UTF-8 JSON, with `format_version: 1`, `backup_id` (opaque UUID), `recipient_id`, `signer_id`, `recipient_suite`, `signature_suite`, `manifest_ciphertext_bytes`, `payload_ciphertext_bytes`, `manifest_sha256`, and `payload_sha256`. Hashes are lowercase 64-character hex. IDs use restricted validated characters; no filename or relative path is accepted from this file. All public fields are untrusted until signature verification. It contains no database name, host, timestamp, SQL, or secret.

The private manifest has required fields: `format_version`, `backup_id`, `engine: "postgresql"`, `source_server_major`, `source_server_version`, `dump_client_version`, `application_version`, `recipient_suite`, `signature_suite`, `started_at_utc`, `completed_at_utc`, `source_fingerprint` (non-secret, redacted), `profile_snapshot`, `requested_selection`, `resolved_selection`, `archive_format: "custom"`, `compression`, `subscription_policy`, `globals_policy`, `payload_ciphertext_sha256`, `payload_ciphertext_bytes`, `archive_plaintext_bytes`, `archive_toc_sha256`, `verification_level`, and `compatibility_notes`. Optional fields must be explicitly versioned; unknown critical fields cause rejection. The manifest never copies connection strings, passwords, raw SQL, or signing/decryption private keys. Its archive can nevertheless contain database-held credentials.

## Origin signature

An age recipient public key allows anyone to create an encrypted file for that recipient; age alone does not authenticate the sender. v1 therefore requires a detached signature made with a service signing key held **outside** the artifact store. A trusted verifying key is installed independently of the artifact. The signing key is distinct from the age decryption identity. The signature is **hybrid**: Ed25519 plus ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)), so a break in either primitive alone does not yield a forgery. Maintained implementations only, such as [`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/) and the RustCrypto [`ml-dsa`](https://docs.rs/ml-dsa) crate, after M4b dependency review. The `signer_id` in `public.json` selects a trusted key; an attacker cannot add a trusted key by editing the artifact.

Both halves sign exactly this same domain-separated byte string:

```text
ASCII("backupctl-artifact-v1\0") ||
UUID_bytes(backup_id) ||
SHA256_bytes(manifest.age) ||
SHA256_bytes(payload.age)
```

No JSON canonicalization is needed for signing. `signature.hybrid` is the fixed-length Ed25519 signature (64 bytes) followed by the fixed-length ML-DSA-65 signature (3309 bytes per [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) with no separators, so its expected 3373-byte size is derived from the recorded `signature_suite` rather than parsed; M4b pins these lengths against the implementation's own test vectors. `ed25519` is a permitted recorded suite for migrated or development artifacts; a new write never chooses it. `public.json` repeats the two digest values for discovery; readers recompute them and use the signed binary tuple as authority. The encrypted manifest repeats the payload digest and ID; readers compare both after decryption. A reader verifies **both** halves against the trusted verifying key and fails if either is invalid; it does not accept a signature that only satisfies one primitive. The signature proves that a trusted signer authorized this exact pair of ciphertext files for the suite it names, assuming its private keys were not compromised. It does not prove the source database was honest, prevent a valid older signed artifact from being replayed, or prevent deletion. A monotonic external inventory/immutable storage is required for rollback resistance.

## Writer order and durability

1. Allocate an unpredictable UUID and a private staging directory (mode 0700) under the destination filesystem. Reject symlinks and existing IDs.
2. Run `pg_dump -Fc --no-subscriptions` into age encryption with the configured hybrid recipient, finishing and fsyncing `payload.age`. Write exactly one `mlkem768x25519` recipient stanza and reject any configuration that would add a second recipient stanza for the same file key; the single random `*-grease` stanza age appends to every header is expected and is not a recipient. Record dump exit status and warnings. Do not publish on failure.
3. Compute payload ciphertext digest. Build the private manifest from resolved source facts and the suites actually used, encrypt/finish/fsync `manifest.age`, and compute its digest. No unencrypted manifest is written to disk.
4. Sign the fixed binary tuple with both signing primitives; write/fsync `signature.hybrid` and `public.json`. Ensure public sizes/hashes match actual files.
5. Fsync the staging directory, atomically rename it to the immutable ID, fsync the parent, create/fsync `complete`, and fsync the artifact directory. If the final marker fails, the artifact remains incomplete and is quarantined on recovery.
6. Index only after verification succeeds at the required level. Never mutate completed artifacts in place. Rotation creates a new signed encrypted generation, optionally under a newer suite, and swaps catalog references only after verification.

## Reader order

1. Validate path/ID, file types, strict file-size limits, and presence of `complete`; never follow symlinks. Bound JSON parsing and file sizes before allocating.
2. Read the recorded `recipient_suite` and `signature_suite` and check each is a suite this reader is allowed to accept; an unlisted or downgraded suite fails before any cryptographic work.
3. Recompute ciphertext hashes and sizes; validate both halves of `signature.hybrid`, sized from the recorded suite, against a trusted, independently configured verifying key over the fixed binary tuple. Unknown signer or bad signature fails before decryption or restore.
4. Decrypt/authenticate the **entire** `manifest.age`; validate schema, ID, source/format fields, suite agreement with the public header, and payload digest/size binding. Before decryption, reject any header that does not carry exactly one `mlkem768x25519` recipient stanza, or that carries any stanza other than that one and age's mandatory `*-grease` stanza: an extra classical-only stanza is a suite downgrade that age's own label check will not catch, because this recipient type claims no label.
5. Decrypt/authenticate the **entire** `payload.age` into a private capacity-checked staging file. Only then call `pg_restore --list` or restore. A streaming reader must not release unauthenticated tail data to the restore process.
6. Report separate results for signed-artifact integrity, PostgreSQL archive parse, and isolated restore test. Any mismatch marks the artifact quarantined; never turn a partial result into `complete`.

## Compatibility and migration

Only version 1 is published initially, frozen at M4b. Readers reject unknown major format versions, unknown critical fields, and suites outside their accepted list; writer changes that affect signature input or required semantics create v2. Keep a golden v1 fixture from M4b and test it against every future reader. Preserve original immutable artifact bytes; a suite change is a migration to a new artifact generation with the new recorded suite, never an in-place rewrite, and the old generation is retained until the new one verifies and the transition is audited. Cross-major PostgreSQL restore is a separate compatibility policy and does not follow automatically from artifact format compatibility.

## Security limits and tests

Test bit flips, truncation, reordered age chunks, payload/manifest swaps, signature/public-header alteration, wrong identity, wrong trusted signer, missing final marker, replay of an older valid artifact, catalog rebuild, hybrid signature vectors for both primitives, and suite downgrade: an artifact that claims a classical-only suite, a public header whose suite disagrees with the encrypted manifest, a file with only one of the two signature halves, and a header carrying a second classical-only recipient stanza must all be refused before decryption or restore. Recipient-level tests already passing from the M4a spike must be re-implemented as repository tests: deterministic seed expansion, exact 1216/1120-byte key and encapsulated-key lengths with ±1-byte rejection, stanza-body tampering (fails at the age header MAC), payload tampering and truncation (fail at the stream AEAD), wrong-identity rejection, and the single-recipient rule tested against artifacts age itself wrote — including the mandatory grease stanza they carry, which must be tolerated while any other foreign stanza is refused. A replay should be *detected by an independent inventory if configured*; v1 alone cannot reject an older valid signed artifact. Treat decrypted archive SQL as untrusted executable input even if the artifact signature is valid. [PostgreSQL restore warning](https://www.postgresql.org/docs/18/app-pgdump.html).
