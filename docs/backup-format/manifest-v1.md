# Published artifact v1 contract

Status: M0 wire-format proposal; freeze only after the M4a encryption tests and the M4b signature and interoperability tests. Development-only M1 plaintext output is **not** v1. This document defines field and validation requirements, not Rust serialization code.

## Layout

```text
artifacts/<opaque-uuid>/
  public.json
  manifest.age
  payload.age
  signature.hybrid
  complete
```

`payload.age` is a standard binary age file whose plaintext is one PostgreSQL `pg_dump -Fc` archive. `manifest.age` is a separate standard age file whose plaintext is a UTF-8 JSON manifest. Both encrypt to the configured recipient. Age's Rust implementation supports streaming and requires finishing the stream writer to make a complete decryptable file. [Age crate](https://docs.rs/age/latest/age/), [stream writer](https://docs.rs/age/latest/age/struct.Encryptor.html).

**The container is provisional; the suite is not.** Whether a hybrid recipient is carried by age's own `age-encryption.org/v1` stream or by a thin suite-labeled envelope around the same authenticated stream is decided by the M4a spike and recorded in [ADR 0001](../architecture/adr-0001-foundations.md); this document names the `.age` files using the first option. What is settled is that every artifact states the algorithm suite it was written with, so a reader can tell a hybrid artifact from a classical-only one instead of assuming.

`suite` is a fixed set of fields, not a free-form string:

| Field | Values | Meaning |
| --- | --- | --- |
| `recipient_suite` | `x25519`, `x25519+ml-kem-768` | How the payload key was agreed |
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
2. Run `pg_dump -Fc --no-subscriptions` into age encryption with the configured hybrid recipient, finishing and fsyncing `payload.age`. Record dump exit status and warnings. Do not publish on failure.
3. Compute payload ciphertext digest. Build the private manifest from resolved source facts and the suites actually used, encrypt/finish/fsync `manifest.age`, and compute its digest. No unencrypted manifest is written to disk.
4. Sign the fixed binary tuple with both signing primitives; write/fsync `signature.hybrid` and `public.json`. Ensure public sizes/hashes match actual files.
5. Fsync the staging directory, atomically rename it to the immutable ID, fsync the parent, create/fsync `complete`, and fsync the artifact directory. If the final marker fails, the artifact remains incomplete and is quarantined on recovery.
6. Index only after verification succeeds at the required level. Never mutate completed artifacts in place. Rotation creates a new signed encrypted generation, optionally under a newer suite, and swaps catalog references only after verification.

## Reader order

1. Validate path/ID, file types, strict file-size limits, and presence of `complete`; never follow symlinks. Bound JSON parsing and file sizes before allocating.
2. Read the recorded `recipient_suite` and `signature_suite` and check each is a suite this reader is allowed to accept; an unlisted or downgraded suite fails before any cryptographic work.
3. Recompute ciphertext hashes and sizes; validate both halves of `signature.hybrid`, sized from the recorded suite, against a trusted, independently configured verifying key over the fixed binary tuple. Unknown signer or bad signature fails before decryption or restore.
4. Decrypt/authenticate the **entire** `manifest.age`; validate schema, ID, source/format fields, suite agreement with the public header, and payload digest/size binding.
5. Decrypt/authenticate the **entire** `payload.age` into a private capacity-checked staging file. Only then call `pg_restore --list` or restore. A streaming reader must not release unauthenticated tail data to the restore process.
6. Report separate results for signed-artifact integrity, PostgreSQL archive parse, and isolated restore test. Any mismatch marks the artifact quarantined; never turn a partial result into `complete`.

## Compatibility and migration

Only version 1 is published initially, frozen at M4b. Readers reject unknown major format versions, unknown critical fields, and suites outside their accepted list; writer changes that affect signature input or required semantics create v2. Keep a golden v1 fixture from M4b and test it against every future reader. Preserve original immutable artifact bytes; a suite change is a migration to a new artifact generation with the new recorded suite, never an in-place rewrite, and the old generation is retained until the new one verifies and the transition is audited. Cross-major PostgreSQL restore is a separate compatibility policy and does not follow automatically from artifact format compatibility.

## Security limits and tests

Test bit flips, truncation, reordered age chunks, payload/manifest swaps, signature/public-header alteration, wrong identity, wrong trusted signer, missing final marker, replay of an older valid artifact, catalog rebuild, hybrid signature vectors for both primitives, and suite downgrade: an artifact that claims a classical-only suite, a public header whose suite disagrees with the encrypted manifest, and a file with only one of the two signature halves must all be refused before decryption or restore. A replay should be *detected by an independent inventory if configured*; v1 alone cannot reject an older valid signed artifact. Treat decrypted archive SQL as untrusted executable input even if the artifact signature is valid. [PostgreSQL restore warning](https://www.postgresql.org/docs/18/app-pgdump.html).
