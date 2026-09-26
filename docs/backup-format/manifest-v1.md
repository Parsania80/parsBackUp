# Published artifact v1 contract

Status: M0 wire-format proposal; freeze only after M4 interoperability and failure tests. Development-only M1 plaintext output is **not** v1. This document defines field and validation requirements, not Rust serialization code.

## Layout

```text
artifacts/<opaque-uuid>/
  public.json
  manifest.age
  payload.age
  signature.ed25519
  complete
```

`payload.age` is a standard binary age file whose plaintext is one PostgreSQL `pg_dump -Fc` archive. `manifest.age` is a separate standard age file whose plaintext is a UTF-8 JSON manifest. Both encrypt to the configured recipient. Age's Rust implementation supports streaming and requires finishing the stream writer to make a complete decryptable file. [Age crate](https://docs.rs/age/latest/age/), [stream writer](https://docs.rs/age/latest/age/struct.Encryptor.html).

`public.json` is bounded to 4 KiB, UTF-8 JSON, with `format_version: 1`, `backup_id` (opaque UUID), `recipient_id`, `signer_id`, `manifest_ciphertext_bytes`, `payload_ciphertext_bytes`, `manifest_sha256`, and `payload_sha256`. Hashes are lowercase 64-character hex. IDs use restricted validated characters; no filename or relative path is accepted from this file. All public fields are untrusted until signature verification. It contains no database name, host, timestamp, SQL, or secret.

The private manifest has required fields: `format_version`, `backup_id`, `engine: "postgresql"`, `source_server_major`, `source_server_version`, `dump_client_version`, `application_version`, `started_at_utc`, `completed_at_utc`, `source_fingerprint` (non-secret, redacted), `profile_snapshot`, `requested_selection`, `resolved_selection`, `archive_format: "custom"`, `compression`, `subscription_policy`, `globals_policy`, `payload_ciphertext_sha256`, `payload_ciphertext_bytes`, `archive_plaintext_bytes`, `archive_toc_sha256`, `verification_level`, and `compatibility_notes`. Optional fields must be explicitly versioned; unknown critical fields cause rejection. The manifest never copies connection strings, passwords, raw SQL, or signing/decryption private keys. Its archive can nevertheless contain database-held credentials.

## Origin signature

An age recipient public key allows anyone to create an encrypted file for that recipient; age alone does not authenticate the sender. v1 therefore requires a detached Ed25519 signature made with a service signing key held **outside** the artifact store. A trusted verifying key is installed independently of the artifact. The signing key is distinct from the age decryption identity. Use a maintained implementation such as [`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/) after M4 dependency review. The `signer_id` in `public.json` selects a trusted key; an attacker cannot add a trusted key by editing the artifact.

Sign exactly this domain-separated byte string:

```text
ASCII("backupctl-artifact-v1\0") ||
UUID_bytes(backup_id) ||
SHA256_bytes(manifest.age) ||
SHA256_bytes(payload.age)
```

No JSON canonicalization is needed for signing. `signature.ed25519` contains exactly the 64 raw signature bytes. `public.json` repeats the two digest values for discovery; readers recompute them and use the signed binary tuple as authority. The encrypted manifest repeats the payload digest and ID; readers compare both after decryption. The signature proves that a trusted signer authorized this exact pair of ciphertext files, assuming its private key was not compromised. It does not prove the source database was honest, prevent a valid older signed artifact from being replayed, or prevent deletion. A monotonic external inventory/immutable storage is required for rollback resistance.

## Writer order and durability

1. Allocate an unpredictable UUID and a private staging directory (mode 0700) under the destination filesystem. Reject symlinks and existing IDs.
2. Run `pg_dump -Fc --no-subscriptions` into age encryption, finishing and fsyncing `payload.age`. Record dump exit status and warnings. Do not publish on failure.
3. Compute payload ciphertext digest. Build the private manifest from resolved source facts, encrypt/finish/fsync `manifest.age`, and compute its digest. No unencrypted manifest is written to disk.
4. Sign the fixed binary tuple; write/fsync `signature.ed25519` and `public.json`. Ensure public sizes/hashes match actual files.
5. Fsync the staging directory, atomically rename it to the immutable ID, fsync the parent, create/fsync `complete`, and fsync the artifact directory. If the final marker fails, the artifact remains incomplete and is quarantined on recovery.
6. Index only after verification succeeds at the required level. Never mutate completed artifacts in place. Rotation creates a new signed encrypted generation and swaps catalog references only after verification.

## Reader order

1. Validate path/ID, file types, strict file-size limits, and presence of `complete`; never follow symlinks. Bound JSON parsing and file sizes before allocating.
2. Recompute ciphertext hashes and sizes; validate the 64-byte signature against a trusted, independently configured verifying key over the fixed binary tuple. Unknown signer or bad signature fails before decryption or restore.
3. Decrypt/authenticate the **entire** `manifest.age`; validate schema, ID, source/format fields, and payload digest/size binding.
4. Decrypt/authenticate the **entire** `payload.age` into a private capacity-checked staging file. Only then call `pg_restore --list` or restore. A streaming reader must not release unauthenticated tail data to the restore process.
5. Report separate results for signed-artifact integrity, PostgreSQL archive parse, and isolated restore test. Any mismatch marks the artifact quarantined; never turn a partial result into `complete`.

## Compatibility and migration

Only version 1 is published initially. Readers reject unknown major format versions and unknown critical fields; writer changes that affect signature input or required semantics create v2. Keep a golden v1 fixture from M4 and test it against every future reader. Preserve original immutable artifact bytes; migrations create a new artifact generation, retain the old until verified, and audit the transition. Cross-major PostgreSQL restore is a separate compatibility policy and does not follow automatically from artifact format compatibility.

## Security limits and tests

Test bit flips, truncation, reordered age chunks, payload/manifest swaps, signature/public-header alteration, wrong identity, wrong trusted signer, missing final marker, replay of an older valid artifact, and catalog rebuild. A replay should be *detected by an independent inventory if configured*; v1 alone cannot reject an older valid signed artifact. Treat decrypted archive SQL as untrusted executable input even if the artifact signature is valid. [PostgreSQL restore warning](https://www.postgresql.org/docs/18/app-pgdump.html).
