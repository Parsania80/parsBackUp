# Published artifact v1 contract

Status: **frozen** (2026-10-01) at the shape `backupctl` writes and reads today, validated by
`tests/m4b_docker_smoke.sh` and the signing half of `tests/m4a_key_drill.sh` on PostgreSQL 16,
17 and 18. The M4b implementation shape, the measured signature and key lengths, and the one
step by which `globals.age` is bound are in [ADR 0002](../architecture/adr-0002-artifact-v1-and-signing.md),
which records the two limits this contract ships with. Development-only M1 plaintext output is
**not** v1. This document defines field and validation requirements, not Rust serialization
code; the field list below is reconciled against `ArtifactManifest` and `PublicHeader` in
`crates/backup-domain/src/artifact_v1.rs`, and a drift between the two is a contract change.
The operator path for this shape — the commands, what each verification level may touch, the
disaster-recovery host's refusal to write, and the exact refusal every tampering variant
produces — is the [M4b signed store guide](../development/m4b-signing.md).

## Layout

```text
artifacts/<opaque-uuid>/
  public.json
  manifest.age
  payload.age
  globals.age          only when export_globals is on
  signature.hybrid
  complete
```

`payload.age` is a binary `age-encryption.org/v1` file whose plaintext is one PostgreSQL `pg_dump -Fc` archive. `manifest.age` is a separate such file whose plaintext is a UTF-8 JSON manifest. Both encrypt to the configured recipient. Age's Rust implementation supports streaming and requires finishing the stream writer to make a complete decryptable file. [Age crate](https://docs.rs/age/latest/age/), [stream writer](https://docs.rs/age/latest/age/struct.Encryptor.html).

**The M4a development artifact is this same stream carried by the M1 directory shape.** Its `format` tag is `m4a-development-age`, its manifest stays a plaintext JSON file, and only the two payload names change: `payload.age`, plus `globals.age` when `export_globals` is on. A store configured without an `[encryption]` block keeps writing `payload.dump` and `globals.sql` under `m1-development-plaintext`, so encryption is a property of the deployment rather than of the format. Two manifest fields carry what a ciphertext cannot reveal:

- `recipient_suite` names the suite the payload was sealed under, and a reader must refuse a suite it is not allowed to open *before* handing anything to `pg_restore`.
- `payload_plaintext_bytes` records the size the payload decrypts to, which is the bound the decrypt itself runs under; a payload that inflates past its own manifest is refused while streaming. It is recorded because the published size no longer tells anyone how much plaintext to expect.

Decrypted bytes exist only transiently, in a mode-0700 `scratch/` directory under the storage root that the operation which needed them owns and removes; like `staging/`, it is emptied by nothing else — opening a store removes no entries, and only `backup create`'s recovery pass clears one, and only while it holds the store's activity claim exclusively ([ADR 0004](../architecture/adr-0004-working-directory-ownership.md)). An artifact directory holding both `payload.dump` and `payload.age` is refused rather than resolved by guesswork: the manifest's `format` names the files it binds, so a stray sibling means either a tampered manifest or a dump that leaked plaintext.

The recipient stanza is ours and the authenticated stream is age's; this is the container decision recorded in [ADR 0001](../architecture/adr-0001-foundations.md). A v1 artifact carries exactly one recipient stanza:

```text
-> mlkem768x25519 <base64(1120-byte encapsulated key
   = ML-KEM-768 ciphertext (1088) || X25519 ephemeral public key (32))>
<base64(HPKE ChaCha20-Poly1305 ciphertext wrapping the 16-byte age file key)>
```

The 32-byte HPKE shared secret is `HKDF-SHA256-Extract(salt = "backupctl-MLKEM768-X25519-v0", ikm = ss_ml-kem-768 || ss_x25519 || ct_x25519 || pk_x25519)`: the component secrets in that order per [RFC 10024](https://www.rfc-editor.org/info/rfc10024/), with both X25519 public keys additionally bound into the input. HPKE `info` is the fixed string `backupctl-artifact-v1`. That transcript binding is a deliberate deviation from RFC 9180's bare `Extract(salt = 0, ss_1 || ss_2)`; it belongs to this suite's identity, so changing it introduces a new suite rather than reinterpreting old bytes. Keys are lowercase hex (a 1216-byte public key, a 32-byte seed as the identity), not Bech32, so **stock `rage` cannot read a v1 artifact in either direction** — encrypting, decrypting, or accepting our key files. Only `backupctl` does, and that is the contract, not a gap. `tests/m4b_docker_smoke.sh` feeds a freshly written `payload.age` to stock `rage` and asserts the refusal, which is the CLI-level form of the check the M4a spike held only at crate level.

Writer and reader must enforce **exactly one `mlkem768x25519` recipient stanza per artifact and no other recipient stanza for the same file key**. Our recipient claims no age `postquantum` label, so age happily accepts a mixed `[x25519, mlkem768x25519]` header in which either identity alone decrypts; a classical-only recovery recipient added for convenience silently cancels the harvest-now-decrypt-later protection. The rule is about recipient stanzas, not stanza count: `HeaderV1::new` appends one random `*-grease` stanza to every age header it writes, so a rule of "exactly one stanza in total" would reject every artifact age itself produces. That grease stanza is the only foreign stanza a v1 header may contain — its tag and arguments are random printable strings that no identity, ours or age's, can read as a key — and the reader rejects any header carrying another tag. Lost-key recovery is handled by protecting the hybrid identity, never by a parallel classical stanza.

**The suite fields are mandatory.** Every artifact states the algorithm suite it was written with, so a reader can tell a hybrid artifact from a classical-only one instead of assuming, and a reader can never infer a suite from key sizes or stanza counts. A reader checks the header's claim against its readable list at discovery and against the signed manifest after decryption; the manifest's claim is the authoritative one.

`suite` is a fixed set of fields, not a free-form string:

| Field | Values | Meaning |
| --- | --- | --- |
| `recipient_suite` | `x25519`, `mlkem768x25519-v0` | How the payload key was agreed. `-v0` covers the exact combiner above (salt, ordering, HPKE `info`); changing any of them requires a new version suffix. `x25519` is readable-only for development output and never written for a real artifact. |
| `signature_suite` | `ed25519`, `ed25519+ml-dsa-65` | How the artifact was signed. `ed25519` is a name a reader may record as readable; the v1 reader has no code path that accepts a 64-byte classical signature, so it cannot be forged into a pass. |
| `application_version`, `dump_client_version` | version strings, in the encrypted manifest only | Crate/binary version that wrote the bytes, and the `pg_dump` version that produced the archive |

`public.json` is bounded to 4 KiB, UTF-8 JSON, with `format_version: 1`, `backup_id` (opaque UUID), `recipient_id`, `signer_id`, `recipient_suite`, `signature_suite`, `manifest_ciphertext_bytes`, `payload_ciphertext_bytes`, `manifest_sha256`, and `payload_sha256`. Hashes are lowercase 64-character hex. IDs are 16 lowercase hex characters; no filename or relative path is accepted from this file, and the artifact directory is chosen from the requested ID, never from this record — a `public.json` naming a different `backup_id` than its own directory is refused. It contains no database name, host, timestamp, SQL, or secret.

Its fields are untrusted in **two steps**, and the distinction matters: the two digests and the payload size are bound to the files on disk and to the signed tuple, so signature verification is about them; the suite and ID strings are bound only through the comparison against the decrypted manifest, one step later. "All public fields are untrusted until signature verification" therefore understates it for the suite fields — see "Exactly what those 3373 bytes cover".

The private manifest fields are exactly these, in this order; every one is present in the serialized document, and `serde`'s `deny_unknown_fields` means an extra key is a refusal rather than something a reader ignores:

| Field | Presence | Notes |
| --- | --- | --- |
| `format_version` | required | `1`; a reader refuses any other value by name |
| `backup_id` | required | the opaque UUID that names the directory |
| `engine` | required | `"postgresql"` |
| `source_server_major`, `source_server_version`, `dump_client_version`, `application_version` | required | server major, `server_version_num` as reported, client `--version` string, this binary's version |
| `recipient_id` | required | 16 lowercase hex: `SHA256(domain ‖ recipient public key bytes)`, derived not configured |
| `signer_id` | required | 16 lowercase hex, derived the same way from the verifying key |
| `recipient_suite`, `signature_suite` | required | see the suite table above |
| `started_at_utc`, `completed_at_utc` | required | validated UTC timestamps |
| `source_fingerprint` | required | 16 lowercase hex over the source reference, so two artifacts can be bound to one source without either stating where it is |
| `profile_snapshot`, `requested_selection`, `resolved_selection` | required | see "What a v1 manifest says about scope" below |
| `archive_format` | required | `"custom"` |
| `compression` | required | `"gzip"` — the recorded form of the `--compress` level, which names a level rather than an algorithm |
| `subscription_policy` | required | `"dropped"` (`pg_dump --no-subscriptions` is not optional here) |
| `globals_policy` | required | `"exported"` or `"skipped"` |
| `globals_sha256`, `globals_ciphertext_bytes` | **paired optional** | present exactly when `globals_policy` is `exported`; a manifest that disagrees with its own policy is refused |
| `payload_ciphertext_sha256`, `payload_ciphertext_bytes` | required | the digest `signature.hybrid` covers, and the published size |
| `archive_plaintext_bytes` | required | the bound a decrypt runs under. This is the same quantity the M4a development manifest calls `payload_plaintext_bytes`; v1 renames it, and a reader picks the field by `format` |
| `archive_toc_sha256` | optional in the type, **always written by v1** | see below |
| `verification_level` | required | pinned to `"none"` at publish — see below |
| `compatibility_notes` | required | a bounded list of short printable strings; the writer currently emits an empty one |

The manifest never copies connection strings, passwords, raw SQL, or signing/decryption private keys. Its archive can nevertheless contain database-held credentials.

### What a signed manifest cannot learn later

`verification_level` is `"none"` in every published v1 manifest, and `ArtifactManifest::validate` refuses to parse any other value rather than warning about it. The reason is the signature: these bytes are sealed into `manifest.age` and hashed into the signed tuple, so recording `archive-tested` or `restore-tested` after the fact would change what the signature covers. A verification therefore *reports* a level without writing one into the artifact, and `restore run` on a signed artifact reports `recorded_in_artifact: false` — the restore did happen to this archive, but no byte in it can say so. This is a deliberate consequence of freeze-at-write, not a gap: the authoritative record of what a host did with an artifact is its own audit trail, which arrives with the M5 catalog.

`archive_toc_sha256` is the one field that looks like the exception and is not. It records the digest of the table of contents listed from the staged archive *before* anything was sealed — the only moment a signed manifest can learn it. `backup verify --level archive` on a v1 artifact re-lists the payload and compares against this write-time digest, and refuses an artifact whose manifest recorded none ("the signed manifest records no archive table of contents, so archive level cannot be proven"). So an archive-level pass proves the archive still parses *and* parses to the same table of contents the signer saw; a payload re-dumped under the same sealed bytes cannot claim archive verification.

### What a v1 manifest says about scope

A dump that names no profile still records a scope, under the reserved synthetic profile name `whole-database`. The manifest is the only record of what was selected, and a missing one is indistinguishable from a filtered dump that claimed otherwise. The name is reserved in `Config::validate`'s profile loop, **not** in `Profile::validate`, because `ArtifactManifest::validate` re-validates the snapshot it signs: a rule that made the writer's own snapshot an invalid profile would make every signed backup refuse its own manifest. `resolved_selection.whole_database` and the requested lists must agree with that snapshot, and a filtered selection must list exactly the objects it resolved to and no others.

### `source_fingerprint` binding

`restore plan` refuses an artifact whose recorded `source_fingerprint` does not match the configured source, and `restore run` re-checks the plan it is executing, so a plan cannot be replayed against a different database than the one it was made for. The fingerprint is a digest over engine, major, host, port and database name with the domains separated by `0x00`, precisely so that binding two artifacts to one source does not print where that source is.

## Origin signature

An age recipient public key allows anyone to create an encrypted file for that recipient; age alone does not authenticate the sender. v1 therefore requires a detached signature made with a service signing key held **outside** the artifact store. A trusted verifying key is installed independently of the artifact. The signing key is distinct from the age decryption identity. The signature is **hybrid**: Ed25519 plus ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)), so a break in either primitive alone does not yield a forgery. Maintained implementations only, such as [`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/) and the RustCrypto [`ml-dsa`](https://docs.rs/ml-dsa) crate, after M4b dependency review. The `signer_id` in `public.json` selects a trusted key; an attacker cannot add a trusted key by editing the artifact.

Both halves sign exactly this same domain-separated byte string:

```text
ASCII("backupctl-artifact-v1\0") ||
UUID_bytes(backup_id) ||
SHA256_bytes(manifest.age) ||
SHA256_bytes(payload.age)
```

### Exactly what those 3373 bytes cover

The tuple is `backup_id` plus the two ciphertext digests, and nothing else. It does **not**
cover `signature_suite`, `recipient_suite`, `signer_id` or `recipient_id` — those live in
`public.json`, which the signature cannot authenticate because the signature does not read
it. So a storage editor who rewrites `public.json` to claim `signature_suite: "ed25519"`
passes `backup verify --level signature`, and the false claim is caught one step later, when
the decrypted manifest is compared against the header ("public header and manifest disagree
on signature_suite"). `--level checksum`, `--level archive` and `restore plan` all reach that
comparison, so no restore path acts on the header's word alone — but a reader that trusts a
suite string *because a signature verified* has misread what the signature authenticated.
`tests/m4b_docker_smoke.sh` case 6.11 pins this behavior in both directions, including the
fact that signature level still passes, so it cannot be quietly reinterpreted later.

The header and the manifest share eight fields — `format_version`, `backup_id`,
`recipient_id`, `signer_id`, `recipient_suite`, `signature_suite`, the payload digest and the
payload size — and `ArtifactManifest::matches_header` requires all eight to agree. Two records
that disagree describe two different artifacts that happen to share a directory.

A writer's refusal message can also be less specific than this contract's language: a missing
`complete` marker is refused, and refused before any crypto work, but what the operator sees
is the bare `No such file or directory (os error 2)` from the stat rather than a sentence
naming the marker. Same shape for a missing key file. The position of the refusal is the
guarantee; an absent component speaks in errno.

No JSON canonicalization is needed for signing. `signature.hybrid` is the fixed-length Ed25519 signature (64 bytes) followed by the fixed-length ML-DSA-65 signature (3309 bytes per [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) with no separators. Its expected 3373-byte size is a property of the suite this build writes — `HybridSignature` is a fixed-length array, so a shorter or longer file is refused rather than parsed — and M4b pins these lengths against the implementation's own test vectors. `ed25519` is a permitted recorded suite for migrated or development artifacts; a new write never chooses it. `public.json` repeats the two digest values for discovery; readers recompute them and use the signed binary tuple as authority. The encrypted manifest repeats the payload digest and ID; readers compare both after decryption. A reader verifies **both** halves against the trusted verifying key and fails if either is invalid; it does not accept a signature that only satisfies one primitive. The signature proves that a trusted signer authorized this exact pair of ciphertext files for the suite it names, assuming its private keys were not compromised. It does not prove the source database was honest, prevent a valid older signed artifact from being replayed, or prevent deletion. A monotonic external inventory/immutable storage is required for rollback resistance.

## Writer order and durability

1. Allocate an unpredictable UUID and a private staging directory (mode 0700) under the destination filesystem. Reject symlinks and existing IDs.
2. Run `pg_dump -Fc --no-subscriptions` into age encryption with the configured hybrid recipient, finishing and fsyncing `payload.age`. Write exactly one `mlkem768x25519` recipient stanza and reject any configuration that would add a second recipient stanza for the same file key; the single random `*-grease` stanza age appends to every header is expected and is not a recipient. Record dump exit status and warnings. Do not publish on failure.
3. Compute payload ciphertext digest. Build the private manifest from resolved source facts and the suites actually used, encrypt/finish/fsync `manifest.age`, and compute its digest. No unencrypted manifest is written to disk.
4. Sign the fixed binary tuple with both signing primitives; write/fsync `signature.hybrid` and `public.json`. Ensure public sizes/hashes match actual files.
5. Fsync the staging directory, atomically rename it to the immutable ID, fsync the parent, create/fsync `complete`, and fsync the artifact directory. If the final marker fails, the artifact remains incomplete and is quarantined on recovery.
6. Index only after verification succeeds at the required level. Never mutate completed artifacts in place. Rotation creates a new signed encrypted generation, optionally under a newer suite, and swaps catalog references only after verification.

## Reader order

1. Validate path/ID, file types, strict file-size limits, and presence of `complete`; never follow symlinks. Bound JSON parsing and file sizes before allocating.
2. Read the recorded `recipient_suite` and `signature_suite` and check each against this reader's **readable** list, so a suite outside it fails before any cryptographic work. A suite that is readable-but-never-written (`x25519`, `ed25519`) is *not* refused here: the header is untrusted input, and the authoritative suite is the signed manifest's. See "Exactly what those 3373 bytes cover" for the step that catches a downgrade claim.
3. Recompute ciphertext hashes and sizes; validate both halves of `signature.hybrid` against a trusted, independently configured verifying key over the fixed binary tuple. The expected length comes from the signature *type* (`HybridSignature` is a 3373-byte array, so a file of any other length is refused at parse time) rather than from the header's `signature_suite` claim — which is stricter than "sized from the recorded suite", and means a header that claims `ed25519` still has to present a full hybrid signature to get anywhere. Unknown signer or bad signature fails before decryption or restore.
4. Decrypt/authenticate the **entire** `manifest.age`; validate schema, ID, source/format fields, suite agreement with the public header, and payload digest/size binding. Reject any header that does not carry exactly one `mlkem768x25519` recipient stanza, or that carries any stanza other than that one and age's mandatory `*-grease` stanza: an extra classical-only stanza is a suite downgrade that age's own label check will not catch, because this recipient type claims no label. That rule lives in the identity's `unwrap_stanzas`, so age enforces it while parsing the header — no plaintext body byte is released before the refusal.
5. Decrypt/authenticate the **entire** `payload.age` into a private capacity-checked staging file. Only then call `pg_restore --list` or restore. A streaming reader must not release unauthenticated tail data to the restore process.
6. Report separate results for signed-artifact integrity, PostgreSQL archive parse, and isolated restore test. Any mismatch marks the artifact quarantined; never turn a partial result into `complete`.

## Compatibility and migration

Only version 1 is published initially, frozen at M4b. Readers reject unknown major format versions, unknown critical fields, and suites outside their accepted list; writer changes that affect signature input or required semantics create v2. Preserve original immutable artifact bytes; a suite change is a migration to a new artifact generation with the new recorded suite, never an in-place rewrite, and the old generation is retained until the new one verifies and the transition is audited. Cross-major PostgreSQL restore is a separate compatibility policy and does not follow automatically from artifact format compatibility.

**What pins the frozen shape today, and the fixture this contract originally promised.** No v1 artifact is checked into the repository: every v1 byte in existence was written by this same tree, and a checked-in fixture would be a file whose reader rules can only be exercised by a reader that already agrees with the writer. The freeze is pinned instead by the deterministic signature and key-encoding vectors in `backup-crypto`, by `backup-local`'s `signed_write_path`/`signed_store` tests, and by `tests/m4b_docker_smoke.sh`, which asserts on a freshly written artifact that `payload.age` carries exactly one `mlkem768x25519` recipient stanza plus age's own `*-grease` and nothing else, that `signature.hybrid` is 3373 bytes, and that stock `rage` refuses the file. When the first artifact produced by a *different* build or host arrives — an upgrade test, or a real cross-generation restore drill — that is the moment a checked-in golden fixture earns its keep, and it should be added then rather than guessed now.

## Security limits and tests

The contract asks for bit flips, truncation, reordered age chunks, payload/manifest swaps, signature/public-header alteration, wrong identity, wrong trusted signer, missing final marker, replay of an older valid artifact, catalog rebuild, hybrid signature vectors for both primitives, and suite downgrade in all four of its shapes: an artifact that claims a classical-only suite, a public header whose suite disagrees with the encrypted manifest, a file with only one of the two signature halves, and a header carrying a second classical-only recipient stanza.

Where each of those is actually enforced, as of this freeze:

| Requirement | Enforced by |
| --- | --- |
| Hybrid signature vectors, ±1-byte lengths, one-half-only refusal, determinism, seed round-trip, `ZeroizeOnDrop` | `backup-crypto` crate tests |
| Recipient stanza rules, ±1-byte key/encapsulated-key lengths, stanza-body tampering, wrong identity, grease tolerated and any other foreign stanza refused | `backup-crypto` recipient tests |
| Writer order (no `complete` without a signature), swapped `globals.age`, unsigned or truncated `signature.hybrid`, oversized/unknown-field/version-2 `public.json`, header-manifest disagreement, foreign signer | `backup-local` `signed_write_path.rs` / `signed_store.rs`, and `tests/m4b_docker_smoke.sh` cases 6.x against real `pg_dump` output |
| Payload bit flip and truncation, symlinked component, replaced `public.json`, foreign key pair | `tests/m4b_docker_smoke.sh`, `tests/m4a_docker_smoke.sh` |
| Suite downgrade claim surviving signature level and dying at checksum level | `tests/m4b_docker_smoke.sh` case 6.11, deliberately asserting the *pass* as well as the refusal |

**Not covered yet, and not claimed here:** replay of an older valid signed artifact (needs the M5 inventory — v1 alone cannot reject one), catalog rebuild (M5), and a v1 artifact written by a build other than this one (see the fixture note above). Treat decrypted archive SQL as untrusted executable input even if the artifact signature is valid. [PostgreSQL restore warning](https://www.postgresql.org/docs/18/app-pgdump.html).
