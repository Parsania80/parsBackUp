# Why the artifact crypto is hybrid classical + post-quantum

Status: decision rationale, 2026-09-27. Normative fields live in [artifact v1](../backup-format/manifest-v1.md); the alternatives table lives in [ADR 0001](../architecture/adr-0001-foundations.md).

## The property being bought

A backup is read years after it is written. That time gap is the whole argument: an adversary who cannot decrypt today can copy the artifact today and decrypt it whenever the mathematics underneath it gets worse, either from a classical attack or from a quantum one. Threat **T01** in the [threat model](threat-model.md) is written as harvest-now-decrypt-later for exactly this reason. A database dump also carries credentials and application data whose sensitivity does not decay on the same schedule as the retention policy that deletes it.

Conversely, the primitives that would replace X25519 and Ed25519 outright are new. Lattice assumptions have been attacked productively for only a few years, and the Rust implementations are younger still. Choosing one of them *instead of* a classical primitive would make artifact confidentiality depend on the least-reviewed link in the chain.

Hybrid construction rejects both failure modes: an attacker must break **both** primitives to read a payload or forge a signature, and neither primitive being young is sufficient to break it.

## Chosen primitives

| Role | Construction | Standard | Why this one |
| --- | --- | --- | --- |
| Payload key agreement | X25519 + ML-KEM-768, combined | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), combined per [RFC 10024](https://www.rfc-editor.org/info/rfc10024/) (post-quantum/traditional hybrid key agreement) | ML-KEM is the NIST-standardized KEM; 768 is the level-3 parameter set; RFC 10024 defines the hybrid combination and its transcript-based key derivation instead of an ad hoc concatenation. |
| Origin signature | Ed25519 + ML-DSA-65 | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | ML-DSA is the NIST-standardized signature; 65 matches the security level of ML-KEM-768; Ed25519 is kept because it is the better-analyzed half and costs almost nothing. |

ML-KEM-768 adds an 1184-byte public key, a 1088-byte ciphertext per wrapped file, and a 32-byte shared secret; ML-DSA-65 adds a 1952-byte verifying key and a 3309-byte signature. Against a `pg_dump -Fc` payload this is a size rounding error, not a storage plan input — but it is still measured and published at M4a rather than assumed away.

## What does not change

Age's authenticated streaming format remains the workhorse: per-file data keys, recipient wrapping, per-chunk authentication, and truncation detection, with the stream writer finished before an artifact is considered written. The hybrid primitives are used to agree the key; they do not replace the AEAD stream, and no custom AEAD framing is introduced. Compression stays inside `pg_dump`, because ciphertext does not compress meaningfully.

Whether the hybrid recipient rides inside age's own `age-encryption.org/v1` container or inside a thin suite-labeled envelope is the M4a spike's open question, documented in [ADR 0001](../architecture/adr-0001-foundations.md). What is settled is the fallback: if the native path does not work with a software identity, the envelope wraps the key agreement only and still hands age the stream, and the artifact is documented as no longer stock-age-decryptable. A third-party, unaudited post-quantum file-encryption container is rejected outright — buying a novel file format for a backup tool imports its authors' correctness assumptions along with its cryptography.

## Recorded suite and rotation

Confidentiality decisions made in 2026 must be revisable in 2031 without guessing. Every artifact therefore records `recipient_suite` and `signature_suite`, a reader refuses a suite outside its accepted list, and a new write never selects a classical-only suite. Migrating to a better suite is rotation: decrypt with the old identity, re-encrypt and re-sign under the new suite as a new validated generation, verify it, then let the old generation age out under normal retention. Artifacts are never rewritten in place.

The cost of that model is honest: rotation re-reads and re-writes whole payloads, so it is an operational event with a duration, not a header edit.

## Limits of this decision

- It does not protect a live compromised host, where the identity is readable in memory.
- It does not resist deletion or rollback of an older valid signed artifact; that needs inventory or an immutable store.
- It is not a claim that lattice cryptography is settled. It is a claim that requiring two independent breaks is better than requiring one.
- Key material is larger and less familiar to operators, so the recovery drill in M4a is run against the real file format rather than a documented assumption.
