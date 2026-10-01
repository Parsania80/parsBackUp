//! The values that are part of this crate's wire vocabulary: the recipient stanza
//! tag, the domain-separation strings, the exact key and stanza sizes, and the
//! suite names a manifest records.
//!
//! Every constant here is observable outside the process — written into an artifact,
//! a key file, or a manifest — so none of it may change without introducing a new
//! suite name. Anything that would silently reinterpret existing bytes is a format
//! break, not a refactor.

/// The age recipient stanza tag for the hybrid suite. A stanza line in an age header
/// reads `-> mlkem768x25519 <base64 encapsulated key>`, so this string is what a
/// reader uses to recognise our recipient type.
pub const STANZA_TAG: &str = "mlkem768x25519";

/// Suffix on the tag of age's compatibility noise stanza. `HeaderV1::new` appends one
/// to every header it writes, so it is the only foreign stanza a `backupctl` artifact
/// may contain: its tag and args are random printable strings, which no identity —
/// ours or age's — can read as a key.
pub const GREASE_SUFFIX: &str = "-grease";

/// Suite name recorded in a manifest or public header for this recipient type. The
/// `-v0` suffix covers the exact combiner below: changing the salt, the component
/// ordering, or the HPKE `info` requires a new suffix, never a reinterpretation.
pub const SUITE_HYBRID: &str = "mlkem768x25519-v0";

/// Suite name for age's classical X25519 recipient. It is never written by this
/// crate and is listed only so a reader can accept pre-encryption development
/// output instead of guessing from key sizes.
pub const SUITE_X25519: &str = "x25519";

/// HPKE `info` binding every stanza to this artifact format. Changing it invalidates
/// all previously written stanzas, so it is versioned together with the suite name.
pub const HPKE_INFO: &[u8] = b"backupctl-artifact-v1";

/// Salt for the HKDF-SHA256-Extract that fuses the two component shared secrets.
/// A non-zero, versioned salt means a future combiner change cannot cross-derive
/// an old artifact's key material.
pub const COMBINE_SALT: &[u8] = b"backupctl-MLKEM768-X25519-v0";

/// Local domain separator for the labeled key-derivation hash. RFC 9180 assigns no
/// private-use range for KEM identifiers and IANA has no X25519 + ML-KEM entry, so
/// this value is never transmitted and claims nothing: it exists only to keep this
/// derivation apart from other `shake256_labeled` users.
pub const KEM_DOMAIN_ID: u16 = 0x00FF;

/// First line of a key file written by this crate, naming the suite the remaining
/// line belongs to. A key file never relies on inference from key length or shape.
pub const IDENTITY_MARKER: &str = "!backupctl-mlkem768x25519-v0";
/// First line of a recipient file, with the same purpose as `IDENTITY_MARKER`.
pub const RECIPIENT_MARKER: &str = IDENTITY_MARKER;

/// Bytes in the hybrid public key: ML-KEM-768 encapsulation key (1184) followed by
/// the X25519 public key (32).
pub const PUBLIC_KEY_BYTES: usize = 1216;
/// Bytes in an encapsulated key: ML-KEM-768 ciphertext (1088) followed by the
/// sender's ephemeral X25519 public key (32).
pub const ENCAPPED_BYTES: usize = 1120;
/// Bytes in the authoritative identity seed, from which both component secret keys
/// are deterministically expanded.
pub const SEED_BYTES: usize = 32;

/// Suite name recorded in a manifest or `public.json` for the origin signature. The
/// name lists both legs in the order they are concatenated below, so changing either
/// leg, that order, or the signed tuple requires a new name — never a reinterpretation
/// of bytes already written.
pub const SUITE_SIGNATURE_HYBRID: &str = "ed25519+ml-dsa-65";

/// First line of a signing key file, with the same purpose as `IDENTITY_MARKER`.
pub const SIGNING_MARKER: &str = "!backupctl-ed25519mldsa65-v0";
/// First line of a verifying key file, with the same purpose as `SIGNING_MARKER`.
pub const VERIFYING_MARKER: &str = SIGNING_MARKER;

/// Domain-separation prefix of the signed tuple, terminated by a NUL so a prefix of
/// one field can never be read as another. It is a distinct constant from `HPKE_INFO`
/// even though the bytes overlap: encryption binds a stanza to this format through
/// HPKE's `info`, and signing binds a signature to this format's *contents* digest,
/// and the two must not be interchangeable.
pub const SIGNATURE_DOMAIN: &[u8] = b"backupctl-artifact-v1\0";
/// Bytes in an artifact's backup id, which is a UUID and therefore fixed-width.
pub const BACKUP_ID_BYTES: usize = 16;
/// Bytes in a SHA-256 digest.
pub const DIGEST_BYTES: usize = 32;
/// Bytes in the exact tuple a signature covers: the domain prefix, the backup id, and
/// the two digests. The reader recomputes it and never parses a signature, so a change
/// here is a new suite name.
pub const SIGNED_TUPLE_BYTES: usize = 22 + 16 + 32 + 32;

/// Bytes in each half of a signing seed line: the Ed25519 seed and the ML-DSA-65 seed
/// are independent 32-byte values, concatenated rather than derived from one another so
/// a weakness in one expansion does not automatically reach the other.
pub const SIGNING_COMPONENT_SEED_BYTES: usize = 32;
/// Bytes in a signing key file's secret line: both component seeds.
pub const SIGNING_SEED_BYTES: usize = SIGNING_COMPONENT_SEED_BYTES * 2;
/// Bytes in an Ed25519 verifying key.
pub const ED25519_VERIFYING_KEY_BYTES: usize = 32;
/// Bytes in an ML-DSA-65 verifying key. Measured against `ml-dsa` 0.1.1 rather than
/// assumed: a reader cannot size a verifying key file without it, and this suite's
/// encodings are exactly where the round-3 candidate and final FIPS 204 disagree — the
/// signature grew from 3293 to 3309 bytes, so a size carried over from the older
/// literature would silently mis-shape every artifact.
pub const MLDSA65_VERIFYING_KEY_BYTES: usize = 1952;
/// Bytes in a verifying key file's public line: both component verifying keys, in the
/// same order as the signature halves.
pub const HYBRID_VERIFYING_KEY_BYTES: usize =
    ED25519_VERIFYING_KEY_BYTES + MLDSA65_VERIFYING_KEY_BYTES;

/// Bytes in the Ed25519 half of an origin signature.
pub const ED25519_SIGNATURE_BYTES: usize = 64;
/// Bytes in the ML-DSA-65 half of an origin signature. As above: FIPS 204 sign, not the
/// round-3 candidate's 3293.
pub const MLDSA65_SIGNATURE_BYTES: usize = 3309;
/// Bytes in `signature.hybrid`. This is the only length the reader accepts for the
/// hybrid suite, and it is derived from the recorded suite name rather than from the
/// file, so a truncated or padded signature is a refusal rather than a parse.
pub const HYBRID_SIGNATURE_BYTES: usize = ED25519_SIGNATURE_BYTES + MLDSA65_SIGNATURE_BYTES;

/// Hex characters in a serialized seed, public key, or encapsulated key.
pub const fn hex_len(bytes: usize) -> usize {
    bytes * 2
}

/// A key file larger than this is not a key file; refuse before allocating or
/// parsing anything.
pub const MAX_KEY_FILE_BYTES: u64 = 8 * 1024;
/// The longest secret key line this crate writes is a 64-byte signing seed pair, so a
/// hex line longer than this is not a key the operator generated: they pasted something
/// else into the file, and no secret parser should be handed it.
pub const MAX_SECRET_HEX_CHARS: usize = 256;

/// A private identity file that is readable or writable by anyone but its owner is
/// refused; this is the mask that must be entirely clear.
pub const PRIVATE_FILE_FORBIDDEN_MODE_BITS: u32 = 0o077;

/// Upper bound on the decrypted plaintext of an artifact, checked while streaming
/// rather than after allocation, so a hostile ciphertext cannot drive unbounded
/// writes into a staging directory.
pub const MAX_DECRYPTED_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    /// These sizes are the ones the artifact contract documents; a typo here would
    /// silently change the wire format.
    #[test]
    fn documented_sizes_are_consistent() {
        assert_eq!(hex_len(PUBLIC_KEY_BYTES), 2432);
        assert_eq!(hex_len(SEED_BYTES), 64);
        assert_eq!(
            age_core::format::FILE_KEY_BYTES,
            16,
            "the wrapped plaintext is one age file key"
        );
        assert_eq!(IDENTITY_MARKER, RECIPIENT_MARKER);
        assert_eq!(
            STANZA_TAG, "mlkem768x25519",
            "changing the stanza tag is a new suite"
        );
        assert_eq!(SIGNING_MARKER, VERIFYING_MARKER);
        assert_eq!(
            SUITE_SIGNATURE_HYBRID, "ed25519+ml-dsa-65",
            "renaming the signature suite is a new suite, not a relabel"
        );
        assert_eq!(
            SIGNATURE_DOMAIN, b"backupctl-artifact-v1\0",
            "the signed tuple's domain prefix is part of the format"
        );
        assert_eq!(
            SIGNED_TUPLE_BYTES,
            SIGNATURE_DOMAIN.len() + BACKUP_ID_BYTES + DIGEST_BYTES * 2
        );
        assert_eq!(hex_len(SIGNING_SEED_BYTES), 128);
        assert_eq!(hex_len(HYBRID_VERIFYING_KEY_BYTES), 3968);
        assert_eq!(hex_len(MLDSA65_VERIFYING_KEY_BYTES), 3904);
        assert_eq!(HYBRID_SIGNATURE_BYTES, 3373);
        assert!(
            MAX_SECRET_HEX_CHARS >= hex_len(SIGNING_SEED_BYTES),
            "a signing seed must fit under the secret-line cap"
        );
        assert!(
            u64::try_from(hex_len(HYBRID_VERIFYING_KEY_BYTES) + VERIFYING_MARKER.len() + 2)
                .expect("a verifying key line is a sane size")
                <= MAX_KEY_FILE_BYTES,
            "the longest key file this crate writes must fit under the size limit"
        );
    }
}
