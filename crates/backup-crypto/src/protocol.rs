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
/// Hex characters in a serialized seed, public key, or encapsulated key.
pub const fn hex_len(bytes: usize) -> usize {
    bytes * 2
}

/// A key file larger than this is not a key file; refuse before allocating or
/// parsing anything.
pub const MAX_KEY_FILE_BYTES: u64 = 8 * 1024;
/// An identity seed must be 32 bytes, so its hex line is exactly this long; a
/// longer line means the operator pasted something else into the file.
pub const MAX_IDENTITY_HEX_CHARS: usize = 256;

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
    }
}
