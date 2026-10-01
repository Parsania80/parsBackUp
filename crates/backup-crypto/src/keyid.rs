//! The derived key fingerprints a v1 artifact records as `recipient_id` and `signer_id`.
//!
//! An id an operator could set is an id that could lie about which key opened an artifact,
//! so both are computed from public key bytes alone, each under its own domain prefix. The
//! prefixes are why the same bytes would still yield two different ids: an id identifies a
//! *role*, not a bit pattern.
//!
//! Truncation to [`crate::protocol::KEY_ID_HEX_CHARS`] is deliberate. These ids are printed
//! so a human can see a mis-set configuration; the binding an artifact actually relies on
//! is the signature, which covers full-length digests.

use sha2::{Digest as _, Sha256};

use crate::protocol::{KEY_ID_HEX_CHARS, RECIPIENT_ID_DOMAIN, SIGNER_ID_DOMAIN};
use crate::recipient::hex;

/// `KEY_ID_HEX_CHARS` lowercase hex characters of `SHA-256(domain ‖ public key)`.
fn derive(domain: &[u8], public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(public_key);
    let digest = hasher.finalize();
    hex::encode(&digest[..KEY_ID_HEX_CHARS / 2])
}

/// The fingerprint of a recipient public key, as a manifest's `recipient_id`.
pub fn recipient_id(public_key: &[u8]) -> String {
    derive(RECIPIENT_ID_DOMAIN, public_key)
}

/// The fingerprint of a verifying key, as a manifest's and `public.json`'s `signer_id`.
pub fn signer_id(public_key: &[u8]) -> String {
    derive(SIGNER_ID_DOMAIN, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{HYBRID_VERIFYING_KEY_BYTES, PUBLIC_KEY_BYTES};

    /// A golden per domain, on an all-zero key. Without these, changing a prefix string
    /// would silently relabel every artifact this project has ever written.
    #[test]
    fn derivation_is_the_documented_domain_prefix() {
        assert_eq!(
            recipient_id(&[0u8; PUBLIC_KEY_BYTES]),
            "aa4f47e4765ea953",
            "recipient id is SHA-256 over the recipient domain and the key bytes"
        );
        assert_eq!(
            signer_id(&[0u8; HYBRID_VERIFYING_KEY_BYTES]),
            "066b3a10521b73ac"
        );
    }

    /// The two ids must never agree for one key, or a store could not tell a recipient
    /// file from a verifying file by the ids it records.
    #[test]
    fn the_two_roles_derive_different_ids_from_the_same_bytes() {
        let key = [7u8; 64];
        assert_ne!(recipient_id(&key), signer_id(&key));
    }

    #[test]
    fn an_id_is_lowercase_hex_of_the_recorded_width() {
        let id = recipient_id(b"any public key bytes");
        assert_eq!(id.len(), KEY_ID_HEX_CHARS);
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{id}"
        );
    }
}
