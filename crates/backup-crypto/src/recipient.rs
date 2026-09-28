//! The `mlkem768x25519` recipient type: age's `age-encryption.org/v1` stream with a
//! hybrid post-quantum stanza.
//!
//! Both traits here are age's documented extension joint. Nothing in this module
//! touches the payload stream, the header MAC, or AEAD framing — age writes and
//! authenticates the file, and this code only wraps and unwraps the 16-byte file key.

use std::collections::HashSet;
use std::fmt;

use age::{DecryptError, Identity, Recipient};
use age_core::{
    format::{FILE_KEY_BYTES, FileKey, Stanza, is_arbitrary_string},
    primitives::{hpke_open, hpke_seal},
    secrecy::{ExposeSecret, zeroize::Zeroize},
};
use anyhow::{Result, bail};
use base64::{Engine as _, prelude::BASE64_STANDARD_NO_PAD};
use hpke::{Deserializable as _, Serializable as _};
use rand::{RngCore as _, rngs::OsRng};

use crate::{
    kem::{MlKem768X25519, PrivateKey, PublicKey},
    protocol::{
        ENCAPPED_BYTES, GREASE_SUFFIX, HPKE_INFO, PUBLIC_KEY_BYTES, SEED_BYTES, STANZA_TAG,
    },
};

type Kem = MlKem768X25519;

/// The public half: wraps an age file key into one artifact header stanza.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridRecipient(PublicKey);

impl HybridRecipient {
    /// Parses the fixed-length hybrid public key encoding.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        // HpkeError is not a std::error::Error, so it is turned into message text
        // here rather than chained.
        let key = PublicKey::from_bytes(encoded)
            .map_err(|_| anyhow::anyhow!("invalid {STANZA_TAG} recipient key"))?;
        Ok(Self(key))
    }

    /// The fixed-length public key encoding written into a recipient file.
    pub fn as_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.0.to_bytes_array()
    }
}

impl From<PublicKey> for HybridRecipient {
    fn from(key: PublicKey) -> Self {
        Self(key)
    }
}

impl fmt::Debug for HybridRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public, but a 1216-byte key is noise inside a log or an error message.
        write!(f, "HybridRecipient({STANZA_TAG})")
    }
}

impl fmt::Display for HybridRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.as_bytes()))
    }
}

impl Recipient for HybridRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        // age-core's helper is HPKE base mode with ChaCha20-Poly1305 + HKDF-SHA256 and
        // empty AAD, which is the only mode this KEM implements.
        let (encapped, ciphertext) =
            hpke_seal::<Kem, _>(&self.0, HPKE_INFO, file_key.expose_secret(), &mut OsRng);

        let stanza = Stanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![BASE64_STANDARD_NO_PAD.encode(encapped.to_bytes().as_slice())],
            body: ciphertext,
        };

        // No labels. age's `postquantum` label is age's own promise about age's own
        // recipient semantics; claiming it would advertise a compatibility this
        // recipient does not have. Claiming nothing is what makes the mixed-header
        // refusal in `HybridIdentity::unwrap_stanzas` necessary rather than redundant.
        Ok((vec![stanza], HashSet::new()))
    }
}

/// The private half. The 32-byte seed is expanded once at load time and is zeroized
/// when this value is dropped; the component keys derived from it are held plainly,
/// the same way age's own recipients hold theirs.
pub struct HybridIdentity {
    key: PrivateKey,
}

impl HybridIdentity {
    /// Expands a fresh random seed. The seed is what a key file stores, so backing up
    /// one 32-byte value recovers both component keys.
    pub fn generate() -> Self {
        let mut seed = [0u8; SEED_BYTES];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: [u8; SEED_BYTES]) -> Self {
        // The only failure mode of this conversion is a wrong length, which the
        // parameter type already prevents.
        Self {
            key: <PrivateKey as hpke::Deserializable>::from_bytes(&seed)
                .expect("a 32-byte seed always expands"),
        }
    }

    pub fn to_recipient(&self) -> HybridRecipient {
        HybridRecipient(<Kem as hpke::Kem>::sk_to_pk(&self.key))
    }

    /// The authoritative seed. Secret: callers pass it straight into a key file write
    /// and drop it.
    pub fn seed(&self) -> [u8; SEED_BYTES] {
        self.key.seed_bytes()
    }

    /// Parses the single secret line of an identity file.
    pub fn from_seed_hex(text: &str) -> Result<Self> {
        let bytes = hex::decode(text.trim())
            .map_err(|e| anyhow::anyhow!("identity seed is not valid lowercase hex: {e}"))?;
        if bytes.len() != SEED_BYTES {
            bail!(
                "identity seed must be exactly {SEED_BYTES} bytes ({} hex characters), got {}",
                SEED_BYTES * 2,
                bytes.len()
            );
        }
        let mut seed = [0u8; SEED_BYTES];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(seed))
    }

    /// The single secret line written into an identity file.
    pub fn to_seed_hex(&self) -> String {
        hex::encode(&self.seed())
    }
}

impl fmt::Debug for HybridIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridIdentity([redacted])")
    }
}

impl Identity for HybridIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != STANZA_TAG {
            // Not our stanza: "no match" rather than an error, so age can keep
            // trying other identities.
            return None;
        }
        if stanza.args.len() != 1 {
            return Some(Err(DecryptError::InvalidHeader));
        }

        let encoded = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[0]) {
            Ok(bytes) => bytes,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        // Exactly one ML-KEM ciphertext plus one ephemeral X25519 key. Short and long
        // stanzas are refused before any decapsulation happens.
        if encoded.len() != ENCAPPED_BYTES {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let Ok(encapped) = <Kem as hpke::Kem>::EncappedKey::from_bytes(&encoded) else {
            return Some(Err(DecryptError::InvalidHeader));
        };

        let mut plaintext = match hpke_open::<Kem>(&encapped, &self.key, HPKE_INFO, &stanza.body) {
            Ok(plaintext) => plaintext,
            // Wrong key, tampered stanza, or a forged ML-KEM ciphertext whose
            // implicit-rejection secret does not open the AEAD.
            Err(_) => return Some(Err(DecryptError::InvalidMac)),
        };

        let result = if plaintext.len() != FILE_KEY_BYTES {
            // Authenticated, and still not a file key: the header is not ours.
            Err(DecryptError::InvalidHeader)
        } else {
            FileKey::try_init_with_mut(|key| {
                key.copy_from_slice(&plaintext);
                Ok::<(), ()>(())
            })
            .map_err(|_| DecryptError::InvalidHeader)
        };
        plaintext.zeroize();
        Some(result)
    }

    /// Refuse any header this identity is asked to open that is not exactly one
    /// stanza of our own type.
    ///
    /// age happily writes several stanzas for one file key, and our recipient claims
    /// no labels, so nothing else stops an operator from adding a classical-only
    /// recovery recipient — and such an artifact then decrypts with an X25519 key
    /// alone, which is exactly the single break the hybrid construction exists to
    /// remove. A header holding only foreign stanzas returns `None`, so a genuinely
    /// classical file can still be opened by a classical identity in the same keyring.
    ///
    /// The one exception is age's grease stanza, which `HeaderV1::new` appends to
    /// every header it writes: a rule that demanded a single stanza in total would
    /// reject every artifact this crate itself produces. A grease tag ends in
    /// `-grease` and carries only arbitrary printable strings, so it can never be a
    /// key-bearing stanza any identity would recognise; anything else in the header is
    /// a second recipient and is refused.
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, DecryptError>> {
        let ours: Vec<&Stanza> = stanzas
            .iter()
            .filter(|stanza| stanza.tag == STANZA_TAG)
            .collect();
        if ours.is_empty() {
            return None;
        }
        let foreign = stanzas
            .iter()
            .filter(|stanza| stanza.tag != STANZA_TAG && !is_grease_stanza(stanza))
            .count();
        if ours.len() != 1 || foreign != 0 {
            return Some(Err(DecryptError::InvalidHeader));
        }
        self.unwrap_stanza(ours[0])
    }
}

/// age's compatibility noise stanza, which `HeaderV1::new` appends to every header it
/// writes. Recognising it is required for the single-recipient rule to describe real
/// artifacts rather than an idealized header; nothing else may share a header with our
/// stanza.
fn is_grease_stanza(stanza: &Stanza) -> bool {
    stanza.tag.ends_with(GREASE_SUFFIX)
        && is_arbitrary_string(&stanza.tag)
        && stanza.args.iter().all(is_arbitrary_string)
}

/// Minimal lowercase hex, private to this crate. One canonical form (lowercase, no
/// separators) with no room for a per-module variation in a format that is already
/// versioned by name.
pub(crate) mod hex {
    /// Encodes bytes as lowercase hex.
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(char::from_digit((byte >> 4).into(), 16).expect("4 bits"));
            out.push(char::from_digit((byte & 0x0f).into(), 16).expect("4 bits"));
        }
        out
    }

    /// Decodes strictly lowercase hex. Uppercase, inner whitespace, and odd lengths
    /// are all rejected: a key file that needs tolerance is a key file that would
    /// need guessing.
    pub fn decode(text: &str) -> std::result::Result<Vec<u8>, String> {
        let digits = text.as_bytes();
        if !digits.len().is_multiple_of(2) {
            return Err("odd number of hex characters".to_string());
        }
        let mut out = Vec::with_capacity(digits.len() / 2);
        for pair in digits.chunks_exact(2) {
            out.push((value(pair[0])? << 4) | value(pair[1])?);
        }
        Ok(out)
    }

    fn value(byte: u8) -> std::result::Result<u8, String> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(format!("invalid lowercase hex byte {byte:#04x}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519;

    /// Poly1305 tag length HPKE adds to the wrapped file key.
    const AEAD_TAG_BYTES: usize = 16;

    fn file_key(byte: u8) -> FileKey {
        FileKey::init_with_mut(|key| key.copy_from_slice(&[byte; FILE_KEY_BYTES]))
    }

    /// age's `Stanza` is not `Clone`, and a tampering test must not consume the
    /// original it compares against.
    fn copy(stanza: &Stanza) -> Stanza {
        Stanza {
            tag: stanza.tag.clone(),
            args: stanza.args.clone(),
            body: stanza.body.clone(),
        }
    }

    /// Wrapping and unwrapping one file key returns exactly what went in, and the
    /// stanza carries the sizes the artifact contract records.
    #[test]
    fn wrap_unwrap_round_trip_and_stanza_shape() {
        let identity = HybridIdentity::generate();
        let recipient = identity.to_recipient();
        let key = file_key(3);

        let (stanzas, labels) = recipient.wrap_file_key(&key).unwrap();
        assert_eq!(stanzas.len(), 1);
        assert_eq!(stanzas[0].tag, STANZA_TAG);
        assert!(labels.is_empty(), "this recipient claims no age labels");
        assert_eq!(
            BASE64_STANDARD_NO_PAD
                .decode(&stanzas[0].args[0])
                .unwrap()
                .len(),
            ENCAPPED_BYTES,
            "one ML-KEM ciphertext plus an ephemeral X25519 key"
        );
        assert_eq!(
            stanzas[0].body.len(),
            FILE_KEY_BYTES + AEAD_TAG_BYTES,
            "the wrapped file key plus a Poly1305 tag"
        );

        let opened = identity
            .unwrap_stanzas(&stanzas)
            .expect("our own stanza matches")
            .expect("unwrap succeeds");
        assert_eq!(opened.expose_secret(), key.expose_secret());
    }

    /// Two fresh identities share nothing, and the seed's text form round trips.
    #[test]
    fn generation_is_random_and_text_forms_round_trip() {
        let a = HybridIdentity::generate();
        let b = HybridIdentity::generate();
        assert_ne!(a.seed(), b.seed());
        assert_ne!(a.to_recipient(), b.to_recipient());

        let seed_hex = a.to_seed_hex();
        assert_eq!(seed_hex.len(), SEED_BYTES * 2);
        let reloaded = HybridIdentity::from_seed_hex(&seed_hex).unwrap();
        assert_eq!(reloaded.seed(), a.seed());
        assert_eq!(reloaded.to_recipient(), a.to_recipient());

        let recipient_hex = a.to_recipient().to_string();
        assert_eq!(recipient_hex.len(), PUBLIC_KEY_BYTES * 2);
        assert_eq!(
            HybridRecipient::from_bytes(&hex::decode(&recipient_hex).unwrap()).unwrap(),
            a.to_recipient()
        );
    }

    /// Every malformed stanza is rejected, with the parser and the AEAD never
    /// confused about which one failed.
    #[test]
    fn malformed_stanzas_are_rejected() {
        let identity = HybridIdentity::generate();
        let (stanzas, _) = identity.to_recipient().wrap_file_key(&file_key(9)).unwrap();
        let good = &stanzas[0];

        let foreign = Stanza {
            tag: "x25519".to_string(),
            args: good.args.clone(),
            body: good.body.clone(),
        };
        assert!(
            identity.unwrap_stanza(&foreign).is_none(),
            "a foreign tag must be no-match, not an error"
        );

        for args in [vec![], vec![good.args[0].clone(); 2]] {
            let stanza = Stanza {
                tag: STANZA_TAG.to_string(),
                args,
                body: good.body.clone(),
            };
            assert!(matches!(
                identity.unwrap_stanza(&stanza),
                Some(Err(DecryptError::InvalidHeader))
            ));
        }

        let encoded = BASE64_STANDARD_NO_PAD.decode(&good.args[0]).unwrap();
        for bad in [
            encoded[..ENCAPPED_BYTES - 1].to_vec(),
            [encoded.as_slice(), &[0u8]].concat(),
        ] {
            let stanza = Stanza {
                tag: STANZA_TAG.to_string(),
                args: vec![BASE64_STANDARD_NO_PAD.encode(&bad)],
                body: good.body.clone(),
            };
            assert!(
                matches!(
                    identity.unwrap_stanza(&stanza),
                    Some(Err(DecryptError::InvalidHeader))
                ),
                "encapsulated key of {} bytes must be refused",
                bad.len()
            );
        }

        let stanza = Stanza {
            tag: STANZA_TAG.to_string(),
            args: vec!["not base64!!!".to_string()],
            body: good.body.clone(),
        };
        assert!(matches!(
            identity.unwrap_stanza(&stanza),
            Some(Err(DecryptError::InvalidHeader))
        ));

        // An empty body is well-formed and fails authentication instead.
        let stanza = Stanza {
            tag: STANZA_TAG.to_string(),
            args: good.args.clone(),
            body: vec![],
        };
        assert!(matches!(
            identity.unwrap_stanza(&stanza),
            Some(Err(DecryptError::InvalidMac))
        ));
    }

    /// A wrong identity and a tampered stanza both fail on the AEAD tag, including
    /// a bit flipped inside the encapsulated key where ML-KEM reports success.
    #[test]
    fn wrong_key_and_tampering_fail_closed() {
        let identity = HybridIdentity::generate();
        let other = HybridIdentity::generate();
        let (stanzas, _) = identity.to_recipient().wrap_file_key(&file_key(5)).unwrap();

        assert!(matches!(
            other.unwrap_stanzas(&stanzas),
            Some(Err(DecryptError::InvalidMac))
        ));

        let mut flipped_body = vec![copy(&stanzas[0])];
        let last = flipped_body[0].body.len() - 1;
        flipped_body[0].body[last] ^= 0x01;
        assert!(matches!(
            identity.unwrap_stanzas(&flipped_body),
            Some(Err(DecryptError::InvalidMac))
        ));

        let mut reencoded = BASE64_STANDARD_NO_PAD.decode(&stanzas[0].args[0]).unwrap();
        reencoded[0] ^= 0x01;
        let mut flipped_key = vec![copy(&stanzas[0])];
        flipped_key[0].args[0] = BASE64_STANDARD_NO_PAD.encode(&reencoded);
        assert!(
            matches!(
                identity.unwrap_stanzas(&flipped_key),
                Some(Err(DecryptError::InvalidMac))
            ),
            "implicit rejection must still be stopped by the tag"
        );
    }

    /// The single-stanza rule, which is the whole defense against a classical
    /// escape hatch.
    #[test]
    fn mixed_or_duplicated_headers_are_refused() {
        let identity = HybridIdentity::generate();
        let (ours, _) = identity.to_recipient().wrap_file_key(&file_key(7)).unwrap();
        let ours = ours.into_iter().next().unwrap();

        let foreign = Stanza {
            tag: "x25519".to_string(),
            args: vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
            body: vec![],
        };

        for mixed in [[copy(&ours), copy(&foreign)], [copy(&foreign), copy(&ours)]] {
            assert!(
                matches!(
                    identity.unwrap_stanzas(&mixed),
                    Some(Err(DecryptError::InvalidHeader))
                ),
                "a classical-only stanza beside ours must fail the artifact"
            );
        }

        assert!(
            matches!(
                identity.unwrap_stanzas(&[copy(&ours), copy(&ours)]),
                Some(Err(DecryptError::InvalidHeader))
            ),
            "two stanzas for one file key is ambiguous and refused"
        );

        // Only foreign stanzas: not our file, so a classical identity in the same
        // keyring still gets its chance.
        assert!(identity.unwrap_stanzas(&[foreign]).is_none());
    }

    /// age appends a random grease stanza to every header it writes, so the
    /// single-recipient rule has to tolerate exactly that and refuse everything else.
    #[test]
    fn grease_is_the_only_foreign_stanza_a_header_may_carry() {
        let identity = HybridIdentity::generate();
        let (stanzas, _) = identity
            .to_recipient()
            .wrap_file_key(&file_key(11))
            .unwrap();
        let ours = &stanzas[0];

        // Grease tags and args are random printable strings, so the shape has to be
        // probed over many draws rather than one lucky sample.
        for _ in 0..64 {
            let grease = age_core::format::grease_the_joint();
            assert!(
                identity
                    .unwrap_stanzas(&[copy(ours), copy(&grease)])
                    .expect("our stanza makes this header ours")
                    .is_ok(),
                "grease stanza tag {:?} must not break the artifact",
                grease.tag
            );
            assert!(grease.tag.ends_with(GREASE_SUFFIX));
        }

        // A tag that merely ends in `-grease` is tolerated because no identity reads it
        // as a key: age's own classical recipient matches its exact tag, not a suffix.
        let disguised = Stanza {
            tag: format!("X25519{GREASE_SUFFIX}"),
            args: vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
            body: vec![],
        };
        assert!(
            x25519::Identity::generate()
                .unwrap_stanza(&disguised)
                .is_none(),
            "a disguised tag must be inert for the classical recipient too"
        );
        assert!(
            identity
                .unwrap_stanzas(&[copy(ours), copy(&disguised)])
                .expect("header is ours")
                .is_ok()
        );
    }

    /// age's own checks will not stop a mixed recipient list, so the refusal has to
    /// live where it does. This is the regression test for that assumption.
    #[test]
    fn age_accepts_mixed_recipients_so_the_identity_must_refuse() {
        let hybrid = HybridIdentity::generate().to_recipient();
        let classical = x25519::Identity::generate().to_public();

        let encryptor = age::Encryptor::with_recipients(
            [&classical as &dyn Recipient, &hybrid as &dyn Recipient].into_iter(),
        );
        assert!(
            encryptor.is_ok(),
            "both report empty labels, so age sees no conflict: {} of ours must refuse it",
            STANZA_TAG
        );
    }

    /// Key material must never reach `Debug`, an error string, or a log line.
    #[test]
    fn private_material_stays_unprintable() {
        let identity = HybridIdentity::generate();
        let seed_hex = identity.to_seed_hex();
        assert_eq!(format!("{identity:?}"), "HybridIdentity([redacted])");
        assert!(
            !format!("{:?}", identity.key).contains(&seed_hex),
            "the inner private key must not render its seed"
        );

        let error = HybridRecipient::from_bytes(&[0u8; 1])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(STANZA_TAG),
            "the error names the recipient type"
        );
        assert!(!error.contains(&seed_hex), "and never echoes key material");
    }

    /// Hex codec edge cases a real key file can hit.
    #[test]
    fn hex_codec_is_strict_lowercase() {
        assert_eq!(hex::encode(&[0x0a, 0xff]), "0aff");
        assert_eq!(hex::decode("0aff").unwrap(), vec![0x0a, 0xff]);
        assert!(hex::decode("0AFF").is_err(), "uppercase is rejected");
        assert!(hex::decode("0a f").is_err(), "inner whitespace is rejected");
        assert!(
            hex::decode(" 0aff").is_err(),
            "leading whitespace is rejected"
        );
        assert!(hex::decode("0af").is_err(), "odd length is rejected");
        assert!(hex::decode("0g").is_err(), "non-hex is rejected");
        assert!(hex::decode("").is_ok());
    }

    /// An identity file line with the wrong length or shape is refused rather than
    /// padded or truncated into a usable key.
    #[test]
    fn seed_text_validation_is_exact() {
        assert!(HybridIdentity::from_seed_hex(&"0".repeat(63)).is_err());
        assert!(HybridIdentity::from_seed_hex(&"0".repeat(65)).is_err());
        assert!(HybridIdentity::from_seed_hex(&"g".repeat(64)).is_err());
        // Surrounding whitespace from an editor is tolerated; the codec itself is strict.
        assert!(HybridIdentity::from_seed_hex(&format!(" {}\n", "f".repeat(64))).is_ok());
        assert!(HybridIdentity::from_seed_hex(&"f".repeat(64)).is_ok());
    }
}
