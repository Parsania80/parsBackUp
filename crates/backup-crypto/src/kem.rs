//! The hybrid ML-KEM-768 + X25519 key agreement behind the `mlkem768x25519`
//! recipient, exposed as an [`hpke::Kem`] so all framing stays in the `hpke` crate.
//!
//! Only the key agreement lives here. The AEAD, the nonce, the key schedule and the
//! age stream all come from `age-core`/`hpke`, which is the reason this crate can
//! claim a post-quantum property without owning any confidential-data-processing
//! code of its own.
//!
//! Two rules this module exists to enforce:
//!
//! - **Component ordering.** The combined secret puts the ML-KEM shared secret
//!   first, per RFC 10024's convention for `X25519MLKEM768`. Swapping the two would
//!   change every derived key and is therefore a suite change, not a fix.
//! - **Base mode only.** HPKE's `Auth`/`PSK` modes are unreachable. The sealing and
//!   opening helpers used by this crate are `age_core`'s base-mode helpers, and
//!   [`hpke::Kem::encap`]/[`hpke::Kem::decap`] reject a sender-identity parameter
//!   rather than panicking on it, so an authenticated-mode call fails as an error
//!   instead of aborting the process.

use age_core::secrecy::zeroize::{Zeroize, Zeroizing};
use hkdf::Hkdf;
use hpke::{
    Deserializable, HpkeError, Serializable,
    generic_array::{GenericArray, typenum::Unsigned},
    kem::SharedSecret,
};
use ml_kem::{
    Ciphertext, EncodedSizeUser, KemCore, MlKem768,
    kem::{Decapsulate, Encapsulate},
};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use typenum::{Sum, U32};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use crate::protocol::{COMBINE_SALT, KEM_DOMAIN_ID, PUBLIC_KEY_BYTES, SEED_BYTES};

/// ML-KEM-768 encapsulation key length (1184 bytes).
type MlkemEkLen = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
/// ML-KEM-768 ciphertext length (1088 bytes).
type MlkemCtLen = <MlKem768 as KemCore>::CiphertextSize;
/// X25519 public key and shared secret length (32 bytes).
type GroupLen = U32;

/// Hybrid post-quantum + classical key agreement.
pub struct MlKem768X25519;

impl hpke::Kem for MlKem768X25519 {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;
    type NSecret = U32;

    /// Local domain separator only; see [`crate::protocol::KEM_DOMAIN_ID`].
    const KEM_ID: u16 = KEM_DOMAIN_ID;

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        PublicKey {
            ek_pq: sk.dk_pq.encapsulation_key().clone(),
            pk_x: X25519PublicKey::from(&sk.sk_x),
        }
    }

    /// Deterministically derives a key pair from keying material. The result has the
    /// same shape a stored identity seed expands to, so a derived key and a random
    /// key are interchangeable in a key file.
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let seed = shake256_labeled::<SEED_BYTES>(ikm, Self::KEM_ID, b"DeriveKeyPair", b"");
        let (dk_pq, sk_x) = expand_seed(&seed);
        let sk = PrivateKey {
            seed: Zeroizing::new(seed),
            dk_pq,
            sk_x,
        };
        let pk = Self::sk_to_pk(&sk);
        (sk, pk)
    }

    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        if sender_id_keypair.is_some() {
            return Err(HpkeError::ValidationError);
        }

        // Post-quantum leg. ml-kem reports RNG failure as `()`; there is no
        // malformed-encapsulation-key path, so this only fails if the CSPRNG does.
        let (ct_pq, ss_pq) = pk_recip
            .ek_pq
            .encapsulate(csprng)
            .map_err(|()| HpkeError::EncapError)?;

        // Classical leg: an ephemeral X25519 key pair against the recipient's key.
        let sk_e = EphemeralSecret::random_from_rng(&mut *csprng);
        let ct_x = X25519PublicKey::from(&sk_e);
        let ss_x = sk_e.diffie_hellman(&pk_recip.pk_x);

        let shared = combine(
            ss_pq.as_slice(),
            ss_x.as_bytes(),
            ct_x.as_bytes(),
            pk_recip.pk_x.as_bytes(),
        );
        Ok((
            SharedSecret(shared),
            EncappedKey {
                ct_pq,
                ct_x: *ct_x.as_bytes(),
            },
        ))
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        if pk_sender_id.is_some() {
            return Err(HpkeError::ValidationError);
        }

        // ML-KEM decapsulation is implicit rejection: a forged or malformed
        // ciphertext yields a pseudorandom secret rather than an error, and the HPKE
        // AEAD tag check in the caller then fails. There is therefore no PQ validity
        // check to oracle, and no partial-success path to leak.
        let ss_pq = sk_recip
            .dk_pq
            .decapsulate(&encapped_key.ct_pq)
            .map_err(|()| HpkeError::DecapError)?;
        let pk_x = X25519PublicKey::from(&sk_recip.sk_x);
        let ss_x = sk_recip
            .sk_x
            .diffie_hellman(&X25519PublicKey::from(encapped_key.ct_x));

        Ok(SharedSecret(combine(
            ss_pq.as_slice(),
            ss_x.as_bytes(),
            &encapped_key.ct_x,
            pk_x.as_bytes(),
        )))
    }
}

/// Hybrid secret key. The 32-byte seed is authoritative: both component secret keys
/// are deterministically expanded from it, which is what makes a key file a single
/// short line and what lets rotation discard one copy rather than two.
#[derive(Clone)]
pub struct PrivateKey {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    dk_pq: <MlKem768 as KemCore>::DecapsulationKey,
    sk_x: StaticSecret,
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        // Derived material, so the seed is the whole identity of the key.
        self.seed[..] == other.seed[..]
    }
}

impl Eq for PrivateKey {}

/// Never print key material, and never let `{:?}` reach a log.
impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let seed: [u8; SEED_BYTES] = encoded.try_into().map_err(|_| {
            HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        let (dk_pq, sk_x) = expand_seed(&seed);
        Ok(Self {
            seed: Zeroizing::new(seed),
            dk_pq,
            sk_x,
        })
    }
}

impl Serializable for PrivateKey {
    /// The seed alone is the serialized private key.
    type OutputSize = U32;

    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(self.seed.as_ref());
    }
}

impl PrivateKey {
    /// The authoritative seed, for writing a key file. Callers must treat the
    /// returned bytes as secret; they exist as an escape hatch from `Zeroizing`,
    /// not as a licence to copy them around.
    pub(crate) fn seed_bytes(&self) -> [u8; SEED_BYTES] {
        *self.seed
    }
}

/// Hybrid public key: ML-KEM-768 encapsulation key followed by the X25519 key.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    ek_pq: <MlKem768 as KemCore>::EncapsulationKey,
    pk_x: X25519PublicKey,
}

/// `ml-kem`'s encoded types are `PartialEq` but not `Eq`; equality over the
/// encapsulation key bytes is total, so the extra bound is asserted here.
impl Eq for PublicKey {}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Exact length, no truncation and no trailing bytes: a key file with one
        // stray character is a corrupt key file, not a key file plus noise.
        if encoded.len() != Self::OutputSize::to_usize() {
            return Err(HpkeError::IncorrectInputLength(
                Self::OutputSize::to_usize(),
                encoded.len(),
            ));
        }
        let (encoded_pq, encoded_x) = encoded.split_at(MlkemEkLen::to_usize());
        let ek_pq = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(
            encoded_pq.try_into().expect("checked above"),
        );
        // Every 32-byte string is an acceptable X25519 window here. A hostile
        // ephemeral key cannot zero the combined secret, because the ML-KEM half is
        // independent and the transcript binding below changes with it.
        let pk_x = X25519PublicKey::from(<[u8; 32]>::try_from(encoded_x).expect("checked above"));
        Ok(Self { ek_pq, pk_x })
    }
}

impl Serializable for PublicKey {
    type OutputSize = Sum<MlkemEkLen, GroupLen>;

    fn write_exact(&self, buf: &mut [u8]) {
        let ek_len = MlkemEkLen::to_usize();
        buf[..ek_len].copy_from_slice(&self.ek_pq.as_bytes());
        buf[ek_len..].copy_from_slice(self.pk_x.as_bytes());
    }
}

impl PublicKey {
    /// The hybrid public key in its `PUBLIC_KEY_BYTES` encoding.
    pub fn to_bytes_array(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let mut out = [0u8; PUBLIC_KEY_BYTES];
        self.write_exact(&mut out);
        out
    }
}

/// Encapsulated key: ML-KEM-768 ciphertext followed by the sender's ephemeral
/// X25519 public key.
#[derive(Clone, Debug)]
pub struct EncappedKey {
    ct_pq: Ciphertext<MlKem768>,
    ct_x: [u8; 32],
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != Self::OutputSize::to_usize() {
            return Err(HpkeError::IncorrectInputLength(
                Self::OutputSize::to_usize(),
                encoded.len(),
            ));
        }
        let (encoded_pq, encoded_x) = encoded.split_at(MlkemCtLen::to_usize());
        let ct_pq = <[u8; MlkemCtLen::USIZE]>::try_from(encoded_pq)
            .expect("checked above")
            .into();
        Ok(Self {
            ct_pq,
            ct_x: <[u8; 32]>::try_from(encoded_x).expect("checked above"),
        })
    }
}

impl Serializable for EncappedKey {
    type OutputSize = Sum<MlkemCtLen, GroupLen>;

    fn write_exact(&self, buf: &mut [u8]) {
        let ct_len = MlkemCtLen::to_usize();
        buf[..ct_len].copy_from_slice(&self.ct_pq.0);
        buf[ct_len..].copy_from_slice(&self.ct_x);
    }
}

/// Expands the authoritative seed into both component secret keys.
///
/// `SHAKE256(seed)` supplies 96 bytes: the first 64 are ML-KEM's `(d, z)` pair,
/// which FIPS 203 defines as the key-derivation input, and the next 32 are the
/// X25519 scalar, which RFC 7748 accepts verbatim after clamping. The two legs read
/// disjoint regions of one extendable output, so no per-leg domain separator is
/// needed; age's own post-quantum KEM expands its seed the same way.
fn expand_seed(seed: &[u8; SEED_BYTES]) -> (<MlKem768 as KemCore>::DecapsulationKey, StaticSecret) {
    let mut pq_material = [0u8; 64];
    let mut scalar = [0u8; 32];
    let mut xof = Shake256::default().chain(seed).finalize_xof();
    xof.read(&mut pq_material);
    xof.read(&mut scalar);

    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&pq_material[..32]);
    z.copy_from_slice(&pq_material[32..]);
    let (dk_pq, _ek_pq) = MlKem768::generate_deterministic(&d.into(), &z.into());
    let sk_x = StaticSecret::from(scalar);

    pq_material.zeroize();
    d.zeroize();
    z.zeroize();
    scalar.zeroize();

    (dk_pq, sk_x)
}

/// RFC 9180's labeled hash, used only by [`hpke::Kem::derive_keypair`].
fn shake256_labeled<const L: usize>(
    ikm: &[u8],
    kem_id: u16,
    label: &[u8],
    context: &[u8],
) -> [u8; L] {
    let mut out = [0u8; L];
    Shake256::default()
        .chain(ikm)
        .chain(b"HPKE-v1")
        // suite_id
        .chain(b"KEM")
        .chain(kem_id.to_be_bytes())
        // prefixed_label
        .chain(
            u16::try_from(label.len())
                .expect("short enough")
                .to_be_bytes(),
        )
        .chain(label)
        .chain(u16::try_from(L).expect("short enough").to_be_bytes())
        .chain(context)
        .finalize_xof_into(&mut out);
    out
}

/// Fuses the two component shared secrets into the single 32-byte HPKE secret.
///
/// `HKDF-SHA256-Extract(salt = COMBINE_SALT, ikm = ss_ml-kem || ss_x25519 ||
/// ct_x25519 || pk_x25519)`. The secrets are in RFC 10024's order — the
/// FIPS-approved component first — and both X25519 public keys are bound into the
/// input so a secret produced under one key pair cannot be replayed against
/// another. This is deliberately *not* RFC 9180's bare `Extract(salt = 0, ss1 ||
/// ss2)`; the binding is the point, and age's own hybrid recipient does the same
/// thing with a labeled SHA3-256. Extract-only (no Expand) is correct here because
/// the `hpke` key schedule runs its own labeled expands over the result.
fn combine(ss_pq: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> GenericArray<u8, U32> {
    let mut ikm = Vec::with_capacity(ss_pq.len() + ss_x.len() + ct_x.len() + pk_x.len());
    ikm.extend_from_slice(ss_pq);
    ikm.extend_from_slice(ss_x);
    ikm.extend_from_slice(ct_x);
    ikm.extend_from_slice(pk_x);

    let (prk, _expanded) = Hkdf::<Sha256>::extract(Some(COMBINE_SALT), &ikm);
    ikm.zeroize();
    prk
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ENCAPPED_BYTES;

    fn keypair(seed: [u8; SEED_BYTES]) -> (PrivateKey, PublicKey) {
        (
            <MlKem768X25519 as hpke::Kem>::PrivateKey::from_bytes(&seed).unwrap(),
            <MlKem768X25519 as hpke::Kem>::sk_to_pk(
                &<MlKem768X25519 as hpke::Kem>::PrivateKey::from_bytes(&seed).unwrap(),
            ),
        )
    }

    /// One seed must always produce one key pair, in both directions of the
    /// seed/public-key round trip, or a key file cannot be trusted to be stable.
    #[test]
    fn seed_expansion_is_deterministic_and_round_trips() {
        let seed = [7u8; SEED_BYTES];
        let (sk_a, pk_a) = keypair(seed);
        let (sk_b, pk_b) = keypair(seed);
        assert_eq!(sk_a, sk_b);
        assert_eq!(pk_a, pk_b);
        assert_eq!(
            pk_a.to_bytes_array().to_vec(),
            pk_b.to_bytes_array().to_vec()
        );
        assert_eq!(sk_a.seed_bytes(), seed);
        assert_eq!(
            <PrivateKey as Serializable>::to_bytes(&sk_a).as_slice(),
            &seed[..]
        );

        // A different seed is a different key, with no partial collision.
        let (_, other_pk) = keypair([8u8; SEED_BYTES]);
        assert_ne!(pk_a, other_pk);
    }

    /// The public key and encapsulated key have exactly the sizes the artifact
    /// contract records, and both deserializations reject ±1 byte.
    #[test]
    fn serialization_sizes_and_length_rejection() {
        let (sk, pk) = keypair([42u8; SEED_BYTES]);
        assert_eq!(PUBLIC_KEY_BYTES, <PublicKey as Serializable>::size());
        assert_eq!(
            PUBLIC_KEY_BYTES,
            <MlkemEkLen as Unsigned>::to_usize() + 32,
            "ML-KEM-768 encapsulation key plus X25519"
        );
        assert_eq!(
            ENCAPPED_BYTES,
            <MlkemCtLen as Unsigned>::to_usize() + 32,
            "ML-KEM-768 ciphertext plus ephemeral X25519"
        );
        assert_eq!(
            ENCAPPED_BYTES,
            <EncappedKey as Serializable>::size(),
            "the deserializer checks against this same length"
        );

        let encoded = pk.to_bytes_array().to_vec();
        assert_eq!(encoded.len(), PUBLIC_KEY_BYTES);
        assert_eq!(PublicKey::from_bytes(&encoded).unwrap(), pk);

        assert!(
            PublicKey::from_bytes(&encoded[..PUBLIC_KEY_BYTES - 1]).is_err(),
            "one byte short"
        );
        let mut long = encoded.clone();
        long.push(0);
        assert!(PublicKey::from_bytes(&long).is_err(), "one byte long");

        assert!(PrivateKey::from_bytes(&[0u8; 31]).is_err(), "short seed");
        let mut long_seed = vec![0u8; 33];
        long_seed[32] = 1;
        assert!(PrivateKey::from_bytes(&long_seed).is_err(), "long seed");

        assert_eq!(sk, sk.clone());
        assert_eq!(
            format!("{sk:?}"),
            "PrivateKey { .. }",
            "a private key must never render its material"
        );
    }

    /// HPKE authenticated mode is not implemented, and asking for it is an error
    /// rather than a panic.
    #[test]
    fn sender_identity_is_rejected_not_panicking() {
        let (sk, pk) = keypair([1u8; SEED_BYTES]);
        let (sender_sk, sender_pk) = keypair([2u8; SEED_BYTES]);
        let mut rng = rand::rngs::OsRng;

        let authenticated =
            <MlKem768X25519 as hpke::Kem>::encap(&pk, Some((&sender_sk, &sender_pk)), &mut rng);
        assert!(
            matches!(authenticated, Err(HpkeError::ValidationError)),
            "authenticated encapsulation must fail closed as an error"
        );

        let (_, encapped) = <MlKem768X25519 as hpke::Kem>::encap(&pk, None, &mut rng).unwrap();
        let authenticated_open =
            <MlKem768X25519 as hpke::Kem>::decap(&sk, Some(&sender_pk), &encapped);
        assert!(
            matches!(authenticated_open, Err(HpkeError::ValidationError)),
            "authenticated decapsulation must fail closed as an error"
        );
    }

    /// Both legs must contribute: with the classical half forced to a constant, the
    /// combined secret still depends on the ML-KEM ciphertext, and vice versa.
    #[test]
    fn combiner_depends_on_every_component() {
        let base = combine(
            b"post-quantum-secret-32-bytes-ok!",
            b"classical-32",
            &[1u8; 32],
            &[2u8; 32],
        );
        let pq_changed = combine(
            b"post-quantum-secret-32-bytes-OK!",
            b"classical-32",
            &[1u8; 32],
            &[2u8; 32],
        );
        let classical_changed = combine(
            b"post-quantum-secret-32-bytes-ok!",
            b"classical-31",
            &[1u8; 32],
            &[2u8; 32],
        );
        let eph_changed = combine(
            b"post-quantum-secret-32-bytes-ok!",
            b"classical-32",
            &[3u8; 32],
            &[2u8; 32],
        );
        let recipient_changed = combine(
            b"post-quantum-secret-32-bytes-ok!",
            b"classical-32",
            &[1u8; 32],
            &[3u8; 32],
        );

        assert_ne!(base, pq_changed);
        assert_ne!(base, classical_changed);
        assert_ne!(base, eph_changed);
        assert_ne!(base, recipient_changed);

        // Swapping the component order is a different suite: the derivation must not
        // be symmetric, otherwise a future reordering would silently decrypt.
        let swapped = combine(
            b"classical-32",
            b"post-quantum-secret-32-bytes-ok!",
            &[1u8; 32],
            &[2u8; 32],
        );
        assert_ne!(base, swapped, "ML-KEM first is part of the format");
    }

    /// `derive_keypair` and a stored seed produce interchangeable keys.
    #[test]
    fn derived_keypair_uses_the_same_seed_expansion() {
        let (sk, pk) = <MlKem768X25519 as hpke::Kem>::derive_keypair(&[9u8; SEED_BYTES]);
        assert_eq!(<MlKem768X25519 as hpke::Kem>::sk_to_pk(&sk), pk);
        let reresolved = PrivateKey::from_bytes(&sk.seed_bytes()).unwrap();
        assert_eq!(reresolved, sk, "a derived key round-trips through its seed");
    }
}
