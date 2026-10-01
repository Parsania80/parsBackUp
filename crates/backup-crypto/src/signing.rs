//! The M4b origin signature: a hybrid Ed25519 + ML-DSA-65 key pair, the exact byte
//! tuple it covers, and the key files that hold both halves.
//!
//! Encryption proves nobody else read the artifact. This proves who wrote it, which is
//! a different claim and needs a different key: the recipient half can be handed to a
//! host that may only produce backups, while this private half is what an attacker would
//! need to make a forged backup look like yours.
//!
//! Both legs sign the same bytes and both must verify. A break in one scheme alone
//! yields no forgery, which is the same reasoning behind the hybrid KEM in
//! [`crate::recipient`] and the reason a signature is stored as two concatenated parts
//! rather than as whichever leg happened to be checked.
//!
//! Signing is deterministic: both schemes take only the message and the key, so no RNG
//! is consulted at sign time and re-signing the same artifact yields the same bytes. The
//! only randomness here is the seed drawn when a key is generated.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use rand::{RngCore as _, rngs::OsRng};
use zeroize::ZeroizeOnDrop;

use crate::keystore::{KeyFileRules, read_key_line, write_key_file};
use crate::protocol::{
    BACKUP_ID_BYTES, DIGEST_BYTES, ED25519_SIGNATURE_BYTES, ED25519_VERIFYING_KEY_BYTES,
    HYBRID_SIGNATURE_BYTES, HYBRID_VERIFYING_KEY_BYTES, MLDSA65_SIGNATURE_BYTES,
    MLDSA65_VERIFYING_KEY_BYTES, SIGNATURE_DOMAIN, SIGNED_TUPLE_BYTES,
    SIGNING_COMPONENT_SEED_BYTES, SIGNING_MARKER, SIGNING_SEED_BYTES, SUITE_SIGNATURE_HYBRID,
    hex_len,
};
use crate::recipient::hex;

type MldsaSigningKey = ml_dsa::SigningKey<ml_dsa::MlDsa65>;
type MldsaVerifyingKey = ml_dsa::VerifyingKey<ml_dsa::MlDsa65>;
type MldsaSignature = ml_dsa::Signature<ml_dsa::MlDsa65>;

/// The secret halves of both legs must be wiped when they are dropped, and the crates
/// only provide that behind a non-default feature. This assertion is the reason the pins
/// in the workspace manifest name `zeroize` explicitly: dropping the feature — or losing
/// it silently to a dependency resolution change — breaks the build instead of quietly
/// leaving a signing key in freed memory.
const _: fn() = || {
    fn assert_zeroized_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroized_on_drop::<ed25519_dalek::SigningKey>();
    assert_zeroized_on_drop::<MldsaSigningKey>();
};

/// The exact bytes an origin signature covers.
///
/// A newtype rather than a byte slice on purpose: the only way to make one is
/// [`signature_tuple`], so no caller can sign an arbitrary buffer of the right length and
/// still call it an artifact signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedTuple([u8; SIGNED_TUPLE_BYTES]);

impl SignedTuple {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Builds the tuple the signature of one artifact covers:
/// `domain ‖ backup id ‖ SHA256(manifest.age) ‖ SHA256(payload.age)`.
///
/// Both digests arrive already computed because the writer produces them while streaming,
/// and a reader must be able to rebuild the same tuple from what it has on disk without
/// decrypting anything.
///
/// `globals.age` is deliberately absent: it is bound one step further in, by the
/// `globals_sha256` field inside the signed manifest. Every other file of a v1 artifact
/// is either bound directly here, or is public metadata whose digest the manifest repeats.
pub fn signature_tuple(
    backup_id: &[u8; BACKUP_ID_BYTES],
    manifest_sha256: &[u8; DIGEST_BYTES],
    payload_sha256: &[u8; DIGEST_BYTES],
) -> SignedTuple {
    let mut bytes = [0u8; SIGNED_TUPLE_BYTES];
    let mut cursor = 0usize;
    for part in [
        SIGNATURE_DOMAIN,
        backup_id.as_slice(),
        manifest_sha256,
        payload_sha256,
    ] {
        bytes[cursor..cursor + part.len()].copy_from_slice(part);
        cursor += part.len();
    }
    debug_assert_eq!(cursor, SIGNED_TUPLE_BYTES);
    SignedTuple(bytes)
}

/// One artifact's origin signature: the Ed25519 signature followed by the ML-DSA-65
/// signature, with no framing between them.
///
/// The length is the whole of its encoding, which is what lets a reader size it from the
/// suite name recorded in `public.json` and never parse it.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature([u8; HYBRID_SIGNATURE_BYTES]);

impl HybridSignature {
    /// Parses a signature, requiring the exact length this suite has.
    ///
    /// A reader that accepted a short buffer and padded it, or a long one and truncated
    /// it, would turn a truncated file into a plausible signature over different bytes
    /// than the ones the writer had.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        if encoded.len() != HYBRID_SIGNATURE_BYTES {
            bail!(
                "{SUITE_SIGNATURE_HYBRID} signature must be exactly {HYBRID_SIGNATURE_BYTES} bytes \
                 ({ED25519_SIGNATURE_BYTES} + {MLDSA65_SIGNATURE_BYTES}), got {}",
                encoded.len()
            );
        }
        let mut bytes = [0u8; HYBRID_SIGNATURE_BYTES];
        bytes.copy_from_slice(encoded);
        Ok(Self(bytes))
    }

    /// The bytes to write into `signature.hybrid`.
    pub fn as_bytes(&self) -> &[u8; HYBRID_SIGNATURE_BYTES] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public data, but 3373 bytes of it is noise in a log or an error chain.
        write!(f, "HybridSignature({SUITE_SIGNATURE_HYBRID})")
    }
}

/// The private half of the origin signature: both component keys, expanded once at load
/// time, and wiped when this value is dropped.
pub struct HybridSigner {
    ed25519: ed25519_dalek::SigningKey,
    mldsa: MldsaSigningKey,
    /// Cached because a writer needs it for every artifact, and both legs derive it
    /// deterministically from the seeds held above.
    verifier: HybridVerifier,
}

impl HybridSigner {
    /// Draws both component seeds. Backing up the one 64-byte line of a signing key file
    /// recovers both halves.
    pub fn generate() -> Self {
        let mut seeds = [0u8; SIGNING_SEED_BYTES];
        OsRng.fill_bytes(&mut seeds);
        Self::from_seeds(seeds)
    }

    pub fn from_seeds(seeds: [u8; SIGNING_SEED_BYTES]) -> Self {
        let (ed25519_seed, mldsa_seed) = seeds.split_at(SIGNING_COMPONENT_SEED_BYTES);
        let mut ed25519_bytes = [0u8; SIGNING_COMPONENT_SEED_BYTES];
        ed25519_bytes.copy_from_slice(ed25519_seed);
        let mut mldsa_bytes = [0u8; SIGNING_COMPONENT_SEED_BYTES];
        mldsa_bytes.copy_from_slice(mldsa_seed);
        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&ed25519_bytes);
        // Both expansions are total and deterministic: any 32 bytes are a valid seed for
        // either scheme, which is why a key file can carry a seed at all.
        let mldsa = MldsaSigningKey::from_seed(&ml_dsa::Seed::from(mldsa_bytes));
        let verifier = HybridVerifier {
            ed25519: ed25519.verifying_key(),
            mldsa: ml_dsa::Keypair::verifying_key(&mldsa),
        };
        Self {
            ed25519,
            mldsa,
            verifier,
        }
    }

    /// The public half, which is what a verifying key file holds and what a reader needs.
    pub fn to_verifier(&self) -> HybridVerifier {
        self.verifier.clone()
    }

    pub fn verifier(&self) -> &HybridVerifier {
        &self.verifier
    }

    /// Signs the tuple. Deterministic: the same key and the same tuple always produce
    /// byte-identical output, so a re-run is comparable and no RNG is consulted.
    pub fn try_sign(&self, tuple: &SignedTuple) -> Result<HybridSignature> {
        // Each leg's `Signer` is called by qualified path because the two crates pin
        // different major versions of the `signature` trait those methods come from;
        // importing both by name would not compile.
        let ed = ed25519_dalek::Signer::try_sign(&self.ed25519, tuple.as_bytes())
            .context("ed25519 signature failed")?;
        let pq = ml_dsa::Signer::try_sign(&self.mldsa, tuple.as_bytes())
            .context("ml-dsa-65 signature failed")?
            .encode();

        let mut bytes = [0u8; HYBRID_SIGNATURE_BYTES];
        bytes[..ED25519_SIGNATURE_BYTES].copy_from_slice(&ed.to_bytes());
        bytes[ED25519_SIGNATURE_BYTES..].copy_from_slice(pq.as_slice());
        Ok(HybridSignature(bytes))
    }

    /// The single secret line of a signing key file: both seeds, concatenated.
    pub fn to_seed_hex(&self) -> String {
        let mut bytes = [0u8; SIGNING_SEED_BYTES];
        bytes[..SIGNING_COMPONENT_SEED_BYTES].copy_from_slice(&self.ed25519.to_bytes());
        bytes[SIGNING_COMPONENT_SEED_BYTES..].copy_from_slice(self.mldsa.to_seed().as_slice());
        hex::encode(&bytes)
    }

    /// Parses the single secret line of a signing key file.
    pub fn from_seed_hex(text: &str) -> Result<Self> {
        let bytes = hex::decode(text.trim())
            .map_err(|e| anyhow::anyhow!("signing seed is not valid lowercase hex: {e}"))?;
        if bytes.len() != SIGNING_SEED_BYTES {
            bail!(
                "signing seed must be exactly {SIGNING_SEED_BYTES} bytes ({} hex characters), \
                 got {}",
                hex_len(SIGNING_SEED_BYTES),
                bytes.len()
            );
        }
        let mut seeds = [0u8; SIGNING_SEED_BYTES];
        seeds.copy_from_slice(&bytes);
        Ok(Self::from_seeds(seeds))
    }
}

impl fmt::Debug for HybridSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridSigner([redacted])")
    }
}

/// The public half of the origin signature: the key that decides whether an artifact came
/// from the holder of a signing key.
#[derive(Clone)]
pub struct HybridVerifier {
    ed25519: ed25519_dalek::VerifyingKey,
    mldsa: MldsaVerifyingKey,
}

impl HybridVerifier {
    /// Parses the fixed-length encoding: an Ed25519 verifying key followed by an
    /// ML-DSA-65 verifying key.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        if encoded.len() != HYBRID_VERIFYING_KEY_BYTES {
            bail!(
                "{SUITE_SIGNATURE_HYBRID} verifying key must be exactly {HYBRID_VERIFYING_KEY_BYTES} \
                 bytes ({ED25519_VERIFYING_KEY_BYTES} + {MLDSA65_VERIFYING_KEY_BYTES}), got {}",
                encoded.len()
            );
        }
        let mut ed25519_bytes = [0u8; ED25519_VERIFYING_KEY_BYTES];
        ed25519_bytes.copy_from_slice(&encoded[..ED25519_VERIFYING_KEY_BYTES]);
        let ed25519 = ed25519_dalek::VerifyingKey::from_bytes(&ed25519_bytes)
            .map_err(|e| anyhow::anyhow!("invalid ed25519 verifying key: {e}"))?;
        // `from_bytes` only requires the bytes to decode to a point; the small-order
        // check is separate, and a weak key is exactly what a hand-written verifying key
        // file can carry. Such a key admits signatures valid for nearly any message, so
        // it is refused here rather than discovered as an artifact that mysteriously
        // verifies — or, on the reading side, one that never does.
        if ed25519.is_weak() {
            bail!("invalid ed25519 verifying key: it has small order");
        }
        let mldsa: MldsaVerifyingKey =
            ml_dsa::KeyInit::new_from_slice(&encoded[ED25519_VERIFYING_KEY_BYTES..])
                .map_err(|_| anyhow::anyhow!("invalid ml-dsa-65 verifying key"))?;
        Ok(Self { ed25519, mldsa })
    }

    pub fn to_bytes(&self) -> [u8; HYBRID_VERIFYING_KEY_BYTES] {
        let mldsa = self.mldsa.encode();
        let mut bytes = [0u8; HYBRID_VERIFYING_KEY_BYTES];
        bytes[..ED25519_VERIFYING_KEY_BYTES].copy_from_slice(self.ed25519.as_bytes());
        bytes[ED25519_VERIFYING_KEY_BYTES..].copy_from_slice(mldsa.as_slice());
        bytes
    }

    /// Checks a signature over a tuple, refusing unless both legs hold.
    ///
    /// The Ed25519 leg is checked with `verify_strict`, which rejects a signature whose
    /// `R` is non-canonical or of small order — the classical malleability that would
    /// otherwise let anyone rewrite a valid signature into a second valid one for the
    /// same bytes.
    pub fn verify(&self, tuple: &SignedTuple, signature: &HybridSignature) -> Result<()> {
        let encoded = signature.as_bytes();
        let (ed_bytes, pq_bytes) = encoded.split_at(ED25519_SIGNATURE_BYTES);
        let ed25519 = ed25519_dalek::Signature::from_bytes(
            ed_bytes
                .try_into()
                .expect("a signature half is exactly its own length"),
        );
        if self
            .ed25519
            .verify_strict(tuple.as_bytes(), &ed25519)
            .is_err()
        {
            bail!(
                "ed25519 signature check failed: this artifact was not written by the \
                 holder of the configured signing key, or its contents changed"
            );
        }
        let Ok(pq) = MldsaSignature::try_from(pq_bytes) else {
            bail!(
                "ml-dsa-65 signature is not a decodable signature for this suite, \
                 which a signature written by this software always is"
            )
        };
        if ml_dsa::Verifier::verify(&self.mldsa, tuple.as_bytes(), &pq).is_err() {
            bail!(
                "ml-dsa-65 signature check failed: this artifact was not written by the \
                 holder of the configured signing key, or its contents changed"
            );
        }
        Ok(())
    }
}

impl PartialEq for HybridVerifier {
    fn eq(&self, other: &Self) -> bool {
        // Encoded bytes rather than the component keys' own equality, so "the same key"
        // means the same thing a verifying key file would carry.
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for HybridVerifier {}

impl fmt::Debug for HybridVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridVerifier({SUITE_SIGNATURE_HYBRID})")
    }
}

impl fmt::Display for HybridVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.to_bytes()))
    }
}

/// How a caller intends to use a signing key file. As with [`crate::keystore::KeyRole`],
/// the role decides the expected key length, so the two files cannot be swapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningRole {
    /// Signs artifacts; holds both 32-byte seeds.
    Signing,
    /// Verifies artifacts; holds both verifying keys.
    Verifying,
}

impl SigningRole {
    fn rules(self) -> &'static KeyFileRules {
        match self {
            Self::Signing => &SIGNING_RULES,
            Self::Verifying => &VERIFYING_RULES,
        }
    }
}

const SIGNING_RULES: KeyFileRules = KeyFileRules {
    label: "signing",
    marker: SIGNING_MARKER,
    hex_chars: hex_len(SIGNING_SEED_BYTES),
    secret: true,
    key_kind: "signing key",
    suite: SUITE_SIGNATURE_HYBRID,
};

const VERIFYING_RULES: KeyFileRules = KeyFileRules {
    label: "verifying",
    marker: SIGNING_MARKER,
    hex_chars: hex_len(HYBRID_VERIFYING_KEY_BYTES),
    secret: false,
    key_kind: "verifying key",
    suite: SUITE_SIGNATURE_HYBRID,
};

/// A signing or verifying key file loaded from disk.
pub struct SigningKeyFile {
    path: PathBuf,
    role: SigningRole,
    signer: Option<HybridSigner>,
    verifier: HybridVerifier,
}

/// Names the file and its role, never its contents — the same reason as
/// [`crate::keystore::KeyFile`]'s `Debug`: a signing seed can end up inside an error
/// chain that reaches a log.
impl fmt::Debug for SigningKeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKeyFile({:?} {})", self.role, self.path.display())
    }
}

impl SigningKeyFile {
    /// Reads and validates a signing key file for the requested role, under exactly the
    /// rules an identity file is held to.
    pub fn load(path: impl AsRef<Path>, role: SigningRole) -> Result<Self> {
        let path = path.as_ref();
        let rules = role.rules();
        let line = read_key_line(path, rules)?;
        let (signer, verifier) = match role {
            SigningRole::Signing => {
                let signer = HybridSigner::from_seed_hex(&line)
                    .with_context(|| format!("{} key file {}", rules.label, path.display()))?;
                let verifier = signer.to_verifier();
                (Some(signer), verifier)
            }
            SigningRole::Verifying => {
                let bytes = hex::decode(&line)
                    .map_err(|e| anyhow::anyhow!("verifying key is not valid lowercase hex: {e}"))
                    .with_context(|| format!("{} key file {}", rules.label, path.display()))?;
                let verifier = HybridVerifier::from_bytes(&bytes)
                    .with_context(|| format!("{} key file {}", rules.label, path.display()))?;
                (None, verifier)
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            role,
            signer,
            verifier,
        })
    }

    /// Generates a fresh signing key and writes it to `path`, refusing to overwrite an
    /// existing file. Its verifying half is written nowhere: publishing it is a separate,
    /// deliberate step, exactly as with a recipient file.
    pub fn create_signing(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let signer = HybridSigner::generate();
        let text = format!("{SIGNING_MARKER}\n{}\n", signer.to_seed_hex());
        write_key_file(path, text.as_bytes(), SIGNING_RULES.secret)
            .with_context(|| format!("create signing key file {}", path.display()))?;
        let loaded = Self::load(path, SigningRole::Signing)?;
        // A generated key that does not read back as the same public half would mean the
        // store and the process disagree about the same bytes.
        if loaded.verifier != signer.to_verifier() {
            bail!(
                "signing key file {} did not read back as the key it was written with",
                path.display()
            );
        }
        Ok(loaded)
    }

    /// Writes the public half of a signer — or any verifying key — to `path`. Public
    /// material, so no private-file mode is imposed.
    pub fn write_verifying(path: impl AsRef<Path>, verifier: &HybridVerifier) -> Result<Self> {
        let path = path.as_ref();
        let text = format!("{SIGNING_MARKER}\n{verifier}\n");
        write_key_file(path, text.as_bytes(), VERIFYING_RULES.secret)
            .with_context(|| format!("create verifying key file {}", path.display()))?;
        Self::load(path, SigningRole::Verifying)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn role(&self) -> SigningRole {
        self.role
    }

    /// The suite this key belongs to, as `public.json` records it.
    pub fn suite(&self) -> &'static str {
        self.role.rules().suite
    }

    /// The public half, safe to print and the value that proves two key files belong
    /// together.
    pub fn verifier(&self) -> &HybridVerifier {
        &self.verifier
    }

    /// The private half, if this file holds one.
    pub fn signer(&self) -> Result<&HybridSigner> {
        self.signer
            .as_ref()
            .context("key file holds only a verifying key; a signing key is required to sign")
    }
}

/// Gives a writer the key that signs artifacts. Separate from [`VerifyingProvider`]
/// because the hosts that produce backups are precisely the ones that should not have to
/// hold this.
pub trait SigningProvider {
    fn signer(&self) -> Result<&HybridSigner>;
}

/// Gives a reader the key that decides where an artifact came from.
pub trait VerifyingProvider {
    fn verifier(&self) -> Result<&HybridVerifier>;
}

impl SigningProvider for SigningKeyFile {
    fn signer(&self) -> Result<&HybridSigner> {
        SigningKeyFile::signer(self)
    }
}

impl VerifyingProvider for SigningKeyFile {
    fn verifier(&self) -> Result<&HybridVerifier> {
        Ok(self.verifier())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::IDENTITY_MARKER;
    use sha2::{Digest as _, Sha256};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use uuid::Uuid;

    /// anyhow prints only the outermost context with `to_string`; assertions need the
    /// whole chain, because the refusal reason is the cause.
    fn chain(error: anyhow::Error) -> String {
        format!("{error:#}")
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("backupctl-signing-{name}-{}", Uuid::new_v4()))
    }

    fn tuple() -> SignedTuple {
        signature_tuple(
            &[0x01; BACKUP_ID_BYTES],
            &[0x02; DIGEST_BYTES],
            &[0x03; DIGEST_BYTES],
        )
    }

    /// A generated signing key round-trips through its own file, and its verifying half
    /// is the same key a verifying file carries — the property `key status` depends on.
    #[test]
    fn generated_signing_and_verifying_files_agree() {
        let signing_path = temp_path("signing");
        let verifying_path = temp_path("verifying");
        let created = SigningKeyFile::create_signing(&signing_path).unwrap();
        assert_eq!(created.role(), SigningRole::Signing);
        assert_eq!(created.suite(), SUITE_SIGNATURE_HYBRID);

        let public = SigningKeyFile::write_verifying(&verifying_path, created.verifier()).unwrap();
        assert_eq!(public.role(), SigningRole::Verifying);
        assert_eq!(public.verifier(), created.verifier());

        let reloaded = SigningKeyFile::load(&signing_path, SigningRole::Signing).unwrap();
        assert_eq!(reloaded.verifier(), created.verifier());

        // The two provider ports must agree on the same files for writer and reader.
        let as_signer: &dyn SigningProvider = &reloaded;
        let as_verifier: &dyn VerifyingProvider = &public;
        assert_eq!(
            as_signer.signer().unwrap().to_verifier(),
            *as_verifier.verifier().unwrap()
        );

        // A verifying file can never sign. That refusal is the point: the backup hosts
        // are the machines that hold only this file.
        assert!(
            public
                .signer()
                .expect_err("no signing half")
                .to_string()
                .contains("only a verifying key")
        );

        for path in [signing_path, verifying_path] {
            let _ = fs::remove_file(path);
        }
    }

    /// The signature is the size the contract records, in the documented order, and
    /// signing twice is the same operation twice.
    #[test]
    fn signature_shape_is_exact_and_deterministic() {
        let signer = HybridSigner::generate();
        let message = tuple();
        let first = signer.try_sign(&message).unwrap();
        let second = signer.try_sign(&message).unwrap();
        assert_eq!(first, second, "signing must not consult an RNG");
        assert_eq!(first.as_bytes().len(), HYBRID_SIGNATURE_BYTES);

        // Both halves really are their own scheme's output: the classical half parses as
        // an Ed25519 signature on its own, the post-quantum half as an ML-DSA one.
        let (ed_bytes, pq_bytes) = first.as_bytes().split_at(ED25519_SIGNATURE_BYTES);
        let ed = ed25519_dalek::Signature::from_bytes(ed_bytes.try_into().unwrap());
        assert_eq!(ed.to_bytes().len(), ED25519_SIGNATURE_BYTES);
        let pq = MldsaSignature::try_from(pq_bytes)
            .expect("the second half must be a standalone ML-DSA-65 signature");
        assert_eq!(pq.encode().len(), MLDSA65_SIGNATURE_BYTES);

        // The sizes the protocol records are the ones the crates actually produce.
        assert_eq!(
            signer.verifier().to_bytes().len(),
            HYBRID_VERIFYING_KEY_BYTES
        );
        assert_eq!(
            signer.verifier().to_bytes()[ED25519_VERIFYING_KEY_BYTES..].len(),
            MLDSA65_VERIFYING_KEY_BYTES
        );
        assert_eq!(
            signer.to_seed_hex().len(),
            hex_len(SIGNING_SEED_BYTES),
            "one line holding both 32-byte seeds"
        );
    }

    /// A fixed key, tuple and signature. If the domain prefix, the half ordering, or a
    /// dependency's encoding ever changes, this stops matching — which turns a format
    /// break into a test failure instead of a silently unverifiable artifact.
    #[test]
    fn golden_signature_vector_is_stable() {
        let signer = HybridSigner::from_seeds([0x11; SIGNING_SEED_BYTES]);
        assert_eq!(
            signer.to_seed_hex(),
            "11".repeat(SIGNING_SEED_BYTES),
            "the seed line is the seeds, verbatim and in order"
        );
        let signature = signer.try_sign(&tuple()).unwrap();
        assert_eq!(
            hex::encode(&signature.as_bytes()[..16]),
            "4f15ceaa62c36a1b8e121ee0a41cdd46"
        );
        assert_eq!(
            hex::encode(&Sha256::digest(signature.as_bytes())),
            "9d968270008b88c55f4ad93deae14815140803d5be977c7fddefbe9d386c3729"
        );
    }

    /// Every way a signature can be wrong is a refusal, including a change confined to
    /// one leg — which is why both are always checked.
    #[test]
    fn tampering_is_refused_by_either_leg() {
        let signer = HybridSigner::generate();
        let message = tuple();
        let good = signer.try_sign(&message).unwrap();
        signer.verifier().verify(&message, &good).unwrap();

        let mut tampered = *good.as_bytes();
        for offset in [
            0,
            ED25519_SIGNATURE_BYTES / 2,
            ED25519_SIGNATURE_BYTES - 1,
            ED25519_SIGNATURE_BYTES,
            ED25519_SIGNATURE_BYTES + MLDSA65_SIGNATURE_BYTES / 2,
            HYBRID_SIGNATURE_BYTES - 1,
        ] {
            tampered[offset] ^= 0x01;
            let error = chain(
                signer
                    .verifier()
                    .verify(&message, &HybridSignature::from_bytes(&tampered).unwrap())
                    .unwrap_err(),
            );
            assert!(
                error.contains("signature check failed") || error.contains("not a decodable"),
                "mutation at byte {offset} must be refused, got: {error}"
            );
            tampered.copy_from_slice(good.as_bytes());
        }

        // The same signature over different contents must fail: this is the case where an
        // attacker keeps a real signature and swaps in a payload it was never made for.
        let other = signature_tuple(
            &[0x01; BACKUP_ID_BYTES],
            &[0x02; DIGEST_BYTES],
            &[0x04; DIGEST_BYTES],
        );
        assert!(
            signer
                .verifier()
                .verify(&other, &good)
                .expect_err("a different payload digest must not verify")
                .to_string()
                .contains("ed25519 signature check failed")
        );

        // A different backup id, with both digests untouched.
        let other_id = signature_tuple(
            &[0x09; BACKUP_ID_BYTES],
            &[0x02; DIGEST_BYTES],
            &[0x03; DIGEST_BYTES],
        );
        assert!(signer.verifier().verify(&other_id, &good).is_err());
    }

    /// A signature from another key is refused, and only its own key opens it — the
    /// property that makes "this came from that signing key" mean something.
    #[test]
    fn wrong_signer_is_refused() {
        let signer = HybridSigner::generate();
        let other = HybridSigner::generate();
        let message = tuple();
        let signature = signer.try_sign(&message).unwrap();

        assert!(
            other
                .verifier()
                .verify(&message, &signature)
                .expect_err("a foreign signature must not verify")
                .to_string()
                .contains("ed25519 signature check failed")
        );
        assert_ne!(
            other.verifier(),
            signer.verifier(),
            "two fresh keys must share nothing"
        );
    }

    /// Lengths are refused before any key material is parsed, and neither half alone is
    /// a signature.
    #[test]
    fn signature_lengths_are_exact() {
        let signer = HybridSigner::generate();
        let good = signer.try_sign(&tuple()).unwrap();
        for bad in [
            Vec::new(),
            good.to_vec()[..HYBRID_SIGNATURE_BYTES - 1].to_vec(),
            [good.as_bytes().as_slice(), &[0u8]].concat(),
            // One half alone: exactly the size of a classical-only or PQ-only signature,
            // which is what an artifact stripped of one leg would carry.
            good.as_bytes()[..ED25519_SIGNATURE_BYTES].to_vec(),
            good.as_bytes()[ED25519_SIGNATURE_BYTES..].to_vec(),
        ] {
            let error = HybridSignature::from_bytes(&bad).unwrap_err().to_string();
            assert!(
                error.contains(&HYBRID_SIGNATURE_BYTES.to_string())
                    && error.contains(&bad.len().to_string()),
                "a {} byte signature must be refused with both lengths named, got: {error}",
                bad.len()
            );
        }
    }

    /// A signing file is secret, so its permissions are enforced; a verifying file is
    /// public by design and is not.
    #[test]
    fn world_readable_signing_key_is_refused_and_verifying_key_is_not() {
        let signing_path = temp_path("mode");
        let created = SigningKeyFile::create_signing(&signing_path).unwrap();
        let seed_hex = created.signer().unwrap().to_seed_hex();
        fs::set_permissions(&signing_path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = chain(SigningKeyFile::load(&signing_path, SigningRole::Signing).unwrap_err());
        assert!(error.contains("mode 0600"), "got: {error}");
        assert!(
            !error.contains(&seed_hex),
            "the refusal must not echo the seed"
        );

        fs::set_permissions(&signing_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(SigningKeyFile::load(&signing_path, SigningRole::Signing).is_ok());

        let verifying_path = temp_path("public-mode");
        SigningKeyFile::write_verifying(&verifying_path, created.verifier()).unwrap();
        fs::set_permissions(&verifying_path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            SigningKeyFile::load(&verifying_path, SigningRole::Verifying).is_ok(),
            "a readable verifying key is not a finding"
        );

        for path in [signing_path, verifying_path] {
            let _ = fs::remove_file(path);
        }
    }

    /// Malformed files fail with a message naming the file and the reason, and neither
    /// key family accepts the other's marker — the check that stops an age identity being
    /// loaded as a signing key.
    #[test]
    fn malformed_files_are_rejected_by_name() {
        let path = temp_path("malformed");

        // The encryption suite's marker on a signing path.
        fs::write(&path, format!("{IDENTITY_MARKER}\n{}\n", "f".repeat(128))).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = chain(SigningKeyFile::load(&path, SigningRole::Signing).unwrap_err());
        assert!(error.contains(SIGNING_MARKER), "got: {error}");
        assert!(error.contains("marker"), "got: {error}");

        // Our marker, but a line sized for the other role of this family.
        fs::write(&path, format!("{SIGNING_MARKER}\n{}\n", "f".repeat(128))).unwrap();
        let error = chain(SigningKeyFile::load(&path, SigningRole::Verifying).unwrap_err());
        assert!(
            error.contains("3968") && error.contains("128"),
            "a seed line must be refused as a verifying key with both lengths named: {error}"
        );
        // The same line the other way round is over the secret cap, so a signing file can
        // never be a 1984-byte blob.
        fs::write(&path, format!("{SIGNING_MARKER}\n{}\n", "f".repeat(3968))).unwrap();
        let error = chain(SigningKeyFile::load(&path, SigningRole::Signing).unwrap_err());
        assert!(error.contains("limit"), "got: {error}");

        // A marker with no key line, and a file with two lines.
        fs::write(&path, format!("{SIGNING_MARKER}\n")).unwrap();
        let error = chain(SigningKeyFile::load(&path, SigningRole::Signing).unwrap_err());
        assert!(error.contains("no key line"), "got: {error}");
        fs::write(
            &path,
            format!(
                "{SIGNING_MARKER}\n{}\n{}\n",
                "f".repeat(128),
                "e".repeat(128)
            ),
        )
        .unwrap();
        let error = chain(SigningKeyFile::load(&path, SigningRole::Signing).unwrap_err());
        assert!(error.contains("exactly one"), "got: {error}");

        // Right length, wrong alphabet.
        fs::write(&path, format!("{SIGNING_MARKER}\n{}\n", "z".repeat(128))).unwrap();
        let error = chain(SigningKeyFile::load(&path, SigningRole::Signing).unwrap_err());
        assert!(error.contains("lowercase hex"), "got: {error}");

        // Right length and alphabet, but a classical half with a small-order point:
        // this is the weak key a hand-written verifying key file could carry.
        // The ML-DSA half cannot be used for this, because FIPS 204's `pkDecode` accepts
        // every 1952-byte string, so the only malformed key in this suite is the curve.
        fs::write(
            &path,
            format!(
                "{SIGNING_MARKER}\n{}\n",
                ["0".repeat(64), "f".repeat(3904)].concat()
            ),
        )
        .unwrap();
        let error = chain(SigningKeyFile::load(&path, SigningRole::Verifying).unwrap_err());
        assert!(
            error.contains("ed25519") && error.contains("verifying key file"),
            "got: {error}"
        );

        // A directory is not a key file.
        let dir = temp_path("directory");
        fs::create_dir(&dir).unwrap();
        assert!(SigningKeyFile::load(&dir, SigningRole::Signing).is_err());

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir(dir);
    }

    /// Generating over an existing key would silently orphan every artifact signed by the
    /// old one, so the writer refuses.
    #[test]
    fn creation_never_overwrites() {
        let path = temp_path("no-clobber");
        let created = SigningKeyFile::create_signing(&path).unwrap();
        let error = chain(SigningKeyFile::create_signing(&path).unwrap_err());
        assert!(error.contains("File exists"), "got: {error}");
        let still = SigningKeyFile::load(&path, SigningRole::Signing).unwrap();
        assert_eq!(
            still.verifier(),
            created.verifier(),
            "the original survives"
        );
        let _ = fs::remove_file(path);
    }

    /// Key material must never reach `Debug`, an error string, or a log line.
    #[test]
    fn private_material_stays_unprintable() {
        let signer = HybridSigner::generate();
        let seed_hex = signer.to_seed_hex();
        assert_eq!(format!("{signer:?}"), "HybridSigner([redacted])");

        let path = temp_path("debug");
        let file = SigningKeyFile::create_signing(&path).unwrap();
        let rendered = format!("{file:?}");
        assert!(!rendered.contains(&seed_hex), "got: {rendered}");
        assert!(rendered.contains("Signing"));

        let error = HybridVerifier::from_bytes(&[0u8; 4])
            .unwrap_err()
            .to_string();
        assert!(error.contains(SUITE_SIGNATURE_HYBRID), "got: {error}");
        assert!(!error.contains(&seed_hex), "never echoes key material");

        // A signature is public, but its bytes are not for a log line either.
        assert_eq!(
            format!("{:?}", signer.try_sign(&tuple()).unwrap()),
            format!("HybridSignature({SUITE_SIGNATURE_HYBRID})")
        );
        let _ = fs::remove_file(path);
    }

    /// The tuple is the documented concatenation, byte for byte.
    #[test]
    fn signed_tuple_is_the_documented_concatenation() {
        let message = tuple();
        assert_eq!(message.as_bytes().len(), SIGNED_TUPLE_BYTES);
        assert_eq!(
            &message.as_bytes()[..SIGNATURE_DOMAIN.len()],
            SIGNATURE_DOMAIN
        );
        let id = SIGNATURE_DOMAIN.len()..SIGNATURE_DOMAIN.len() + BACKUP_ID_BYTES;
        assert_eq!(&message.as_bytes()[id.clone()], &[0x01; BACKUP_ID_BYTES]);
        assert_eq!(
            &message.as_bytes()[id.end..id.end + DIGEST_BYTES],
            &[0x02; DIGEST_BYTES]
        );
        assert_eq!(
            &message.as_bytes()[id.end + DIGEST_BYTES..],
            &[0x03; DIGEST_BYTES]
        );

        // Same inputs, same bytes; one changed digest, a different tuple — so a signature
        // cannot be moved between artifacts even when their other halves match.
        assert_eq!(
            message,
            signature_tuple(
                &[0x01; BACKUP_ID_BYTES],
                &[0x02; DIGEST_BYTES],
                &[0x03; DIGEST_BYTES]
            )
        );
        assert_ne!(
            message,
            signature_tuple(
                &[0x01; BACKUP_ID_BYTES],
                &[0x02; DIGEST_BYTES],
                &[0x04; DIGEST_BYTES]
            )
        );
    }

    /// Both seeds are independent: changing either half of the secret line yields a
    /// different key, which is why the file carries two rather than deriving one.
    #[test]
    fn either_seed_half_changes_the_key() {
        let base = [0x22u8; SIGNING_SEED_BYTES];
        let mut ed_only = base;
        ed_only[0] ^= 0x01;
        let mut pq_only = base;
        pq_only[SIGNING_COMPONENT_SEED_BYTES] ^= 0x01;

        let signer = HybridSigner::from_seeds(base);
        let from_ed = HybridSigner::from_seeds(ed_only);
        let from_pq = HybridSigner::from_seeds(pq_only);
        assert_ne!(from_ed.verifier(), signer.verifier());
        assert_ne!(from_pq.verifier(), signer.verifier());

        // A mutated ML-DSA seed leaves the classical half of the verifying key alone and
        // changes only the post-quantum half, which is the ordering the format documents.
        let half = ED25519_VERIFYING_KEY_BYTES;
        assert_eq!(
            &from_pq.verifier().to_bytes()[..half],
            &signer.verifier().to_bytes()[..half]
        );
        assert_ne!(
            &from_pq.verifier().to_bytes()[half..],
            &signer.verifier().to_bytes()[half..]
        );
        assert_ne!(
            &from_ed.verifier().to_bytes()[..half],
            &signer.verifier().to_bytes()[..half]
        );
    }

    /// A file written for the encryption family is refused for the signing one at the
    /// marker, so no command can be pointed at the wrong key by a config typo.
    #[test]
    fn an_identity_file_is_not_a_signing_file() {
        let path = temp_path("cross-family");
        let identity = crate::recipient::HybridIdentity::generate();
        fs::write(
            &path,
            format!("{IDENTITY_MARKER}\n{}\n", identity.to_seed_hex()),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = chain(SigningKeyFile::load(&path, SigningRole::Signing).unwrap_err());
        assert!(error.contains(SIGNING_MARKER), "got: {error}");
        assert!(
            !error.contains(&identity.to_seed_hex()),
            "the refusal must not echo the seed it refused to load"
        );

        // And the reverse: a signing key file is not an identity file either.
        let signing_path = temp_path("cross-family-2");
        SigningKeyFile::create_signing(&signing_path).unwrap();
        let error = chain(
            crate::keystore::KeyFile::load(&signing_path, crate::keystore::KeyRole::Identity)
                .unwrap_err(),
        );
        assert!(error.contains(IDENTITY_MARKER), "got: {error}");

        for path in [path, signing_path] {
            let _ = fs::remove_file(path);
        }
    }
}
