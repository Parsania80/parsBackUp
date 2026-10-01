//! Encrypting and authenticating a `backupctl` artifact: one custom age recipient
//! type that combines a post-quantum and a classical key agreement, the key files
//! that hold its two halves, and the streaming helpers that keep plaintext out of
//! the artifact store.
//!
//! The payload stream itself is age's, not this crate's. `age` writes and
//! authenticates every chunk; what is ours is the recipient stanza that carries the
//! file key, which is why the whole post-quantum claim rests on roughly one hundred
//! lines of key agreement rather than a new file format.
//!
//! Nothing here knows about databases, schedules, or the artifact layout: it exposes
//! recipients, identities, signers, and streams, and reports the suite it used.

pub mod keystore;
pub mod protocol;
pub mod signing;

mod kem;
mod recipient;
pub mod stream;

// The KEM types stay internal on purpose: the only supported way to reach the key
// agreement is through a recipient or an identity, and an exported `hpke::Kem` impl
// would invite callers to run HPKE modes this format does not define.
pub use recipient::{HybridIdentity, HybridRecipient};
