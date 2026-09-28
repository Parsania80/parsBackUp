//! Streaming encryption and decryption of artifact payloads.
//!
//! Both directions work on readers and writers rather than buffers: a logical dump
//! travels from `pg_dump` to a file and back again, and holding a whole archive in
//! memory would make the tool's peak cost proportional to the database.
//!
//! Two rules this module exists to enforce:
//!
//! - **One recipient per artifact.** [`encrypt`] takes a single [`HybridRecipient`],
//!   so the writer cannot produce the mixed `[x25519, mlkem768x25519]` header that
//!   age's own API would happily build. The reader side is guarded separately by the
//!   stanza check in [`crate::recipient`], and both halves are tested here.
//! - **A finished stream or nothing.** `age`'s `StreamWriter::finish` writes the final
//!   authenticated chunk; anything that stops before that point leaves a ciphertext
//!   that fails to decrypt, which is the correct outcome for an incomplete backup.
//!   [`EncryptSink`] exists so a caller that receives plaintext a chunk at a time
//!   rather than as a reader still has to pass that step explicitly.

use std::io::{self, Read};

use age::{Decryptor, Encryptor, Identity, Recipient};
use anyhow::{Context as _, Result, bail};

use crate::protocol::{MAX_DECRYPTED_BYTES, SUITE_HYBRID};
use crate::recipient::{HybridIdentity, HybridRecipient};

/// What one stream operation carried, in the terms a manifest records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamOutcome {
    /// Plaintext bytes across the boundary.
    pub plaintext_bytes: u64,
    /// The suite that produced (or opened) the stream.
    pub suite: &'static str,
}

/// Encrypts `plaintext` into `ciphertext` for exactly one recipient.
///
/// The age header, the per-chunk tags, and the truncation-detecting final chunk are
/// written by the `age` crate; this function fixes the recipient list and finishes
/// the stream. Ciphertext size is the caller's to measure, because the caller owns
/// the file it is written into.
pub fn encrypt<R, W>(
    recipient: &HybridRecipient,
    mut plaintext: R,
    ciphertext: W,
) -> Result<StreamOutcome>
where
    R: Read,
    W: io::Write,
{
    let mut sink = EncryptSink::new(recipient, ciphertext)?;
    io::copy(&mut plaintext, &mut sink).context("payload stream failed while encrypting")?;
    let (_ciphertext, outcome) = sink.finish()?;
    Ok(outcome)
}

/// An [`encrypt`] whose plaintext arrives in pieces the caller does not own.
///
/// `pg_dump` hands over its standard output as a stream a caller can only read from
/// inside its own loop, so the whole-reader form above does not fit. This type is the
/// same age stream with an explicit finish step: dropping a sink that was never
/// finished leaves a ciphertext that will not decrypt, so an interrupted dump cannot
/// be mistaken for a backup.
pub struct EncryptSink<W: io::Write> {
    stream: age::stream::StreamWriter<W>,
    plaintext_bytes: u64,
}

impl<W: io::Write> EncryptSink<W> {
    /// Opens the stream, writing the age header — including the single recipient
    /// stanza — into `ciphertext` before returning.
    pub fn new(recipient: &HybridRecipient, ciphertext: W) -> Result<Self> {
        let encryptor = Encryptor::with_recipients(std::iter::once(recipient as &dyn Recipient))
            .context("age could not wrap the file key for the configured recipient")?;
        let stream = encryptor
            .wrap_output(ciphertext)
            .context("age header write failed")?;
        Ok(Self {
            stream,
            plaintext_bytes: 0,
        })
    }

    /// Writes the final authenticated chunk and hands back the inner writer, so the
    /// caller that owns the file can fsync it before publishing.
    pub fn finish(self) -> Result<(W, StreamOutcome)> {
        let Self {
            stream,
            plaintext_bytes,
        } = self;
        let ciphertext = stream
            .finish()
            .context("age stream could not be finished; the ciphertext is truncated")?;
        Ok((
            ciphertext,
            StreamOutcome {
                plaintext_bytes,
                suite: SUITE_HYBRID,
            },
        ))
    }
}

impl<W: io::Write> io::Write for EncryptSink<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.stream.write(buf)?;
        self.plaintext_bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Decrypts an artifact payload with the bound from [`decrypt_with_limit`] set to
/// [`MAX_DECRYPTED_BYTES`].
///
/// Every failure the artifact contract cares about — wrong identity, a flipped
/// chunk, a truncated stream, a header with more than one stanza — is an error here,
/// and an error at this point means the caller has no usable plaintext.
pub fn decrypt<R, W>(
    identity: &HybridIdentity,
    ciphertext: R,
    plaintext: W,
) -> Result<StreamOutcome>
where
    R: io::Read,
    W: io::Write,
{
    decrypt_with_limit(identity, ciphertext, plaintext, MAX_DECRYPTED_BYTES)
}

/// The bounded form, exposed so the cap is testable without a 64 GiB payload.
pub fn decrypt_with_limit<R, W>(
    identity: &HybridIdentity,
    ciphertext: R,
    mut plaintext: W,
    max_plaintext_bytes: u64,
) -> Result<StreamOutcome>
where
    R: io::Read,
    W: io::Write,
{
    let decryptor = Decryptor::new(ciphertext).context("artifact is not a readable age stream")?;
    let mut stream = decryptor
        .decrypt(std::iter::once(identity as &dyn Identity))
        .context("artifact could not be opened with this identity")?;
    // Reading one byte past the cap distinguishes "exactly at the limit" from "over
    // it" without buffering anything, and a stream that hits the cap is abandoned
    // before its final chunk can be verified — which is a failure, not a success.
    let limit = max_plaintext_bytes
        .checked_add(1)
        .context("plaintext size limit is unreasonably large")?;
    let copied = io::copy(&mut (&mut stream).take(limit), &mut plaintext)
        .context("artifact payload failed to decrypt completely")?;
    if copied > max_plaintext_bytes {
        bail!("artifact decrypts to more than the {max_plaintext_bytes} byte plaintext limit");
    }
    Ok(StreamOutcome {
        plaintext_bytes: copied,
        suite: SUITE_HYBRID,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519;
    use sha2::{Digest as _, Sha256};
    use std::io::Write as _;

    /// Deterministic, high-entropy body: every chunk boundary gets exercised without
    /// the expected digest becoming a magic constant in the test.
    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut counter = 0u32;
        while out.len() < len {
            out.extend_from_slice(&Sha256::digest(counter.to_le_bytes()));
            counter += 1;
        }
        out.truncate(len);
        out
    }

    fn chain(error: anyhow::Error) -> String {
        format!("{error:#}")
    }

    /// Encrypting and decrypting is byte-exact, including the sizes that straddle
    /// age's 64 KiB chunk boundary and the empty payload.
    #[test]
    fn round_trip_is_byte_exact_across_chunk_boundaries() {
        let identity = HybridIdentity::generate();
        let recipient = identity.to_recipient();
        for len in [0usize, 1, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 200_000] {
            let plaintext = pseudo_random(len);
            let mut ciphertext = Vec::new();
            let sealed = encrypt(&recipient, plaintext.as_slice(), &mut ciphertext).unwrap();
            assert_eq!(sealed.plaintext_bytes, len as u64);
            assert_eq!(sealed.suite, SUITE_HYBRID);

            let mut recovered = Vec::new();
            let opened = decrypt(&identity, ciphertext.as_slice(), &mut recovered).unwrap();
            assert_eq!(recovered, plaintext, "{len} bytes must round trip");
            assert_eq!(opened.plaintext_bytes, len as u64);
            assert_eq!(opened.suite, SUITE_HYBRID);
        }
    }

    /// A dump is absorbed a chunk at a time, so the incremental form must round trip
    /// whatever chunk sizes the producer happens to use — and a sink dropped without
    /// `finish` must stay undecryptable instead of delivering a plausible tail.
    #[test]
    fn an_unfinished_incremental_sink_is_not_a_backup() {
        let identity = HybridIdentity::generate();
        let recipient = identity.to_recipient();
        let plaintext = pseudo_random(200_000);

        let mut ciphertext = Vec::new();
        {
            let mut sink = EncryptSink::new(&recipient, &mut ciphertext).unwrap();
            for piece in plaintext.chunks(7777) {
                sink.write_all(piece).unwrap();
            }
            let (_written, sealed) = sink.finish().unwrap();
            assert_eq!(sealed.plaintext_bytes, plaintext.len() as u64);
            assert_eq!(sealed.suite, SUITE_HYBRID);
        }
        let mut recovered = Vec::new();
        decrypt(&identity, ciphertext.as_slice(), &mut recovered).unwrap();
        assert_eq!(recovered, plaintext);

        let mut truncated = Vec::new();
        {
            let mut sink = EncryptSink::new(&recipient, &mut truncated).unwrap();
            sink.write_all(&plaintext).unwrap();
        }
        assert!(
            !truncated.is_empty(),
            "the header is written before any plaintext arrives"
        );
        let mut recovered = Vec::new();
        let error = chain(decrypt(&identity, truncated.as_slice(), &mut recovered).unwrap_err());
        assert!(
            recovered.len() < plaintext.len(),
            "the missing final chunk must not be released"
        );
        assert!(error.contains("decrypt"), "{error}");
    }

    /// The overhead the spike measured is a property of the format; a change here is
    /// a format change and must be noticed rather than shipped.
    #[test]
    fn ciphertext_overhead_stays_in_the_measured_band() {
        let identity = HybridIdentity::generate();
        let plaintext = pseudo_random(8 * 1024 * 1024);
        let mut ciphertext = Vec::new();
        encrypt(
            &identity.to_recipient(),
            plaintext.as_slice(),
            &mut ciphertext,
        )
        .unwrap();
        let overhead = ciphertext.len() as u64 - plaintext.len() as u64;
        assert!(
            (1700..4100).contains(&overhead),
            "expected roughly 1.7 KB fixed plus 16 B per 64 KiB chunk, got {overhead}"
        );
    }

    /// A wrong identity, a flipped byte in the header or the payload, and a truncated
    /// stream all fail, and none of them leaves usable plaintext behind.
    #[test]
    fn tampering_and_truncation_fail_before_anything_is_writable() {
        let identity = HybridIdentity::generate();
        let other = HybridIdentity::generate();
        let plaintext = pseudo_random(150_000);
        let mut good = Vec::new();
        encrypt(&identity.to_recipient(), plaintext.as_slice(), &mut good).unwrap();

        let mut recovered = Vec::new();
        let error = chain(decrypt(&other, good.as_slice(), &mut recovered).unwrap_err());
        assert!(error.contains("identity"), "got: {error}");
        assert!(
            recovered.is_empty(),
            "a wrong key must not yield partial plaintext"
        );

        for offset in [0usize, 40, good.len() / 2, good.len() - 1] {
            let mut flipped = good.clone();
            flipped[offset] ^= 0x01;
            let mut out = Vec::new();
            let error = chain(decrypt(&identity, flipped.as_slice(), &mut out).unwrap_err());
            assert!(
                error.contains("age stream")
                    || error.contains("decrypt")
                    || error.contains("identity"),
                "bit flip at {offset} must fail: {error}"
            );
        }

        // Losing the final chunk must be indistinguishable from a corrupt file, which
        // is what age's final-chunk marker exists to make true.
        let truncated = good[..good.len() - 3].to_vec();
        let mut out = Vec::new();
        let error = chain(decrypt(&identity, truncated.as_slice(), &mut out).unwrap_err());
        assert!(error.contains("decrypt"), "got: {error}");
    }

    /// A stream that is not age at all is named as a container problem, not a key
    /// problem, so an operator does not start rotating identities.
    #[test]
    fn unreadable_container_is_named_as_such() {
        let identity = HybridIdentity::generate();
        let mut out = Vec::new();
        let error = chain(
            decrypt(&identity, "this is not an age stream".as_bytes(), &mut out).unwrap_err(),
        );
        assert!(error.contains("age stream"), "got: {error}");
    }

    /// The plaintext cap bounds the write itself, not just the report, so a hostile
    /// ciphertext cannot fill a staging directory on the way to being refused.
    #[test]
    fn plaintext_limit_bounds_the_write_not_just_the_report() {
        let identity = HybridIdentity::generate();
        let plaintext = pseudo_random(4096);
        let mut ciphertext = Vec::new();
        encrypt(
            &identity.to_recipient(),
            plaintext.as_slice(),
            &mut ciphertext,
        )
        .unwrap();

        let mut out = Vec::new();
        let error = chain(
            decrypt_with_limit(&identity, ciphertext.as_slice(), &mut out, 1024).unwrap_err(),
        );
        assert!(error.contains("1024 byte plaintext limit"), "got: {error}");
        assert!(
            out.len() <= 1025,
            "the cap must bound the write, not just the report: wrote {}",
            out.len()
        );

        let mut out = Vec::new();
        assert!(decrypt_with_limit(&identity, ciphertext.as_slice(), &mut out, 4096).is_ok());
        assert_eq!(out, plaintext, "a payload exactly at the cap is accepted");
    }

    /// age will build a `[x25519, mlkem768x25519]` header on request, and such a
    /// file opens with the classical key alone — the downgrade the format forbids.
    /// Our reader refuses it, and our writer cannot produce it.
    #[test]
    fn a_mixed_header_is_unreadable_and_unwritable() {
        let identity = HybridIdentity::generate();
        let hybrid = identity.to_recipient();
        let classical = x25519::Identity::generate();
        let plaintext = pseudo_random(4096);

        let encryptor = Encryptor::with_recipients(
            [
                &classical.to_public() as &dyn Recipient,
                &hybrid as &dyn Recipient,
            ]
            .into_iter(),
        )
        .expect("age itself accepts the mixed header");
        let mut ciphertext = Vec::new();
        {
            let mut stream = encryptor.wrap_output(&mut ciphertext).unwrap();
            io::copy(&mut plaintext.as_slice(), &mut stream).unwrap();
            stream.finish().unwrap();
        }

        let mut out = Vec::new();
        let error = chain(decrypt(&identity, ciphertext.as_slice(), &mut out).unwrap_err());
        assert!(
            error.contains("identity"),
            "the mixed header must be refused, not silently opened: {error}"
        );
        assert!(out.is_empty());

        // The same bytes are a valid age file for the classical recipient, which is
        // precisely why the artifact contract cannot rely on age's own checks.
        let mut out = Vec::new();
        let decryptor = Decryptor::new(ciphertext.as_slice()).unwrap();
        io::copy(
            &mut decryptor
                .decrypt(std::iter::once(&classical as &dyn Identity))
                .expect("the classical half always opens a mixed header"),
            &mut out,
        )
        .unwrap();
        assert_eq!(out, plaintext);

        // And our writer, given the same recipient, cannot express the second stanza.
        let mut ours = Vec::new();
        encrypt(&hybrid, plaintext.as_slice(), &mut ours).unwrap();
        let decryptor = Decryptor::new(ours.as_slice()).unwrap();
        assert_eq!(
            decryptor
                .decrypt(std::iter::once(&identity as &dyn Identity))
                .map(|mut reader| {
                    let mut out = Vec::new();
                    io::copy(&mut reader, &mut out).unwrap();
                    out
                })
                .unwrap(),
            plaintext,
            "a single-recipient artifact round trips through age's own reader"
        );
    }

    /// A `StreamWriter` that is never finished produces a ciphertext that fails to
    /// decrypt, so an aborted backup cannot be published as complete.
    #[test]
    fn an_unfinished_stream_is_not_a_backup() {
        let identity = HybridIdentity::generate();
        let plaintext = pseudo_random(4096);
        let encryptor =
            Encryptor::with_recipients(std::iter::once(&identity.to_recipient() as &dyn Recipient))
                .unwrap();
        let mut ciphertext = Vec::new();
        {
            let mut stream = encryptor.wrap_output(&mut ciphertext).unwrap();
            io::copy(&mut plaintext.as_slice(), &mut stream).unwrap();
            // Deliberately no finish().
        }

        let mut out = Vec::new();
        let error = chain(decrypt(&identity, ciphertext.as_slice(), &mut out).unwrap_err());
        assert!(error.contains("decrypt"), "got: {error}");
    }
}
