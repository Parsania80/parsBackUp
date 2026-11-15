//! What a dump writes into a stage, and how that stage becomes a sealed file.
//!
//! A stage is written through exactly one of these sinks, and the choice between a plain file and
//! an age stream is made from the store's configured keys at the moment the sink is opened — never
//! per call. So the crate's headline claim, that plaintext exists only inside a staging directory,
//! is decided here: the plaintext mode lands bytes as written, the encrypted mode authenticates
//! every chunk on its way into the file and leaves the stage holding only ciphertext.
//!
//! The sink also owns the seal flags on [`LocalStage`] it writes. A stream that was opened but
//! never finished has written an age header and nothing else, and the publish paths refuse such a
//! stage by reading those flags — which is why finishing is the only thing that sets them.

use crate::resources::ResourceWriter;
use crate::{LocalStage, LocalStore};
use anyhow::{Context, Result};
use backup_application::{PayloadSink, StagedBytes};
use backup_crypto::stream::EncryptSink;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::Ordering;

/// Which half of a stage a sink writes.
#[derive(Clone, Copy)]
pub(crate) enum Target {
    Payload,
    Globals,
}

impl Target {
    fn name(self) -> &'static str {
        match self {
            Self::Payload => "payload file",
            Self::Globals => "globals file",
        }
    }
}

enum Writer {
    /// Plaintext mode: the bytes land in the file exactly as they were written.
    Plain { file: ResourceWriter, written: u64 },
    /// Encrypted mode: age authenticates every chunk on its way into the file.
    Age(EncryptSink<ResourceWriter>),
}

struct StageSink<'a> {
    /// `None` only after the sink has been finished; a sealed stream cannot be reopened.
    writer: Option<Writer>,
    target: Target,
    stage: &'a LocalStage,
    plaintext_limit: u64,
    plaintext_written: u64,
}

impl Write for StageSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self
            .plaintext_written
            .checked_add(buf.len() as u64)
            .is_none_or(|n| n > self.plaintext_limit)
        {
            return Err(io::Error::other("RESOURCE_LIMIT"));
        }
        let written = match self.writer.as_mut() {
            None => Err(io::Error::other("staged stream was already finished")),
            Some(Writer::Plain { file, written }) => {
                let n = file.write(buf)?;
                *written += n as u64;
                Ok(n)
            }
            Some(Writer::Age(stream)) => stream.write(buf),
        }?;
        self.plaintext_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.writer.as_mut() {
            None => Err(io::Error::other("staged stream was already finished")),
            Some(Writer::Plain { file, .. }) => file.flush(),
            Some(Writer::Age(stream)) => stream.flush(),
        }
    }
}

impl PayloadSink for StageSink<'_> {
    fn finish(&mut self) -> Result<StagedBytes> {
        let writer = self
            .writer
            .take()
            .context("staged stream was already finished")?;
        let staged = match writer {
            Writer::Plain { mut file, written } => {
                file.flush()?;
                file.into_inner().sync_all()?;
                StagedBytes {
                    plaintext_bytes: written,
                    recipient_suite: None,
                }
            }
            Writer::Age(stream) => {
                let (file, outcome) = stream.finish()?;
                file.into_inner().sync_all()?;
                StagedBytes {
                    plaintext_bytes: outcome.plaintext_bytes,
                    recipient_suite: Some(outcome.suite),
                }
            }
        };
        match self.target {
            Target::Payload => self.stage.sealed_payload.store(true, Ordering::Relaxed),
            Target::Globals => self.stage.sealed_globals.store(true, Ordering::Relaxed),
        }
        Ok(staged)
    }
}

impl LocalStore {
    pub(crate) fn stage_sink<'a>(
        &'a self,
        stage: &'a LocalStage,
        target: Target,
    ) -> Result<Box<dyn PayloadSink + 'a>> {
        let path = match target {
            Target::Payload => stage.payload.clone(),
            Target::Globals => stage
                .globals
                .clone()
                .with_context(|| format!("stage has no {}", target.name()))?,
        };
        // Resolved before the file is created: a store that cannot seal a stream should not
        // leave an empty staged file behind on its way to refusing the call.
        let writer = match &self.keys {
            None => None,
            Some(keys) => Some(
                keys.recipient
                    .as_ref()
                    .context("this store holds no recipient file, so it cannot seal a new dump")?,
            ),
        };
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("create staged {}", target.name()))?;
        let file = ResourceWriter::new(
            file,
            u64::MAX,
            self.resources.as_ref().map_or(0, |r| r.min_free_bytes),
            stage.quota.clone(),
        );
        let plaintext_limit = self.resources.as_ref().map_or(u64::MAX, |r| match target {
            Target::Payload => r.max_payload_bytes,
            Target::Globals => r.max_globals_bytes,
        });
        let writer = match writer {
            None => Writer::Plain { file, written: 0 },
            Some(recipient) => Writer::Age(
                file.encrypt(recipient.recipient())
                    .with_context(|| format!("open {} stream", target.name()))?,
            ),
        };
        Ok(Box::new(StageSink {
            writer: Some(writer),
            target,
            stage,
            plaintext_limit,
            plaintext_written: 0,
        }))
    }
}
