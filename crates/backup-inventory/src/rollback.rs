//! Monotone local history; callers supply facts only after private-manifest authentication.
use crate::{AuditAction, Inventory, in_transaction, is_hex_id, job};
use anyhow::{Result, ensure};
use backup_domain::CompletionMark;
use rusqlite::{OptionalExtension, params};

impl Inventory {
    /// Pre-v8 history is unknown. Reading never migrates or reconstructs it from discovery.
    pub fn completion_mark(&self, source: &str, signer: &str) -> Result<Option<CompletionMark>> {
        ensure!(
            source == self.estate.source_fingerprint && is_hex_id(signer),
            "invalid completion scope"
        );
        if self.schema_version()? < 8 {
            return Ok(None);
        }
        let found: Option<(String, String)> = self.conn.query_row(
            "SELECT backup_id, completed_at_utc FROM completion_high_water WHERE source_fingerprint=?1 AND signer_id=?2",
            params![source, signer], |r| Ok((r.get(0)?, r.get(1)?))
        ).optional()?;
        found
            .map(|(id, completed_at_utc)| {
                let artifact_id = uuid::Uuid::parse_str(&id)?;
                ensure!(
                    id == artifact_id.to_string(),
                    "invalid completion artifact ID"
                );
                let mark = CompletionMark {
                    artifact_id,
                    completed_at_utc,
                };
                mark.validate()?;
                Ok(mark)
            })
            .transpose()
    }

    pub fn observe_completion(
        &self,
        source: &str,
        signer: &str,
        mark: &CompletionMark,
    ) -> Result<CompletionMark> {
        in_transaction(&self.conn, |_| {
            self.advance_completion(source, signer, mark)
        })
    }

    /// Called inside the publication, verification or explicit observation transaction.
    pub(crate) fn advance_completion(
        &self,
        source: &str,
        signer: &str,
        mark: &CompletionMark,
    ) -> Result<CompletionMark> {
        mark.validate()?;
        ensure!(
            self.schema_version()? >= 8,
            "completion ledger requires schema v8"
        );
        let current = self.completion_mark(source, signer)?;
        if let Some(current) = current {
            ensure!(
                current.artifact_id != mark.artifact_id
                    || current.completed_at_utc == mark.completed_at_utc,
                "conflicting authenticated completion time"
            );
            if current.completed_at_utc >= mark.completed_at_utc {
                return Ok(current);
            }
        }
        self.conn.execute(
            "INSERT INTO completion_high_water(source_fingerprint,signer_id,backup_id,completed_at_utc) VALUES(?1,?2,?3,?4) ON CONFLICT(source_fingerprint,signer_id) DO UPDATE SET backup_id=excluded.backup_id, completed_at_utc=excluded.completed_at_utc",
            params![source, signer, mark.artifact_id.to_string(), mark.completed_at_utc]
        )?;
        job::record(
            &self.conn,
            AuditAction::CompletionAdvanced,
            None,
            Some(mark.artifact_id),
        )?;
        Ok(mark.clone())
    }
}
