//! Local authenticated history is an accident warning, not independent replay protection.
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

pub const RESTORE_PLAN_V2: &str = "m5b-restore-plan-v2";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionMark {
    pub artifact_id: Uuid,
    pub completed_at_utc: String,
}

impl CompletionMark {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.artifact_id.get_version_num() == 4
                && self.artifact_id.get_variant() == uuid::Variant::RFC4122
                && crate::is_utc_timestamp(&self.completed_at_utc),
            "invalid authenticated completion mark"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackBinding {
    pub source_fingerprint: String,
    pub signer_id: String,
    pub completed_at_utc: String,
    pub payload_sha256: String,
    pub manifest_sha256: String,
    #[serde(deserialize_with = "required_mark")]
    pub high_water: Option<CompletionMark>,
    pub acknowledged: bool,
}

fn required_mark<'de, D: Deserializer<'de>>(
    de: D,
) -> std::result::Result<Option<CompletionMark>, D::Error> {
    Option::<CompletionMark>::deserialize(de)
}

impl RollbackBinding {
    pub fn is_older(&self) -> bool {
        self.high_water
            .as_ref()
            .is_some_and(|m| self.completed_at_utc < m.completed_at_utc)
    }

    pub fn validate(&self) -> Result<()> {
        let hex = |s: &str, n| {
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        ensure!(
            hex(&self.source_fingerprint, crate::ID_HEX_LEN)
                && hex(&self.signer_id, crate::ID_HEX_LEN)
                && hex(&self.payload_sha256, crate::DIGEST_HEX_LEN)
                && hex(&self.manifest_sha256, crate::DIGEST_HEX_LEN)
                && crate::is_utc_timestamp(&self.completed_at_utc),
            "invalid restore rollback binding"
        );
        if let Some(mark) = &self.high_water {
            mark.validate()?;
        }
        ensure!(
            self.acknowledged == self.is_older(),
            "OLDER_SNAPSHOT_ACK_REQUIRED: acknowledgement must match the older-snapshot warning"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RollbackWarning {
    pub artifact_id: Uuid,
    pub source_fingerprint: String,
    pub signer_id: String,
    pub completed_at_utc: String,
    pub high_water: CompletionMark,
}
