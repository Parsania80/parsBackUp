//! Deployment budgets are independent of immutable artifact and plan formats.
use anyhow::{Result, ensure};
use serde::Deserialize;
pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;
pub const MAX_PAYLOAD: u64 = 64 * GIB;
pub const MAX_GLOBALS: u64 = 8 * MIB;
pub const MAX_STAGE: u64 = 65 * GIB + 16 * MIB;
pub const MAX_SCRATCH: u64 = 64 * GIB + 16 * MIB;
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceLimits {
    pub max_payload_bytes: u64,
    pub max_globals_bytes: u64,
    pub max_stage_bytes: u64,
    pub max_scratch_bytes: u64,
    pub min_free_bytes: u64,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: MAX_PAYLOAD,
            max_globals_bytes: MAX_GLOBALS,
            max_stage_bytes: MAX_STAGE,
            max_scratch_bytes: MAX_SCRATCH,
            min_free_bytes: 64 * MIB,
        }
    }
}
impl ResourceLimits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_PAYLOAD).contains(&self.max_payload_bytes)
                && (1..=MAX_GLOBALS).contains(&self.max_globals_bytes)
                && (1..=MAX_STAGE).contains(&self.max_stage_bytes)
                && (1..=MAX_SCRATCH).contains(&self.max_scratch_bytes)
                && (MIB..=1024 * GIB).contains(&self.min_free_bytes),
            "invalid resource limits"
        );
        Ok(())
    }
    pub fn ciphertext_limit(plaintext: u64) -> u64 {
        // Validated limits never approach overflow; checked operations retain that
        // boundary if a future library caller supplies an unvalidated value.
        plaintext
            .checked_add((plaintext / 65536 + 1).saturating_mul(16))
            .and_then(|n| n.checked_add(65536))
            .unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_are_closed_defaulted_and_bounded() {
        let defaults: ResourceLimits = serde_json::from_str("{}").unwrap();
        defaults.validate().unwrap();
        assert_eq!(defaults.max_payload_bytes, MAX_PAYLOAD);
        for field in [
            "max_payload_bytes",
            "max_globals_bytes",
            "max_stage_bytes",
            "max_scratch_bytes",
            "min_free_bytes",
        ] {
            for value in [0, u64::MAX] {
                let text = format!("{{\"{field}\":{value}}}");
                let limits: ResourceLimits = serde_json::from_str(&text).unwrap();
                assert!(limits.validate().is_err());
            }
        }
        assert!(serde_json::from_str::<ResourceLimits>(r#"{"unexpected":1}"#).is_err());
        assert!(
            serde_json::from_str::<ResourceLimits>(r#"{"max_payload_bytes":18446744073709551616}"#)
                .is_err()
        );
        assert_eq!(ResourceLimits::ciphertext_limit(65536), 65536 + 32 + 65536);
        assert_eq!(ResourceLimits::ciphertext_limit(u64::MAX), u64::MAX);
    }
}
