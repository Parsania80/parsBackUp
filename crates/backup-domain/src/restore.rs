use crate::protocol::{
    FIXTURE_PREFIX, PLAN_FORMAT, SECTION_DATA, SECTION_POST_DATA, SECTION_PRE_DATA,
};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSections {
    pub pre_data: bool,
    pub data: bool,
    pub post_data: bool,
}

impl Default for RestoreSections {
    fn default() -> Self {
        Self::full()
    }
}

impl RestoreSections {
    pub fn full() -> Self {
        Self {
            pre_data: true,
            data: true,
            post_data: true,
        }
    }

    pub fn is_full(&self) -> bool {
        self.pre_data && self.data && self.post_data
    }

    pub fn validate(&self) -> Result<()> {
        if !(self.pre_data || self.data || self.post_data) {
            bail!("restore sections must select at least one of pre-data, data, post-data");
        }
        // M3 restores only into a database it creates, so a section set that
        // skips an earlier section would run against objects that do not exist
        // yet. pg_restore cannot be made to prove otherwise.
        if !self.pre_data && (self.data || self.post_data) {
            bail!(
                "restoring into a new database requires the pre-data section; select pre-data plus the sections after it"
            );
        }
        if self.pre_data && !self.data && self.post_data {
            bail!(
                "post-data without data skips the rows its indexes, constraints, and triggers would apply to; select data as well or drop post-data"
            );
        }
        Ok(())
    }

    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::new();
        if self.pre_data {
            argv.push(format!("--section={SECTION_PRE_DATA}"));
        }
        if self.data {
            argv.push(format!("--section={SECTION_DATA}"));
        }
        if self.post_data {
            argv.push(format!("--section={SECTION_POST_DATA}"));
        }
        argv
    }

    /// Pure input check, kept separate so a service can run it before any
    /// environment probing: a partial restore cannot rebuild what it skips.
    pub fn check_security(&self, security: &RestoreSecurityPolicy) -> Result<()> {
        if !self.is_full() && (security.roles || security.ownership || security.privileges) {
            bail!(
                "a section-limited restore cannot reconstruct roles, ownership, or privileges; use the portable policy or restore every section"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSecurityPolicy {
    pub roles: bool,
    pub ownership: bool,
    pub privileges: bool,
}

impl RestoreSecurityPolicy {
    pub fn dr_full() -> Self {
        Self {
            roles: true,
            ownership: true,
            privileges: true,
        }
    }

    pub fn portable() -> Self {
        Self {
            roles: false,
            ownership: false,
            privileges: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePlan {
    pub format: String,
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub artifact_database: String,
    pub source_major: u32,
    pub client_version: String,
    pub target_database: String,
    pub security: RestoreSecurityPolicy,
    pub sections: RestoreSections,
    /// The profile name the artifact was recorded with, when selective.
    pub artifact_scope: Option<String>,
    pub created_unix_ms: u128,
    pub expires_unix_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<crate::RollbackBinding>,
}

impl RestorePlan {
    pub fn validate(&self, now_unix_ms: u128) -> Result<()> {
        if self.format != PLAN_FORMAT && self.format != crate::RESTORE_PLAN_V2 {
            bail!("unrecognized restore plan format");
        }
        match (&self.rollback, self.format.as_str()) {
            (None, PLAN_FORMAT) => {}
            (Some(binding), crate::RESTORE_PLAN_V2) => binding.validate()?,
            _ => bail!("restore plan version does not match its rollback binding"),
        }
        if !self.target_database.starts_with(FIXTURE_PREFIX) {
            bail!("restore target must be a synthetic fixture database");
        }
        if self.target_database == self.artifact_database {
            bail!("restore target must differ from the backup source database");
        }
        if self.expires_unix_ms <= self.created_unix_ms {
            bail!("restore plan expiry must be after its creation");
        }
        self.sections.validate()?;
        self.sections.check_security(&self.security)?;
        if now_unix_ms >= self.expires_unix_ms {
            bail!("restore plan has expired; create a new plan");
        }
        if self.format == crate::RESTORE_PLAN_V2
            && (now_unix_ms < self.created_unix_ms
                || self
                    .created_unix_ms
                    .checked_add(u128::from(crate::PLAN_TTL_SECONDS) * 1000)
                    != Some(self.expires_unix_ms))
        {
            bail!("invalid restore plan time window");
        }
        Ok(())
    }

    pub fn is_expired(&self, now_unix_ms: u128) -> bool {
        now_unix_ms >= self.expires_unix_ms
    }

    pub fn digest(&self) -> String {
        // Canonical serialization: fixed struct field order plus serde_json
        // keeps this stable, and any content change alters the digest.
        let bytes = serde_json::to_vec(self).expect("plan serializes");
        format!("{:x}", sha2::Sha256::digest(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;

    #[test]
    fn legacy_plan_bytes_and_digest_remain_compatible() {
        let bytes = br#"{"format":"m3-restore-plan","id":"11111111-1111-4111-8111-111111111111","artifact_id":"22222222-2222-4222-8222-222222222222","artifact_database":"backupctl_fixture_m1","source_major":16,"client_version":"pg_restore (PostgreSQL) 16.4","target_database":"backupctl_fixture_dr","security":{"roles":false,"ownership":false,"privileges":false},"sections":{"pre_data":true,"data":true,"post_data":true},"artifact_scope":null,"created_unix_ms":1000,"expires_unix_ms":2000}"#;
        let plan: RestorePlan = serde_json::from_slice(bytes).unwrap();
        assert!(plan.rollback.is_none());
        assert_eq!(serde_json::to_vec(&plan).unwrap(), bytes);
        assert_eq!(plan.digest(), format!("{:x}", sha2::Sha256::digest(bytes)));
    }

    #[test]
    fn version_two_binds_acknowledgement_history_bytes_and_time() {
        let mut plan = fixture::plan("backupctl_fixture_dr", RestoreSecurityPolicy::portable());
        plan.format = crate::RESTORE_PLAN_V2.to_string();
        plan.expires_unix_ms = plan.created_unix_ms + 900_000;
        plan.rollback = Some(crate::RollbackBinding {
            source_fingerprint: "a".repeat(16),
            signer_id: "b".repeat(16),
            completed_at_utc: "2026-11-01T00:00:00Z".into(),
            payload_sha256: "c".repeat(64),
            manifest_sha256: "d".repeat(64),
            high_water: Some(crate::CompletionMark {
                artifact_id: Uuid::new_v4(),
                completed_at_utc: "2026-11-02T00:00:00Z".into(),
            }),
            acknowledged: true,
        });
        plan.validate(1500).unwrap();
        let digest = plan.digest();
        let mut edited = plan.clone();
        edited.rollback.as_mut().unwrap().acknowledged = false;
        assert_ne!(edited.digest(), digest);
        assert!(edited.validate(1500).is_err());
        for key in [
            "source_fingerprint",
            "signer_id",
            "completed_at_utc",
            "payload_sha256",
            "manifest_sha256",
        ] {
            let mut value = serde_json::to_value(&plan).unwrap();
            value["rollback"][key] = serde_json::json!("bad");
            let edited: RestorePlan = serde_json::from_value(value).unwrap();
            assert_ne!(edited.digest(), digest);
            assert!(edited.validate(1500).is_err());
        }
        for key in ["high_water", "acknowledged"] {
            let mut value = serde_json::to_value(&plan).unwrap();
            value["rollback"].as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<RestorePlan>(value).is_err());
        }
        let mut value = serde_json::to_value(&plan).unwrap();
        value["rollback"]["extra"] = serde_json::json!(0);
        assert!(serde_json::from_value::<RestorePlan>(value).is_err());
        assert!(plan.validate(999).is_err());
        assert!(plan.validate(plan.expires_unix_ms).is_err());
        edited = plan.clone();
        edited.expires_unix_ms += 1;
        assert!(edited.validate(1500).is_err());
        edited = plan.clone();
        edited.format = PLAN_FORMAT.into();
        assert!(edited.validate(1500).is_err());
        edited = plan.clone();
        edited.rollback = None;
        assert!(edited.validate(1500).is_err());
        let duplicate = serde_json::to_string(&plan).unwrap().replace(
            "\"acknowledged\":true",
            "\"acknowledged\":true,\"acknowledged\":true",
        );
        assert!(serde_json::from_str::<RestorePlan>(&duplicate).is_err());
        let binding = plan.rollback.as_mut().unwrap();
        binding.high_water.as_mut().unwrap().completed_at_utc = binding.completed_at_utc.clone();
        assert!(plan.validate(1500).is_err());
        plan.rollback.as_mut().unwrap().acknowledged = false;
        plan.validate(1500).unwrap();
    }

    #[test]
    fn plan_digest_binds_security_policy_and_target() {
        let base = fixture::plan("backupctl_fixture_dr", RestoreSecurityPolicy::dr_full());
        let digest = base.digest();
        assert_eq!(digest.len(), 64);
        assert_eq!(base.digest(), digest);

        let mut flipped = fixture::plan("backupctl_fixture_dr", RestoreSecurityPolicy::portable());
        flipped.id = base.id;
        flipped.artifact_id = base.artifact_id;
        flipped.created_unix_ms = base.created_unix_ms;
        flipped.expires_unix_ms = base.expires_unix_ms;
        assert_ne!(flipped.digest(), digest);

        let mut retargeted = base.clone();
        retargeted.target_database = "backupctl_fixture_other".to_string();
        assert_ne!(retargeted.digest(), digest);
    }

    #[test]
    fn plan_rejects_source_target_and_expiry_violations() {
        let dr = fixture::plan("backupctl_fixture_dr", RestoreSecurityPolicy::dr_full());
        assert!(dr.validate(1_500).is_ok());
        let same = fixture::plan("backupctl_fixture_m1", RestoreSecurityPolicy::dr_full());
        assert!(same.validate(1_500).is_err());
        assert!(dr.validate(2_000).is_err());
        assert!(dr.validate(2_500).is_err());
        assert!(dr.is_expired(2_000));
        assert!(!dr.is_expired(1_999));
    }

    #[test]
    fn sections_must_start_at_pre_data_and_cannot_skip_data() {
        assert!(RestoreSections::full().validate().is_ok());
        assert!(RestoreSections::full().is_full());
        assert!(
            RestoreSections {
                pre_data: true,
                data: true,
                post_data: false,
            }
            .validate()
            .is_ok()
        );
        assert!(
            RestoreSections {
                pre_data: true,
                data: false,
                post_data: false,
            }
            .validate()
            .is_ok()
        );
        for skipped in [
            RestoreSections {
                pre_data: false,
                data: true,
                post_data: false,
            },
            RestoreSections {
                pre_data: false,
                data: false,
                post_data: true,
            },
            RestoreSections {
                pre_data: true,
                data: false,
                post_data: true,
            },
            RestoreSections {
                pre_data: false,
                data: false,
                post_data: false,
            },
        ] {
            assert!(skipped.validate().is_err());
        }
        assert_eq!(
            RestoreSections {
                pre_data: true,
                data: false,
                post_data: false,
            }
            .argv(),
            vec![format!("--section={SECTION_PRE_DATA}")]
        );
        assert_eq!(RestoreSections::full().argv().len(), 3);
    }

    #[test]
    fn a_partial_section_plan_cannot_claim_security_or_be_expired() {
        let mut partial = fixture::plan("backupctl_fixture_dr", RestoreSecurityPolicy::portable());
        partial.sections = RestoreSections {
            pre_data: true,
            data: true,
            post_data: false,
        };
        assert!(partial.validate(1_500).is_ok());

        let mut dr_partial =
            fixture::plan("backupctl_fixture_dr", RestoreSecurityPolicy::dr_full());
        dr_partial.sections = partial.sections;
        assert!(dr_partial.validate(1_500).is_err());

        // The digest covers the section set, so a plan cannot be reinterpreted.
        let mut other_sections =
            fixture::plan("backupctl_fixture_dr", RestoreSecurityPolicy::portable());
        other_sections.id = partial.id;
        other_sections.artifact_id = partial.artifact_id;
        other_sections.created_unix_ms = partial.created_unix_ms;
        other_sections.expires_unix_ms = partial.expires_unix_ms;
        assert_ne!(other_sections.digest(), partial.digest());
    }
}
