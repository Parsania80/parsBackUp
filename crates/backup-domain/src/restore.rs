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
}

impl RestorePlan {
    pub fn validate(&self, now_unix_ms: u128) -> Result<()> {
        if self.format != PLAN_FORMAT {
            bail!("unrecognized restore plan format");
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
