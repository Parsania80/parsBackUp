use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::path::PathBuf;
use uuid::Uuid;

pub const DEV_FORMAT: &str = "m1-development-plaintext";
pub const FIXTURE_PREFIX: &str = "backupctl_fixture_";
pub const PLAN_FORMAT: &str = "m2-restore-plan";
pub const VERIFY_CHECKSUM: &str = "checksum";
pub const VERIFY_ARCHIVE: &str = "archive";
pub const VERIFY_RESTORE_TESTED: &str = "restore-tested";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub source: Source,
    pub storage: Storage,
    #[serde(default)]
    pub export_globals: bool,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    300
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub database: String,
    pub client_bin_dir: PathBuf,
    pub password_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub root: PathBuf,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.source.host.as_str(), "localhost" | "127.0.0.1" | "::1")
            && !self.source.host.starts_with('/')
        {
            bail!("M1 permits only local PostgreSQL connections");
        }
        if self.source.port == 0 || self.source.user.is_empty() {
            bail!("source port and user are required");
        }
        if !self.source.database.starts_with(FIXTURE_PREFIX) {
            bail!("M1 database name must start with {FIXTURE_PREFIX}");
        }
        if !self.source.client_bin_dir.is_absolute() || !self.storage.root.is_absolute() {
            bail!("client_bin_dir and storage.root must be absolute paths");
        }
        if let Some(path) = &self.source.password_file
            && !path.is_absolute()
        {
            bail!("password_file must be an absolute path");
        }
        if !(1..=3600).contains(&self.timeout_seconds) {
            bail!("timeout_seconds must be between 1 and 3600");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentManifest {
    pub format: String,
    pub id: Uuid,
    pub synthetic_only: bool,
    pub database: String,
    pub source_major: u32,
    pub source_version: String,
    pub dump_client_version: String,
    pub application_version: String,
    pub archive_format: String,
    pub compression: String,
    pub created_unix_ms: u128,
    pub size_bytes: u64,
    pub sha256: String,
    pub status: String,
    pub security_globals: bool,
    pub globals_sha256: Option<String>,
    pub globals_size_bytes: Option<u64>,
    pub verification_level: Option<String>,
    pub verified_unix_ms: Option<u128>,
}

impl DevelopmentManifest {
    pub fn validate_shape(&self) -> Result<()> {
        if self.format != DEV_FORMAT
            || !self.synthetic_only
            || !self.database.starts_with(FIXTURE_PREFIX)
            || !matches!(self.source_major, 16..=18)
            || self.archive_format != "custom"
            || self.compression != "gzip"
            || self.status != "complete"
            || self.size_bytes == 0
            || self.sha256.len() != 64
            || !self.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("invalid M1 development manifest");
        }
        let globals_present = self.globals_sha256.is_some() || self.globals_size_bytes.is_some();
        if self.security_globals != globals_present {
            bail!("manifest globals fields must be present exactly when security_globals is set");
        }
        if let Some(sha) = &self.globals_sha256
            && (sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            bail!("invalid manifest globals checksum");
        }
        if let Some(size) = self.globals_size_bytes
            && size == 0
        {
            bail!("manifest globals file must not be empty");
        }
        if let Some(level) = &self.verification_level
            && !matches!(level.as_str(), VERIFY_ARCHIVE | VERIFY_RESTORE_TESTED)
        {
            bail!("invalid manifest verification level");
        }
        if self.verified_unix_ms.is_some() != self.verification_level.is_some() {
            bail!("manifest verification fields must appear together");
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
    pub created_unix_ms: u128,
    pub expires_unix_ms: u128,
}

impl RestorePlan {
    pub fn validate(&self, now_unix_ms: u128) -> Result<()> {
        if self.format != PLAN_FORMAT {
            bail!("unrecognized restore plan format");
        }
        if !self.target_database.starts_with(FIXTURE_PREFIX) {
            bail!("M2 restore target must be a synthetic fixture database");
        }
        if self.target_database == self.artifact_database {
            bail!("restore target must differ from the backup source database");
        }
        if self.expires_unix_ms <= self.created_unix_ms {
            bail!("restore plan expiry must be after its creation");
        }
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

    fn config(database: &str) -> Config {
        Config {
            source: Source {
                host: "127.0.0.1".to_string(),
                port: 5432,
                user: "fixture".to_string(),
                database: database.to_string(),
                client_bin_dir: PathBuf::from("/usr/lib/postgresql/16/bin"),
                password_file: None,
            },
            storage: Storage {
                root: PathBuf::from("/tmp/backupctl-fixture-test"),
            },
            export_globals: false,
            timeout_seconds: 30,
        }
    }

    #[test]
    fn only_local_fixture_sources_are_accepted() {
        assert!(config("backupctl_fixture_m1").validate().is_ok());
        assert!(config("production").validate().is_err());
        let mut remote = config("backupctl_fixture_m1");
        remote.source.host = "db.example.invalid".to_string();
        assert!(remote.validate().is_err());
    }

    fn plan(target: &str, policy: RestoreSecurityPolicy) -> RestorePlan {
        RestorePlan {
            format: PLAN_FORMAT.to_string(),
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            artifact_database: "backupctl_fixture_m1".to_string(),
            source_major: 16,
            client_version: "pg_restore (PostgreSQL) 16.4".to_string(),
            target_database: target.to_string(),
            security: policy,
            created_unix_ms: 1_000,
            expires_unix_ms: 2_000,
        }
    }

    #[test]
    fn plan_digest_binds_security_policy_and_target() {
        let base = plan("backupctl_fixture_dr", RestoreSecurityPolicy::dr_full());
        let digest = base.digest();
        assert_eq!(digest.len(), 64);
        assert_eq!(base.digest(), digest);

        let mut flipped = plan("backupctl_fixture_dr", RestoreSecurityPolicy::portable());
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
        let dr = plan("backupctl_fixture_dr", RestoreSecurityPolicy::dr_full());
        assert!(dr.validate(1_500).is_ok());
        let same = plan("backupctl_fixture_m1", RestoreSecurityPolicy::dr_full());
        assert!(same.validate(1_500).is_err());
        assert!(dr.validate(2_000).is_err());
        assert!(dr.validate(2_500).is_err());
        assert!(dr.is_expired(2_000));
        assert!(!dr.is_expired(1_999));
    }

    #[test]
    fn manifest_globals_and_verification_fields_are_consistent() {
        let mut manifest = DevelopmentManifest {
            format: DEV_FORMAT.to_string(),
            id: Uuid::new_v4(),
            synthetic_only: true,
            database: "backupctl_fixture_m1".to_string(),
            source_major: 16,
            source_version: "160004".to_string(),
            dump_client_version: "pg_dump (PostgreSQL) 16.4".to_string(),
            application_version: "0.1.0".to_string(),
            archive_format: "custom".to_string(),
            compression: "gzip".to_string(),
            created_unix_ms: 1,
            size_bytes: 10,
            sha256: "a".repeat(64),
            status: "complete".to_string(),
            security_globals: false,
            globals_sha256: None,
            globals_size_bytes: None,
            verification_level: None,
            verified_unix_ms: None,
        };
        assert!(manifest.validate_shape().is_ok());
        manifest.security_globals = true;
        assert!(manifest.validate_shape().is_err());
        manifest.globals_sha256 = Some("b".repeat(64));
        manifest.globals_size_bytes = Some(5);
        assert!(manifest.validate_shape().is_ok());
        manifest.verification_level = Some(VERIFY_RESTORE_TESTED.to_string());
        assert!(manifest.validate_shape().is_err());
        manifest.verified_unix_ms = Some(2);
        assert!(manifest.validate_shape().is_ok());
    }
}
