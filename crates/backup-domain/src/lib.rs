use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

pub const DEV_FORMAT: &str = "m1-development-plaintext";
pub const FIXTURE_PREFIX: &str = "backupctl_fixture_";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub source: Source,
    pub storage: Storage,
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
        Ok(())
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
}
