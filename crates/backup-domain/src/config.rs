use crate::profile::Profile;
use crate::protocol::FIXTURE_PREFIX;
use anyhow::{Result, bail};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub source: Source,
    pub storage: Storage,
    #[serde(default)]
    pub export_globals: bool,
    /// Configured with `[[profile]]` blocks in the service TOML.
    #[serde(default, rename = "profile")]
    pub profiles: Vec<Profile>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    crate::protocol::DEFAULT_TIMEOUT_SECONDS
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
            bail!("only local PostgreSQL connections are permitted");
        }
        if self.source.port == 0 || self.source.user.is_empty() {
            bail!("source port and user are required");
        }
        if !self.source.database.starts_with(FIXTURE_PREFIX) {
            bail!("database name must start with {FIXTURE_PREFIX}");
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
        let mut names: Vec<&str> = Vec::with_capacity(self.profiles.len());
        for profile in &self.profiles {
            profile.validate()?;
            if names.contains(&profile.name.as_str()) {
                bail!("duplicate profile name {}", profile.name);
            }
            names.push(&profile.name);
            if profile.database != self.source.database {
                bail!(
                    "profile {} targets database {} but only {} is configured",
                    profile.name,
                    profile.database,
                    self.source.database
                );
            }
        }
        Ok(())
    }

    pub fn profile(&self, name: &str) -> Result<&Profile> {
        self.profiles
            .iter()
            .find(|profile| profile.name == name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown profile {name}; configured profiles: {}",
                    if self.profiles.is_empty() {
                        "none".to_string()
                    } else {
                        self.profiles
                            .iter()
                            .map(|profile| profile.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::fixture;

    #[test]
    fn only_local_fixture_sources_are_accepted() {
        assert!(fixture::config("backupctl_fixture_m1").validate().is_ok());
        assert!(fixture::config("production").validate().is_err());
        let mut remote = fixture::config("backupctl_fixture_m1");
        remote.source.host = "db.example.invalid".to_string();
        assert!(remote.validate().is_err());
    }

    #[test]
    fn configuration_requires_known_profiles_and_a_matching_database() {
        let mut base = fixture::config("backupctl_fixture_m1");
        base.profiles = vec![fixture::profile("app-only")];
        assert!(base.validate().is_ok());
        assert_eq!(base.profile("app-only").unwrap().name, "app-only");
        assert!(base.profile("missing").is_err());

        let mut duplicated = fixture::config("backupctl_fixture_m1");
        duplicated.profiles = vec![fixture::profile("app-only"), fixture::profile("app-only")];
        assert!(duplicated.validate().is_err());

        let mut other_database = fixture::config("backupctl_fixture_m1");
        let mut misplaced = fixture::profile("app-only");
        misplaced.database = "backupctl_fixture_other".to_string();
        other_database.profiles = vec![misplaced];
        assert!(other_database.validate().is_err());
    }
}
