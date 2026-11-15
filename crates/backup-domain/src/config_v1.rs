//! Deployment configuration is independent of the frozen artifact and legacy fixture
//! configuration. Validation describes allowed inputs; it never enables production.
use crate::{FIXTURE_PREFIX, Profile, SelectionMode, Storage, WHOLE_DATABASE_PROFILE};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfigMode {
    Fixture,
    Production,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Writer,
    Reader,
    Public,
    Inventory,
}

impl ConfigMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Production => "production",
        }
    }
}
impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Writer => "writer",
            Self::Reader => "reader",
            Self::Public => "public",
            Self::Inventory => "inventory",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigV1 {
    pub config_version: u32,
    pub mode: ConfigMode,
    pub access: Access,
    pub read_only: bool,
    pub storage: Storage,
    pub source: Option<SourceV1>,
    pub tools: Option<Tools>,
    pub encryption: Option<EncryptionV1>,
    pub signing: Option<SigningV1>,
    pub scratch: Option<Scratch>,
    #[serde(default)]
    pub export_globals: bool,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
    #[serde(default, rename = "profile")]
    pub profiles: Vec<Profile>,
}
fn timeout() -> u64 {
    crate::DEFAULT_TIMEOUT_SECONDS
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceV1 {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub database: String,
    pub maintenance_database: String,
    pub auth: LocalAuth,
    pub password_file: Option<PathBuf>,
}
impl SourceV1 {
    pub fn validate_connection(&self) -> Result<()> {
        ensure!(
            self.port != 0
                && is_literal_database_name(&self.user)
                && is_literal_database_name(&self.database)
                && is_literal_database_name(&self.maintenance_database),
            "invalid source name/port"
        );
        match self.auth {
            LocalAuth::Peer => ensure!(
                absolute(Path::new(&self.host)) && self.password_file.is_none(),
                "invalid peer connection"
            ),
            LocalAuth::ScramPassfile => ensure!(
                matches!(self.host.as_str(), "127.0.0.1" | "::1")
                    && self.password_file.as_ref().is_some_and(|p| absolute(p)),
                "invalid SCRAM connection"
            ),
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocalAuth {
    Peer,
    ScramPassfile,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tools {
    pub client_bin_dir: PathBuf,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scratch {
    pub root: PathBuf,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionV1 {
    pub identity_file: Option<PathBuf>,
    pub recipient_file: Option<PathBuf>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningV1 {
    pub signing_key_file: Option<PathBuf>,
    pub verifying_key_file: Option<PathBuf>,
}

pub(crate) fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && !path.as_os_str().as_encoded_bytes().contains(&0)
        && !path
            .as_os_str()
            .as_encoded_bytes()
            .split(|b| *b == b'/')
            .any(|s| s == b".")
}
pub fn is_literal_database_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 63 && crate::profile::is_valid_schema_name(value)
}
fn disjoint(a: &Path, b: &Path) -> bool {
    !a.starts_with(b) && !b.starts_with(a)
}

impl ConfigV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.config_version == 1, "unsupported config version");
        ensure!(
            (1..=3600).contains(&self.timeout_seconds),
            "invalid timeout"
        );
        ensure!(absolute(&self.storage.root), "invalid storage root");
        ensure!(
            !self.export_globals || self.access == Access::Writer,
            "globals require writer"
        );
        ensure!(
            self.access != Access::Writer || !self.read_only,
            "writer cannot be read-only"
        );
        ensure!(
            self.access != Access::Public || self.read_only,
            "public must be read-only"
        );
        if matches!(self.access, Access::Public | Access::Inventory) {
            ensure!(
                self.source.is_none()
                    && self.tools.is_none()
                    && self.scratch.is_none()
                    && self.encryption.is_none()
                    && self.profiles.is_empty(),
                "forbidden role fields"
            );
        }
        let identity = self
            .encryption
            .as_ref()
            .and_then(|e| e.identity_file.as_ref());
        let recipient = self
            .encryption
            .as_ref()
            .and_then(|e| e.recipient_file.as_ref());
        let signer = self
            .signing
            .as_ref()
            .and_then(|s| s.signing_key_file.as_ref());
        let verifier = self
            .signing
            .as_ref()
            .and_then(|s| s.verifying_key_file.as_ref());
        match self.access {
            Access::Writer => ensure!(
                identity.is_some() && recipient.is_some() && signer.is_some() && verifier.is_some(),
                "writer requires all keys"
            ),
            Access::Reader => ensure!(
                identity.is_some() && verifier.is_some() && recipient.is_none() && signer.is_none(),
                "invalid reader custody"
            ),
            Access::Public => ensure!(
                self.encryption.is_none() && signer.is_none() && verifier.is_some(),
                "invalid public custody"
            ),
            Access::Inventory => ensure!(self.signing.is_none(), "inventory forbids key blocks"),
        }
        let keys: Vec<_> = [identity, recipient, signer, verifier]
            .into_iter()
            .flatten()
            .collect();
        for (index, key) in keys.iter().enumerate() {
            ensure!(
                absolute(key) && disjoint(key, &self.storage.root),
                "unsafe key path"
            );
            ensure!(!keys[..index].contains(key), "aliased key paths");
        }
        if let Some(tools) = &self.tools {
            ensure!(absolute(&tools.client_bin_dir), "invalid tools path");
        }
        if let Some(scratch) = &self.scratch {
            ensure!(
                self.access == Access::Reader && self.read_only,
                "scratch requires snapshot reader"
            );
            ensure!(
                absolute(&scratch.root) && disjoint(&scratch.root, &self.storage.root),
                "unsafe scratch path"
            );
            for key in &keys {
                ensure!(
                    key.parent().is_some_and(|p| disjoint(p, &scratch.root)),
                    "scratch overlaps key directory"
                );
            }
        }
        if let Some(source) = &self.source {
            source.validate_connection()?;
            if self.mode == ConfigMode::Fixture {
                ensure!(
                    source.database.starts_with(FIXTURE_PREFIX),
                    "fixture database required"
                );
            }
            if let Some(passfile) = &source.password_file {
                ensure!(
                    absolute(passfile) && disjoint(passfile, &self.storage.root),
                    "unsafe passfile path"
                );
                ensure!(
                    self.scratch
                        .as_ref()
                        .is_none_or(|s| disjoint(passfile, &s.root)),
                    "passfile overlaps scratch"
                );
                ensure!(!keys.contains(&passfile), "passfile aliases key");
            }
        }
        let mut names: Vec<&str> = Vec::new();
        for profile in &self.profiles {
            let Some(source) = &self.source else {
                bail!("profiles require source");
            };
            ensure!(
                profile.database == source.database && profile.name != WHOLE_DATABASE_PROFILE,
                "invalid profile database/name"
            );
            ensure!(
                !names.contains(&profile.name.as_str()),
                "duplicate profile name"
            );
            names.push(&profile.name);
            profile.validate_selection()?;
            if self.mode == ConfigMode::Production {
                ensure!(
                    profile.mode != SelectionMode::DataOnly,
                    "production data-only unsupported"
                );
            }
        }
        Ok(())
    }
}
