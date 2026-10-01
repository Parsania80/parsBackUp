use crate::profile::Profile;
use crate::protocol::{FIXTURE_PREFIX, WHOLE_DATABASE_PROFILE};
use anyhow::{Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub source: Source,
    pub storage: Storage,
    #[serde(default)]
    pub export_globals: bool,
    /// Absent leaves artifacts plaintext, which is what a synthetic-only
    /// deployment runs with. Present turns every write into an age stream and every
    /// read into a decrypt, so a deployment opts in per store rather than per
    /// backup: there is no flag that can be forgotten on one run.
    #[serde(default)]
    pub encryption: Option<Encryption>,
    /// Absent leaves artifacts unsigned, which is what the development shapes do.
    /// Present makes every write a signed artifact v1 generation, so signing too is a
    /// property of the deployment rather than of a run.
    #[serde(default)]
    pub signing: Option<Signing>,
    /// Configured with `[[profile]]` blocks in the service TOML.
    #[serde(default, rename = "profile")]
    pub profiles: Vec<Profile>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

/// The two halves of the hybrid key pair, held as service-owned files. They are
/// configured separately because a host that may only write backups needs the
/// recipient and nothing else.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Encryption {
    /// Private identity key file, mode 0600, required to verify or restore.
    pub identity_file: PathBuf,
    /// Public recipient key file, required to write a backup.
    pub recipient_file: PathBuf,
}

/// The origin signature half of the configuration. It is a separate block from
/// `[encryption]` because its two files have genuinely different distribution: writing an
/// artifact needs `signing_key_file`, and verifying or restoring one must not have it, only
/// the trusted `verifying_key_file` plus the decryption identity.
///
/// `signing_key_file` is optional for exactly that reason: a disaster-recovery host
/// configures the verifying key alone and can then read signed artifacts it could never
/// write. `verifying_key_file` is required because a reader that does not say which key it
/// trusts is not verifying anything.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signing {
    /// Private signing key file, mode 0600, seed form. Absent means this host may read
    /// signed artifacts but may not write any.
    #[serde(default)]
    pub signing_key_file: Option<PathBuf>,
    /// Public verifying key file, mode 0644, the half every reader trusts.
    pub verifying_key_file: PathBuf,
}

/// Key file paths are opened by the crypto adapters, but a relative one or one inside the
/// artifact store is a configuration mistake worth naming at load time rather than after a
/// dump has run.
///
/// `label` is the first words of both messages, so the text an operator reads keeps saying
/// which block was wrong; the two callers pass "encryption key files" and "signing key
/// files".
fn validate_key_files(label: &str, paths: &[&PathBuf], root: &Path) -> Result<()> {
    for path in paths {
        if !path.is_absolute() {
            bail!("{label} must be absolute paths");
        }
        if path.starts_with(root) {
            bail!(
                "{label} must live outside the artifact store; {} is inside {}",
                path.display(),
                root.display()
            );
        }
    }
    Ok(())
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
        if let Some(encryption) = &self.encryption {
            validate_key_files(
                "encryption key files",
                &[&encryption.identity_file, &encryption.recipient_file],
                &self.storage.root,
            )?;
        }
        if let Some(signing) = &self.signing {
            // A signature is made over the two ciphertext files, so a store that writes
            // plaintext has nothing for it to authenticate: the block would be a lie about
            // what the artifacts are.
            if self.encryption.is_none() {
                bail!(
                    "a [signing] block requires an [encryption] block: the origin signature \
                     covers the ciphertext pair, which a plaintext store does not have"
                );
            }
            let mut paths: Vec<&PathBuf> = vec![&signing.verifying_key_file];
            if let Some(path) = &signing.signing_key_file {
                paths.push(path);
            }
            validate_key_files("signing key files", &paths, &self.storage.root)?;
            // The contract states the signing key is distinct from the decryption identity,
            // and one file cannot serve both suites: the age identity is 64 hex characters
            // and a signing seed is 128, so the second would fail to load as the first.
            if let (Some(encryption), Some(signing_path)) =
                (&self.encryption, &signing.signing_key_file)
                && signing_path == &encryption.identity_file
            {
                bail!(
                    "signing_key_file and identity_file must not name the same file: the origin \
                     signing key is not the age decryption identity"
                );
            }
        }
        if !(1..=3600).contains(&self.timeout_seconds) {
            bail!("timeout_seconds must be between 1 and 3600");
        }
        let mut names: Vec<&str> = Vec::with_capacity(self.profiles.len());
        for profile in &self.profiles {
            // A signed manifest records this name for a dump that named no profile, so a
            // configurable profile must not be able to claim it: called this, a filtered
            // artifact would report a scope it never had. The check belongs here rather than
            // in `Profile::validate`, because the synthetic snapshot the writer builds is
            // allowed to carry the name and nothing else is.
            if profile.name == WHOLE_DATABASE_PROFILE {
                bail!(
                    "profile name {WHOLE_DATABASE_PROFILE} is reserved for a dump that names no profile"
                );
            }
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
    use super::*;
    use crate::fixture;

    /// Encryption is opt-in per store, and its key files have to live where a
    /// leaked artifact store cannot reach them.
    #[test]
    fn encryption_configuration_names_two_absolute_files_outside_the_store() {
        let mut base = fixture::config("backupctl_fixture_m1");
        assert!(base.encryption.is_none());
        base.encryption = Some(Encryption {
            identity_file: PathBuf::from("/etc/backupctl/identity.key"),
            recipient_file: PathBuf::from("/etc/backupctl/recipient.key"),
        });
        assert!(base.validate().is_ok());

        let mut inside = base.clone();
        inside.encryption.as_mut().unwrap().identity_file =
            PathBuf::from("/tmp/backupctl-fixture-test/identity.key");
        let error = inside.validate().unwrap_err().to_string();
        assert!(error.contains("outside the artifact store"), "{error}");

        let mut relative = base.clone();
        relative.encryption.as_mut().unwrap().recipient_file = PathBuf::from("recipient.key");
        assert!(relative.validate().is_err());
    }

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

    /// The name a profile-less v1 dump records in its signed snapshot stays unconfigurable,
    /// while remaining a valid `Profile` — the writer builds exactly one of these to seal.
    #[test]
    fn the_whole_database_name_is_reserved_for_a_dump_that_names_no_profile() {
        let mut reserved = fixture::config("backupctl_fixture_m1");
        reserved.profiles = vec![fixture::profile(WHOLE_DATABASE_PROFILE)];
        let error = reserved.validate().unwrap_err().to_string();
        assert!(
            error.contains("is reserved for a dump that names no profile"),
            "{error}"
        );
        assert!(fixture::profile(WHOLE_DATABASE_PROFILE).validate().is_ok());
    }

    /// Signing is a property of the deployment like encryption, and it only means
    /// something on top of it: the signature is made over the two ciphertext files.
    #[test]
    fn signing_requires_encryption_and_holds_its_files_to_the_same_rules() {
        let base = signed_config();
        assert!(base.validate().is_ok());

        let mut no_encryption = base.clone();
        no_encryption.encryption = None;
        let error = no_encryption
            .validate()
            .expect_err("a signed plaintext store would authenticate nothing")
            .to_string();
        assert!(
            error.contains("[signing] block requires an [encryption] block"),
            "{error}"
        );

        let mut relative = base.clone();
        relative.signing.as_mut().unwrap().verifying_key_file = PathBuf::from("verifying.key");
        let error = relative.validate().unwrap_err().to_string();
        assert!(
            error.contains("signing key files must be absolute paths"),
            "{error}"
        );

        let mut inside = base.clone();
        inside.signing.as_mut().unwrap().verifying_key_file =
            PathBuf::from("/tmp/backupctl-fixture-test/verifying.key");
        let error = inside.validate().unwrap_err().to_string();
        assert!(
            error.contains("signing key files must live outside the artifact store"),
            "{error}"
        );

        let mut shared = base.clone();
        shared.signing.as_mut().unwrap().signing_key_file =
            Some(PathBuf::from("/etc/backupctl/identity.key"));
        let error = shared.validate().unwrap_err().to_string();
        assert!(error.contains("not the age decryption identity"), "{error}");
    }

    /// The half a reader must never hold is the one it can be configured to omit, so a
    /// disaster-recovery host can trust a verifying key without holding any secret.
    #[test]
    fn a_verify_only_host_configures_no_signing_secret() {
        let mut reader = signed_config();
        reader.signing.as_mut().unwrap().signing_key_file = None;
        assert!(reader.validate().is_ok());

        // The trusted half, however, is not optional: a reader that does not say which key
        // it trusts is not verifying anything.
        let mut trusting = signed_config();
        trusting.signing = None;
        assert!(trusting.validate().is_ok());
        trusting.encryption = None;
        trusting.signing = Some(Signing {
            signing_key_file: None,
            verifying_key_file: PathBuf::from("/etc/backupctl/verifying.key"),
        });
        assert!(trusting.validate().is_err());
    }

    fn signed_config() -> Config {
        let mut config = fixture::config("backupctl_fixture_m1");
        config.encryption = Some(Encryption {
            identity_file: PathBuf::from("/etc/backupctl/identity.key"),
            recipient_file: PathBuf::from("/etc/backupctl/recipient.key"),
        });
        config.signing = Some(Signing {
            signing_key_file: Some(PathBuf::from("/etc/backupctl/signing.key")),
            verifying_key_file: PathBuf::from("/etc/backupctl/verifying.key"),
        });
        config
    }

    /// The three shapes an operator can configure, parsed from TOML rather than built in
    /// Rust, because the shapes are the documentation: which blocks are present is what
    /// decides whether this store writes plaintext, unsigned ciphertext, or signed
    /// artifacts.
    #[test]
    fn the_three_store_shapes_parse_from_toml() {
        let common = "[source]\nhost = \"127.0.0.1\"\nport = 5432\nuser = \"postgres\"\ndatabase = \"backupctl_fixture_m1\"\nclient_bin_dir = \"/usr/lib/postgresql/16/bin\"\n\n[storage]\nroot = \"/tmp/backupctl-fixture-test\"\n\n";
        let keys = "[encryption]\nidentity_file = \"/keys/identity.key\"\nrecipient_file = \"/keys/recipient.key\"\n";
        let signing = "[signing]\nsigning_key_file = \"/keys/signing.key\"\nverifying_key_file = \"/keys/verifying.key\"\n";

        let plaintext: Config = toml::from_str(common).unwrap();
        assert!(plaintext.encryption.is_none() && plaintext.signing.is_none());
        assert!(plaintext.validate().is_ok());

        let encrypted: Config = toml::from_str(&format!("{common}{keys}")).unwrap();
        assert!(encrypted.encryption.is_some() && encrypted.signing.is_none());
        assert!(encrypted.validate().is_ok());

        let signed: Config = toml::from_str(&format!("{common}{keys}{signing}")).unwrap();
        let signing = signed.signing.as_ref().unwrap();
        assert!(signing.signing_key_file.is_some());
        assert_eq!(
            signing.verifying_key_file,
            PathBuf::from("/keys/verifying.key")
        );
        assert!(signed.validate().is_ok());

        // A closed field set: an unknown key inside the new block is refused rather than
        // silently ignored, which is what keeps a typo from disabling a rule.
        let typo = "[signing]\nsigning_key = \"/keys/signing.key\"\nverifying_key_file = \"/keys/verifying.key\"\n";
        let error = toml::from_str::<Config>(&format!("{common}{keys}{typo}"))
            .expect_err("an unknown signing field must not load");
        assert!(error.to_string().contains("signing_key"), "{error}");
    }
}
