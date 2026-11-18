use crate::model::{ErrorCode, MAX_TIME, Operation, binding, digest, hash, uuid4};
use anyhow::{Context, Result, ensure};
use backup_domain::{Access, ConfigMode, ConfigV1};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Read,
    net::SocketAddr,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub(crate) fn uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

pub(crate) fn pinned_parent(path: &Path) -> Result<(File, PathBuf)> {
    ensure!(
        path.is_absolute()
            && !path
                .as_os_str()
                .as_encoded_bytes()
                .split(|b| *b == b'/')
                .any(|part| matches!(part, b"." | b"..")),
        "UNSAFE_PATH"
    );
    let directory = backup_local::protected_directory(path.parent().context("MISSING_PARENT")?)?;
    let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .join(path.file_name().context("MISSING_FILENAME")?);
    Ok((directory, pinned))
}

pub(crate) fn private_file(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == uid() && meta.mode() & 0o7777 == 0o600 && meta.nlink() == 1,
        "UNSAFE_PRIVATE_FILE"
    );
    Ok(file)
}

fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let (_directory, pinned) = pinned_parent(path)?;
    let mut bytes = Vec::new();
    private_file(&pinned, false)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "CONFIG_LIMIT");
    Ok(bytes)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    format: String,
    listen: SocketAddr,
    public_origin: String,
    development_http: bool,
    control_database: PathBuf,
    credential_registry: PathBuf,
    profiles: Vec<Profile>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    id: String,
    display_name: String,
    writer_config: Option<PathBuf>,
    reader_config: PathBuf,
    core_profile: Option<String>,
    operations: Vec<Operation>,
}

#[derive(Serialize)]
struct Revision<'a> {
    id: &'a str,
    display_name: &'a str,
    writer_config: &'a Option<PathBuf>,
    reader_config: &'a Path,
    core_profile: &'a Option<String>,
    operations: &'a [Operation],
    writer_sha256: Option<String>,
    reader_sha256: String,
}

struct LoadedProfile {
    spec: Profile,
    revision: String,
}

pub struct Config {
    pub(crate) path: PathBuf,
    pub(crate) source_hash: String,
    pub(crate) database: PathBuf,
    registry: PathBuf,
    profiles: BTreeMap<String, LoadedProfile>,
}

pub(crate) struct Selection {
    pub config: ConfigV1,
    pub core_profile: Option<String>,
    pub revision: String,
}

fn load_core(path: &Path, access: Access) -> Result<(ConfigV1, String)> {
    let bytes = read_private(path, 64 * 1024)?;
    let config: ConfigV1 =
        toml::from_str(std::str::from_utf8(&bytes)?).map_err(|_| ErrorCode::ConfigChanged)?;
    config.validate()?;
    ensure!(
        config.mode == ConfigMode::Fixture && config.access == access && !config.read_only,
        ErrorCode::PolicyRefused
    );
    Ok((config, hash(&bytes)))
}

impl Profile {
    fn load(&self) -> Result<(ConfigV1, Option<ConfigV1>, String)> {
        let (reader, reader_sha256) = load_core(&self.reader_config, Access::Reader)?;
        let writer = self
            .writer_config
            .as_deref()
            .map(|p| load_core(p, Access::Writer))
            .transpose()?;
        let revision = binding(
            "backupctl-api-config-v1",
            &Revision {
                id: &self.id,
                display_name: &self.display_name,
                writer_config: &self.writer_config,
                reader_config: &self.reader_config,
                core_profile: &self.core_profile,
                operations: &self.operations,
                writer_sha256: writer.as_ref().map(|(_, h)| h.clone()),
                reader_sha256,
            },
        )?;
        Ok((reader, writer.map(|(c, _)| c), revision))
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_private(path, 256 * 1024)?;
        let mut input: Input =
            toml::from_str(std::str::from_utf8(&bytes)?).map_err(|_| ErrorCode::ConfigChanged)?;
        ensure!(
            input.format == "api-config-v1"
                && input.listen.ip().is_loopback()
                && !input.profiles.is_empty()
                && input.profiles.len() <= 256,
            ErrorCode::ConfigChanged
        );
        let origin_ok = if input.development_http {
            input.public_origin == format!("http://{}", input.listen)
        } else {
            input
                .public_origin
                .strip_prefix("https://")
                .is_some_and(|host| {
                    !host.is_empty()
                        && host
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
                })
        };
        ensure!(
            origin_ok
                && input.control_database != input.credential_registry
                && input.control_database != path
                && input.credential_registry != path,
            ErrorCode::ConfigChanged
        );
        pinned_parent(&input.control_database)?;
        let mut profiles = BTreeMap::new();
        let mut root = None;
        let mut estate = None;
        for mut profile in input.profiles.drain(..) {
            let id = &profile.id;
            ensure!(
                id.len() <= 64
                    && id.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                    && id.bytes().all(|b| b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b == b'_'
                        || b == b'-')
                    && !profile.display_name.is_empty()
                    && profile.display_name.chars().count() <= 128
                    && !profile.display_name.chars().any(char::is_control)
                    && !profile.operations.is_empty(),
                ErrorCode::ConfigChanged
            );
            if id == "default" {
                ensure!(profile.core_profile.is_none(), ErrorCode::ConfigChanged);
            } else {
                ensure!(
                    profile.core_profile.is_some()
                        && profile.operations.iter().all(|op| matches!(
                            op,
                            Operation::Backup
                                | Operation::RetentionPreview
                                | Operation::RetentionRun
                        )),
                    ErrorCode::ConfigChanged
                );
            }
            profile
                .operations
                .sort_by_key(|op| serde_json::to_string(op).expect("operation serializes"));
            let len = profile.operations.len();
            profile.operations.dedup();
            ensure!(len == profile.operations.len(), ErrorCode::ConfigChanged);
            let (reader, writer, revision) = profile.load()?;
            if profile.operations.contains(&Operation::Backup) {
                ensure!(
                    writer
                        .as_ref()
                        .is_some_and(|c| c.source.is_some() && c.tools.is_some()),
                    ErrorCode::ConfigChanged
                );
            }
            if profile
                .operations
                .iter()
                .any(|op| matches!(op, Operation::RestorePlan | Operation::Restore))
            {
                ensure!(
                    reader.source.is_some() && reader.tools.is_some(),
                    ErrorCode::ConfigChanged
                );
            }
            for core in std::iter::once(&reader).chain(writer.as_ref()) {
                let storage = &core.storage.root;
                ensure!(
                    root.get_or_insert_with(|| storage.clone()) == storage,
                    ErrorCode::ConfigChanged
                );
                if let Some(source) = &core.source {
                    let identity = (source.host.clone(), source.port, source.database.clone());
                    ensure!(
                        estate.get_or_insert_with(|| identity.clone()) == &identity,
                        ErrorCode::ConfigChanged
                    );
                    ensure!(
                        source.database.starts_with(backup_domain::FIXTURE_PREFIX),
                        ErrorCode::PolicyRefused
                    );
                }
                for state in [path, &input.control_database, &input.credential_registry] {
                    ensure!(
                        !state.starts_with(storage) && !storage.starts_with(state),
                        ErrorCode::ConfigChanged
                    );
                    let keys = core
                        .encryption
                        .iter()
                        .flat_map(|e| [&e.identity_file, &e.recipient_file])
                        .chain(
                            core.signing
                                .iter()
                                .flat_map(|s| [&s.signing_key_file, &s.verifying_key_file]),
                        );
                    for key in keys.flatten() {
                        ensure!(
                            key.parent()
                                .is_some_and(|parent| !state.starts_with(parent)),
                            ErrorCode::ConfigChanged
                        );
                    }
                }
                ensure!(
                    input.control_database != profile.reader_config
                        && profile.writer_config.as_ref() != Some(&input.control_database),
                    ErrorCode::ConfigChanged
                );
            }
            if let Some(name) = &profile.core_profile {
                let has_profile = |core: &ConfigV1| core.profiles.iter().any(|p| p.name == *name);
                if profile.operations.contains(&Operation::Backup) {
                    ensure!(
                        writer.as_ref().is_some_and(has_profile),
                        ErrorCode::ConfigChanged
                    );
                }
                if profile.operations.contains(&Operation::RetentionPreview) {
                    ensure!(has_profile(&reader), ErrorCode::ConfigChanged);
                }
            }
            ensure!(
                profiles
                    .insert(
                        id.clone(),
                        LoadedProfile {
                            spec: profile,
                            revision
                        }
                    )
                    .is_none(),
                ErrorCode::ConfigChanged
            );
        }
        ensure!(profiles.contains_key("default"), ErrorCode::ConfigChanged);
        let config = Self {
            path: path.to_owned(),
            source_hash: hash(&bytes),
            database: input.control_database,
            registry: input.credential_registry,
            profiles,
        };
        config.registry()?;
        Ok(config)
    }

    pub(crate) fn select(&self, profile: &str, operation: Operation) -> Result<Selection> {
        let entry = self
            .profiles
            .get(profile)
            .context(ErrorCode::PolicyRefused)?;
        ensure!(
            entry.spec.operations.contains(&operation),
            ErrorCode::PolicyRefused
        );
        ensure!(
            hash(&read_private(&self.path, 256 * 1024)?) == self.source_hash,
            ErrorCode::ConfigChanged
        );
        let (reader, writer, revision) = entry.spec.load()?;
        ensure!(revision == entry.revision, ErrorCode::ConfigChanged);
        Ok(Selection {
            config: if operation == Operation::Backup {
                writer.context(ErrorCode::PolicyRefused)?
            } else {
                reader
            },
            core_profile: entry.spec.core_profile.clone(),
            revision,
        })
    }

    fn registry(&self) -> Result<Registry> {
        let bytes = read_private(&self.registry, 1024 * 1024).context(ErrorCode::AccessDenied)?;
        let registry: Registry =
            serde_json::from_slice(&bytes).map_err(|_| ErrorCode::AccessDenied)?;
        ensure!(
            registry.format == "api-credentials-v1" && registry.credentials.len() <= 4096,
            ErrorCode::AccessDenied
        );
        let mut ids = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        let mut actors = BTreeMap::new();
        for c in &registry.credentials {
            let policy = (c.revision, c.roles.iter().copied().collect::<BTreeSet<_>>());
            ensure!(
                uuid4(c.actor_id)
                    && uuid4(c.credential_id)
                    && (1..=MAX_TIME).contains(&c.revision)
                    && !c.roles.is_empty()
                    && policy.1.len() == c.roles.len()
                    && digest(&c.token_sha256)
                    && ids.insert(c.credential_id)
                    && hashes.insert(&c.token_sha256)
                    && actors.entry(c.actor_id).or_insert_with(|| policy.clone()) == &policy,
                ErrorCode::AccessDenied
            );
        }
        Ok(registry)
    }

    pub(crate) fn authorize(&self, who: Actor, operation: Option<Operation>) -> Result<Authority> {
        let credential = self
            .registry()?
            .credentials
            .into_iter()
            .find(|c| c.active && c.binding() == who)
            .context(ErrorCode::AccessDenied)?;
        let authority = Authority(credential.roles);
        ensure!(
            operation.is_none_or(|op| authority.allows(op)),
            ErrorCode::AccessDenied
        );
        Ok(authority)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub actor_id: Uuid,
    pub credential_id: Uuid,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Viewer,
    Backup,
    Restore,
    Retention,
    Admin,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    format: String,
    credentials: Vec<Credential>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    actor_id: Uuid,
    credential_id: Uuid,
    revision: u64,
    active: bool,
    roles: Vec<Role>,
    token_sha256: String,
}

impl Credential {
    fn binding(&self) -> Actor {
        Actor {
            actor_id: self.actor_id,
            credential_id: self.credential_id,
            revision: self.revision,
        }
    }
}

pub(crate) struct Authority(Vec<Role>);
impl Authority {
    pub(crate) fn admin(&self) -> bool {
        self.0.contains(&Role::Admin)
    }
    pub(crate) fn cancel(&self) -> bool {
        self.0.iter().any(|role| *role != Role::Viewer)
    }
    pub(crate) fn allows(&self, op: Operation) -> bool {
        self.admin()
            || self.0.iter().any(|role| match role {
                Role::Backup => matches!(
                    op,
                    Operation::Backup | Operation::Inspection | Operation::Verification
                ),
                Role::Restore => matches!(
                    op,
                    Operation::RestorePlan
                        | Operation::Restore
                        | Operation::Inspection
                        | Operation::Verification
                ),
                Role::Retention => matches!(
                    op,
                    Operation::RetentionPreview
                        | Operation::RetentionRun
                        | Operation::ArtifactProtection
                ),
                _ => false,
            })
    }
}
