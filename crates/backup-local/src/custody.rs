//! Protected versioned key custody and create-only multi-file publication.
//! No store resource is opened until all required key descriptors have been parsed.
use anyhow::{Context, Result, bail, ensure};
use backup_crypto::HybridIdentity;
use backup_crypto::keystore::{KeyFile, KeyRole};
use backup_crypto::protocol::{IDENTITY_MARKER, RECIPIENT_MARKER, SIGNING_MARKER};
use backup_crypto::signing::{HybridSigner, SigningKeyFile, SigningRole};
use backup_domain::{Access, ConfigMode, ConfigV1};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Identity,
    Signing,
    Recipient,
    Verifying,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Signing => "signing",
            Self::Recipient => "recipient",
            Self::Verifying => "verifying",
        }
    }
    fn secret(self) -> bool {
        matches!(self, Self::Identity | Self::Signing)
    }
    fn mode(self) -> u32 {
        if self.secret() { 0o600 } else { 0o644 }
    }
}
#[derive(Clone, Copy)]
pub enum KeyUse {
    Writer,
    Reader,
    Signature,
    Status,
}
#[derive(Clone, Copy)]
pub enum KeyMutation {
    Generate,
    Publish,
}

struct Slot {
    path: PathBuf,
    parent: usize,
    name: CString,
    role: Role,
}
struct Resources {
    parents: Vec<File>,
    slots: Vec<Slot>,
}
impl Resources {
    fn open(config: &ConfigV1, usage: KeyUse, exclusive: bool) -> Result<Self> {
        config.validate().context("CONFIG_INVALID")?;
        ensure!(config.mode == ConfigMode::Fixture, "PRODUCTION_NOT_ENABLED");
        let writer = matches!(usage, KeyUse::Writer)
            || (matches!(usage, KeyUse::Status) && config.access == Access::Writer);
        let identity = writer
            || matches!(usage, KeyUse::Reader)
            || (matches!(usage, KeyUse::Status) && config.access == Access::Reader);
        let verifier = writer
            || matches!(usage, KeyUse::Signature)
            || identity
            || (matches!(usage, KeyUse::Status) && config.access == Access::Public);
        let mut paths = Vec::new();
        if identity {
            paths.push((
                Role::Identity,
                config
                    .encryption
                    .as_ref()
                    .and_then(|e| e.identity_file.as_ref())
                    .context("CONFIG_INVALID")?,
            ));
        }
        if writer {
            paths.push((
                Role::Signing,
                config
                    .signing
                    .as_ref()
                    .and_then(|s| s.signing_key_file.as_ref())
                    .context("CONFIG_INVALID")?,
            ));
            paths.push((
                Role::Recipient,
                config
                    .encryption
                    .as_ref()
                    .and_then(|e| e.recipient_file.as_ref())
                    .context("CONFIG_INVALID")?,
            ));
        }
        if verifier {
            paths.push((
                Role::Verifying,
                config
                    .signing
                    .as_ref()
                    .and_then(|s| s.verifying_key_file.as_ref())
                    .context("CONFIG_INVALID")?,
            ));
        }
        let mut parents = Vec::<File>::new();
        let mut identities = BTreeMap::new();
        let mut slots = Vec::new();
        for (role, path) in paths {
            let directory = protected_directory(path.parent().context("KEY_UNSAFE")?)?;
            let meta = directory.metadata().context("KEY_UNSAFE")?;
            let identity = (meta.dev(), meta.ino());
            let next = parents.len();
            let index = *identities.entry(identity).or_insert(next);
            if index == next {
                parents.push(directory);
            }
            let name = CString::new(path.file_name().context("KEY_UNSAFE")?.as_bytes())
                .context("KEY_UNSAFE")?;
            ensure!(
                !slots
                    .iter()
                    .any(|s: &Slot| s.parent == index && s.name == name),
                "KEY_UNSAFE"
            );
            slots.push(Slot {
                path: path.clone(),
                parent: index,
                name,
                role,
            });
        }
        // Stable global inode order, even when different configurations list paths differently.
        for index in identities.values() {
            let flags = if exclusive {
                libc::LOCK_EX
            } else {
                libc::LOCK_SH
            } | libc::LOCK_NB;
            // SAFETY: live owned directory descriptor, documented flock flags.
            let result = unsafe { libc::flock(parents[*index].as_raw_fd(), flags) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    bail!("KEY_BUSY");
                }
                return Err(error).context("KEY_UNSAFE");
            }
        }
        Ok(Self { parents, slots })
    }
    fn occupied(&self, slot: &Slot) -> Result<bool> {
        // SAFETY: stat storage is initialized by fstatat on success; valid fd/name.
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                self.parents[slot.parent].as_raw_fd(),
                slot.name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(false);
        }
        Err(error).context("KEY_UNSAFE")
    }
    fn read(&self, slot: &Slot) -> Result<File> {
        // SAFETY: valid parent fd/name; no creation, no symlink traversal or FIFO wait.
        let fd = unsafe {
            libc::openat(
                self.parents[slot.parent].as_raw_fd(),
                slot.name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        ensure!(fd >= 0, "KEY_UNSAFE");
        // SAFETY: successful openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        validate_file(&file.metadata().context("KEY_UNSAFE")?, slot.role)?;
        Ok(file)
    }
}

/// Open and pin a directory through trusted, non-symlink ancestors.
pub fn protected_directory(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute()
            && !path
                .as_os_str()
                .as_bytes()
                .split(|b| *b == b'/')
                .any(|p| p == b"." || p == b".."),
        "KEY_UNSAFE"
    );
    let mut dir = File::open("/").context("KEY_UNSAFE")?;
    for part in path.components().skip(1) {
        check_directory(&dir)?;
        let Component::Normal(name) = part else {
            bail!("KEY_UNSAFE");
        };
        let name = CString::new(name.as_bytes()).context("KEY_UNSAFE")?;
        // SAFETY: valid parent descriptor/C name and read-only directory flags.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        ensure!(fd >= 0, "KEY_UNSAFE");
        // SAFETY: new owned descriptor from successful openat.
        dir = unsafe { File::from_raw_fd(fd) };
    }
    check_directory(&dir)?;
    Ok(dir)
}
fn check_directory(dir: &File) -> Result<()> {
    let m = dir.metadata().context("KEY_UNSAFE")?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        m.is_dir()
            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
            && m.mode() & 0o022 == 0,
        "KEY_UNSAFE"
    );
    Ok(())
}
fn validate_file(meta: &Metadata, role: Role) -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let allowed = if role.secret() { 0o600 } else { 0o644 };
    ensure!(
        meta.is_file()
            && (meta.uid() == uid || (!role.secret() && meta.uid() == 0))
            && meta.mode() & 0o7777 & !allowed == 0
            && meta.len() <= backup_crypto::protocol::MAX_KEY_FILE_BYTES,
        "KEY_UNSAFE"
    );
    Ok(())
}

#[derive(Default)]
struct Loaded {
    identity: Option<KeyFile>,
    recipient: Option<KeyFile>,
    signing: Option<SigningKeyFile>,
    verifying: Option<SigningKeyFile>,
    facts: Vec<Value>,
    identities: Vec<(u64, u64)>,
}
impl Loaded {
    fn add(&mut self, slot: &Slot, file: &File) -> Result<()> {
        let meta = file.metadata().context("KEY_UNSAFE")?;
        validate_file(&meta, slot.role)?;
        let identity = (meta.dev(), meta.ino());
        ensure!(!self.identities.contains(&identity), "KEY_UNSAFE");
        self.identities.push(identity);
        let (suite, fingerprint) = match slot.role {
            Role::Identity | Role::Recipient => {
                let role = if slot.role == Role::Identity {
                    KeyRole::Identity
                } else {
                    KeyRole::Recipient
                };
                let key = KeyFile::load_opened(&slot.path, file, role).context("KEY_INVALID")?;
                let fingerprint = backup_crypto::keyid::recipient_id(&key.recipient().as_bytes());
                let suite = key.suite();
                if role == KeyRole::Identity {
                    self.identity = Some(key);
                } else {
                    self.recipient = Some(key);
                }
                (suite, fingerprint)
            }
            Role::Signing | Role::Verifying => {
                let role = if slot.role == Role::Signing {
                    SigningRole::Signing
                } else {
                    SigningRole::Verifying
                };
                let key =
                    SigningKeyFile::load_opened(&slot.path, file, role).context("KEY_INVALID")?;
                let fingerprint = backup_crypto::keyid::signer_id(&key.verifier().to_bytes());
                let suite = key.suite();
                if role == SigningRole::Signing {
                    self.signing = Some(key);
                } else {
                    self.verifying = Some(key);
                }
                (suite, fingerprint)
            }
        };
        self.facts.push(
            json!({"path": slot.path, "role": slot.role.name(), "suite": suite,
            "mode": format!("{:04o}", meta.mode() & 0o777), "fingerprint": fingerprint}),
        );
        Ok(())
    }
    fn check_pairs(&self) -> Result<()> {
        if let (Some(identity), Some(recipient)) = (&self.identity, &self.recipient) {
            ensure!(identity.recipient() == recipient.recipient(), "KEY_INVALID");
        }
        if let (Some(signing), Some(verifying)) = (&self.signing, &self.verifying) {
            ensure!(signing.verifier() == verifying.verifier(), "KEY_INVALID");
        }
        Ok(())
    }
}

/// Public key facts for the material this configuration is permitted to hold.
pub fn protected_key_status(config: &ConfigV1) -> Result<Value> {
    let resources = Resources::open(config, KeyUse::Status, false)?;
    let loaded = load_all(&resources)?;
    Ok(json!({"keys": loaded.facts}))
}
fn load_all(resources: &Resources) -> Result<Loaded> {
    let mut loaded = Loaded::default();
    for slot in &resources.slots {
        loaded.add(slot, &resources.read(slot)?)?;
    }
    loaded.check_pairs()?;
    Ok(loaded)
}

/// Opens a writable store only after loading exactly the operation's protected custody.
pub fn open_protected_store(config: &ConfigV1, usage: KeyUse) -> Result<crate::LocalStore> {
    ensure!(
        matches!(usage, KeyUse::Writer | KeyUse::Reader | KeyUse::Signature),
        "CONFIG_INVALID"
    );
    ensure!(!config.read_only, "READ_ONLY");
    ensure!(
        matches!(config.access, Access::Writer | Access::Reader),
        "ACCESS_DENIED"
    );
    ensure!(
        !matches!(usage, KeyUse::Writer) || config.access == Access::Writer,
        "ACCESS_DENIED"
    );
    let resources = Resources::open(config, usage, false)?;
    let loaded = load_all(&resources)?;
    let keys = crate::StoreKeys {
        identity: if matches!(usage, KeyUse::Signature) {
            None
        } else {
            Some(loaded.identity.context("KEY_INVALID")?)
        },
        recipient: loaded.recipient,
        signing: loaded.signing,
        verifying: loaded.verifying,
    };
    crate::filesystem::open_store(
        config,
        keys,
        &resources.parents,
        matches!(usage, KeyUse::Writer),
    )
}

pub(crate) fn snapshot_keys(
    config: &ConfigV1,
    decrypt: bool,
) -> Result<(Option<crate::StoreKeys>, Option<SigningKeyFile>, Vec<File>)> {
    // Status on a public projection uses exactly the verifier; no identity probe.
    let mut projection = config.clone();
    let usage = if decrypt {
        KeyUse::Reader
    } else {
        projection.access = Access::Public;
        projection.encryption = None;
        projection.source = None;
        projection.tools = None;
        projection.scratch = None;
        projection.profiles.clear();
        KeyUse::Status
    };
    let resources = Resources::open(&projection, usage, false)?;
    let loaded = load_all(&resources)?;
    let (keys, verifier) = if decrypt {
        (
            Some(crate::StoreKeys {
                identity: Some(loaded.identity.context("KEY_INVALID")?),
                recipient: None,
                signing: None,
                verifying: loaded.verifying,
            }),
            None,
        )
    } else {
        (None, loaded.verifying)
    };
    Ok((keys, verifier, resources.parents))
}

/// A multi-file publication receipt. Created names are never removed on failure.
pub struct KeyMutationOutcome {
    pub data: Value,
    pub error: Option<&'static str>,
    pub partial: bool,
}

pub fn mutate_protected_keys(config: &ConfigV1, action: KeyMutation) -> Result<KeyMutationOutcome> {
    ensure!(config.access == Access::Writer, "ACCESS_DENIED");
    ensure!(!config.read_only, "READ_ONLY");
    let resources = Resources::open(config, KeyUse::Writer, true)?;
    let (loaded, staged) = prepare(&resources, action)?;
    Ok(publish(&resources, &loaded, &staged, |_, _| Ok(())))
}

fn prepare(resources: &Resources, action: KeyMutation) -> Result<(Loaded, Vec<(usize, File)>)> {
    let mut loaded = Loaded::default();
    let mut missing = Vec::new();
    for (index, slot) in resources.slots.iter().enumerate() {
        let occupied = resources.occupied(slot)?;
        if matches!(action, KeyMutation::Generate) {
            ensure!(!occupied, "KEY_OCCUPIED");
        }
        if occupied {
            loaded.add(slot, &resources.read(slot)?)?;
        } else {
            missing.push(index);
        }
    }
    loaded.check_pairs()?;
    if matches!(action, KeyMutation::Publish) {
        ensure!(
            loaded.identity.is_some() && loaded.signing.is_some(),
            "KEY_INVALID"
        );
    }
    let identity = matches!(action, KeyMutation::Generate).then(HybridIdentity::generate);
    let signing = matches!(action, KeyMutation::Generate).then(HybridSigner::generate);
    let mut staged = Vec::new();
    for index in missing {
        let slot = &resources.slots[index];
        let text = Zeroizing::new(match slot.role {
            Role::Identity => {
                let seed = Zeroizing::new(identity.as_ref().context("KEY_INVALID")?.to_seed_hex());
                format!("{IDENTITY_MARKER}\n{}\n", seed.as_str())
            }
            Role::Signing => {
                let seed = Zeroizing::new(signing.as_ref().context("KEY_INVALID")?.to_seed_hex());
                format!("{SIGNING_MARKER}\n{}\n", seed.as_str())
            }
            Role::Recipient => {
                let recipient = match &identity {
                    Some(i) => i.to_recipient(),
                    None => loaded
                        .identity
                        .as_ref()
                        .context("KEY_INVALID")?
                        .recipient()
                        .clone(),
                };
                format!("{RECIPIENT_MARKER}\n{recipient}\n")
            }
            Role::Verifying => {
                let verifier = match &signing {
                    Some(s) => s.to_verifier(),
                    None => loaded
                        .signing
                        .as_ref()
                        .context("KEY_INVALID")?
                        .verifier()
                        .clone(),
                };
                format!("{SIGNING_MARKER}\n{verifier}\n")
            }
        });
        // All staging remains anonymous: failures cannot leave named temporary seeds.
        // SAFETY: live destination directory fd, constant name and O_TMPFILE flags.
        let fd = unsafe {
            libc::openat(
                resources.parents[slot.parent].as_raw_fd(),
                c".".as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                slot.role.mode(),
            )
        };
        ensure!(fd >= 0, "KEY_OPERATION_FAILED");
        // SAFETY: successful anonymous open returns a fresh owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.set_permissions(std::fs::Permissions::from_mode(slot.role.mode()))
            .context("KEY_OPERATION_FAILED")?;
        file.write_all(text.as_bytes())
            .context("KEY_OPERATION_FAILED")?;
        file.sync_all().context("KEY_OPERATION_FAILED")?;
        file.seek(SeekFrom::Start(0))
            .context("KEY_OPERATION_FAILED")?;
        loaded.add(slot, &file)?;
        staged.push((index, file));
    }
    loaded.check_pairs()?;
    Ok((loaded, staged))
}

fn publish(
    resources: &Resources,
    loaded: &Loaded,
    staged: &[(usize, File)],
    mut before: impl FnMut(usize, &Slot) -> Result<()>,
) -> KeyMutationOutcome {
    let mut created = Vec::new();
    let mut durability_confirmed = true;
    for (step, (index, file)) in staged.iter().enumerate() {
        let slot = &resources.slots[*index];
        let result = (|| -> Result<()> {
            before(step, slot)?;
            let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
            // SAFETY: valid source C path/parent fd/name; linkat refuses occupied destinations.
            let rc = unsafe {
                libc::linkat(
                    libc::AT_FDCWD,
                    source.as_ptr(),
                    resources.parents[slot.parent].as_raw_fd(),
                    slot.name.as_ptr(),
                    libc::AT_SYMLINK_FOLLOW,
                )
            };
            ensure!(rc == 0, "KEY_OPERATION_FAILED");
            created.push(slot.role.name());
            durability_confirmed = false;
            resources.parents[slot.parent].sync_all()?;
            durability_confirmed = true;
            Ok(())
        })();
        if result.is_err() {
            let pending = staged
                .iter()
                .map(|(i, _)| resources.slots[*i].role.name())
                .filter(|r| !created.contains(r))
                .collect::<Vec<_>>();
            return KeyMutationOutcome {
                partial: !created.is_empty(),
                error: Some(if created.is_empty() {
                    "KEY_OPERATION_FAILED"
                } else {
                    "KEY_PARTIAL"
                }),
                data: json!({"keys": [], "created": created, "pending": pending, "durability_confirmed": durability_confirmed}),
            };
        }
    }
    KeyMutationOutcome {
        partial: false,
        error: None,
        data: json!({"keys": loaded.facts, "created": created, "pending": [], "durability_confirmed": true}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    struct Scene(PathBuf);
    impl Scene {
        fn new() -> Self {
            let root = PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(format!(".backupctl-custody-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }
        fn config(&self, access: &str, read_only: bool) -> ConfigV1 {
            let mut value = json!({"config_version":1,"mode":"fixture","access":access,
                "read_only": read_only, "storage":{"root":self.0.join("absent-store")}});
            if matches!(access, "writer" | "reader") {
                value["encryption"] = json!({"identity_file":self.0.join("identity")});
            }
            if access != "inventory" {
                value["signing"] = json!({"verifying_key_file":self.0.join("verifying")});
            }
            if access == "writer" {
                value["encryption"]["recipient_file"] = json!(self.0.join("recipient"));
                value["signing"]["signing_key_file"] = json!(self.0.join("signing"));
            }
            serde_json::from_value(value).unwrap()
        }
        fn generate(&self) {
            let outcome =
                mutate_protected_keys(&self.config("writer", false), KeyMutation::Generate)
                    .unwrap();
            assert!(outcome.error.is_none());
        }
        fn names(&self) -> Vec<String> {
            let mut names = fs::read_dir(&self.0)
                .unwrap()
                .map(|p| p.unwrap().file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            names.sort();
            names
        }
    }
    impl Drop for Scene {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn code(error: anyhow::Error, expected: &str) {
        assert!(
            error.chain().any(|e| e.to_string() == expected),
            "{error:#}"
        );
    }

    #[test]
    fn bootstrap_status_and_publish_use_exact_custody_and_preserve_seeds() {
        let scene = Scene::new();
        let config = scene.config("writer", false);
        let generated = mutate_protected_keys(&config, KeyMutation::Generate).unwrap();
        assert_eq!(
            generated.data["created"],
            json!(["identity", "signing", "recipient", "verifying"])
        );
        assert_eq!(
            scene.names(),
            vec!["identity", "recipient", "signing", "verifying"]
        );
        let before = protected_key_status(&config).unwrap();
        assert_eq!(before["keys"].as_array().unwrap().len(), 4);
        let identity = fs::read(scene.0.join("identity")).unwrap();
        let signing = fs::read(scene.0.join("signing")).unwrap();
        fs::remove_file(scene.0.join("recipient")).unwrap();
        fs::remove_file(scene.0.join("verifying")).unwrap();
        let published = mutate_protected_keys(&config, KeyMutation::Publish).unwrap();
        assert!(published.error.is_none());
        assert_eq!(published.data["created"], json!(["recipient", "verifying"]));
        assert_eq!(protected_key_status(&config).unwrap(), before);
        assert_eq!(fs::read(scene.0.join("identity")).unwrap(), identity);
        assert_eq!(fs::read(scene.0.join("signing")).unwrap(), signing);
        let no_op = mutate_protected_keys(&config, KeyMutation::Publish).unwrap();
        assert_eq!(no_op.data["created"], json!([]));
        code(
            mutate_protected_keys(&config, KeyMutation::Generate)
                .err()
                .unwrap(),
            "KEY_OCCUPIED",
        );
        fs::remove_file(scene.0.join("signing")).unwrap();
        fs::remove_file(scene.0.join("recipient")).unwrap();
        let reader = scene.config("reader", true);
        let reader_status = protected_key_status(&reader).unwrap();
        assert_eq!(reader_status["keys"].as_array().unwrap().len(), 2);
        assert_eq!(
            protected_key_status(&scene.config("public", true)).unwrap()["keys"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            protected_key_status(&scene.config("inventory", true)).unwrap(),
            json!({"keys":[]})
        );
        assert!(!scene.0.join("absent-store").exists());
        code(
            open_protected_store(&reader, KeyUse::Reader).err().unwrap(),
            "READ_ONLY",
        );
        fs::create_dir(scene.0.join("absent-store")).unwrap();
        fs::set_permissions(
            scene.0.join("absent-store"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let loaded = open_protected_store(&scene.config("reader", false), KeyUse::Reader).unwrap();
        assert!(loaded.keys.as_ref().unwrap().signing.is_none());
        assert!(loaded.keys.as_ref().unwrap().recipient.is_none());
    }

    #[test]
    fn all_destinations_and_signing_inputs_are_validated_before_any_publication() {
        let scene = Scene::new();
        let mut config = scene.config("writer", false);
        // A bad fourth destination cannot leave either secret or recipient behind.
        config.signing.as_mut().unwrap().verifying_key_file =
            Some(scene.0.join("missing-parent/verifying"));
        code(
            mutate_protected_keys(&config, KeyMutation::Generate)
                .err()
                .unwrap(),
            "KEY_UNSAFE",
        );
        assert!(scene.names().is_empty());
        config = scene.config("writer", false);
        symlink("missing", scene.0.join("verifying")).unwrap();
        code(
            mutate_protected_keys(&config, KeyMutation::Generate)
                .err()
                .unwrap(),
            "KEY_OCCUPIED",
        );
        assert_eq!(scene.names(), vec!["verifying"]);
        fs::remove_file(scene.0.join("verifying")).unwrap();
        scene.generate();
        fs::remove_file(scene.0.join("recipient")).unwrap();
        fs::remove_file(scene.0.join("verifying")).unwrap();
        fs::write(scene.0.join("signing"), b"invalid synthetic key").unwrap();
        code(
            mutate_protected_keys(&config, KeyMutation::Publish)
                .err()
                .unwrap(),
            "KEY_INVALID",
        );
        assert_eq!(scene.names(), vec!["identity", "signing"]);
    }

    #[test]
    fn mismatched_pairs_and_hard_links_refuse_without_mutating_any_file() {
        let scene = Scene::new();
        let other = Scene::new();
        scene.generate();
        other.generate();
        let path = scene.0.join("verifying");
        fs::copy(other.0.join("verifying"), &path).unwrap();
        code(
            protected_key_status(&scene.config("writer", false))
                .err()
                .unwrap(),
            "KEY_INVALID",
        );
        fs::remove_file(scene.0.join("recipient")).unwrap();
        code(
            mutate_protected_keys(&scene.config("writer", false), KeyMutation::Publish)
                .err()
                .unwrap(),
            "KEY_INVALID",
        );
        assert!(!scene.0.join("recipient").exists());
        fs::remove_file(&path).unwrap();
        fs::hard_link(scene.0.join("identity"), &path).unwrap();
        code(
            protected_key_status(&scene.config("reader", true))
                .err()
                .unwrap(),
            "KEY_UNSAFE",
        );
    }

    #[test]
    fn descriptor_parsing_survives_path_replacement_and_rejects_unsafe_files() {
        let scene = Scene::new();
        scene.generate();
        let resources =
            Resources::open(&scene.config("reader", false), KeyUse::Reader, false).unwrap();
        let slot = &resources.slots[0];
        let file = resources.read(slot).unwrap();
        fs::rename(&slot.path, scene.0.join("saved-identity")).unwrap();
        fs::write(&slot.path, b"replacement").unwrap();
        let mut loaded = Loaded::default();
        loaded.add(slot, &file).unwrap();
        assert!(loaded.identity.is_some());
        fs::remove_file(&slot.path).unwrap();
        symlink("saved-identity", &slot.path).unwrap();
        code(resources.read(slot).err().unwrap(), "KEY_UNSAFE");
        fs::remove_file(&slot.path).unwrap();
        fs::rename(scene.0.join("saved-identity"), &slot.path).unwrap();
        for mode in [0o644, 0o700, 0o1600] {
            fs::set_permissions(&slot.path, fs::Permissions::from_mode(mode)).unwrap();
            code(resources.read(slot).err().unwrap(), "KEY_UNSAFE");
        }
        fs::set_permissions(&slot.path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &slot.path,
            vec![0; backup_crypto::protocol::MAX_KEY_FILE_BYTES as usize + 1],
        )
        .unwrap();
        code(resources.read(slot).err().unwrap(), "KEY_UNSAFE");
        fs::remove_file(&slot.path).unwrap();
        let name = CString::new(slot.path.as_os_str().as_bytes()).unwrap();
        // SAFETY: private fixture path and valid C string.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = std::time::Instant::now();
        code(resources.read(slot).err().unwrap(), "KEY_UNSAFE");
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn directory_locks_are_ordered_nonblocking_and_leave_no_lock_files() {
        let scene = Scene::new();
        let config = scene.config("writer", false);
        let held = Resources::open(&config, KeyUse::Writer, true).unwrap();
        code(
            mutate_protected_keys(&config, KeyMutation::Generate)
                .err()
                .unwrap(),
            "KEY_BUSY",
        );
        code(protected_key_status(&config).err().unwrap(), "KEY_BUSY");
        assert!(scene.names().is_empty());
        drop(held);
        scene.generate();
        let first = Resources::open(&config, KeyUse::Status, false).unwrap();
        let second = Resources::open(&config, KeyUse::Status, false).unwrap();
        code(
            mutate_protected_keys(&config, KeyMutation::Publish)
                .err()
                .unwrap(),
            "KEY_BUSY",
        );
        drop((first, second));
        assert_eq!(
            scene.names(),
            vec!["identity", "recipient", "signing", "verifying"]
        );
    }

    #[test]
    fn handled_publication_failures_preserve_exact_prefix_and_allow_public_recovery() {
        for stop in 0..4 {
            let scene = Scene::new();
            let config = scene.config("writer", false);
            let resources = Resources::open(&config, KeyUse::Writer, true).unwrap();
            let (loaded, staged) = prepare(&resources, KeyMutation::Generate).unwrap();
            assert!(scene.names().is_empty(), "anonymous staging has no names");
            let outcome = publish(&resources, &loaded, &staged, |step, _| {
                ensure!(step != stop, "synthetic failure");
                Ok(())
            });
            assert_eq!(outcome.partial, stop > 0);
            let roles = ["identity", "signing", "recipient", "verifying"];
            assert_eq!(outcome.data["created"], json!(&roles[..stop]));
            assert_eq!(outcome.data["pending"], json!(&roles[stop..]));
            assert_eq!(outcome.data["keys"], json!([]));
            drop((resources, loaded, staged));
            assert_eq!(scene.names().len(), stop);
            if stop > 0 {
                code(
                    mutate_protected_keys(&config, KeyMutation::Generate)
                        .err()
                        .unwrap(),
                    "KEY_OCCUPIED",
                );
            }
            if stop >= 2 {
                let recovered = mutate_protected_keys(&config, KeyMutation::Publish).unwrap();
                assert!(recovered.error.is_none());
                protected_key_status(&config).unwrap();
            } else if stop == 1 {
                code(
                    mutate_protected_keys(&config, KeyMutation::Publish)
                        .err()
                        .unwrap(),
                    "KEY_INVALID",
                );
                assert_eq!(scene.names(), vec!["identity"]);
            }
        }
    }
    #[test]
    fn reader_store_ignores_invalid_writer_only_files_but_writer_refuses_before_store() {
        let scene = Scene::new();
        scene.generate();
        fs::write(scene.0.join("signing"), b"invalid synthetic signer").unwrap();
        fs::write(scene.0.join("recipient"), b"invalid synthetic recipient").unwrap();
        let config = scene.config("writer", false);
        code(
            open_protected_store(&config, KeyUse::Writer).err().unwrap(),
            "KEY_INVALID",
        );
        assert!(!config.storage.root.exists());
        fs::create_dir(&config.storage.root).unwrap();
        fs::set_permissions(&config.storage.root, fs::Permissions::from_mode(0o700)).unwrap();
        let store = open_protected_store(&config, KeyUse::Reader).unwrap();
        assert!(store.keys.as_ref().unwrap().signing.is_none());
        assert!(store.keys.as_ref().unwrap().recipient.is_none());
    }

    #[test]
    fn sorted_distinct_parent_locks_and_untrusted_parent_refusal_precede_writes() {
        let scene = Scene::new();
        let mut config = scene.config("writer", false);
        for name in ["a", "b"] {
            fs::create_dir(scene.0.join(name)).unwrap();
            fs::set_permissions(scene.0.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        config.encryption.as_mut().unwrap().identity_file = Some(scene.0.join("b/identity"));
        config.signing.as_mut().unwrap().signing_key_file = Some(scene.0.join("a/signing"));
        config.encryption.as_mut().unwrap().recipient_file = Some(scene.0.join("a/recipient"));
        config.signing.as_mut().unwrap().verifying_key_file = Some(scene.0.join("b/verifying"));
        fs::set_permissions(scene.0.join("b"), fs::Permissions::from_mode(0o777)).unwrap();
        code(
            mutate_protected_keys(&config, KeyMutation::Generate)
                .err()
                .unwrap(),
            "KEY_UNSAFE",
        );
        assert_eq!(fs::read_dir(scene.0.join("a")).unwrap().count(), 0);
        fs::set_permissions(scene.0.join("b"), fs::Permissions::from_mode(0o700)).unwrap();
        let resources = Resources::open(&config, KeyUse::Writer, true).unwrap();
        assert_eq!(resources.parents.len(), 2);
        code(
            mutate_protected_keys(&config, KeyMutation::Generate)
                .err()
                .unwrap(),
            "KEY_BUSY",
        );
        drop(resources);
        let outcome = mutate_protected_keys(&config, KeyMutation::Generate).unwrap();
        assert!(outcome.error.is_none());
        protected_key_status(&config).unwrap();
    }
    #[test]
    fn publication_race_never_replaces_a_newly_occupied_destination() {
        let scene = Scene::new();
        let config = scene.config("writer", false);
        let resources = Resources::open(&config, KeyUse::Writer, true).unwrap();
        let (loaded, staged) = prepare(&resources, KeyMutation::Generate).unwrap();
        let outcome = publish(&resources, &loaded, &staged, |step, slot| {
            if step == 2 {
                fs::write(&slot.path, b"unrelated synthetic occupied content")?;
            }
            Ok(())
        });
        assert_eq!(outcome.data["created"], json!(["identity", "signing"]));
        assert_eq!(outcome.error, Some("KEY_PARTIAL"));
        assert_eq!(
            fs::read(scene.0.join("recipient")).unwrap(),
            b"unrelated synthetic occupied content"
        );
        assert!(!scene.0.join("verifying").exists());
    }
}
