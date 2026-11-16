//! Pin writable versioned roots without changing the physical store lock domain.
use anyhow::{Context, Result, ensure};
use backup_domain::ConfigV1;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub struct ProtectedRoot {
    directory: File,
    path: PathBuf,
    configured: PathBuf,
}
impl ProtectedRoot {
    pub fn open(config: &ConfigV1, create: bool) -> Result<Arc<Self>> {
        config.validate().context("CONFIG_INVALID")?;
        ensure!(
            config.mode == backup_domain::ConfigMode::Fixture,
            "PRODUCTION_NOT_ENABLED"
        );
        Self::open_mode(config, create, false)
    }
    fn open_mode(config: &ConfigV1, create: bool, snapshot: bool) -> Result<Arc<Self>> {
        ensure!(!config.read_only || snapshot, "READ_ONLY");
        ensure!(
            !create || config.access == backup_domain::Access::Writer,
            "ACCESS_DENIED"
        );
        let path = &config.storage.root;
        ensure!(path.is_absolute(), "FILESYSTEM_UNSAFE");
        let mut parent = File::open("/").context("FILESYSTEM_UNSAFE")?;
        let parts = path.components().skip(1).collect::<Vec<_>>();
        ensure!(!parts.is_empty(), "FILESYSTEM_UNSAFE");
        for (i, part) in parts.iter().enumerate() {
            let meta = parent.metadata().context("FILESYSTEM_UNSAFE")?;
            // SAFETY: geteuid has no preconditions.
            ensure!(
                (meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() })
                    && meta.mode() & 0o022 == 0,
                "FILESYSTEM_UNSAFE"
            );
            let Component::Normal(name) = part else {
                anyhow::bail!("FILESYSTEM_UNSAFE");
            };
            let name = CString::new(name.as_bytes()).context("FILESYSTEM_UNSAFE")?;
            if create && i + 1 == parts.len() {
                // SAFETY: valid parent/name, mkdirat never replaces an existing name.
                let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
                if rc != 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    anyhow::bail!("FILESYSTEM_UNSAFE");
                }
            }
            parent = open_dir(&parent, &name)?;
        }
        private_dir(&parent)?;
        let io = PathBuf::from(format!(
            "/proc/{}/fd/{}/.",
            std::process::id(),
            parent.as_raw_fd()
        ));
        let guard = Arc::new(Self {
            directory: parent,
            path: io,
            configured: path.clone(),
        });
        guard.validate_layout()?;
        Ok(guard)
    }
    pub(crate) fn snapshot(config: &ConfigV1) -> Result<Arc<Self>> {
        config.validate().context("CONFIG_INVALID")?;
        ensure!(
            config.mode == backup_domain::ConfigMode::Fixture,
            "PRODUCTION_NOT_ENABLED"
        );
        ensure!(config.read_only, "READ_ONLY");
        let guard = Self::open_mode(config, false, true)?;
        for suffix in ["-journal", "-wal", "-shm"] {
            ensure!(
                !exists(
                    &guard.directory,
                    &CString::new(format!("inventory.db{suffix}"))?
                )?,
                "SNAPSHOT_UNSAFE"
            );
        }
        Ok(guard)
    }
    pub(crate) fn external(path: &Path) -> Result<Arc<Self>> {
        let directory = crate::custody::protected_directory(path).context("FILESYSTEM_UNSAFE")?;
        private_dir(&directory)?;
        Ok(Arc::new(Self {
            path: PathBuf::from(format!(
                "/proc/{}/fd/{}/.",
                std::process::id(),
                directory.as_raw_fd()
            )),
            directory,
            configured: path.to_path_buf(),
        }))
    }
    pub(crate) fn reject_overlap(&self, directory: &File) -> Result<()> {
        self.reject_key_parent(directory)?;
        reject_descendant(directory, &self.directory)
    }
    pub(crate) fn directory(&self) -> &File {
        &self.directory
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn keyless_store(self: &Arc<Self>) -> Result<crate::LocalStore> {
        self.initialize()?;
        Ok(crate::LocalStore {
            root: self.path.clone(),
            keys: None,
            snapshot: None,
            resources: None,
            fs_guard: Some(self.clone()),
            scratch_budget: crate::resources::Budget::new(u64::MAX),
        })
    }
    pub(crate) fn display_path(&self, path: &Path) -> PathBuf {
        path.strip_prefix(&self.path)
            .map_or_else(|_| path.to_path_buf(), |p| self.configured.join(p))
    }
    fn validate_layout(&self) -> Result<()> {
        for name in ["artifacts", "staging", "scratch", "plans", "locks"] {
            let name = CString::new(name).unwrap();
            if exists(&self.directory, &name)? {
                private_dir(&open_dir(&self.directory, &name)?)?;
            }
        }
        for name in [
            "inventory.db",
            "inventory.db-journal",
            "inventory.db-wal",
            "inventory.db-shm",
        ] {
            let name = CString::new(name).unwrap();
            if !exists(&self.directory, &name)? {
                continue;
            }
            // SAFETY: valid parent/name, read-only, nonblocking and no symlink traversal.
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            ensure!(fd >= 0, "FILESYSTEM_UNSAFE");
            // SAFETY: successful open returned a fresh descriptor.
            let file = unsafe { File::from_raw_fd(fd) };
            let m = file.metadata().context("FILESYSTEM_UNSAFE")?;
            // SAFETY: geteuid has no preconditions.
            ensure!(
                m.is_file()
                    && m.uid() == unsafe { libc::geteuid() }
                    && m.mode() & 0o7777 & !0o600 == 0
                    && m.nlink() == 1,
                "FILESYSTEM_UNSAFE"
            );
        }
        Ok(())
    }
    pub(crate) fn initialize(&self) -> Result<()> {
        for name in ["artifacts", "staging", "scratch", "plans", "locks"] {
            let name = CString::new(name).unwrap();
            // SAFETY: fixed component under owned root fd, no replace semantics.
            let rc = unsafe { libc::mkdirat(self.directory.as_raw_fd(), name.as_ptr(), 0o700) };
            if rc != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                anyhow::bail!("FILESYSTEM_UNSAFE");
            }
            private_dir(&open_dir(&self.directory, &name)?)?;
        }
        self.directory.sync_all().context("FILESYSTEM_UNSAFE")?;
        Ok(())
    }
    pub(crate) fn reject_key_parent(&self, dir: &File) -> Result<()> {
        reject_descendant(&self.directory, dir)
    }
}
fn reject_descendant(root: &File, dir: &File) -> Result<()> {
    let store = root.metadata().context("FILESYSTEM_UNSAFE")?;
    let mut current = dir.try_clone().context("FILESYSTEM_UNSAFE")?;
    for _ in 0..1024 {
        let meta = current.metadata().context("FILESYSTEM_UNSAFE")?;
        ensure!(
            (meta.dev(), meta.ino()) != (store.dev(), store.ino()),
            "FILESYSTEM_UNSAFE"
        );
        let parent = open_dir(&current, c"..")?;
        let pm = parent.metadata().context("FILESYSTEM_UNSAFE")?;
        if (pm.dev(), pm.ino()) == (meta.dev(), meta.ino()) {
            return Ok(());
        }
        current = parent;
    }
    anyhow::bail!("FILESYSTEM_UNSAFE")
}
fn open_dir(parent: &File, name: &std::ffi::CStr) -> Result<File> {
    // SAFETY: valid live parent and C name; no symlink, creation or blocking special file.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
        )
    };
    ensure!(fd >= 0, "FILESYSTEM_UNSAFE");
    // SAFETY: successful open returns a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn private_dir(dir: &File) -> Result<()> {
    let m = dir.metadata().context("FILESYSTEM_UNSAFE")?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 & !0o700 == 0,
        "FILESYSTEM_UNSAFE"
    );
    Ok(())
}
fn exists(parent: &File, name: &std::ffi::CStr) -> Result<bool> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid fd/name and output storage; no dereference before initialization.
    let rc = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        return Ok(false);
    }
    Err(error).context("FILESYSTEM_UNSAFE")
}

pub(crate) fn open_store(
    config: &ConfigV1,
    keys: crate::StoreKeys,
    key_parents: &[File],
    create: bool,
) -> Result<crate::LocalStore> {
    let guard = ProtectedRoot::open(config, create)?;
    for parent in key_parents {
        guard.reject_key_parent(parent)?;
    }
    guard.initialize()?;
    Ok(crate::LocalStore {
        root: guard.path().to_path_buf(),
        keys: Some(keys),
        snapshot: None,
        resources: Some(config.resources.clone()),
        fs_guard: Some(guard),
        scratch_budget: crate::resources::Budget::new(config.resources.max_scratch_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use backup_application::{ArtifactStore, PlaintextView, WriteOptions};
    use backup_crypto::keystore::{KeyFile, KeyRole};
    use backup_domain::ResourceLimits;
    use backup_inventory::ActivityLock;
    use serde_json::json;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

    struct Scene(PathBuf);
    impl Scene {
        fn new() -> Self {
            let root = PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(format!(".backupctl-fs-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }
        fn config(&self) -> ConfigV1 {
            serde_json::from_value(json!({"config_version":1,"mode":"fixture","access":"writer",
                "read_only":false,"storage":{"root":self.0.join("store")},
                "encryption":{"identity_file":self.0.join("identity"),"recipient_file":self.0.join("recipient")},
                "signing":{"signing_key_file":self.0.join("signing"),"verifying_key_file":self.0.join("verifying")}
            })).unwrap()
        }
        fn guard(&self) -> Arc<ProtectedRoot> {
            ProtectedRoot::open(&self.config(), true).unwrap()
        }
        fn store(&self, limits: ResourceLimits) -> crate::LocalStore {
            let mut store = self.guard().keyless_store().unwrap();
            store.scratch_budget = crate::resources::Budget::new(limits.max_scratch_bytes);
            store.resources = Some(limits);
            store
        }
    }
    impl Drop for Scene {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn unsafe_root(config: &ConfigV1) {
        let error = ProtectedRoot::open(config, false)
            .err()
            .expect("must refuse");
        assert!(
            format!("{error:#}").contains("FILESYSTEM_UNSAFE"),
            "{error:#}"
        );
    }
    #[test]
    fn protected_root_refuses_unsafe_names_modes_links_and_special_inventory() {
        let scene = Scene::new();
        let cfg = scene.config();
        let root = &cfg.storage.root;
        let guard = scene.guard();
        assert_eq!(fs::metadata(root).unwrap().mode() & 0o777, 0o700);
        guard.initialize().unwrap();
        drop(guard);
        fs::set_permissions(root, fs::Permissions::from_mode(0o750)).unwrap();
        unsafe_root(&cfg);
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&scene.0, fs::Permissions::from_mode(0o770)).unwrap();
        unsafe_root(&cfg);
        fs::set_permissions(&scene.0, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(root.join("scratch")).unwrap();
        symlink(scene.0.join("outside"), root.join("scratch")).unwrap();
        unsafe_root(&cfg);
        fs::remove_file(root.join("scratch")).unwrap();
        let path = root.join("inventory.db");
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path C string, synthetic FIFO, removed without reading.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        unsafe_root(&cfg);
        fs::remove_file(&path).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        fs::hard_link(&path, scene.0.join("alias")).unwrap();
        unsafe_root(&cfg);
        fs::remove_file(scene.0.join("alias")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        unsafe_root(&cfg);
        fs::remove_file(path).unwrap();
        fs::rename(root, scene.0.join("moved")).unwrap();
        symlink(scene.0.join("moved"), root).unwrap();
        unsafe_root(&cfg);
        fs::remove_file(root).unwrap();
        let mut cfg = cfg;
        cfg.storage.root = scene.0.join("missing/child");
        assert!(ProtectedRoot::open(&cfg, true).is_err());
        assert!(!scene.0.join("missing").exists());
    }
    #[test]
    fn root_descriptor_survives_replacement_uses_same_locks_and_reaches_children() {
        let scene = Scene::new();
        let guard = scene.guard();
        let store = guard.keyless_store().unwrap();
        let original = scene.0.join("store");
        let moved = scene.0.join("moved");
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        fs::write(store.root.join("proof"), b"held root").unwrap();
        assert!(!original.join("proof").exists());
        assert_eq!(fs::read(moved.join("proof")).unwrap(), b"held root");
        let inventory_path = store.root.join("inventory.db");
        let estate = backup_inventory::Estate::new("0123456789abcdef".into()).unwrap();
        drop(backup_inventory::Inventory::open(&inventory_path, &estate).unwrap());
        drop(backup_inventory::Inventory::open_read_only_bound(&inventory_path).unwrap());
        assert!(!original.join("inventory.db").exists());
        assert!(moved.join("inventory.db").is_file());
        let claim = ActivityLock::hold(&store.root).unwrap();
        assert!(ActivityLock::hold_maintenance(&moved).unwrap().is_none());
        drop(claim);
        assert!(ActivityLock::hold_maintenance(&moved).unwrap().is_some());
        let stage = store
            .begin(
                uuid::Uuid::new_v4(),
                &WriteOptions {
                    with_globals: false,
                },
            )
            .unwrap();
        let path = stage.dir.clone();
        let weak = Arc::downgrade(&guard);
        drop(store);
        drop(guard);
        assert!(weak.upgrade().is_some());
        let cat = fs::canonicalize("/usr/bin/cat").unwrap();
        let out = std::process::Command::new(cat)
            .arg(path.parent().unwrap().parent().unwrap().join("proof"))
            .output()
            .unwrap();
        assert!(out.status.success(), "{:?}", out.stderr);
        assert_eq!(out.stdout, b"held root");
        drop(stage);
        assert!(weak.upgrade().is_none());
        assert_eq!(fs::read_dir(moved.join("staging")).unwrap().count(), 0);
    }
    #[test]
    fn jobs_and_artifact_claims_pin_root_and_new_inventory_is_private() {
        let scene = Scene::new();
        let guard = scene.guard();
        let store = guard.keyless_store().unwrap();
        let id = uuid::Uuid::new_v4();
        let job = store
            .begin_job(&backup_application::JobRequest {
                source_fingerprint: "0123456789abcdef".into(),
                profile_name: "test".into(),
                backup_id: id,
            })
            .unwrap();
        let use_guard = store.claim_artifact(id).unwrap();
        assert_eq!(
            fs::metadata(store.root.join("inventory.db"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        let weak = Arc::downgrade(&guard);
        drop(store);
        drop(guard);
        job.staged().unwrap();
        job.complete().unwrap();
        drop(job);
        assert!(weak.upgrade().is_some());
        drop(use_guard);
        assert!(weak.upgrade().is_none());
        ProtectedRoot::open(&scene.config(), false).unwrap();
    }
    #[test]
    fn key_parent_inode_walk_refuses_store_descendants_and_aliases() {
        let scene = Scene::new();
        let guard = scene.guard();
        fs::create_dir(scene.0.join("store/keys")).unwrap();
        let inner = File::open(scene.0.join("store/keys")).unwrap();
        assert!(guard.reject_key_parent(&inner).is_err());
        symlink(scene.0.join("store/keys"), scene.0.join("key-alias")).unwrap();
        assert!(
            guard
                .reject_key_parent(&File::open(scene.0.join("key-alias")).unwrap())
                .is_err()
        );
        guard
            .reject_key_parent(&File::open(&scene.0).unwrap())
            .unwrap();
    }
    #[test]
    fn stages_have_plaintext_and_combined_budgets_and_hashes_are_bounded() {
        let scene = Scene::new();
        let limits = ResourceLimits {
            max_payload_bytes: 3,
            max_globals_bytes: 3,
            max_stage_bytes: 5,
            ..Default::default()
        };
        let store = scene.store(limits);
        let stage = store
            .begin(uuid::Uuid::new_v4(), &WriteOptions { with_globals: true })
            .unwrap();
        let mut payload = store
            .stage_sink(&stage, crate::stage::Target::Payload)
            .unwrap();
        payload.write_all(b"abc").unwrap();
        assert!(payload.write(b"d").is_err());
        payload.finish().unwrap();
        drop(payload);
        let mut globals = store
            .stage_sink(&stage, crate::stage::Target::Globals)
            .unwrap();
        globals.write_all(b"de").unwrap();
        assert!(globals.write(b"f").is_err());
        drop(globals);
        drop(stage);
        assert_eq!(fs::read_dir(store.root.join("staging")).unwrap().count(), 0);
        let path = store.root.join("payload.age");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.set_len(ResourceLimits::ciphertext_limit(3) + 1)
            .unwrap();
        assert_eq!(
            store.hash_resource(&path).unwrap_err().to_string(),
            "RESOURCE_LIMIT"
        );
    }
    #[test]
    fn scratch_views_share_quota_release_after_removal_and_pin_root() {
        let scene = Scene::new();
        let limits = ResourceLimits {
            max_payload_bytes: 3,
            max_scratch_bytes: 5,
            ..Default::default()
        };
        let mut store = scene.store(limits);
        let (identity, recipient) = crate::fixture::key_pair(&scene.0.join("keys"));
        let recipient = KeyFile::load(&recipient, KeyRole::Recipient).unwrap();
        let cipher = store.root.join("payload.age");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&cipher)
            .unwrap();
        backup_crypto::stream::encrypt(recipient.recipient(), &b"abc"[..], &mut file).unwrap();
        store.keys = Some(crate::StoreKeys {
            identity: KeyFile::load(&identity, KeyRole::Identity).unwrap(),
            recipient: Some(recipient),
            signing: None,
            verifying: None,
        });
        let view = store
            .decrypt_to_scratch(&cipher, "payload.dump", Some(3), None)
            .unwrap();
        assert_eq!(fs::read(view.path()).unwrap(), b"abc");
        let error = store
            .decrypt_to_scratch(&cipher, "payload.dump", Some(3), None)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("RESOURCE_LIMIT"));
        assert_eq!(fs::read_dir(store.root.join("scratch")).unwrap().count(), 1);
        drop(view);
        store.resources.as_mut().unwrap().max_payload_bytes = 2;
        let error = store
            .decrypt_to_scratch(&cipher, "payload.dump", Some(3), None)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("RESOURCE_LIMIT"));
        assert_eq!(fs::read_dir(store.root.join("scratch")).unwrap().count(), 0);
        store.resources.as_mut().unwrap().max_payload_bytes = 3;
        let view = store
            .decrypt_to_scratch(&cipher, "payload.dump", Some(3), None)
            .unwrap();
        let path = view.path().to_path_buf();
        let weak = Arc::downgrade(store.fs_guard.as_ref().unwrap());
        drop(store);
        assert_eq!(fs::read(path).unwrap(), b"abc");
        assert!(weak.upgrade().is_some());
        drop(view);
        assert!(weak.upgrade().is_none());
        assert_eq!(
            fs::read_dir(scene.0.join("store/scratch")).unwrap().count(),
            0
        );
    }
}
