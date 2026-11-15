//! Versioned local connection policy. Legacy fixtures never enter this boundary.
use anyhow::{Result, ensure};
use backup_domain::{ConfigMode, ConfigV1, LocalAuth, NativeRestoreContext};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

const PASS_LIMIT: u64 = 64 * 1024;
#[derive(Clone)]
pub(crate) struct NativePolicy {
    pub(crate) context: NativeRestoreContext,
    keys: Vec<PathBuf>,
}
impl NativePolicy {
    pub(crate) fn new(config: &ConfigV1) -> Result<Self> {
        config.validate()?;
        ensure!(
            config.mode == ConfigMode::Fixture,
            "production native operations disabled"
        );
        let source = config
            .source
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native source required"))?;
        let tools = config
            .tools
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native tools required"))?;
        let keys = [
            config
                .encryption
                .as_ref()
                .and_then(|e| e.identity_file.clone()),
            config
                .encryption
                .as_ref()
                .and_then(|e| e.recipient_file.clone()),
            config
                .signing
                .as_ref()
                .and_then(|s| s.signing_key_file.clone()),
            config
                .signing
                .as_ref()
                .and_then(|s| s.verifying_key_file.clone()),
        ]
        .into_iter()
        .flatten()
        .collect();
        Ok(Self {
            context: NativeRestoreContext {
                mode: config.mode,
                host: source.host.clone(),
                port: source.port,
                user: source.user.clone(),
                maintenance_database: source.maintenance_database.clone(),
                auth: source.auth,
                client_bin_dir: tools.client_bin_dir.clone(),
                password_file: source.password_file.clone(),
            },
            keys,
        })
    }

    pub(crate) fn command(&self, path: &Path, database: Option<&str>) -> Result<Command> {
        let mut tool = protected_open(path, true, false)?;
        let meta = tool.metadata()?;
        ensure!(
            meta.is_file() && meta.mode() & 0o111 != 0,
            "unsafe native executable"
        );
        let mut magic = [0; 4];
        tool.read_exact(&mut magic)?;
        ensure!(magic == *b"\x7fELF", "native executable must be ELF");
        let tool = Arc::new(tool);
        let mut command = Command::new(format!("/proc/self/fd/{}", tool.as_raw_fd()));
        command.env_clear().env("LC_ALL", "C");
        inherit(&mut command, tool);
        if let Some(database) = database {
            ensure!(
                backup_domain::is_literal_database_name(database),
                "invalid native database name"
            );
            command
                .env("PGCONNECT_TIMEOUT", "10")
                .env("PGSSLMODE", "disable")
                .env("PGGSSENCMODE", "disable")
                .env("PGDATABASE", database);
            match self.context.auth {
                LocalAuth::Peer => {
                    protected_open(Path::new(&self.context.host), false, true)?;
                    command.env("PGPASSFILE", "/dev/null");
                }
                LocalAuth::ScramPassfile => {
                    let file = self.passfile(database)?;
                    command
                        .env("PGREQUIREAUTH", "scram-sha-256")
                        .env("PGPASSFILE", format!("/proc/self/fd/{}", file.as_raw_fd()));
                    inherit(&mut command, file);
                }
            }
        }
        Ok(command)
    }

    pub(crate) fn validate_database(&self, database: &str) -> Result<()> {
        if self.context.auth == LocalAuth::ScramPassfile {
            self.passfile(database)?;
        }
        Ok(())
    }

    fn passfile(&self, database: &str) -> Result<Arc<File>> {
        let path = self
            .context
            .password_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing passfile"))?;
        let file = protected_open(path, false, false)?;
        let meta = file.metadata()?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            meta.is_file()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o7777 & !0o600 == 0
                && meta.len() <= PASS_LIMIT,
            "unsafe native passfile"
        );
        for key in &self.keys {
            if let Ok(other) = fs::metadata(key) {
                ensure!(
                    meta.dev() != other.dev() || meta.ino() != other.ino(),
                    "passfile aliases key"
                );
            }
        }
        let mut bytes = Vec::new();
        file.take(PASS_LIMIT + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= PASS_LIMIT,
            "native passfile too large"
        );
        validate_entries(&bytes, &self.context, database)?;
        // A sealed memory file preserves the inspected bytes without a credential
        // temporary pathname or a validation/use race through the configured path.
        let label = c"backupctl-passfile";
        // SAFETY: valid constant C string and documented flags; new owned descriptor.
        let fd = unsafe {
            libc::memfd_create(label.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        ensure!(fd >= 0, "cannot snapshot native passfile");
        // SAFETY: successful memfd_create transfers a fresh descriptor.
        let mut snapshot = unsafe { File::from_raw_fd(fd) };
        snapshot.set_permissions(fs::Permissions::from_mode(0o600))?;
        snapshot.write_all(&bytes)?;
        // SAFETY: owned live descriptor; seals prohibit later changes to credential bytes.
        ensure!(
            unsafe {
                libc::fcntl(
                    fd,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            } == 0,
            "cannot seal native passfile"
        );
        Ok(Arc::new(snapshot))
    }
}

fn inherit(command: &mut Command, file: Arc<File>) {
    // SAFETY: only async-signal-safe fcntl in the child. Capturing the File keeps
    // its descriptor alive through spawn; only the child clears close-on-exec.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Open every path component relative to the previously validated directory.
/// Native tools require root custody; credentials/socket ancestry allows service UID.
fn protected_open(path: &Path, root_only: bool, directory_final: bool) -> Result<File> {
    ensure!(
        path.is_absolute()
            && !path
                .as_os_str()
                .as_bytes()
                .split(|b| *b == b'/')
                .any(|p| p == b"." || p == b".."),
        "unsafe native path"
    );
    let parts: Vec<_> = path.components().collect();
    ensure!(parts.len() > 1, "unsafe native path");
    let mut opened = File::open("/")?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    for (i, part) in parts.iter().enumerate().skip(1) {
        let meta = opened.metadata()?;
        ensure!(
            (meta.uid() == 0 || (!root_only && meta.uid() == uid)) && meta.mode() & 0o022 == 0,
            "unsafe native path ancestry"
        );
        let Component::Normal(name) = part else {
            anyhow::bail!("unsafe native path");
        };
        let name = CString::new(name.as_bytes())?;
        let last = i + 1 == parts.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if !last || directory_final {
                libc::O_DIRECTORY
            } else {
                0
            };
        // SAFETY: live owned parent fd, valid name, flags do not create files.
        let fd = unsafe { libc::openat(opened.as_raw_fd(), name.as_ptr(), flags) };
        ensure!(fd >= 0, "cannot open protected native resource");
        // SAFETY: successful openat returned a fresh descriptor.
        opened = unsafe { File::from_raw_fd(fd) };
    }
    let meta = opened.metadata()?;
    if root_only || directory_final {
        ensure!(
            (meta.uid() == 0 || (!root_only && meta.uid() == uid)) && meta.mode() & 0o022 == 0,
            "unsafe native resource custody"
        );
    }
    Ok(opened)
}

fn validate_entries(bytes: &[u8], context: &NativeRestoreContext, database: &str) -> Result<()> {
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        !text.contains('\0') && !text.contains('\r'),
        "invalid passfile encoding"
    );
    let mut seen = std::collections::BTreeSet::new();
    let mut matched = false;
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let mut fields = vec![String::new()];
        let mut chars = line.chars();
        while let Some(ch) = chars.next() {
            match ch {
                ':' => fields.push(String::new()),
                '\\' => {
                    let escaped = chars
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("invalid passfile escape"))?;
                    ensure!(matches!(escaped, ':' | '\\'), "invalid passfile escape");
                    fields.last_mut().unwrap().push(escaped);
                }
                _ => fields.last_mut().unwrap().push(ch),
            }
        }
        ensure!(
            fields.len() == 5
                && fields.iter().all(|f| !f.is_empty())
                && fields[..4].iter().all(|f| !f.contains('*')),
            "invalid explicit passfile entry"
        );
        let identity = fields[..4].to_vec();
        ensure!(
            seen.insert(identity) && seen.len() <= 256,
            "duplicate or excessive passfile entries"
        );
        matched |= fields[0] == context.host
            && fields[1] == context.port.to_string()
            && fields[2] == database
            && fields[3] == context.user;
    }
    ensure!(
        matched,
        "native passfile has no explicit matching credential"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::symlink;

    fn context(path: PathBuf) -> NativeRestoreContext {
        NativeRestoreContext {
            mode: ConfigMode::Fixture,
            host: "127.0.0.1".into(),
            port: 5432,
            user: "backup".into(),
            maintenance_database: "postgres".into(),
            auth: LocalAuth::ScramPassfile,
            client_bin_dir: "/usr/bin".into(),
            password_file: Some(path),
        }
    }
    struct Scene(PathBuf);
    impl Scene {
        fn new() -> Self {
            let root = PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(format!(".backupctl-native-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }
        fn policy(&self) -> NativePolicy {
            let path = self.0.join("passfile");
            fs::write(
                &path,
                b"127.0.0.1:5432:postgres:backup:synthetic\\:pass\\\\word\n",
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            NativePolicy {
                context: context(path),
                keys: vec![],
            }
        }
    }
    impl Drop for Scene {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn explicit_passfile_matching_obeys_escaping_and_rejects_ambiguity() {
        let c = context("/unused".into());
        let valid = b"# comment\n127.0.0.1:5432:postgres:backup:a\\:b\\\\c\n";
        validate_entries(valid, &c, "postgres").unwrap();
        for invalid in [
            "*:5432:postgres:backup:p\n",
            "127.0.0.1:*:postgres:backup:p\n",
            "127.0.0.1:5432:*:backup:p\n",
            "127.0.0.1:5432:postgres:*:p\n",
            "127.0.0.1:5432:postgres:backup:p:extra\n",
            "127.0.0.1:5432:postgres:backup:p\\q\n",
            "127.0.0.1:5432:postgres:backup:\n",
            "127.0.0.1:5432:other:backup:p\n",
            "127.0.0.1:5432:postgres:other:p\n",
            "localhost:5432:postgres:backup:p\n",
            "127.0.0.1:5432:postgres:backup:p\r\n",
            "127.0.0.1:5432:postgres:backup:p\0\n",
            "127.0.0.1:5432:postgres:backup:p\\",
        ] {
            assert!(validate_entries(invalid.as_bytes(), &c, "postgres").is_err());
        }
        let duplicate = [valid.as_slice(), valid.as_slice()].concat();
        assert!(validate_entries(&duplicate, &c, "postgres").is_err());
        let excessive = (0..257)
            .map(|i| format!("127.0.0.1:5432:postgres:backup{i}:p\n"))
            .collect::<String>();
        assert!(validate_entries(excessive.as_bytes(), &c, "postgres").is_err());
    }

    #[test]
    fn credential_descriptor_is_private_sealed_and_survives_path_replacement() {
        let scene = Scene::new();
        let policy = scene.policy();
        let snapshot = policy.passfile("postgres").unwrap();
        let path = policy.context.password_file.as_ref().unwrap();
        fs::rename(path, scene.0.join("old")).unwrap();
        fs::write(path, b"replacement").unwrap();
        let mut reader = File::open(format!("/proc/self/fd/{}", snapshot.as_raw_fd())).unwrap();
        let mut original = String::new();
        reader.read_to_string(&mut original).unwrap();
        assert!(original.contains("synthetic\\:pass\\\\word"));
        assert_eq!(reader.metadata().unwrap().mode() & 0o777, 0o600);
        reader.seek(SeekFrom::Start(0)).unwrap();
        assert!(reader.write_all(b"changed").is_err());
        // Try a genuinely writable descriptor too: denial must come from seals.
        let writable = fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/self/fd/{}", snapshot.as_raw_fd()))
            .unwrap();
        assert!(writable.set_len(0).is_err());
    }

    #[test]
    fn credential_opens_reject_links_writable_ancestry_modes_and_oversize() {
        let scene = Scene::new();
        let mut policy = scene.policy();
        let path = policy.context.password_file.clone().unwrap();
        fs::hard_link(&path, scene.0.join("key")).unwrap();
        policy.keys.push(scene.0.join("key"));
        assert!(policy.passfile("postgres").is_err());
        policy.keys.clear();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(policy.passfile("postgres").is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(policy.passfile("postgres").is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&scene.0, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(policy.passfile("postgres").is_err());
        fs::set_permissions(&scene.0, fs::Permissions::from_mode(0o700)).unwrap();
        let linked = scene.0.join("linked");
        symlink(&path, &linked).unwrap();
        policy.context.password_file = Some(linked);
        assert!(policy.passfile("postgres").is_err());
        policy.context.password_file = Some(path.clone());
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(PASS_LIMIT + 1).unwrap();
        assert!(policy.passfile("postgres").is_err());
        let fifo = scene.0.join("fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid C path in this private test directory, fixture-only mode.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        policy.context.password_file = Some(fifo);
        let before = std::time::Instant::now();
        assert!(policy.passfile("postgres").is_err());
        assert!(before.elapsed() < std::time::Duration::from_secs(1));
        let directory_link = scene.0.join("directory-link");
        symlink(&scene.0, &directory_link).unwrap();
        assert!(protected_open(&directory_link.join("passfile"), false, false).is_err());
        assert!(protected_open(&scene.0.join("./passfile"), false, false).is_err());
        assert!(protected_open(Path::new("/tmp/absent"), false, false).is_err());
    }

    #[test]
    fn native_command_uses_only_generated_environment_and_pinned_executable() {
        let scene = Scene::new();
        let policy = scene.policy();
        let executable = fs::canonicalize("/usr/bin/true").unwrap();
        let command = policy.command(&executable, Some("postgres")).unwrap();
        let env: std::collections::BTreeMap<_, _> = command
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_str().unwrap().to_string(),
                    v.unwrap().to_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(env.len(), 7);
        assert_eq!(env["PGREQUIREAUTH"], "scram-sha-256");
        assert_eq!(env["PGSSLMODE"], "disable");
        assert_eq!(env["PGGSSENCMODE"], "disable");
        assert!(
            command
                .get_program()
                .to_str()
                .unwrap()
                .starts_with("/proc/self/fd/")
        );
        super::super::tools::run(command, std::time::Duration::from_secs(2), None).unwrap();
        assert!(
            policy
                .command(Path::new("/usr/bin/true"), Some("postgres user=other"))
                .is_err()
        );
    }
    #[test]
    fn restore_adapter_excludes_writer_only_paths_from_native_alias_checks() {
        let config: backup_domain::ConfigV1 = serde_json::from_value(serde_json::json!({
            "config_version":1,"mode":"fixture","access":"writer","read_only":false,
            "storage":{"root":"/private/store"}, "export_globals":true,
            "source":{"host":"127.0.0.1","port":5432,"user":"backup",
                "database":"backupctl_fixture_keys","maintenance_database":"postgres",
                "auth":"scram-passfile","password_file":"/private/passfile"},
            "tools":{"client_bin_dir":"/usr/lib/postgresql/16/bin"},
            "encryption":{"identity_file":"/private/identity","recipient_file":"/forbidden/recipient"},
            "signing":{"signing_key_file":"/forbidden/signing","verifying_key_file":"/private/verifying"}
        })).unwrap();
        let writer = crate::PostgresAdapter::configured(&config)
            .unwrap()
            .policy
            .unwrap();
        let restore = crate::PostgresAdapter::configured_for_restore(&config)
            .unwrap()
            .policy
            .unwrap();
        assert_eq!(writer.keys.len(), 4);
        assert_eq!(
            restore.keys,
            vec![
                PathBuf::from("/private/identity"),
                PathBuf::from("/private/verifying")
            ]
        );
        assert_eq!(writer.context, restore.context);
    }
}
