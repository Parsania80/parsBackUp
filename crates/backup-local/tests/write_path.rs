//! The composed write and read path, with encryption switched on and off.
//!
//! The engine here is a stub on purpose. What these tests ask is what `BackupService`
//! and `LocalStore` do with the bytes between them — whether a dump stream can reach the
//! artifact tree as plaintext, and whether the PostgreSQL tool boundary is ever handed
//! anything but plaintext — and no single-crate test can see that seam.

use anyhow::{Context, Result};
use backup_application::{
    BackupService, DatabaseAdapter, EngineInfo, RestoreService, VerifyService,
};
use backup_crypto::{keystore::KeyFile, protocol::SUITE_HYBRID};
use backup_domain::{
    AGE_FORMAT, Config, DEV_FORMAT, DumpOptions, Encryption, Profile, ResolvedSelection,
    RestoreSections, RestoreSecurityPolicy, Source, Storage, VERIFY_ARCHIVE,
};
use backup_local::LocalStore;
use std::cell::RefCell;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

/// One age chunk is 64 KiB, so repeating this past 64 KiB puts the plaintext across
/// several independently authenticated chunks rather than inside a single header test.
const ARCHIVE_MARKER: &[u8] = b"PGDMP-synthetic-archive-fixture-bytes-";
const GLOBALS_MARKER: &[u8] = b"CREATE ROLE backupctl_fixture_alice LOGIN;";

fn archive_bytes() -> Vec<u8> {
    ARCHIVE_MARKER.repeat(4096)
}

/// Every file the tool boundary was pointed at, with the bytes it held. A `pg_restore`
/// or `psql` call always reads plaintext, so this is where a leak would show up.
#[derive(Default)]
struct Capture {
    reads: RefCell<Vec<(PathBuf, Vec<u8>)>>,
}

impl Capture {
    fn slurp(&self, path: &Path) -> Result<Vec<u8>> {
        let mut file = fs::File::open(path).with_context(|| format!("stub tool reads {path:?}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        self.reads
            .borrow_mut()
            .push((path.to_path_buf(), bytes.clone()));
        Ok(bytes)
    }

    fn reads(&self) -> Vec<(PathBuf, Vec<u8>)> {
        self.reads.borrow().clone()
    }
}

#[derive(Clone, Copy)]
struct StubEngine<'a> {
    capture: &'a Capture,
}

impl DatabaseAdapter for StubEngine<'_> {
    fn preflight(&self, _source: &Source, _timeout: Duration) -> Result<EngineInfo> {
        Ok(EngineInfo {
            source_major: 16,
            source_version: "160004".to_string(),
            dump_client_version: "pg_dump (PostgreSQL) 16.4".to_string(),
        })
    }

    fn resolve_selection(
        &self,
        _source: &Source,
        _profile: &Profile,
        _timeout: Duration,
    ) -> Result<ResolvedSelection> {
        unreachable!("these tests name no profile");
    }

    fn dump_stream(
        &self,
        _source: &Source,
        _options: &DumpOptions,
        _timeout: Duration,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        // `pg_dump` writes its archive to standard output when given no file, which is
        // the shape this stub reproduces; only the bytes come from a fixture.
        consume(&mut archive_bytes().as_slice())
    }

    fn dump_globals_stream(
        &self,
        _source: &Source,
        _timeout: Duration,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        let mut globals = GLOBALS_MARKER;
        consume(&mut globals)
    }

    fn inspect_archive(
        &self,
        _source: &Source,
        archive: &Path,
        _timeout: Duration,
    ) -> Result<Vec<String>> {
        let bytes = self.capture.slurp(archive)?;
        assert_eq!(
            bytes,
            archive_bytes(),
            "the table of contents was read from something other than the archive"
        );
        Ok(vec!["Table public.accounts".to_string()])
    }

    fn database_exists(
        &self,
        _source: &Source,
        _database: &str,
        _timeout: Duration,
    ) -> Result<bool> {
        Ok(false)
    }

    fn role_conflicts(
        &self,
        _source: &Source,
        globals: &Path,
        _timeout: Duration,
    ) -> Result<Vec<String>> {
        let bytes = self.capture.slurp(globals)?;
        assert_eq!(
            bytes, GLOBALS_MARKER,
            "globals reached the tools as ciphertext"
        );
        Ok(Vec::new())
    }

    fn apply_globals(&self, _source: &Source, globals: &Path, _timeout: Duration) -> Result<()> {
        self.capture.slurp(globals).map(|_| ())
    }

    fn create_database(&self, _source: &Source, _database: &str, _timeout: Duration) -> Result<()> {
        Ok(())
    }

    fn create_schemas(
        &self,
        _source: &Source,
        _database: &str,
        _schemas: &[String],
        _timeout: Duration,
    ) -> Result<()> {
        Ok(())
    }

    fn restore_to_database(
        &self,
        _source: &Source,
        _database: &str,
        archive: &Path,
        _security: RestoreSecurityPolicy,
        _sections: RestoreSections,
        _timeout: Duration,
    ) -> Result<()> {
        let bytes = self.capture.slurp(archive)?;
        assert_eq!(
            bytes,
            archive_bytes(),
            "pg_restore was handed something other than plaintext"
        );
        Ok(())
    }
}

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!("backupctl-write-path-{}", Uuid::new_v4()))
}

/// Key files are created outside the storage root, which the configuration is required
/// to insist on anyway.
fn key_pair(dir: &Path) -> (PathBuf, PathBuf) {
    let identity = dir.join("identity.key");
    let recipient = dir.join("recipient.key");
    let key = KeyFile::create_identity(&identity).unwrap();
    KeyFile::write_recipient(&recipient, key.recipient()).unwrap();
    (identity, recipient)
}

fn config(store_root: &Path, keys: Option<(PathBuf, PathBuf)>) -> Config {
    Config {
        source: Source {
            host: "127.0.0.1".to_string(),
            port: 5432,
            user: "postgres".to_string(),
            database: "backupctl_fixture_m4a".to_string(),
            client_bin_dir: PathBuf::from("/bin"),
            password_file: None,
        },
        storage: Storage {
            root: store_root.to_path_buf(),
        },
        export_globals: true,
        encryption: keys.map(|(identity_file, recipient_file)| Encryption {
            identity_file,
            recipient_file,
        }),
        profiles: Vec::new(),
        timeout_seconds: 30,
    }
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn holds(path: &Path, needle: &[u8]) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    bytes.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn an_encrypted_backup_leaves_the_store_no_plaintext_and_the_tools_no_ciphertext() {
    let base = temp_root();
    let store_root = base.join("data");
    let keys_dir = base.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();
    let (identity, recipient) = key_pair(&keys_dir);
    let capture = Capture::default();
    let store = LocalStore::with_keys(store_root.clone(), &identity, &recipient).unwrap();
    let config = config(&store_root, Some((identity.clone(), recipient.clone())));
    let service = BackupService::new(StubEngine { capture: &capture }, store);
    let manifest = service.create(&config, None).unwrap();

    assert_eq!(manifest.format, AGE_FORMAT);
    assert_eq!(manifest.recipient_suite.as_deref(), Some(SUITE_HYBRID));
    assert_eq!(
        manifest.payload_plaintext_bytes,
        Some(archive_bytes().len() as u64)
    );
    assert_ne!(manifest.size_bytes, archive_bytes().len() as u64);

    let files = files_under(&store_root);
    let names: Vec<String> = files
        .iter()
        .map(|file| file.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for expected in ["payload.age", "globals.age", "manifest.json", "complete"] {
        assert!(
            names.iter().any(|name| name == expected),
            "{expected} missing from {names:?}"
        );
    }
    for leaked in ["payload.dump", "globals.sql"] {
        assert!(
            !names.iter().any(|name| name == leaked),
            "a plaintext file name reached the store: {names:?}"
        );
    }
    for file in &files {
        for needle in [ARCHIVE_MARKER, GLOBALS_MARKER] {
            assert!(
                !holds(file, needle),
                "{} holds plaintext that belongs to an encrypted artifact",
                file.display()
            );
        }
    }
    // Nothing staged or decrypted is left behind once the command ends.
    for dir in ["staging", "scratch"] {
        assert!(
            fs::read_dir(store_root.join(dir)).unwrap().next().is_none(),
            "{dir} still holds the work of a finished backup"
        );
    }
    // The table of contents was taken from the scratch copy, which is the only place
    // an encrypted stage's plaintext is ever written.
    let reads = capture.reads();
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert!(reads[0].0.starts_with(store_root.join("scratch")));

    let verify = VerifyService::new(
        StubEngine { capture: &capture },
        LocalStore::with_keys(store_root.clone(), &identity, &recipient).unwrap(),
    );
    verify.verify(&config, manifest.id, VERIFY_ARCHIVE).unwrap();

    let restore = RestoreService::new(
        StubEngine { capture: &capture },
        LocalStore::with_keys(store_root.clone(), &identity, &recipient).unwrap(),
    );
    let plan = restore
        .plan(
            &config,
            manifest.id,
            "backupctl_fixture_m4a_dr",
            RestoreSecurityPolicy::dr_full(),
            RestoreSections::full(),
        )
        .unwrap();
    restore
        .run(&config, plan.id, "backupctl_fixture_m4a_dr")
        .unwrap();

    // Verify and restore each decrypted through the same scratch mechanism, so every
    // read the tools made is a scratch file holding the plaintext it expected.
    let reads = capture.reads();
    assert_eq!(reads.len(), 6, "{reads:?}");
    for (path, _) in &reads {
        assert!(
            path.starts_with(store_root.join("scratch")),
            "the tool boundary read {path:?}, outside scratch"
        );
    }
    for dir in ["staging", "scratch"] {
        assert!(
            fs::read_dir(store_root.join(dir)).unwrap().next().is_none(),
            "{dir} still holds decrypted plaintext"
        );
    }
    fs::remove_dir_all(base).unwrap();
}

/// Encryption is opted into, never assumed: with no `[encryption]` block the same call
/// writes the plaintext layout earlier milestones depend on, and no scratch directory
/// exists to leak.
#[test]
fn a_backup_without_key_files_is_still_written_as_plaintext() {
    let base = temp_root();
    let store_root = base.join("data");
    let capture = Capture::default();
    let store = LocalStore::new(store_root.clone()).unwrap();
    let config = config(&store_root, None);
    let service = BackupService::new(StubEngine { capture: &capture }, store);
    let manifest = service.create(&config, None).unwrap();

    assert_eq!(manifest.format, DEV_FORMAT);
    assert_eq!(manifest.recipient_suite, None);
    assert_eq!(manifest.payload_plaintext_bytes, None);
    assert_eq!(manifest.size_bytes, archive_bytes().len() as u64);
    let names: Vec<String> = files_under(&store_root)
        .iter()
        .map(|file| file.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for expected in ["payload.dump", "globals.sql"] {
        assert!(
            names.iter().any(|name| name == expected),
            "{expected} missing from {names:?}"
        );
    }
    assert!(!store_root.join("scratch").exists());
    let reads = capture.reads();
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert!(
        reads[0].0.starts_with(store_root.join("staging")),
        "a plaintext stage is inspected where it was written, not after publication"
    );
    fs::remove_dir_all(base).unwrap();
}
