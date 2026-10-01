//! The fixture the composed write-and-read paths share: a `DatabaseAdapter` that never runs
//! a PostgreSQL tool, plus the key files and configuration a store is built from.
//!
//! The stub reads every file the tool boundary is pointed at and compares its bytes, so a
//! ciphertext that reaches `pg_restore` fails inside the adapter instead of corrupting a
//! database later. It also records each `CREATE DATABASE`, because "this plan never reached
//! the cluster" is a claim about a call that did not happen.
#![allow(dead_code)]

use anyhow::{Context, Result};
use backup_application::{DatabaseAdapter, EngineInfo};
use backup_crypto::{keystore::KeyFile, signing::SigningKeyFile};
use backup_domain::{
    Config, DumpOptions, Encryption, Profile, ResolvedSelection, RestoreSections,
    RestoreSecurityPolicy, Signing, Source, Storage,
};
use std::cell::RefCell;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

/// One age chunk is 64 KiB, so repeating this past 64 KiB puts the plaintext across
/// several independently authenticated chunks rather than inside a single header test.
pub const ARCHIVE_MARKER: &[u8] = b"PGDMP-synthetic-archive-fixture-bytes-";
pub const GLOBALS_MARKER: &[u8] = b"CREATE ROLE backupctl_fixture_alice LOGIN;";

pub fn archive_bytes() -> Vec<u8> {
    ARCHIVE_MARKER.repeat(4096)
}

/// Every file the tool boundary was pointed at, with the bytes it held. A `pg_restore`
/// or `psql` call always reads plaintext, so this is where a leak would show up.
#[derive(Default)]
pub struct Capture {
    reads: RefCell<Vec<(PathBuf, Vec<u8>)>>,
    created: RefCell<Vec<String>>,
}

impl Capture {
    pub fn slurp(&self, path: &Path) -> Result<Vec<u8>> {
        let mut file = fs::File::open(path).with_context(|| format!("stub tool reads {path:?}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        self.reads
            .borrow_mut()
            .push((path.to_path_buf(), bytes.clone()));
        Ok(bytes)
    }

    pub fn reads(&self) -> Vec<(PathBuf, Vec<u8>)> {
        self.reads.borrow().clone()
    }

    /// The databases this stub was asked to create, in call order.
    pub fn created(&self) -> Vec<String> {
        self.created.borrow().clone()
    }
}

#[derive(Clone, Copy)]
pub struct StubEngine<'a> {
    pub capture: &'a Capture,
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

    fn create_database(&self, _source: &Source, database: &str, _timeout: Duration) -> Result<()> {
        self.capture.created.borrow_mut().push(database.to_string());
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

/// A temporary directory no test leaves behind; the label keeps a failure readable.
pub fn temp_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("backupctl-{label}-{}", Uuid::new_v4()))
}

/// The four key files a v1 writer configures, each one outside the storage root — which is
/// the rule the configuration file itself enforces.
pub struct Keys {
    pub identity: PathBuf,
    pub recipient: PathBuf,
    pub signing: PathBuf,
    pub verifying: PathBuf,
}

impl Keys {
    pub fn generate(dir: &Path) -> Self {
        fs::create_dir_all(dir).unwrap();
        let identity = dir.join("identity.key");
        let recipient = dir.join("recipient.key");
        let key = KeyFile::create_identity(&identity).unwrap();
        KeyFile::write_recipient(&recipient, key.recipient()).unwrap();
        let signing = dir.join("signing.key");
        let signer = SigningKeyFile::create_signing(&signing).unwrap();
        let verifying = dir.join("verifying.key");
        SigningKeyFile::write_verifying(&verifying, signer.verifier()).unwrap();
        Self {
            identity,
            recipient,
            signing,
            verifying,
        }
    }
}

/// The configuration a store built from these key files is paired with. The blocks describe
/// this host; the store's own shape is what decides which artifact is written.
pub fn config(
    store_root: &Path,
    encryption: Option<(PathBuf, PathBuf)>,
    signing: Option<Signing>,
) -> Config {
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
        signing,
        encryption: encryption.map(|(identity_file, recipient_file)| Encryption {
            identity_file,
            recipient_file,
        }),
        profiles: Vec::new(),
        timeout_seconds: 30,
    }
}

/// `[signing]` as a backup host that writes artifacts configures it: both halves present.
pub fn signing_block(keys: &Keys) -> Signing {
    Signing {
        signing_key_file: Some(keys.signing.clone()),
        verifying_key_file: keys.verifying.clone(),
    }
}

/// Where a published artifact's files live, once it is visible at all.
pub fn artifact_dir(root: &Path, id: Uuid) -> PathBuf {
    root.join("artifacts").join(id.to_string())
}

/// The message of a refusal, without requiring the success type to be printable. The types
/// behind those results hold paths into an artifact store and decrypted file names, and a
/// test that dumps one would be exactly the kind of output the tool's rules are meant to
/// keep out of a log.
pub fn failure<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected a refusal, got a success"),
        Err(error) => format!("{error:#}"),
    }
}

pub fn files_under(root: &Path) -> Vec<PathBuf> {
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

pub fn holds(path: &Path, needle: &[u8]) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    bytes.windows(needle.len()).any(|w| w == needle)
}
