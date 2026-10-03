//! The composed v1 path: what a signed store publishes, and what the application layer is
//! willing to do with it.
//!
//! `signed_store.rs` proves the bytes on disk cannot be read without the origin signature
//! having been checked. What is under test here is the seam above that — `RestoreService` and
//! `VerifyService` are readers too, so a forged artifact has to be refused while the cluster
//! still holds nothing new. That is a claim an operator can only act on in a disaster if it
//! is tested without a database in the loop.

mod common;

use backup_application::{
    BackupService, Created, Inventory, Record, RestoreService, VerifyService,
};
use backup_crypto::protocol::{HYBRID_SIGNATURE_BYTES, SUITE_HYBRID};
use backup_domain::{
    ARTIFACT_FORMAT_VERSION, ArtifactManifest, Config, ENGINE_POSTGRESQL, GLOBALS_POLICY_EXPORTED,
    ID_HEX_LEN, PublicHeader, RestoreSections, RestoreSecurityPolicy, SIGNATURE_SUITES,
    VERIFICATION_NONE, VERIFY_ARCHIVE, VERIFY_CHECKSUM, VERIFY_SIGNATURE, WHOLE_DATABASE_PROFILE,
    is_utc_timestamp, profile_fingerprint, source_fingerprint,
};
use backup_inventory::{
    AuditAction, Estate, INVENTORY_FILE, JobGuard, JobLock, JobScope, JobState, SCHEMA_VERSION,
    Shape, State,
};
use backup_local::LocalStore;
use common::{
    ARCHIVE_MARKER, Capture, GLOBALS_MARKER, Keys, StubEngine, archive_bytes, artifact_dir, config,
    failure, files_under, holds, signing_block, temp_root,
};
use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use uuid::Uuid;

const SOURCE_DATABASE: &str = "backupctl_fixture_m4b";
const DR_TARGET: &str = "backupctl_fixture_m4b_dr";

/// One v1 artifact written by the stub dump, with everything a test needs to talk back to it.
struct Fixture {
    base: PathBuf,
    store_root: PathBuf,
    keys: Keys,
    config: Config,
    id: Uuid,
    header: PublicHeader,
    manifest: ArtifactManifest,
}

impl Fixture {
    fn artifact_dir(&self) -> PathBuf {
        artifact_dir(&self.store_root, self.id)
    }

    /// The store a host that writes and reads v1 builds: `[encryption]` plus `[signing]`.
    fn writer(&self) -> LocalStore {
        LocalStore::with_signing_keys(
            self.store_root.clone(),
            &self.keys.identity,
            &self.keys.recipient,
            &self.keys.signing,
            &self.keys.verifying,
        )
        .unwrap()
    }

    /// The disaster-recovery shape: the decryption identity and the trusted verifying key,
    /// with no signing secret and no recipient.
    fn reader(&self) -> LocalStore {
        LocalStore::for_reading(
            self.store_root.clone(),
            &self.keys.identity,
            &self.keys.verifying,
        )
        .unwrap()
    }

    fn remove(self) {
        fs::remove_dir_all(&self.base).unwrap();
    }
}

/// Writes one v1 artifact through the given `Capture`, so a test can count what the
/// PostgreSQL tool boundary was handed and whether a database was ever created.
fn write_signed(capture: &Capture) -> Fixture {
    let base = temp_root("signed-write-path");
    write_signed_in(capture, base).expect("a fresh store root wrote a v1 artifact")
}

/// [`write_signed`], at a root the caller chose.
///
/// A test that has to look at the store *while* the dump runs needs the path first. The failure is
/// returned rather than panicked with, because the caller is the one holding what the store looked
/// like at the moment the dump stopped.
fn write_signed_in(capture: &Capture, base: PathBuf) -> std::result::Result<Fixture, String> {
    let store_root = base.join("data");
    let keys = Keys::generate(&base.join("keys"));
    let mut config = config(
        &store_root,
        Some((keys.identity.clone(), keys.recipient.clone())),
        Some(signing_block(&keys)),
    );
    config.source.database = SOURCE_DATABASE.to_string();
    let created = BackupService::new(
        StubEngine { capture },
        LocalStore::with_signing_keys(
            store_root.clone(),
            &keys.identity,
            &keys.recipient,
            &keys.signing,
            &keys.verifying,
        )
        .unwrap(),
    )
    .create(&config, None);
    let Created::Signed { header, manifest } = (match created {
        Ok(created) => created,
        Err(error) => return Err(format!("{error:#}")),
    }) else {
        panic!("a store with [encryption] and [signing] writes a v1 artifact");
    };
    assert_eq!(header.backup_id, manifest.backup_id);
    Ok(Fixture {
        base,
        store_root,
        keys,
        config,
        id: manifest.backup_id,
        header: *header,
        manifest: *manifest,
    })
}

/// Every file of one artifact with its bytes, so a later "nothing changed" claim covers the
/// whole record rather than only the field a writer would have edited.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

#[test]
fn a_signed_backup_writes_the_v1_files_and_signs_a_record_a_reader_cannot_forge() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);

    assert_eq!(fixture.manifest.format_version, ARTIFACT_FORMAT_VERSION);
    assert_eq!(fixture.manifest.engine, ENGINE_POSTGRESQL);
    assert_eq!(fixture.manifest.source_server_major, 16);
    assert_eq!(fixture.manifest.recipient_suite, SUITE_HYBRID);
    assert_eq!(fixture.manifest.signature_suite, SIGNATURE_SUITES[0]);
    assert_eq!(fixture.manifest.globals_policy, GLOBALS_POLICY_EXPORTED);
    assert_eq!(fixture.manifest.verification_level, VERIFICATION_NONE);
    assert_eq!(
        fixture.manifest.archive_plaintext_bytes,
        archive_bytes().len() as u64
    );
    // What the signature covers is the ciphertext on disk, and it is not the archive.
    assert_eq!(
        fixture.header.payload_ciphertext_bytes,
        fixture.manifest.payload_ciphertext_bytes
    );
    assert_ne!(
        fixture.manifest.payload_ciphertext_bytes,
        archive_bytes().len() as u64
    );
    assert!(fixture.manifest.globals_sha256.is_some());
    // The table of contents is recorded when the artifact is written, because a signed
    // manifest cannot gain a fact later without changing what its signature covers.
    assert!(fixture.manifest.archive_toc_sha256.is_some());

    // The two ids describe different keys: one sealed the payload, the other signed it.
    assert_eq!(fixture.manifest.recipient_id.len(), ID_HEX_LEN);
    assert_eq!(fixture.manifest.signer_id.len(), ID_HEX_LEN);
    assert_ne!(fixture.manifest.recipient_id, fixture.manifest.signer_id);
    assert_eq!(fixture.header.signer_id, fixture.manifest.signer_id);

    // A dump that named no profile still records a scope, under the one name nothing else may
    // use, so a filtered artifact can never claim a whole database.
    let profile = &fixture.manifest.profile_snapshot;
    assert_eq!(profile.name, WHOLE_DATABASE_PROFILE);
    assert_eq!(profile.database, SOURCE_DATABASE);
    assert!(profile.large_objects);
    assert!(profile.is_whole_database());

    // The recorded fingerprint is exactly what planning recomputes from a matching
    // configuration, which is why that comparison can refuse anything at all.
    assert_eq!(
        fixture.manifest.source_fingerprint,
        source_fingerprint(&fixture.config.source, 16)
    );

    let dir = fixture.artifact_dir();
    let files = files_under(&fixture.store_root);
    let names: Vec<String> = files
        .iter()
        .map(|file| file.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for expected in [
        "payload.age",
        "globals.age",
        "manifest.age",
        "signature.hybrid",
        "public.json",
        "complete",
    ] {
        assert!(
            names.iter().any(|name| name == expected),
            "{expected} missing from {names:?}"
        );
    }
    // A v1 artifact keeps no plaintext manifest beside it, and no file names the dump.
    for leaked in ["payload.dump", "globals.sql", "manifest.json"] {
        assert!(
            !names.iter().any(|name| name == leaked),
            "a development-era file name reached a signed artifact: {names:?}"
        );
    }
    assert_eq!(
        fs::read(dir.join("signature.hybrid")).unwrap().len(),
        HYBRID_SIGNATURE_BYTES
    );
    for file in &files {
        for needle in [ARCHIVE_MARKER, GLOBALS_MARKER] {
            assert!(
                !holds(file, needle),
                "{} holds plaintext that belongs to a signed artifact",
                file.display()
            );
        }
    }
    for state in ["staging", "scratch"] {
        assert!(
            fs::read_dir(fixture.store_root.join(state))
                .unwrap()
                .next()
                .is_none(),
            "{state} still holds the work of a finished backup"
        );
    }
    fixture.remove();
}

#[test]
fn every_verification_level_passes_a_signed_artifact_and_signature_level_decrypts_nothing() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);
    let id = fixture.id;
    let scratch = fixture.store_root.join("scratch");

    // Discovery needs no key material, and it hides nothing.
    let Inventory::Public(listing) =
        BackupService::new(StubEngine { capture: &capture }, fixture.reader())
            .list()
            .unwrap()
    else {
        panic!("a signed store is discovered from public.json");
    };
    assert_eq!(listing.signed.len(), 1);
    assert!(listing.unsigned.is_empty());
    assert_eq!(listing.signed[0].backup_id, id);
    assert_eq!(
        listing.signed[0].payload_sha256,
        fixture.header.payload_sha256
    );

    let verify = VerifyService::new(StubEngine { capture: &capture }, fixture.reader());
    let reads = capture.reads().len();

    let signature = verify
        .verify(&fixture.config, id, VERIFY_SIGNATURE)
        .unwrap();
    assert_eq!(signature.level, VERIFY_SIGNATURE);
    assert_eq!(
        signature.payload_size_bytes,
        fixture.header.payload_ciphertext_bytes
    );
    assert_eq!(signature.payload_sha256, fixture.header.payload_sha256);
    // Globals are only reported once something has been decrypted to bind them, which
    // signature level deliberately never does.
    assert_eq!(signature.globals_size_bytes, None);
    assert_eq!(signature.globals_sha256, None);
    let origin = signature.origin.expect("a signed report names its origin");
    assert_eq!(origin.signer_id, fixture.manifest.signer_id);
    assert_eq!(origin.recipient_id, fixture.manifest.recipient_id);
    assert_eq!(origin.signature_suite, fixture.manifest.signature_suite);
    assert_eq!(
        capture.reads().len(),
        reads,
        "signature level reached the PostgreSQL tool boundary"
    );
    assert!(
        fs::read_dir(&scratch).unwrap().next().is_none(),
        "signature level decrypted something into scratch"
    );

    // Checksum level decrypts the manifest — which needs no PostgreSQL tool either.
    let checksum = verify.verify(&fixture.config, id, VERIFY_CHECKSUM).unwrap();
    assert_eq!(checksum.level, VERIFY_CHECKSUM);
    assert_eq!(
        checksum.globals_size_bytes,
        fixture.manifest.globals_ciphertext_bytes
    );
    assert_eq!(checksum.globals_sha256, fixture.manifest.globals_sha256);
    assert_eq!(
        capture.reads().len(),
        reads,
        "checksum level reached the PostgreSQL tool boundary"
    );

    let archive = verify.verify(&fixture.config, id, VERIFY_ARCHIVE).unwrap();
    assert_eq!(archive.level, VERIFY_ARCHIVE);
    let after = capture.reads();
    assert_eq!(after.len(), reads + 1, "archive level: {after:?}");
    assert!(
        after[reads].0.starts_with(&scratch),
        "the table of contents was listed from outside scratch"
    );

    // `backup inspect` reads the manifest inside the authenticated ciphertext.
    let Record::Signed(manifest) =
        BackupService::new(StubEngine { capture: &capture }, fixture.reader())
            .inspect(id)
            .unwrap()
    else {
        panic!("a v1 artifact's record is its signed manifest");
    };
    assert_eq!(manifest.backup_id, id);
    assert_eq!(manifest.profile_snapshot.name, WHOLE_DATABASE_PROFILE);
    fixture.remove();
}

#[test]
fn a_forged_signature_is_refused_before_the_target_database_is_created() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);
    let restore = RestoreService::new(StubEngine { capture: &capture }, fixture.writer());

    // The control first: with the artifact intact, planning and running really do create the
    // target, so the empty list asserted below is a refusal rather than a stub that never
    // reaches that call.
    let plan = restore
        .plan(
            &fixture.config,
            fixture.id,
            DR_TARGET,
            RestoreSecurityPolicy::dr_full(),
            RestoreSections::full(),
        )
        .unwrap();
    assert_eq!(plan.artifact_scope.as_deref(), Some(WHOLE_DATABASE_PROFILE));
    let before = snapshot(&fixture.artifact_dir());
    let executed = restore
        .run(&fixture.config, plan.id, DR_TARGET)
        .expect("an authenticated artifact restores");
    assert_eq!(capture.created(), vec![DR_TARGET.to_string()]);
    // Replaying the archive is what proves it restores, but a signed manifest is immutable:
    // recording that fact would need the signing key, which a DR host does not hold.
    assert!(!executed.recorded_in_artifact);
    assert_eq!(executed.verification_level, VERIFICATION_NONE);
    assert_eq!(snapshot(&fixture.artifact_dir()), before);

    // Now forge it: one bit of the ed25519 half, every digest left as published.
    let signature = fixture.artifact_dir().join("signature.hybrid");
    let mut bytes = fs::read(&signature).unwrap();
    bytes[0] ^= 0x01;
    fs::write(&signature, &bytes).unwrap();

    let verify = VerifyService::new(StubEngine { capture: &capture }, fixture.reader());
    for level in [VERIFY_SIGNATURE, VERIFY_CHECKSUM, VERIFY_ARCHIVE] {
        let error = failure(verify.verify(&fixture.config, fixture.id, level));
        assert!(
            error.contains("ed25519 signature check failed"),
            "{level} accepted a forged artifact: {error}"
        );
    }

    let error = failure(restore.plan(
        &fixture.config,
        fixture.id,
        "backupctl_fixture_m4b_forged",
        RestoreSecurityPolicy::dr_full(),
        RestoreSections::full(),
    ));
    assert!(
        error.contains("ed25519 signature check failed"),
        "planning accepted a forged artifact: {error}"
    );
    assert_eq!(
        capture.created(),
        vec![DR_TARGET.to_string()],
        "a refused plan still reached CREATE DATABASE"
    );
    fixture.remove();
}

/// A real `backup create` is the only writer the inventory has today, so the row it lands is
/// checked against both records it must agree with: `public.json` for everything a keyless
/// reader can re-derive later, and the sealed manifest for the two fields only the writer host
/// can know. Then the negative half, which is the reason the index is a separate file with its
/// own threat model: an operator copies `inventory.db` off-site without copying a single key,
/// so a row that named the database, the host, or the profile in plaintext would undo what
/// `manifest.age` exists to hide.
#[test]
fn a_signed_backup_registers_a_row_that_leaks_nothing_the_sealed_manifest_hides() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);

    let inventory_path = fixture.store_root.join(INVENTORY_FILE);
    assert!(
        inventory_path.is_file(),
        "publishing left no inventory at {}",
        inventory_path.display()
    );
    assert!(fixture.store_root.join("locks").is_dir());

    // Read-only, because that is the open a DR host can perform: it creates nothing, migrates
    // nothing, and refuses a file it did not find. The estate is recomputed from the
    // configuration rather than reused from the row, so a row written for a stranger's source
    // would fail the binding check instead of being read.
    let estate = Estate::new(source_fingerprint(&fixture.config.source, 16)).unwrap();
    let index = backup_inventory::Inventory::open_read_only(&inventory_path, &estate)
        .expect("the inventory a signed publish wrote opens read-only for its own estate");
    assert_eq!(index.schema_version().unwrap(), SCHEMA_VERSION);
    assert!(index.integrity_problems().unwrap().is_empty());

    let rows = index.artifacts().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.backup_id, fixture.id);
    assert_eq!(row.source_fingerprint, estate.source_fingerprint);
    assert_eq!(row.shape, Shape::V1Signed);
    assert_eq!(row.state, State::Registered);

    // Every field a rebuild reads back off `public.json` must already equal it exactly.
    assert_eq!(
        row.signer_id.as_deref(),
        Some(fixture.header.signer_id.as_str())
    );
    assert_eq!(
        row.recipient_id.as_deref(),
        Some(fixture.header.recipient_id.as_str())
    );
    assert_eq!(
        row.payload_sha256.as_deref(),
        Some(fixture.header.payload_sha256.as_str())
    );
    assert_eq!(
        row.manifest_sha256.as_deref(),
        Some(fixture.header.manifest_sha256.as_str())
    );
    assert_eq!(
        row.recipient_suite.as_deref(),
        Some(fixture.header.recipient_suite.as_str())
    );
    assert_eq!(
        row.signature_suite.as_deref(),
        Some(fixture.header.signature_suite.as_str())
    );
    assert_eq!(
        row.payload_bytes,
        Some(fixture.header.payload_ciphertext_bytes)
    );
    assert_eq!(
        row.manifest_bytes,
        Some(fixture.header.manifest_ciphertext_bytes)
    );

    // The two columns a rebuild cannot fill, filled because this host just sealed the manifest.
    assert_eq!(
        row.profile_fingerprint.as_deref(),
        Some(profile_fingerprint(&fixture.manifest.profile_snapshot.name).as_str())
    );
    assert_eq!(
        row.profile_fingerprint.as_deref(),
        Some(profile_fingerprint(WHOLE_DATABASE_PROFILE).as_str())
    );
    assert_eq!(
        row.completed_at_utc.as_deref(),
        Some(fixture.manifest.completed_at_utc.as_str())
    );

    let stored = fs::read(&inventory_path).unwrap();
    for secret in [SOURCE_DATABASE, "127.0.0.1", "backupctl_fixture"] {
        assert!(
            !stored
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "the inventory holds {secret:?} in plaintext, beside an artifact tree that hides it"
        );
    }
    fixture.remove();
}

#[test]
fn an_artifact_signed_for_a_different_source_is_refused_while_planning() {
    let capture = Capture::default();
    let mut fixture = write_signed(&capture);

    // The artifact is intact and its origin verifies; only this host's configured source has
    // moved, which is the case the recorded fingerprint exists to catch.
    let report = VerifyService::new(StubEngine { capture: &capture }, fixture.reader())
        .verify(&fixture.config, fixture.id, VERIFY_SIGNATURE)
        .expect("a freshly written artifact verifies at signature level");
    assert_eq!(report.level, VERIFY_SIGNATURE);

    fixture.config.source.port = 5433;
    let restore = RestoreService::new(StubEngine { capture: &capture }, fixture.writer());
    let error = failure(restore.plan(
        &fixture.config,
        fixture.id,
        DR_TARGET,
        RestoreSecurityPolicy::dr_full(),
        RestoreSections::full(),
    ));
    assert!(
        error.contains("dumped from a different source than the configured one"),
        "{error}"
    );
    assert!(
        capture.created().is_empty(),
        "the refused plan created {:?}",
        capture.created()
    );
    fixture.remove();
}

/// The job half of the same real path. A store an operator reads after the fact has to be able to
/// say which operation produced an artifact and that it finished, which no file inside
/// `artifacts/<id>/` states about the command that wrote it.
#[test]
fn a_signed_backup_records_a_finished_job_and_the_trail_that_shows_how() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);

    let estate = Estate::new(source_fingerprint(&fixture.config.source, 16)).unwrap();
    let index = backup_inventory::Inventory::open_read_only(
        &fixture.store_root.join(INVENTORY_FILE),
        &estate,
    )
    .unwrap();

    let jobs = index.jobs().unwrap();
    assert_eq!(jobs.len(), 1, "{jobs:?}");
    let job = &jobs[0];
    assert_eq!(job.state, JobState::Complete);
    assert!(job.state.is_terminal());
    assert_eq!(job.backup_id, Some(fixture.id));
    assert_eq!(job.source_fingerprint, estate.source_fingerprint);
    // The scope is the digest of what the command was configured with, and this one configured no
    // profile at all — which the reserved whole-database name is what it selected.
    assert_eq!(
        job.profile_fingerprint,
        profile_fingerprint(WHOLE_DATABASE_PROFILE)
    );
    // The job opens before the dump starts and updates when it ends. Timestamps carry second
    // resolution, so a stub dump that finishes inside one second legitimately writes the same
    // string twice; what the pair can prove is that they are UTC and in the right order.
    assert!(is_utc_timestamp(&job.started_at_utc));
    assert!(is_utc_timestamp(&job.updated_at_utc));
    assert!(job.updated_at_utc >= job.started_at_utc, "{job:?}");

    let events = index.audit_events().unwrap();
    assert_eq!(
        events.iter().map(|event| event.action).collect::<Vec<_>>(),
        vec![
            AuditAction::JobStarted,
            AuditAction::JobStaged,
            // Registration is part of publication, so the artifact is in the index before the
            // operation that wrote it reports itself finished.
            AuditAction::ArtifactRegistered,
            AuditAction::JobCompleted,
        ]
    );
    for event in &events {
        if event.action == AuditAction::ArtifactRegistered {
            // The publish path holds no job of its own; the link is the artifact id.
            assert_eq!(event.job_id, None);
            assert_eq!(event.backup_id, Some(fixture.id));
        } else {
            assert_eq!(event.job_id, Some(job.job_id));
        }
    }

    // The scope is free again with the command over, and only its own lock file was left behind.
    let locks: Vec<String> = fs::read_dir(fixture.store_root.join("locks"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        locks,
        vec![format!(
            "{}-{}.lock",
            estate.source_fingerprint,
            profile_fingerprint(WHOLE_DATABASE_PROFILE)
        )],
        "a lock file names more than two fingerprints"
    );
    assert!(
        JobLock::is_free(
            &fixture.store_root,
            &estate.source_fingerprint,
            &profile_fingerprint(WHOLE_DATABASE_PROFILE)
        )
        .unwrap()
    );

    let stored = fs::read(fixture.store_root.join(INVENTORY_FILE)).unwrap();
    for secret in [SOURCE_DATABASE, "127.0.0.1", "backupctl_fixture"] {
        assert!(
            !stored
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "the inventory holds {secret:?} in plaintext, beside an artifact tree that hides it"
        );
    }
    fixture.remove();
}

/// What the store looked like from inside a dump that was still running.
#[derive(Default)]
struct MidDump {
    lock_files: Vec<String>,
    refused: String,
    /// Every job row and its state, read at the moment the refusal happened.
    rows: Vec<(String, JobState)>,
    /// The id of the job opened for a *different* profile, which is `failed` once its own drop
    /// runs — the real writer for that state, reached through the real command path.
    other_scope: String,
}

/// ADR 0003's gate 9, asked at the only moment it means anything: while the first dump is still
/// writing, with no SQL transaction open anywhere. A second `backup create` started after the
/// first had written its rows would be refused by SQLite's lock and would prove nothing about the
/// overlap rule, because in the real window there is no database lock to refuse with — only the
/// kernel's.
///
/// Stated as a limit: this is one process with two open file descriptions, which is the same
/// mechanism `flock` gives two processes (the spike measured that locks belong to the description,
/// not the pid). The two-process version, with a `SIGKILL` between the dump's first byte and its
/// last, belongs to `tests/m5a_docker_smoke.sh`.
#[test]
fn a_second_dump_of_one_scope_is_refused_while_the_first_is_still_running() {
    let base = temp_root("signed-overlap");
    let store_root = base.join("data");
    // The same helper the fixture builds its own configuration from, so the source this test
    // expects and the source the dump runs with cannot be two different things.
    let mut source = config(&store_root, None, None).source;
    source.database = SOURCE_DATABASE.to_string();
    let fingerprint = source_fingerprint(&source, 16);
    let profile = profile_fingerprint(WHOLE_DATABASE_PROFILE);
    let other_profile = "aabbccddeeff0011";

    let seen = Rc::<RefCell<MidDump>>::default();
    let capture = Capture::default();
    {
        let seen = seen.clone();
        let store_root = store_root.clone();
        let fingerprint = fingerprint.clone();
        let profile = profile.clone();
        capture.on_dump_read(move || {
            let mut seen = seen.borrow_mut();
            let inventory_path = store_root.join(INVENTORY_FILE);
            let estate = Estate::new(fingerprint.clone()).unwrap();
            seen.lock_files = fs::read_dir(store_root.join("locks"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            // The live row is the only one, and it is still `running`: the refusal has to leave
            // the history exactly as it found it.
            let index =
                backup_inventory::Inventory::open_read_only(&inventory_path, &estate).unwrap();
            seen.rows = index
                .jobs()
                .unwrap()
                .into_iter()
                .map(|row| (row.profile_fingerprint, row.state))
                .collect();

            let outcome = JobGuard::begin(
                &store_root,
                &JobScope {
                    source_fingerprint: fingerprint.clone(),
                    profile_fingerprint: profile.clone(),
                    backup_id: Uuid::new_v4(),
                },
            );
            seen.refused = match outcome {
                Ok(_) => String::new(),
                Err(error) => format!("{error:#}"),
            };

            // Another profile of one source is another scope, so it runs — and its guard dropping
            // without finishing is what writes a real `failed` row through the real command path.
            let other = JobGuard::begin(
                &store_root,
                &JobScope {
                    source_fingerprint: fingerprint.clone(),
                    profile_fingerprint: other_profile.to_string(),
                    backup_id: Uuid::new_v4(),
                },
            )
            .expect("a different profile is a different scope");
            seen.other_scope = other.id().to_string();
            drop(other);
        });
    }

    let fixture = write_signed_in(&capture, base).expect("the first dump was not disturbed by it");
    // The hook itself holds a reference to the report, so it has to go before the report can.
    drop(capture);
    let seen = match Rc::try_unwrap(seen) {
        Ok(cell) => cell.into_inner(),
        Err(_) => panic!("the dump hook still holds the report"),
    };

    assert_eq!(
        seen.lock_files,
        vec![format!("{fingerprint}-{profile}.lock")],
        "the running dump's lock is not the only file, or is not named by two fingerprints"
    );
    assert_eq!(
        seen.rows,
        vec![(profile.clone(), JobState::Running)],
        "the refusal left a row of its own behind"
    );
    assert!(
        seen.refused.contains("already running"),
        "a second dump of one scope was accepted mid-dump: {:?}",
        seen.refused
    );
    assert!(
        seen.refused.contains(
            &store_root
                .join("locks")
                .join(format!("{fingerprint}-{profile}.lock"))
                .display()
                .to_string()
        ),
        "the refusal did not name the lock it met: {}",
        seen.refused
    );

    let estate = Estate::new(fingerprint).unwrap();
    let index =
        backup_inventory::Inventory::open_read_only(&store_root.join(INVENTORY_FILE), &estate)
            .unwrap();
    let jobs = index.jobs().unwrap();
    assert_eq!(jobs.len(), 2, "{jobs:?}");
    let finished = jobs
        .iter()
        .find(|row| row.backup_id == Some(fixture.id))
        .expect("the dump that ran has a job row");
    assert_eq!(finished.state, JobState::Complete);
    let abandoned = jobs
        .iter()
        .find(|row| row.job_id.to_string() == seen.other_scope)
        .expect("the other scope's job is recorded too");
    assert_eq!(abandoned.state, JobState::Failed);
    assert_eq!(abandoned.profile_fingerprint, other_profile);
    assert_ne!(abandoned.backup_id, Some(fixture.id));

    fixture.remove();
}
