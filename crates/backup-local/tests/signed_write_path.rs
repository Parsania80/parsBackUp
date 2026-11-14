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
    ArtifactStore, BackupService, Created, Inventory, Record, RestoreService, VerifyService,
    WriteOptions,
};
use backup_crypto::protocol::{HYBRID_SIGNATURE_BYTES, SUITE_HYBRID};
use backup_domain::{
    ARTIFACT_FORMAT_VERSION, ArtifactManifest, Config, ENGINE_POSTGRESQL, GLOBALS_POLICY_EXPORTED,
    ID_HEX_LEN, PublicHeader, RestoreSections, RestoreSecurityPolicy, SIGNATURE_SUITES,
    VERIFICATION_NONE, VERIFY_ARCHIVE, VERIFY_CHECKSUM, VERIFY_SIGNATURE, WHOLE_DATABASE_PROFILE,
    is_utc_timestamp, profile_fingerprint, source_fingerprint,
};
use backup_inventory::{
    ACTIVITY_FILE, ActivityLock, AuditAction, Estate, INVENTORY_FILE, JobGuard, JobLock, JobScope,
    JobState, SCHEMA_VERSION, Shape, State,
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

fn rebuild_fixture(fixture: &Fixture) {
    let scanner = backup_local::LocalReconciler(fixture.store_root.clone());
    let (id, _) = scanner
        .prepare_rebuild(&fixture.manifest.source_fingerprint)
        .unwrap();
    scanner
        .rebuild(&fixture.manifest.source_fingerprint, id)
        .unwrap();
}

fn publish_at(fixture: &Fixture, time: &str, profile: &str) -> Uuid {
    let store = fixture.writer();
    let id = Uuid::new_v4();
    let globals = fixture.manifest.globals_sha256.is_some();
    let stage = store
        .begin(
            id,
            &WriteOptions {
                with_globals: globals,
            },
        )
        .unwrap();
    let mut sink = store.payload_sink(&stage).unwrap();
    std::io::Write::write_all(&mut sink, &archive_bytes()).unwrap();
    sink.finish().unwrap();
    drop(sink);
    let mut manifest = fixture.manifest.clone();
    manifest.backup_id = id;
    manifest.started_at_utc = time.to_owned();
    manifest.completed_at_utc = time.to_owned();
    manifest.profile_snapshot.name = profile.to_owned();
    (
        manifest.payload_ciphertext_bytes,
        manifest.payload_ciphertext_sha256,
    ) = store.measure(&stage).unwrap();
    if globals {
        let mut sink = store.globals_sink(&stage).unwrap();
        std::io::Write::write_all(&mut sink, GLOBALS_MARKER).unwrap();
        sink.finish().unwrap();
        drop(sink);
        let (size, hash) = store.measure_globals(&stage).unwrap();
        manifest.globals_ciphertext_bytes = Some(size);
        manifest.globals_sha256 = Some(hash);
    }
    store.publish_signed(stage, &manifest).unwrap();
    id
}

#[test]
fn rollback_publication_is_cross_profile_monotone_and_listing_borrows_only_matching_facts() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);
    let old = publish_at(&fixture, "2099-01-01T00:00:00Z", WHOLE_DATABASE_PROFILE);
    let newest = publish_at(&fixture, "2099-01-02T00:00:00Z", "different-profile");
    let tie = publish_at(&fixture, "2099-01-02T00:00:00Z", WHOLE_DATABASE_PROFILE);
    let store = fixture.reader();
    let handle = store.open_signed(old).unwrap();
    let mark = store.completion_mark(&handle).unwrap().unwrap();
    assert_eq!(mark.artifact_id, newest);
    let before = fs::read(fixture.store_root.join(INVENTORY_FILE)).unwrap();
    let artifacts = files_under(&fixture.store_root.join("artifacts"))
        .into_iter()
        .map(|p| (p.clone(), fs::read(p).unwrap()))
        .collect::<Vec<_>>();
    let listing = store.list_signed().unwrap();
    assert!(
        listing
            .rollback_warnings
            .iter()
            .any(|w| w.artifact_id == old && w.high_water == mark)
    );
    assert!(
        !listing
            .rollback_warnings
            .iter()
            .any(|w| w.artifact_id == tie || w.artifact_id == newest)
    );
    assert!(listing.rollback_unknown.is_empty());
    assert_eq!(
        fs::read(fixture.store_root.join(INVENTORY_FILE)).unwrap(),
        before
    );
    assert_eq!(
        artifacts,
        files_under(&fixture.store_root.join("artifacts"))
            .into_iter()
            .map(|p| (p.clone(), fs::read(p).unwrap()))
            .collect::<Vec<_>>()
    );
    let public = artifact_dir(&fixture.store_root, old).join("public.json");
    let mut header: PublicHeader = serde_json::from_slice(&fs::read(&public).unwrap()).unwrap();
    header.payload_sha256 = "a".repeat(64);
    fs::write(public, serde_json::to_vec(&header).unwrap()).unwrap();
    let listing = store.list_signed().unwrap();
    assert!(listing.rollback_unknown.contains(&old));
    assert!(
        !listing
            .rollback_warnings
            .iter()
            .any(|w| w.artifact_id == old)
    );
    drop(handle);
    fixture.remove();
}

#[test]
fn restore_older_acknowledgement_is_bound_and_changed_or_lost_history_refuses_before_mutation() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);
    let old = publish_at(&fixture, "2099-01-01T00:00:00Z", WHOLE_DATABASE_PROFILE);
    let newest = publish_at(&fixture, "2099-01-02T00:00:00Z", WHOLE_DATABASE_PROFILE);
    let service = RestoreService::new(StubEngine { capture: &capture }, fixture.reader());
    let plans = files_under(&fixture.store_root.join("plans"));
    assert!(
        failure(service.plan(
            &fixture.config,
            old,
            DR_TARGET,
            RestoreSecurityPolicy::dr_full(),
            RestoreSections::full()
        ))
        .contains("OLDER_SNAPSHOT_ACK_REQUIRED")
    );
    assert_eq!(plans, files_under(&fixture.store_root.join("plans")));
    assert!(capture.created().is_empty());
    assert_eq!(capture.globals_applied.get(), 0);
    assert!(
        failure(service.plan_with_acknowledgement(
            &fixture.config,
            newest,
            DR_TARGET,
            RestoreSecurityPolicy::portable(),
            RestoreSections::full(),
            true
        ))
        .contains("ACK_NOT_APPLICABLE")
    );
    let plan = service
        .plan_with_acknowledgement(
            &fixture.config,
            old,
            DR_TARGET,
            RestoreSecurityPolicy::dr_full(),
            RestoreSections::full(),
            true,
        )
        .unwrap();
    assert_eq!(plan.format, backup_domain::RESTORE_PLAN_V2);
    assert!(plan.rollback.as_ref().unwrap().acknowledged);
    let immutable = snapshot(&artifact_dir(&fixture.store_root, old));
    service.run(&fixture.config, plan.id, DR_TARGET).unwrap();
    assert_eq!(capture.created(), [DR_TARGET]);
    assert_eq!(snapshot(&artifact_dir(&fixture.store_root, old)), immutable);

    let fresh_capture = Capture::default();
    let service = RestoreService::new(
        StubEngine {
            capture: &fresh_capture,
        },
        fixture.reader(),
    );
    let mut legacy = plan.clone();
    legacy.id = Uuid::new_v4();
    legacy.format = backup_domain::PLAN_FORMAT.into();
    legacy.rollback = None;
    fixture.reader().save_plan(&legacy).unwrap();
    assert!(
        failure(service.run(&fixture.config, legacy.id, DR_TARGET))
            .contains("OLDER_SNAPSHOT_REPLAN_REQUIRED")
    );
    publish_at(&fixture, "2099-01-03T00:00:00Z", WHOLE_DATABASE_PROFILE);
    assert!(
        failure(service.run(&fixture.config, plan.id, DR_TARGET))
            .contains("OLDER_SNAPSHOT_REPLAN_REQUIRED")
    );
    assert!(fresh_capture.created().is_empty());
    assert_eq!(fresh_capture.globals_applied.get(), 0);
    let acknowledged = service
        .plan_with_acknowledgement(
            &fixture.config,
            old,
            DR_TARGET,
            RestoreSecurityPolicy::dr_full(),
            RestoreSections::full(),
            true,
        )
        .unwrap();
    rebuild_fixture(&fixture);
    assert!(
        failure(service.run(&fixture.config, acknowledged.id, DR_TARGET))
            .contains("OLDER_SNAPSHOT_REPLAN_REQUIRED")
    );
    assert!(fresh_capture.created().is_empty());
    assert_eq!(fresh_capture.globals_applied.get(), 0);
    fixture.remove();
}

#[test]
fn rollback_observation_requires_writable_private_authentication_and_rebuild_loses_history() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);
    let store = fixture.reader();
    let index = fixture.store_root.join(INVENTORY_FILE);
    rebuild_fixture(&fixture);
    let before = fs::read(&index).unwrap();
    store.list_signed().unwrap();
    store.open_signed(fixture.id).unwrap();
    let verify = VerifyService::new(StubEngine { capture: &capture }, fixture.reader());
    verify
        .verify_read_only(&fixture.config, fixture.id, VERIFY_CHECKSUM)
        .unwrap();
    assert_eq!(fs::read(&index).unwrap(), before);
    verify
        .verify(&fixture.config, fixture.id, VERIFY_SIGNATURE)
        .unwrap();
    let artifact = store.open_signed(fixture.id).unwrap();
    assert!(store.completion_mark(&artifact).unwrap().is_none());
    verify
        .verify(&fixture.config, fixture.id, VERIFY_CHECKSUM)
        .unwrap();
    assert_eq!(
        store
            .completion_mark(&artifact)
            .unwrap()
            .unwrap()
            .artifact_id,
        fixture.id
    );
    drop(artifact);
    rebuild_fixture(&fixture);
    let service = RestoreService::new(StubEngine { capture: &capture }, fixture.reader());
    let current_plan = service
        .plan(
            &fixture.config,
            fixture.id,
            DR_TARGET,
            RestoreSecurityPolicy::portable(),
            RestoreSections::full(),
        )
        .unwrap();
    let mut legacy = current_plan.clone();
    legacy.id = Uuid::new_v4();
    legacy.format = backup_domain::PLAN_FORMAT.into();
    legacy.rollback = None;
    store.save_plan(&legacy).unwrap();
    service.run(&fixture.config, legacy.id, DR_TARGET).unwrap();
    assert!(
        store
            .completion_mark(&store.open_signed(fixture.id).unwrap())
            .unwrap()
            .is_some()
    );
    let scanner = backup_local::LocalReconciler(fixture.store_root.clone());
    let (plan, _) = scanner
        .prepare_rebuild(&fixture.manifest.source_fingerprint)
        .unwrap();
    scanner
        .rebuild(&fixture.manifest.source_fingerprint, plan)
        .unwrap();
    let listing = store.list_signed().unwrap();
    assert_eq!(listing.rollback_unknown, [fixture.id]);
    assert!(
        store
            .completion_mark(&store.open_signed(fixture.id).unwrap())
            .unwrap()
            .is_none()
    );
    fs::remove_file(&index).unwrap();
    let plan = service
        .plan(
            &fixture.config,
            fixture.id,
            DR_TARGET,
            RestoreSecurityPolicy::portable(),
            RestoreSections::full(),
        )
        .unwrap();
    assert!(plan.rollback.unwrap().high_water.is_none());
    assert!(!index.exists());
    fixture.remove();
}

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
fn verification_events_enrich_only_after_authenticated_manifest_and_can_be_read_only() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);
    let scanner = backup_local::LocalReconciler(fixture.store_root.clone());
    let (plan, _) = scanner
        .prepare_rebuild(&fixture.manifest.source_fingerprint)
        .unwrap();
    scanner
        .rebuild(&fixture.manifest.source_fingerprint, plan)
        .unwrap();
    let path = fixture.store_root.join(INVENTORY_FILE);
    let inventory = backup_inventory::Inventory::open_read_only_bound(&path).unwrap();
    assert!(inventory.is_provisional(fixture.id).unwrap());
    assert_eq!(
        inventory
            .artifact(fixture.id)
            .unwrap()
            .unwrap()
            .profile_fingerprint,
        None
    );
    drop(inventory);
    let service = VerifyService::new(StubEngine { capture: &capture }, fixture.reader());
    assert!(
        service
            .verify(&fixture.config, fixture.id, VERIFY_SIGNATURE)
            .unwrap()
            .audit_recorded
    );
    let inventory = backup_inventory::Inventory::open_read_only_bound(&path).unwrap();
    assert!(inventory.is_provisional(fixture.id).unwrap());
    assert_eq!(inventory.verification_events(fixture.id).unwrap().len(), 1);
    drop(inventory);
    assert!(
        !service
            .verify_read_only(&fixture.config, fixture.id, VERIFY_CHECKSUM)
            .unwrap()
            .audit_recorded
    );
    let inventory = backup_inventory::Inventory::open_read_only_bound(&path).unwrap();
    assert!(inventory.is_provisional(fixture.id).unwrap());
    assert_eq!(inventory.verification_events(fixture.id).unwrap().len(), 1);
    drop(inventory);
    assert!(
        service
            .verify(&fixture.config, fixture.id, VERIFY_CHECKSUM)
            .unwrap()
            .audit_recorded
    );
    let inventory = backup_inventory::Inventory::open_read_only_bound(&path).unwrap();
    assert!(!inventory.is_provisional(fixture.id).unwrap());
    assert_eq!(
        inventory
            .artifact(fixture.id)
            .unwrap()
            .unwrap()
            .profile_fingerprint
            .as_deref(),
        Some(profile_fingerprint(&fixture.manifest.profile_snapshot.name).as_str())
    );
    let events = inventory.verification_events(fixture.id).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].level, VERIFY_SIGNATURE);
    assert_eq!(events[1].level, VERIFY_CHECKSUM);
    assert_eq!(
        events[1].manifest_sha256.as_deref(),
        Some(fixture.header.manifest_sha256.as_str())
    );
    drop(inventory);
    let path = fixture.artifact_dir().join("signature.hybrid");
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(
        service
            .verify_read_only(&fixture.config, fixture.id, VERIFY_SIGNATURE)
            .is_err()
    );
    let inventory =
        backup_inventory::Inventory::open_read_only_bound(&fixture.store_root.join(INVENTORY_FILE))
            .unwrap();
    assert!(
        inventory
            .verification_events(fixture.id)
            .unwrap()
            .iter()
            .all(|event| event.current)
    );
    drop(inventory);
    assert!(
        service
            .verify(&fixture.config, fixture.id, VERIFY_SIGNATURE)
            .is_err()
    );
    let inventory =
        backup_inventory::Inventory::open_read_only_bound(&fixture.store_root.join(INVENTORY_FILE))
            .unwrap();
    let events = inventory.verification_events(fixture.id).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].outcome, "failure");
    assert!(!events[0].current);
    assert!(!events[1].current);
    assert!(events[2].current);
    assert_eq!(events[2].payload_sha256, None);
    drop(inventory);
    drop(service);
    fixture.remove();
}

#[test]
fn completed_restore_records_safe_resource_associations() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);
    let restore = RestoreService::new(StubEngine { capture: &capture }, fixture.reader());
    let plan = restore
        .plan(
            &fixture.config,
            fixture.id,
            DR_TARGET,
            RestoreSecurityPolicy::portable(),
            RestoreSections::full(),
        )
        .unwrap();
    restore.run(&fixture.config, plan.id, DR_TARGET).unwrap();
    let path = fixture.store_root.join(INVENTORY_FILE);
    let inventory = backup_inventory::Inventory::open_read_only_bound(&path).unwrap();
    let job = inventory
        .jobs()
        .unwrap()
        .into_iter()
        .find(|row| {
            inventory
                .job_operation(row.job_id)
                .unwrap()
                .is_some_and(|(kind, _)| kind == "restore")
        })
        .unwrap();
    assert_eq!(job.state, JobState::Complete);
    assert_eq!(job.backup_id, Some(fixture.id));
    let (_, target) = inventory.job_operation(job.job_id).unwrap().unwrap();
    assert_eq!(target.unwrap().len(), ID_HEX_LEN);
    drop(inventory);
    assert!(
        !fs::read(&path)
            .unwrap()
            .windows(DR_TARGET.len())
            .any(|bytes| bytes == DR_TARGET.as_bytes())
    );
    drop(restore);
    fixture.remove();
}

#[test]
fn restore_refuses_missing_inventory_before_mutating_the_target() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);
    let restore = RestoreService::new(StubEngine { capture: &capture }, fixture.reader());
    let plan = restore
        .plan(
            &fixture.config,
            fixture.id,
            DR_TARGET,
            RestoreSecurityPolicy::portable(),
            RestoreSections::full(),
        )
        .unwrap();
    let inventory = fixture.store_root.join(INVENTORY_FILE);
    fs::remove_file(&inventory).unwrap();
    let error = restore
        .run(&fixture.config, plan.id, DR_TARGET)
        .unwrap_err();
    assert!(format!("{error:#}").contains("rebuild it explicitly"));
    assert!(capture.created().is_empty());
    assert!(!inventory.exists());
    drop(restore);
    fixture.remove();
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
            AuditAction::CompletionAdvanced,
            AuditAction::JobCompleted,
        ]
    );
    for event in &events {
        if matches!(
            event.action,
            AuditAction::ArtifactRegistered | AuditAction::CompletionAdvanced
        ) {
            // The publish path holds no job of its own; the link is the artifact id.
            assert_eq!(event.job_id, None);
            assert_eq!(event.backup_id, Some(fixture.id));
        } else {
            assert_eq!(event.job_id, Some(job.job_id));
        }
    }

    // The scope is free again with the command over, and the only files left are the scope's own
    // lock plus ADR 0004's fixed-named activity claim. Neither carries anything an operator
    // configured: the scope is two fingerprints, the claim is a constant.
    let locks: Vec<String> = fs::read_dir(fixture.store_root.join("locks"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        locks.iter().any(|name| name == ACTIVITY_FILE),
        "a finished command released its claim by deleting it: {locks:?}"
    );
    assert_eq!(
        locks
            .iter()
            .filter(|name| name.as_str() != ACTIVITY_FILE)
            .cloned()
            .collect::<Vec<_>>(),
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
    /// Whether a maintenance claim was refused while this dump was mid-write, which is ADR 0004's
    /// proof that the live stage is under a claim rather than merely present.
    maintenance_refused: bool,
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
            seen.maintenance_refused = ActivityLock::hold_maintenance(&store_root)
                .unwrap()
                .is_none();
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

    // The scope lock and ADR 0004's fixed-named claim: two files, and neither names a database, a
    // profile, a host, or a key.
    let mut locks = seen.lock_files.clone();
    locks.sort();
    assert_eq!(
        locks,
        vec![
            format!("{fingerprint}-{profile}.lock"),
            ACTIVITY_FILE.to_string()
        ],
        "the running dump's lock is not the only file, or is not named by two fingerprints"
    );
    assert!(
        seen.maintenance_refused,
        "a live dump held no claim on the store's working directories"
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

#[test]
fn restore_refusals_precede_cluster_mutation() {
    let capture = Capture::default();
    let fixture = write_signed(&capture);
    let service = RestoreService::new(StubEngine { capture: &capture }, fixture.reader());
    let plan = service
        .plan(
            &fixture.config,
            fixture.id,
            DR_TARGET,
            RestoreSecurityPolicy::dr_full(),
            RestoreSections::full(),
        )
        .unwrap();
    capture.target_exists.set(true);
    let error = failure(service.run(&fixture.config, plan.id, DR_TARGET));
    assert!(
        error.contains("target database appeared after planning"),
        "{error}"
    );
    assert_eq!(capture.globals_applied.get(), 0);
    assert!(capture.created().is_empty());
    capture.target_exists.set(false);
    // Re-sign a corrupt age stream: signature verification succeeds, decryption must
    // still fail before any globals or CREATE DATABASE call.
    use sha2::{Digest, Sha256};
    let path = fixture.artifact_dir().join("payload.age");
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(path, &bytes).unwrap();
    let payload_digest: [u8; 32] = Sha256::digest(&bytes).into();
    let mut manifest = fixture.manifest.clone();
    manifest.payload_ciphertext_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let recipient = backup_crypto::keystore::KeyFile::load(
        &fixture.keys.recipient,
        backup_crypto::keystore::KeyRole::Recipient,
    )
    .unwrap();
    let mut sealed = Vec::new();
    backup_crypto::stream::encrypt(
        recipient.recipient(),
        serde_json::to_vec(&manifest).unwrap().as_slice(),
        &mut sealed,
    )
    .unwrap();
    let manifest_digest: [u8; 32] = Sha256::digest(&sealed).into();
    let header = PublicHeader::seal(
        &manifest,
        &format!("{:x}", Sha256::digest(&sealed)),
        sealed.len() as u64,
    )
    .unwrap();
    let signer = backup_crypto::signing::SigningKeyFile::load(
        &fixture.keys.signing,
        backup_crypto::signing::SigningRole::Signing,
    )
    .unwrap();
    let signature = signer
        .signer()
        .unwrap()
        .try_sign(&backup_crypto::signing::signature_tuple(
            fixture.id.as_bytes(),
            &manifest_digest,
            &payload_digest,
        ))
        .unwrap();
    fs::write(fixture.artifact_dir().join("manifest.age"), sealed).unwrap();
    fs::write(
        fixture.artifact_dir().join("public.json"),
        header.to_json().unwrap(),
    )
    .unwrap();
    fs::write(
        fixture.artifact_dir().join("signature.hybrid"),
        signature.as_bytes(),
    )
    .unwrap();
    use backup_application::ArtifactStore;
    assert!(fixture.reader().open_signed(fixture.id).is_ok());
    let error = failure(service.run(&fixture.config, plan.id, DR_TARGET));
    assert!(error.contains("OLDER_SNAPSHOT_REPLAN_REQUIRED"), "{error}");
    // A pre-B05 plan has no ciphertext binding; it must still reach and enforce R05.
    let mut legacy = plan.clone();
    legacy.id = Uuid::new_v4();
    legacy.format = backup_domain::PLAN_FORMAT.into();
    legacy.rollback = None;
    fixture.reader().save_plan(&legacy).unwrap();
    let error = failure(service.run(&fixture.config, legacy.id, DR_TARGET));
    assert!(error.contains("failed to decrypt completely"), "{error}");
    assert_eq!(capture.globals_applied.get(), 0);
    assert!(capture.created().is_empty());
    fixture.remove();
}
