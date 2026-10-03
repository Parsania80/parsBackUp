//! The composed write and read path, with encryption switched on and off.
//!
//! The engine here is a stub on purpose. What these tests ask is what `BackupService`
//! and `LocalStore` do with the bytes between them — whether a dump stream can reach the
//! artifact tree as plaintext, and whether the PostgreSQL tool boundary is ever handed
//! anything but plaintext — and no single-crate test can see that seam.

mod common;

use backup_application::{BackupService, Created, RestoreService, VerifyService};
use backup_crypto::protocol::SUITE_HYBRID;
use backup_domain::{
    AGE_FORMAT, DEV_FORMAT, RestoreSections, RestoreSecurityPolicy, VERIFY_ARCHIVE,
    VERIFY_SIGNATURE, WHOLE_DATABASE_PROFILE, profile_fingerprint, source_fingerprint,
};
use backup_inventory::{AuditAction, Estate, INVENTORY_FILE, JobLock, JobState};
use backup_local::LocalStore;
use common::{
    ARCHIVE_MARKER, Capture, GLOBALS_MARKER, Keys, StubEngine, archive_bytes, config, files_under,
    holds, temp_root,
};
use std::fs;

#[test]
fn an_encrypted_backup_leaves_the_store_no_plaintext_and_the_tools_no_ciphertext() {
    let base = temp_root("write-path");
    let store_root = base.join("data");
    let keys = Keys::generate(&base.join("keys"));
    let identity = keys.identity.clone();
    let recipient = keys.recipient.clone();
    let capture = Capture::default();
    let store = LocalStore::with_keys(store_root.clone(), &identity, &recipient).unwrap();
    let config = config(
        &store_root,
        Some((identity.clone(), recipient.clone())),
        None,
    );
    let service = BackupService::new(StubEngine { capture: &capture }, store);
    let Created::Development(manifest) = service.create(&config, None).unwrap() else {
        panic!("a store with encryption but no signing key writes a development artifact");
    };

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
    let base = temp_root("write-path");
    let store_root = base.join("data");
    let capture = Capture::default();
    let store = LocalStore::new(store_root.clone()).unwrap();
    let config = config(&store_root, None, None);
    let service = BackupService::new(StubEngine { capture: &capture }, store);
    let Created::Development(manifest) = service.create(&config, None).unwrap() else {
        panic!("a store with no [encryption] block writes a development artifact");
    };

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

/// A development store is a store too: it gets a job table and a lock, even though its `job`
/// rows can point at a `backup_id` the artifact table has never heard of. That is not a
/// contradiction to refuse — the unsigned shape registers nothing on purpose, since a row describing
/// an artifact anyone could forge would be a claim the index cannot support. What has to hold is
/// that the operation itself is recorded, and that a second dump of one scope cannot start while
/// the first is running.
#[test]
fn a_development_store_records_the_job_it_runs() {
    let base = temp_root("write-path");
    let store_root = base.join("data");
    let capture = Capture::default();
    let config = config(&store_root, None, None);
    let manifest = BackupService::new(
        StubEngine { capture: &capture },
        LocalStore::new(store_root.clone()).unwrap(),
    )
    .create(&config, None)
    .unwrap()
    .id();

    let estate = Estate::new(source_fingerprint(&config.source, 16)).unwrap();
    let index =
        backup_inventory::Inventory::open_read_only(&store_root.join(INVENTORY_FILE), &estate)
            .unwrap();
    let jobs = index.jobs().unwrap();
    assert_eq!(jobs.len(), 1, "{jobs:?}");
    assert_eq!(jobs[0].state, JobState::Complete);
    assert_eq!(jobs[0].backup_id, Some(manifest));
    assert_eq!(
        jobs[0].profile_fingerprint,
        profile_fingerprint(WHOLE_DATABASE_PROFILE)
    );
    // The unregistered-artifact half of the point: the row names an id the index holds no
    // artifact for, and the store recorded the run anyway.
    assert!(index.artifacts().unwrap().is_empty());
    assert_eq!(
        index
            .audit_events()
            .unwrap()
            .iter()
            .map(|event| event.action)
            .collect::<Vec<_>>(),
        vec![
            AuditAction::JobStarted,
            AuditAction::JobStaged,
            AuditAction::JobCompleted
        ]
    );
    assert!(
        JobLock::is_free(
            &store_root,
            &estate.source_fingerprint,
            &profile_fingerprint(WHOLE_DATABASE_PROFILE)
        )
        .unwrap(),
        "a finished development backup still holds its scope"
    );
    fs::remove_dir_all(base).unwrap();
}

/// Signature level is a claim about an origin, not about bytes, so a store that signs
/// nothing is refused instead of quietly answering with a weaker level. A host doing DR
/// must never read "signature" as a pass that was never computed.
#[test]
fn signature_level_refuses_a_store_that_has_no_signing_key() {
    let base = temp_root("write-path");
    let store_root = base.join("data");
    let keys = Keys::generate(&base.join("keys"));
    let identity = keys.identity.clone();
    let recipient = keys.recipient.clone();
    let capture = Capture::default();
    let config = config(
        &store_root,
        Some((identity.clone(), recipient.clone())),
        None,
    );
    let id = BackupService::new(
        StubEngine { capture: &capture },
        LocalStore::with_keys(store_root.clone(), &identity, &recipient).unwrap(),
    )
    .create(&config, None)
    .unwrap()
    .id();
    let reads_before = capture.reads().len();

    let verify = VerifyService::new(
        StubEngine { capture: &capture },
        LocalStore::with_keys(store_root.clone(), &identity, &recipient).unwrap(),
    );
    let error = format!(
        "{:#}",
        verify.verify(&config, id, VERIFY_SIGNATURE).unwrap_err()
    );
    assert!(error.contains("carry no origin signature"), "{error}");
    assert_eq!(
        capture.reads().len(),
        reads_before,
        "the refused verification still reached the tool boundary"
    );
    fs::remove_dir_all(base).unwrap();
}
