mod common;
use backup_application::{
    BackupService, Created, DeletionExecutor, InventoryService, RetentionPlanner, VerifyService,
};
use backup_domain::{
    Config, RetentionOperation, RetentionRequest, SavedDeletionPlan, VERIFY_ARCHIVE,
    WHOLE_DATABASE_PROFILE, profile_fingerprint,
};
use backup_inventory::{
    ActivityLock, INVENTORY_FILE, Inventory, JobGuard, JobScope, ResourceLock, State,
};
use backup_local::{LocalProtection, LocalReconciler, LocalRetention, LocalStore};
use common::{
    Capture, Keys, StubEngine, artifact_dir, config, failure, files_under, signing_block, temp_root,
};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use uuid::Uuid;

struct Scene {
    base: PathBuf,
    config: Config,
    keys: Keys,
    ids: Vec<Uuid>,
}
impl Scene {
    fn new(count: usize) -> Self {
        let base = temp_root("retention");
        let root = base.join("data");
        let keys = Keys::generate(&base.join("keys"));
        let config = config(
            &root,
            Some((keys.identity.clone(), keys.recipient.clone())),
            Some(signing_block(&keys)),
        );
        let mut scene = Self {
            base,
            config,
            keys,
            ids: vec![],
        };
        let capture = Capture::default();
        for _ in 0..count {
            let Created::Signed { manifest, .. } =
                BackupService::new(StubEngine { capture: &capture }, scene.writer())
                    .create(&scene.config, None)
                    .unwrap()
            else {
                panic!()
            };
            let id = manifest.backup_id;
            VerifyService::new(StubEngine { capture: &capture }, scene.reader())
                .verify(&scene.config, id, VERIFY_ARCHIVE)
                .unwrap();
            scene.ids.push(id);
        }
        let rows = scene.inventory().artifacts().unwrap();
        scene.ids.sort_by(|a, b| {
            let at = rows
                .iter()
                .find(|r| r.backup_id == *a)
                .unwrap()
                .completed_at_utc
                .as_ref()
                .unwrap();
            let bt = rows
                .iter()
                .find(|r| r.backup_id == *b)
                .unwrap()
                .completed_at_utc
                .as_ref()
                .unwrap();
            bt.cmp(at).then(a.cmp(b))
        });
        scene
    }
    fn root(&self) -> &std::path::Path {
        &self.config.storage.root
    }
    fn db(&self) -> PathBuf {
        self.root().join(INVENTORY_FILE)
    }
    fn inventory(&self) -> Inventory {
        Inventory::open_read_only_bound(&self.db()).unwrap()
    }
    fn writer(&self) -> LocalStore {
        LocalStore::with_signing_keys(
            self.root().to_path_buf(),
            &self.keys.identity,
            &self.keys.recipient,
            &self.keys.signing,
            &self.keys.verifying,
        )
        .unwrap()
    }
    fn reader(&self) -> LocalStore {
        LocalStore::for_reading(
            self.root().to_path_buf(),
            &self.keys.identity,
            &self.keys.verifying,
        )
        .unwrap()
    }
    fn planner(&self) -> LocalRetention {
        LocalRetention(self.config.clone())
    }
    fn prune(n: u64) -> RetentionRequest {
        RetentionRequest::Prune {
            keep_last: n,
            profile_fingerprint: profile_fingerprint(WHOLE_DATABASE_PROFILE),
        }
    }
    fn protect(&self, id: Uuid, value: bool) {
        InventoryService::new(LocalProtection(self.root().to_path_buf()))
            .set_protection(id, value)
            .unwrap();
    }
    fn bytes(&self) -> Vec<(PathBuf, Vec<u8>)> {
        files_under(&self.root().join("artifacts"))
            .into_iter()
            .map(|p| {
                let bytes = fs::read(&p).unwrap();
                (p, bytes)
            })
            .collect()
    }
    fn plan_path(&self, id: Uuid) -> PathBuf {
        self.root()
            .join("plans")
            .join(format!("deletion-{id}.json"))
    }
    fn assert_error(&self, request: &RetentionRequest, code: &str) {
        let before = fs::read(self.db()).unwrap();
        let artifacts = self.bytes();
        let plans = files_under(&self.root().join("plans"));
        let error = failure(self.planner().preview(request));
        assert!(error.contains(code), "{error}");
        assert_eq!(before, fs::read(self.db()).unwrap());
        assert_eq!(artifacts, self.bytes());
        assert_eq!(plans, files_under(&self.root().join("plans")));
    }
}
impl Drop for Scene {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn previews_bind_exact_authenticated_sets_and_leave_everything_except_intent_untouched() {
    let s = Scene::new(3);
    s.protect(s.ids[2], true);
    let index = fs::read(s.db()).unwrap();
    let artifacts = s.bytes();
    // A reader needs neither the signing secret nor the recipient file, nor native tools.
    fs::remove_file(&s.keys.signing).unwrap();
    fs::remove_file(&s.keys.recipient).unwrap();
    let mut planner = s.planner();
    planner.0.source.client_bin_dir = "/nonexistent".into();
    let r = planner.preview(&Scene::prune(1)).unwrap();
    assert_eq!(r.candidates, [s.ids[1]]);
    let mut retained = vec![s.ids[0], s.ids[2]];
    retained.sort();
    assert_eq!(r.retained, retained);
    assert!(!r.audit_recorded);
    let id = r.plan_id.unwrap();
    let digest = r.digest.unwrap();
    let p = planner
        .check_saved_plan(id, RetentionOperation::Prune, &digest)
        .unwrap();
    let bytes = fs::read(s.plan_path(id)).unwrap();
    assert!(bytes.len() < 65536);
    let saved: SavedDeletionPlan = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(saved.plan, p);
    assert_eq!(saved.digest, digest);
    assert_eq!(
        fs::metadata(s.plan_path(id)).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(p.retained.len(), 2);
    assert!(
        p.candidates[0]
            .files
            .iter()
            .any(|f| f.name == "globals.age")
    );
    for needle in [
        "backupctl_fixture_m4a",
        "postgres",
        "127.0.0.1",
        s.keys.identity.to_str().unwrap(),
    ] {
        assert!(!String::from_utf8_lossy(&bytes).contains(needle));
    }
    assert_eq!(index, fs::read(s.db()).unwrap());
    assert_eq!(artifacts, s.bytes());
    assert!(files_under(&s.root().join("scratch")).is_empty());
    let empty = planner.preview(&Scene::prune(u64::MAX)).unwrap();
    assert!(empty.candidates.is_empty());
    assert!(empty.plan_id.is_none());
    assert!(empty.digest.is_none());
    assert!(empty.expires_unix_ms.is_none());
    assert_eq!(files_under(&s.root().join("plans")).len(), 1);
    let request = RetentionRequest::Delete {
        backup_id: s.ids[0],
    };
    let delete = planner.preview(&request).unwrap();
    assert_eq!(delete.candidates, [s.ids[0]]);
    assert_eq!(delete.retained.len(), 2);
}

#[test]
fn archive_evidence_protection_scope_and_last_copy_are_not_guessed() {
    let s = Scene::new(2);
    let target = s.ids[1];
    s.protect(target, true);
    s.assert_error(
        &RetentionRequest::Delete { backup_id: target },
        "RETENTION_PROTECTED",
    );
    s.protect(target, false);
    let db = Inventory::open_existing_current(&s.db(), s.inventory().estate()).unwrap();
    db.record_verification(target, "checksum", false, None, None)
        .unwrap();
    db.record_verification(
        target,
        "checksum",
        true,
        Some((
            db.artifact(target)
                .unwrap()
                .unwrap()
                .payload_sha256
                .as_deref()
                .unwrap(),
            db.artifact(target)
                .unwrap()
                .unwrap()
                .manifest_sha256
                .as_deref(),
        )),
        None,
    )
    .unwrap();
    s.assert_error(
        &RetentionRequest::Delete { backup_id: target },
        "RETENTION_VERIFICATION_REQUIRED",
    );
    let r = s.planner().preview(&Scene::prune(1)).unwrap();
    assert!(r.candidates.is_empty());
    assert_eq!(r.retained, [s.ids[0]]);
    assert!(
        r.excluded
            .iter()
            .any(|e| e.backup_id == Some(target) && e.reasons == ["verification_required"])
    );
    s.assert_error(
        &RetentionRequest::Delete {
            backup_id: s.ids[0],
        },
        "RETENTION_LAST_VALID",
    );
    s.assert_error(
        &RetentionRequest::Prune {
            keep_last: 1,
            profile_fingerprint: profile_fingerprint("another"),
        },
        "RETENTION_SCOPE_UNKNOWN",
    );
    drop(db);
    let source = s.inventory().estate().source_fingerprint.clone();
    let scanner = LocalReconciler(s.root().to_path_buf());
    let (id, _) = scanner.prepare_rebuild(&source).unwrap();
    scanner.rebuild(&source, id).unwrap();
    let capture = Capture::default();
    for id in &s.ids {
        VerifyService::new(StubEngine { capture: &capture }, s.reader())
            .verify(&s.config, *id, VERIFY_ARCHIVE)
            .unwrap();
    }
    s.assert_error(&Scene::prune(1), "RETENTION_PROTECTION_UNKNOWN");
}

#[test]
fn busy_claims_refuse_and_terminal_jobs_do_not_pin_preview() {
    let s = Scene::new(2);
    let claim = ActivityLock::hold(s.root()).unwrap();
    s.assert_error(&Scene::prune(1), "RETENTION_BUSY");
    drop(claim);
    let claim = ResourceLock::artifact(s.root(), s.ids[1], false)
        .unwrap()
        .unwrap();
    s.assert_error(&Scene::prune(1), "RETENTION_BUSY");
    drop(claim);
    let scope = JobScope {
        source_fingerprint: s.inventory().estate().source_fingerprint.clone(),
        profile_fingerprint: profile_fingerprint(WHOLE_DATABASE_PROFILE),
        backup_id: s.ids[1],
    };
    let job = JobGuard::begin(s.root(), &scope).unwrap();
    let r = s
        .inventory()
        .jobs()
        .unwrap()
        .into_iter()
        .find(|j| !j.state.is_terminal())
        .unwrap();
    // Forgetting a guard would leak its locks; use an isolated process fixture elsewhere for death.
    drop(job);
    // A terminal job doesn't pin the artifact.
    assert!(
        !s.planner()
            .preview(&Scene::prune(1))
            .unwrap()
            .candidates
            .is_empty()
    );
    assert!(
        s.inventory()
            .job(r.job_id)
            .unwrap()
            .unwrap()
            .state
            .is_terminal()
    );
}

#[test]
fn saved_plan_checks_reject_stale_inventory_files_and_unreviewed_confirmations() {
    let s = Scene::new(2);
    let planner = s.planner();
    let r = planner.preview(&Scene::prune(1)).unwrap();
    let id = r.plan_id.unwrap();
    let digest = r.digest.unwrap();
    for wrong in [&digest[..16], &digest.to_uppercase(), &"0".repeat(64)] {
        assert!(
            failure(planner.check_saved_plan(id, RetentionOperation::Prune, wrong))
                .contains("RETENTION_CONFIRMATION_MISMATCH")
        );
    }
    assert!(
        failure(planner.check_saved_plan(id, RetentionOperation::Delete, &digest))
            .contains("RETENTION_PLAN_INVALID")
    );
    let before = fs::read(s.db()).unwrap();
    let retained = s.ids[0];
    let path = artifact_dir(s.root(), retained).join("globals.age");
    let original = fs::read(&path).unwrap();
    fs::write(&path, b"swapped").unwrap();
    assert!(
        failure(planner.check_saved_plan(id, RetentionOperation::Prune, &digest))
            .contains("RETENTION_PLAN_STALE")
    );
    fs::write(&path, original).unwrap();
    assert_eq!(before, fs::read(s.db()).unwrap());
    s.protect(retained, true);
    assert!(
        failure(planner.check_saved_plan(id, RetentionOperation::Prune, &digest))
            .contains("RETENTION_PLAN_STALE")
    );
    let next = planner.preview(&Scene::prune(1)).unwrap();
    let next_id = next.plan_id.unwrap();
    let next_digest = next.digest.unwrap();
    let capture = Capture::default();
    VerifyService::new(StubEngine { capture: &capture }, s.reader())
        .verify(&s.config, retained, VERIFY_ARCHIVE)
        .unwrap();
    assert!(
        failure(planner.check_saved_plan(next_id, RetentionOperation::Prune, &next_digest))
            .contains("RETENTION_PLAN_STALE")
    );
    let fresh = planner.preview(&Scene::prune(1)).unwrap();
    let scope = JobScope {
        source_fingerprint: s.inventory().estate().source_fingerprint.clone(),
        profile_fingerprint: profile_fingerprint("unrelated-profile"),
        backup_id: Uuid::new_v4(),
    };
    drop(JobGuard::begin(s.root(), &scope).unwrap());
    assert!(
        failure(planner.check_saved_plan(
            fresh.plan_id.unwrap(),
            RetentionOperation::Prune,
            fresh.digest.as_ref().unwrap()
        ))
        .contains("RETENTION_PLAN_STALE")
    );
}

#[test]
fn unsafe_plan_files_and_extra_or_symlinked_artifact_components_are_refused() {
    let s = Scene::new(2);
    let planner = s.planner();
    let r = planner.preview(&Scene::prune(1)).unwrap();
    let id = r.plan_id.unwrap();
    let digest = r.digest.unwrap();
    let path = s.plan_path(id);
    let original = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        failure(planner.check_saved_plan(id, RetentionOperation::Prune, &digest))
            .contains("RETENTION_PLAN_INVALID")
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&path).unwrap();
    symlink(s.db(), &path).unwrap();
    assert!(
        failure(planner.check_saved_plan(id, RetentionOperation::Prune, &digest))
            .contains("RETENTION_PLAN_INVALID")
    );
    fs::remove_file(&path).unwrap();
    let fifo = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    assert!(
        failure(planner.check_saved_plan(id, RetentionOperation::Prune, &digest))
            .contains("RETENTION_PLAN_INVALID")
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    fs::remove_file(&path).unwrap();
    fs::write(&path, vec![b' '; 65537]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        failure(planner.check_saved_plan(id, RetentionOperation::Prune, &digest))
            .contains("RETENTION_PLAN_TOO_LARGE")
    );
    fs::write(&path, original).unwrap();
    let dir = artifact_dir(s.root(), s.ids[1]);
    fs::write(dir.join("unexpected"), b"private").unwrap();
    s.assert_error(&Scene::prune(1), "RETENTION_ARTIFACT_INVALID");
    fs::remove_file(dir.join("unexpected")).unwrap();
    let payload = dir.join("payload.age");
    let hold = s.base.join("hold.age");
    fs::rename(&payload, &hold).unwrap();
    symlink(&hold, &payload).unwrap();
    // Snapshot helper deliberately reads files here, including the link, to assert no bytes change.
    s.assert_error(&Scene::prune(1), "RETENTION_ARTIFACT_INVALID");
    fs::remove_file(payload).unwrap();
    fs::rename(hold, dir.join("payload.age")).unwrap();
    let marker = dir.join("complete");
    fs::write(&marker, b"unexpected").unwrap();
    s.assert_error(&Scene::prune(2), "RETENTION_ARTIFACT_INVALID");
    fs::write(&marker, []).unwrap();
    let moved = s.root().join("private-plans");
    fs::rename(s.root().join("plans"), &moved).unwrap();
    symlink(&moved, s.root().join("plans")).unwrap();
    assert!(
        failure(planner.check_saved_plan(id, RetentionOperation::Prune, &digest))
            .contains("RETENTION_PLAN_INVALID")
    );
    fs::remove_file(s.root().join("plans")).unwrap();
    fs::rename(moved, s.root().join("plans")).unwrap();
    fs::set_permissions(s.root().join("plans"), fs::Permissions::from_mode(0o755)).unwrap();
    s.assert_error(&Scene::prune(1), "RETENTION_PLAN_INVALID");
}

#[test]
fn planning_refuses_old_sidecar_indexes_and_preserves_diagnosed_missing_rows() {
    let s = Scene::new(2);
    let old = fs::read(s.db()).unwrap();
    fs::write(s.root().join("inventory.db-journal"), b"not a journal").unwrap();
    s.assert_error(&Scene::prune(1), "RETENTION_INVENTORY_INVALID");
    fs::remove_file(s.root().join("inventory.db-journal")).unwrap();
    // Version is at header offset 60, big endian; a lower declaration must never trigger migration.
    let mut bytes = old.clone();
    bytes[60..64].copy_from_slice(&5u32.to_be_bytes());
    fs::write(s.db(), bytes).unwrap();
    s.assert_error(&Scene::prune(1), "RETENTION_INVENTORY_INVALID");
    fs::write(s.db(), &old).unwrap();
    let row = s.inventory().artifacts().unwrap()[0].clone();
    let db = Inventory::open_existing_current(&s.db(), s.inventory().estate()).unwrap();
    db.reconcile_states(
        &db.artifacts().unwrap(),
        &[(row.backup_id, State::Registered, State::Missing)],
    )
    .unwrap();
    let r = s.planner().preview(&Scene::prune(1)).unwrap();
    assert!(r.candidates.is_empty());
    assert!(
        r.excluded
            .iter()
            .any(|e| e.reasons.contains(&"missing".to_string()))
    );
}

#[test]
fn unregistered_and_unsigned_archive_observations_never_count_as_valid_copies() {
    let s = Scene::new(2);
    let capture = Capture::default();
    let mut plain = s.config.clone();
    plain.encryption = None;
    plain.signing = None;
    let Created::Development(manifest) = BackupService::new(
        StubEngine { capture: &capture },
        LocalStore::new(s.root().to_path_buf()).unwrap(),
    )
    .create(&plain, None)
    .unwrap() else {
        panic!()
    };
    let preview = s.planner().preview(&Scene::prune(1)).unwrap();
    assert_eq!(preview.candidates, [s.ids[1]]);
    assert!(
        preview
            .excluded
            .iter()
            .any(|e| e.backup_id == Some(manifest.id) && e.reasons == ["unregistered"])
    );
    let db = Inventory::open_existing_current(&s.db(), s.inventory().estate()).unwrap();
    let row = backup_inventory::ArtifactRow {
        backup_id: manifest.id,
        source_fingerprint: db.estate().source_fingerprint.clone(),
        profile_fingerprint: Some(profile_fingerprint(WHOLE_DATABASE_PROFILE)),
        shape: backup_inventory::Shape::PlaintextDev,
        signer_id: None,
        recipient_id: None,
        payload_sha256: None,
        manifest_sha256: None,
        recipient_suite: None,
        signature_suite: None,
        payload_bytes: None,
        manifest_bytes: None,
        completed_at_utc: Some("2026-11-13T00:00:00Z".into()),
        state: State::Registered,
    };
    db.register(&row).unwrap();
    db.set_protection(row.backup_id, false).unwrap();
    db.record_verification(
        row.backup_id,
        "archive",
        true,
        Some((&manifest.sha256, None)),
        None,
    )
    .unwrap();
    let before = fs::read(s.db()).unwrap();
    let preview = s.planner().preview(&Scene::prune(1)).unwrap();
    assert_eq!(preview.candidates, [s.ids[1]]);
    assert_eq!(preview.retained, [s.ids[0]]);
    assert!(
        preview
            .excluded
            .iter()
            .any(|e| e.backup_id == Some(manifest.id) && e.reasons == ["unsigned"])
    );
    assert_eq!(before, fs::read(s.db()).unwrap());
}

fn saved(s: &Scene, preview: &backup_application::RetentionPreview) -> SavedDeletionPlan {
    serde_json::from_slice(&fs::read(s.plan_path(preview.plan_id.unwrap())).unwrap()).unwrap()
}
fn expire(s: &Scene, mut saved: SavedDeletionPlan) -> SavedDeletionPlan {
    saved.plan.created_unix_ms = 0;
    saved.plan.expires_unix_ms = backup_domain::DELETION_PLAN_TTL_MS;
    saved.digest = saved.plan.digest().unwrap();
    fs::write(
        s.plan_path(saved.plan.plan_id),
        serde_json::to_vec(&saved).unwrap(),
    )
    .unwrap();
    saved
}

#[test]
fn confirmed_run_removes_only_exact_candidates_and_replays_a_receipt_without_writes() {
    use backup_application::{ArtifactStore, SignedArtifactHandle};
    use backup_inventory::AuditAction;
    let s = Scene::new(4);
    s.protect(s.ids[3], true);
    let planner = s.planner();
    let preview = planner.preview(&Scene::prune(1)).unwrap();
    let plan = saved(&s, &preview);
    let retained: Vec<_> = plan
        .plan
        .retained
        .iter()
        .map(|a| {
            (
                a.backup_id,
                files_under(&artifact_dir(s.root(), a.backup_id))
                    .into_iter()
                    .map(|p| (p.clone(), fs::read(p).unwrap()))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let outcome = planner
        .run(plan.plan.plan_id, RetentionOperation::Prune, &plan.digest)
        .unwrap();
    assert_eq!(outcome.error, None);
    assert_eq!(outcome.result.outcome, "complete");
    assert!(outcome.result.audit_recorded);
    assert_eq!(outcome.result.completed, preview.candidates);
    assert!(outcome.result.deleting.is_empty() && outcome.result.pending.is_empty());
    let inventory = s.inventory();
    let events = inventory.audit_events().unwrap();
    assert_eq!(
        inventory
            .job_operation(outcome.result.job_id)
            .unwrap()
            .unwrap()
            .0,
        "prune"
    );
    for id in &preview.candidates {
        assert!(!artifact_dir(s.root(), *id).exists());
        assert_eq!(
            inventory.artifact(*id).unwrap().unwrap().state,
            State::Deleted
        );
        assert!(
            inventory
                .verification_events(*id)
                .unwrap()
                .iter()
                .all(|e| !e.current)
        );
        let actions: Vec<_> = events
            .iter()
            .filter(|e| e.job_id == Some(outcome.result.job_id) && e.backup_id == Some(*id))
            .map(|e| e.action)
            .collect();
        assert_eq!(
            actions,
            [AuditAction::ArtifactDeleting, AuditAction::ArtifactDeleted]
        );
    }
    for (id, files) in retained {
        for (path, bytes) in files {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
        assert_eq!(s.reader().open_signed(id).unwrap().manifest().backup_id, id);
    }
    let index = fs::read(s.db()).unwrap();
    let repeat = planner
        .run(plan.plan.plan_id, RetentionOperation::Prune, &plan.digest)
        .unwrap();
    assert_eq!(repeat.result.job_id, outcome.result.job_id);
    assert_eq!(repeat.result.completed, preview.candidates);
    assert!(!repeat.result.audit_recorded);
    assert_eq!(fs::read(s.db()).unwrap(), index);
    assert!(
        failure(planner.run(plan.plan.plan_id, RetentionOperation::Delete, &plan.digest))
            .contains("RETENTION_PLAN_INVALID")
    );
    assert!(
        failure(planner.run(
            plan.plan.plan_id,
            RetentionOperation::Prune,
            &"0".repeat(64)
        ))
        .contains("RETENTION_CONFIRMATION_MISMATCH")
    );
    assert_eq!(fs::read(s.db()).unwrap(), index);
}

#[test]
fn run_refuses_stale_or_expired_intent_and_live_readers_without_starting_a_job() {
    use backup_application::ArtifactStore;
    let s = Scene::new(2);
    let planner = s.planner();
    let preview = planner.preview(&Scene::prune(1)).unwrap();
    let plan = saved(&s, &preview);
    let index = fs::read(s.db()).unwrap();
    let bytes = s.bytes();
    let handle = s.reader().open_signed(preview.candidates[0]).unwrap();
    assert!(
        failure(planner.run(plan.plan.plan_id, RetentionOperation::Prune, &plan.digest))
            .contains("RETENTION_BUSY")
    );
    let view = s.reader().payload_plaintext(&handle).unwrap();
    drop(handle);
    assert!(
        failure(planner.run(plan.plan.plan_id, RetentionOperation::Prune, &plan.digest))
            .contains("RETENTION_BUSY")
    );
    drop(view);
    let victim = artifact_dir(s.root(), preview.retained[0]).join("payload.age");
    let original = fs::read(&victim).unwrap();
    fs::write(&victim, b"changed witness").unwrap();
    assert!(
        failure(planner.run(plan.plan.plan_id, RetentionOperation::Prune, &plan.digest))
            .contains("RETENTION_PLAN_STALE")
    );
    fs::write(&victim, original).unwrap();
    assert_eq!(fs::read(s.db()).unwrap(), index);
    assert_eq!(s.bytes(), bytes);
    let plan = expire(&s, plan);
    assert!(
        failure(planner.run(plan.plan.plan_id, RetentionOperation::Prune, &plan.digest))
            .contains("RETENTION_PLAN_EXPIRED")
    );
    assert_eq!(fs::read(s.db()).unwrap(), index);
    assert_eq!(s.bytes(), bytes);
}

#[test]
fn keyless_recovery_finishes_only_started_ids_at_each_removal_boundary_even_after_expiry() {
    use backup_inventory::{AuditAction, JobState};
    for boundary in 0..5 {
        let s = Scene::new(3);
        let preview = s.planner().preview(&Scene::prune(1)).unwrap();
        let plan = expire(&s, saved(&s, &preview));
        let inventory = Inventory::open_bound(&s.db()).unwrap().unwrap();
        let job_id = inventory.begin_deletion(&plan).unwrap();
        let first = preview.candidates[0];
        let pending = preview.candidates[1];
        inventory.mark_deleting(job_id, first).unwrap();
        let dir = artifact_dir(s.root(), first);
        if boundary > 0 {
            fs::remove_file(dir.join("complete")).unwrap();
            fs::File::open(&dir).unwrap().sync_all().unwrap();
        }
        if boundary > 1 {
            fs::remove_file(dir.join("payload.age")).unwrap();
        }
        if boundary > 2 {
            for path in files_under(&dir) {
                fs::remove_file(path).unwrap();
            }
        }
        if boundary > 3 {
            fs::remove_dir(&dir).unwrap();
        }
        if boundary % 2 == 0 {
            inventory.finish_deletion(job_id, false).unwrap();
        }
        drop(inventory);
        fs::remove_dir_all(s.keys.identity.parent().unwrap()).unwrap();
        let store = LocalStore::new(s.root().to_path_buf()).unwrap();
        let recovery = store.recover().unwrap();
        assert_eq!(recovery.deleted, [first]);
        assert!(!artifact_dir(s.root(), first).exists());
        assert!(artifact_dir(s.root(), pending).join("complete").is_file());
        let inventory = s.inventory();
        assert_eq!(
            inventory.artifact(first).unwrap().unwrap().state,
            State::Deleted
        );
        assert_eq!(
            inventory.artifact(pending).unwrap().unwrap().state,
            State::Registered
        );
        assert_eq!(
            inventory.job(job_id).unwrap().unwrap().state,
            if boundary % 2 == 0 {
                JobState::Failed
            } else {
                JobState::Interrupted
            }
        );
        assert!(
            !inventory
                .audit_events()
                .unwrap()
                .iter()
                .any(|e| e.job_id == Some(job_id) && e.action == AuditAction::JobCompleted)
        );
        let index = fs::read(s.db()).unwrap();
        let rerun = s
            .planner()
            .run(plan.plan.plan_id, RetentionOperation::Prune, &plan.digest)
            .unwrap();
        assert_eq!(rerun.error, Some("DELETION_RECOVERY_REQUIRED"));
        assert_eq!(rerun.result.completed, [first]);
        assert_eq!(rerun.result.pending, [pending]);
        assert!(!rerun.result.audit_recorded);
        assert!(store.recover().unwrap().deleted.is_empty());
        assert_eq!(fs::read(s.db()).unwrap(), index);
    }
}

#[test]
fn tombstones_override_returned_complete_files_and_cannot_be_revived() {
    use backup_application::{ArtifactStore, Reconciler};
    let s = Scene::new(2);
    let preview = s.planner().preview(&Scene::prune(1)).unwrap();
    let plan = saved(&s, &preview);
    let id = preview.candidates[0];
    let original_row = s.inventory().artifact(id).unwrap().unwrap();
    let inventory = Inventory::open_bound(&s.db()).unwrap().unwrap();
    let job_id = inventory.begin_deletion(&plan).unwrap();
    inventory.mark_deleting(job_id, id).unwrap();
    let reader = s.reader();
    assert!(artifact_dir(s.root(), id).join("complete").is_file());
    assert!(
        failure(
            LocalReconciler(s.root().to_path_buf())
                .prepare_rebuild(&original_row.source_fingerprint)
        )
        .contains("DELETION_RECOVERY_REQUIRED")
    );
    assert!(failure(reader.open_signed(id)).contains("DELETION_RECOVERY_REQUIRED"));
    assert!(failure(reader.verify_signed(id)).contains("DELETION_RECOVERY_REQUIRED"));
    let capture = Capture::default();
    let index = fs::read(s.db()).unwrap();
    assert!(
        failure(
            VerifyService::new(StubEngine { capture: &capture }, s.reader()).verify(
                &s.config,
                id,
                VERIFY_ARCHIVE
            )
        )
        .contains("DELETION_RECOVERY_REQUIRED")
    );
    assert_eq!(fs::read(s.db()).unwrap(), index);
    for deleted in [false, true] {
        if deleted {
            inventory.mark_deleted(job_id, id).unwrap();
        }
        assert!(
            reader
                .begin(
                    id,
                    &backup_application::WriteOptions {
                        with_globals: false
                    }
                )
                .is_err()
        );
        assert!(inventory.register(&original_row).is_err());
        assert!(inventory.set_protection(id, false).is_err());
        assert!(
            inventory
                .record_verification(id, "signature", false, None, None)
                .is_err()
        );
        assert!(
            inventory
                .reconcile_states(
                    &inventory.artifacts().unwrap(),
                    &[(
                        id,
                        if deleted {
                            State::Deleted
                        } else {
                            State::Deleting
                        },
                        State::Registered
                    )]
                )
                .is_err()
        );
        assert!(
            reader
                .list_signed()
                .unwrap()
                .signed
                .iter()
                .all(|h| h.backup_id != id)
        );
        let scanner = LocalReconciler(s.root().to_path_buf());
        let r = scanner.reconcile().unwrap();
        assert_eq!(
            r.entries
                .iter()
                .find(|e| e.backup_id == Some(id))
                .unwrap()
                .status,
            if deleted { "deleted" } else { "deleting" }
        );
        assert!(scanner.adopt(id, &original_row.source_fingerprint).is_err());
    }
}

#[test]
fn recovery_refuses_missing_or_changed_evidence_and_unplanned_remaining_files() {
    for case in 0..6 {
        let s = Scene::new(3);
        let preview = s.planner().preview(&Scene::prune(1)).unwrap();
        let plan = saved(&s, &preview);
        let inventory = Inventory::open_bound(&s.db()).unwrap().unwrap();
        let job_id = inventory.begin_deletion(&plan).unwrap();
        inventory
            .mark_deleting(job_id, preview.candidates[0])
            .unwrap();
        drop(inventory);
        let dir = artifact_dir(s.root(), preview.candidates[0]);
        match case {
            0 => fs::remove_file(s.plan_path(plan.plan.plan_id)).unwrap(),
            1 => fs::write(s.plan_path(plan.plan.plan_id), b"{}").unwrap(),
            2 => {
                let mut changed = plan.clone();
                changed.plan.created_unix_ms += 1;
                changed.plan.expires_unix_ms += 1;
                changed.digest = changed.plan.digest().unwrap();
                fs::write(
                    s.plan_path(plan.plan.plan_id),
                    serde_json::to_vec(&changed).unwrap(),
                )
                .unwrap();
            }
            3 => fs::write(dir.join("unplanned"), b"preserve").unwrap(),
            4 => fs::write(dir.join("payload.age"), b"changed").unwrap(),
            5 => {
                fs::remove_file(dir.join("payload.age")).unwrap();
                symlink("/dev/null", dir.join("payload.age")).unwrap();
            }
            _ => unreachable!(),
        }
        let index = fs::read(s.db()).unwrap();
        let bytes = s.bytes();
        let error = failure(LocalStore::new(s.root().to_path_buf()).unwrap().recover());
        assert!(error.contains("DELETION_RECOVERY_REQUIRED"), "{error}");
        assert_eq!(fs::read(s.db()).unwrap(), index);
        assert_eq!(s.bytes(), bytes);
        assert!(dir.join("complete").is_file());
    }
}

#[test]
fn expired_complete_receipt_needs_no_keys_files_or_new_events() {
    let s = Scene::new(2);
    let preview = s.planner().preview(&Scene::prune(1)).unwrap();
    let plan = expire(&s, saved(&s, &preview));
    let inventory = Inventory::open_bound(&s.db()).unwrap().unwrap();
    let job_id = inventory.begin_deletion(&plan).unwrap();
    let id = preview.candidates[0];
    inventory.mark_deleting(job_id, id).unwrap();
    fs::remove_dir_all(artifact_dir(s.root(), id)).unwrap();
    fs::File::open(s.root().join("artifacts"))
        .unwrap()
        .sync_all()
        .unwrap();
    inventory.mark_deleted(job_id, id).unwrap();
    inventory.finish_deletion(job_id, true).unwrap();
    drop(inventory);
    fs::remove_dir_all(s.keys.identity.parent().unwrap()).unwrap();
    let before = fs::read(s.db()).unwrap();
    let receipt = s
        .planner()
        .run(plan.plan.plan_id, RetentionOperation::Prune, &plan.digest)
        .unwrap();
    assert_eq!(receipt.error, None);
    assert_eq!(receipt.result.completed, [id]);
    assert_eq!(receipt.result.job_id, job_id);
    assert!(!receipt.result.audit_recorded);
    assert_eq!(fs::read(s.db()).unwrap(), before);
}

#[test]
fn open_deletion_jobs_pin_their_whole_exact_set_and_unknown_evidence_blocks_planning() {
    let s = Scene::new(3);
    let planner = s.planner();
    let preview = planner.preview(&Scene::prune(1)).unwrap();
    let plan = saved(&s, &preview);
    let inventory = Inventory::open_bound(&s.db()).unwrap().unwrap();
    let job_id = inventory.begin_deletion(&plan).unwrap();
    drop(inventory);
    let bytes = s.bytes();
    let pinned = planner.preview(&Scene::prune(1)).unwrap();
    assert!(pinned.candidates.is_empty());
    assert_eq!(pinned.retained.len(), 3);
    assert!(
        failure(planner.preview(&RetentionRequest::Delete {
            backup_id: preview.retained[0]
        }))
        .contains("RETENTION_JOB_DEPENDENCY")
    );
    fs::remove_file(s.plan_path(plan.plan.plan_id)).unwrap();
    assert!(failure(planner.preview(&Scene::prune(1))).contains("RETENTION_JOB_DEPENDENCY"));
    let recovered = LocalStore::new(s.root().to_path_buf())
        .unwrap()
        .recover()
        .unwrap();
    assert!(recovered.deleted.is_empty());
    assert_eq!(recovered.interrupted, [job_id]);
    assert_eq!(s.bytes(), bytes);
    assert_eq!(
        planner.preview(&Scene::prune(1)).unwrap().candidates,
        preview.candidates
    );
}
