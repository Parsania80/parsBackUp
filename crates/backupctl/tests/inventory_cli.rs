use backup_inventory::{
    ActivityLock, ArtifactRow, Estate, INVENTORY_FILE, Inventory, JobGuard, JobScope, Shape, State,
};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use uuid::Uuid;

const SOURCE: &str = "0123456789abcdef";
const PROFILE: &str = "fedcba9876543210";

struct Scene(PathBuf);

impl Scene {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!("backupctl-a01-{}", Uuid::new_v4()));
        fs::create_dir_all(&base).unwrap();
        let scene = Self(base);
        fs::write(scene.0.join("config.toml"), format!(
            "[source]\nhost = \"127.0.0.1\"\nport = 5432\nuser = \"postgres\"\ndatabase = \"backupctl_fixture_a01\"\nclient_bin_dir = \"/nonexistent\"\n[storage]\nroot = \"{}\"\n[encryption]\nidentity_file = \"{}\"\nrecipient_file = \"{}\"\n",
            scene.root().display(), scene.0.join("missing-identity").display(), scene.0.join("missing-recipient").display()
        )).unwrap();
        scene
    }

    fn root(&self) -> PathBuf {
        self.0.join("store")
    }
    fn inventory(&self) -> PathBuf {
        self.root().join(INVENTORY_FILE)
    }
    fn run(&self, args: &[&str]) -> Output {
        self.run_output(args, "json")
    }
    fn run_output(&self, args: &[&str], mode: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_backupctl"))
            .args([
                "--config",
                self.0.join("config.toml").to_str().unwrap(),
                "--output",
                mode,
            ])
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn json(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn error(output: Output, category: &str) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(category),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn scope(id: Uuid) -> JobScope {
    JobScope {
        source_fingerprint: SOURCE.into(),
        profile_fingerprint: PROFILE.into(),
        backup_id: id,
    }
}

#[test]
fn rebuild_preview_needs_neither_inventory_nor_keys() {
    let scene = Scene::new();
    fs::create_dir_all(scene.root().join("artifacts")).unwrap();
    let id = Uuid::new_v4();
    fs::create_dir(scene.root().join("artifacts").join(id.to_string())).unwrap();
    let preview = json(scene.run(&[
        "inventory",
        "rebuild",
        "--source-fingerprint",
        SOURCE,
        "--dry-run",
    ]));
    assert_eq!(preview["source_fingerprint"], SOURCE);
    assert_eq!(preview["estate_provenance"], "unconfirmed");
    assert!(
        preview["unknown_facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "source_provenance")
    );
    assert_eq!(preview["entries"][0]["status"], "incomplete");
    assert_eq!(preview["audit_recorded"], false);
    assert!(!scene.inventory().exists());
    fs::write(scene.inventory(), b"damaged inventory").unwrap();
    let before = fs::read(scene.inventory()).unwrap();
    let preview = json(scene.run(&[
        "inventory",
        "rebuild",
        "--source-fingerprint",
        SOURCE,
        "--dry-run",
    ]));
    assert_eq!(preview["entries"][0]["status"], "incomplete");
    assert_eq!(fs::read(scene.inventory()).unwrap(), before);
    assert!(
        !scene
            .run(&[
                "inventory",
                "rebuild",
                "--source-fingerprint",
                "wrong",
                "--dry-run"
            ])
            .status
            .success()
    );
    assert!(
        !scene
            .run(&["inventory", "rebuild", "--source-fingerprint", SOURCE])
            .status
            .success()
    );
    assert!(
        !scene
            .run(&[
                "inventory",
                "rebuild",
                "--source-fingerprint",
                SOURCE,
                "--prepare-rebuild"
            ])
            .status
            .success()
    );
    assert_eq!(fs::read(scene.inventory()).unwrap(), before);
    fs::remove_dir(scene.root().join("artifacts").join(id.to_string())).unwrap();
    assert!(
        !scene
            .run(&[
                "inventory",
                "rebuild",
                "--source-fingerprint",
                SOURCE,
                "--confirm-rebuild"
            ])
            .status
            .success()
    );
    let prepared = json(scene.run(&[
        "inventory",
        "rebuild",
        "--source-fingerprint",
        SOURCE,
        "--prepare-rebuild",
    ]));
    let plan = prepared["plan_id"].as_str().unwrap();
    let report = json(scene.run(&[
        "inventory",
        "rebuild",
        "--source-fingerprint",
        SOURCE,
        "--confirm-rebuild",
        "--plan-id",
        plan,
    ]));
    assert_eq!(report["rebuilt"], true);
    let backup = report["previous_inventory"].as_str().unwrap();
    assert_eq!(fs::read(backup).unwrap(), before);
    assert_eq!(
        Inventory::open_read_only_bound(&scene.inventory())
            .unwrap()
            .estate()
            .source_fingerprint,
        SOURCE
    );
}

#[test]
fn rebuild_refuses_a_job_before_staging_starts() {
    let scene = Scene::new();
    fs::create_dir_all(scene.root().join("artifacts")).unwrap();
    drop(Inventory::open(&scene.inventory(), &Estate::new(SOURCE.into()).unwrap()).unwrap());
    let prepared = json(scene.run(&[
        "inventory",
        "rebuild",
        "--source-fingerprint",
        SOURCE,
        "--prepare-rebuild",
    ]));
    let plan = prepared["plan_id"].as_str().unwrap();
    let job = JobGuard::begin(&scene.root(), &scope(Uuid::new_v4())).unwrap();
    error(
        scene.run(&[
            "inventory",
            "rebuild",
            "--source-fingerprint",
            SOURCE,
            "--confirm-rebuild",
            "--plan-id",
            plan,
        ]),
        "RECONCILE_BUSY",
    );
    job.complete().unwrap();
    error(
        scene.run(&[
            "inventory",
            "rebuild",
            "--source-fingerprint",
            SOURCE,
            "--confirm-rebuild",
            "--plan-id",
            plan,
        ]),
        "RECONCILE_BUSY",
    );
    drop(job);
    error(
        scene.run(&[
            "inventory",
            "rebuild",
            "--source-fingerprint",
            SOURCE,
            "--confirm-rebuild",
            "--plan-id",
            plan,
        ]),
        "stale",
    );
}

#[test]
fn cli_adopts_a_development_artifact_as_unconfirmed() {
    let scene = Scene::new();
    let id = Uuid::new_v4();
    let artifact = scene.root().join("artifacts").join(id.to_string());
    fs::create_dir_all(&artifact).unwrap();
    fs::write(artifact.join("complete"), []).unwrap();
    fs::write(artifact.join("payload.dump"), b"abc").unwrap();
    fs::write(
        artifact.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "format": "m1-development-plaintext", "id": id, "synthetic_only": true,
            "database": "backupctl_fixture_a03", "source_major": 16, "source_version": "16",
            "dump_client_version": "16", "application_version": "test", "archive_format": "custom",
            "compression": "gzip", "created_unix_ms": 1, "size_bytes": 3,
            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "status": "complete", "security_globals": false
        }))
        .unwrap(),
    )
    .unwrap();
    drop(Inventory::open(&scene.inventory(), &Estate::new(SOURCE.into()).unwrap()).unwrap());
    let adopted = json(scene.run(&[
        "inventory",
        "adopt",
        &id.to_string(),
        "--source-fingerprint",
        SOURCE,
    ]));
    assert_eq!(adopted["estate_provenance"], "unconfirmed");
    assert_eq!(adopted["audit_recorded"], true);
    let listing = json(scene.run(&["inventory", "list"]));
    assert_eq!(listing["entries"][0]["provenance"], "unconfirmed");
    assert!(
        !scene
            .run(&[
                "inventory",
                "adopt",
                &id.to_string(),
                "--source-fingerprint",
                SOURCE
            ])
            .status
            .success()
    );
    fs::write(scene.0.join("config.toml"), format!(
        "[source]\nhost = \"127.0.0.1\"\nport = 5432\nuser = \"postgres\"\ndatabase = \"backupctl_fixture_a01\"\nclient_bin_dir = \"/nonexistent\"\n[storage]\nroot = \"{}\"\n", scene.root().display()
    )).unwrap();
    let readonly = json(scene.run(&[
        "backup",
        "verify",
        &id.to_string(),
        "--level",
        "checksum",
        "--read-only",
    ]));
    assert_eq!(readonly["audit_recorded"], false);
    assert_eq!(
        json(scene.run(&["inventory", "verification", &id.to_string()]))["events"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let writable = json(scene.run(&["backup", "verify", &id.to_string(), "--level", "checksum"]));
    assert_eq!(writable["audit_recorded"], true);
    assert_eq!(
        json(scene.run(&["inventory", "verification", &id.to_string()]))["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn cli_reads_verification_events_without_writing() {
    let scene = Scene::new();
    fs::create_dir_all(scene.root()).unwrap();
    let inventory =
        Inventory::open(&scene.inventory(), &Estate::new(SOURCE.into()).unwrap()).unwrap();
    let id = Uuid::new_v4();
    let row = ArtifactRow {
        backup_id: id,
        source_fingerprint: SOURCE.into(),
        profile_fingerprint: None,
        shape: Shape::PlaintextDev,
        signer_id: None,
        recipient_id: None,
        payload_sha256: None,
        manifest_sha256: None,
        recipient_suite: None,
        signature_suite: None,
        payload_bytes: None,
        manifest_bytes: None,
        completed_at_utc: None,
        state: State::Registered,
    };
    inventory.adopt(&row).unwrap();
    let digest = "a".repeat(64);
    inventory
        .record_verification(id, "checksum", true, Some((&digest, None)), None)
        .unwrap();
    drop(inventory);
    let before = fs::read(scene.inventory()).unwrap();
    let report = json(scene.run(&["inventory", "verification", &id.to_string()]));
    assert_eq!(report["audit_recorded"], false);
    assert_eq!(report["events"][0]["outcome"], "success");
    assert_eq!(report["events"][0]["payload_sha256"], digest);
    assert_eq!(report["events"][0]["manifest_sha256"], Value::Null);
    assert_eq!(fs::read(scene.inventory()).unwrap(), before);
}

#[test]
fn job_list_reports_restore_associations_without_private_names() {
    let scene = Scene::new();
    fs::create_dir_all(scene.root()).unwrap();
    let artifact = Uuid::new_v4();
    drop(Inventory::open(&scene.inventory(), &Estate::new(SOURCE.into()).unwrap()).unwrap());
    let guard =
        backup_inventory::RestoreGuard::begin(&scene.root(), "0123456789abcdef", artifact).unwrap();
    let result = json(scene.run(&["job", "list"]));
    let job = &result["jobs"][0];
    assert_eq!(job["operation"], "restore");
    assert_eq!(job["target_fingerprint"], "0123456789abcdef");
    assert_eq!(job["profile_fingerprint"], Value::Null);
    assert_eq!(job["backup_id"], artifact.to_string());
    assert_eq!(job["state"], "running");
    guard.complete().unwrap();
    drop(guard);
    assert_eq!(
        json(scene.run(&["job", "list"]))["jobs"][0]["state"],
        "complete"
    );
}

#[test]
fn reconcile_cli_is_explicit_idempotent_and_transactional() {
    let scene = Scene::new();
    fs::create_dir_all(scene.root().join("artifacts")).unwrap();
    let estate = Estate::new(SOURCE.into()).unwrap();
    let inventory = Inventory::open(&scene.inventory(), &estate).unwrap();
    let row = ArtifactRow {
        backup_id: Uuid::new_v4(),
        source_fingerprint: SOURCE.into(),
        profile_fingerprint: Some(PROFILE.into()),
        shape: Shape::PlaintextDev,
        signer_id: None,
        recipient_id: None,
        payload_sha256: None,
        manifest_sha256: None,
        recipient_suite: None,
        signature_suite: None,
        payload_bytes: None,
        manifest_bytes: None,
        completed_at_utc: Some("2026-01-01T00:00:00Z".into()),
        state: State::Registered,
    };
    inventory.register(&row).unwrap();
    let event_count = inventory.audit_events().unwrap().len();
    drop(inventory);
    let claim = ActivityLock::hold(&scene.root()).unwrap();
    let before = fs::read(scene.inventory()).unwrap();
    let listed = json(scene.run(&["inventory", "list"]));
    assert_eq!(listed["audit_recorded"], false);
    assert_eq!(listed["entries"][0]["status"], "missing");
    assert_eq!(fs::read(scene.inventory()).unwrap(), before);
    error(scene.run(&["inventory", "reconcile"]), "RECONCILE_BUSY");
    drop(claim);
    fs::remove_dir(scene.root().join("artifacts")).unwrap();
    assert!(!scene.run(&["inventory", "reconcile"]).status.success());
    let inventory = Inventory::open_read_only_bound(&scene.inventory()).unwrap();
    assert_eq!(inventory.artifact(row.backup_id).unwrap().unwrap(), row);
    assert_eq!(inventory.audit_events().unwrap().len(), event_count);
    drop(inventory);
    fs::create_dir(scene.root().join("artifacts")).unwrap();
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_observation BEFORE INSERT ON audit_event WHEN NEW.action = 'artifact_missing' BEGIN SELECT RAISE(FAIL, 'test rollback'); END;").unwrap();
    drop(conn);
    assert!(!scene.run(&["inventory", "reconcile"]).status.success());
    let inventory = Inventory::open_read_only_bound(&scene.inventory()).unwrap();
    assert_eq!(inventory.artifact(row.backup_id).unwrap().unwrap(), row);
    assert_eq!(inventory.audit_events().unwrap().len(), event_count);
    drop(inventory);
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute_batch("DROP TRIGGER reject_observation")
        .unwrap();
    drop(conn);
    let first = json(scene.run(&["inventory", "reconcile"]));
    assert_eq!(first["audit_recorded"], true);
    assert_eq!(first["entries"][0]["status"], "missing");
    assert_eq!(first["entries"][0]["backup_id"], row.backup_id.to_string());
    let second = json(scene.run(&["inventory", "reconcile"]));
    assert_eq!(second["audit_recorded"], false);
    let inventory = Inventory::open_read_only_bound(&scene.inventory()).unwrap();
    let updated = inventory.artifact(row.backup_id).unwrap().unwrap();
    assert_eq!(updated.state, State::Missing);
    assert_eq!(updated.profile_fingerprint, row.profile_fingerprint);
    assert_eq!(updated.completed_at_utc, row.completed_at_utc);
    assert_eq!(inventory.audit_events().unwrap().len(), event_count + 1);
}

#[test]
fn reconciliation_refuses_symlinked_inventory() {
    let scene = Scene::new();
    fs::create_dir_all(scene.root().join("artifacts")).unwrap();
    let outside = scene.0.join("outside.db");
    drop(Inventory::open(&outside, &Estate::new(SOURCE.into()).unwrap()).unwrap());
    let before = fs::read(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, scene.inventory()).unwrap();
    error(
        scene.run(&["inventory", "reconcile"]),
        "INVENTORY_OPEN_FAILED",
    );
    assert_eq!(fs::read(outside).unwrap(), before);
}

#[test]
fn reads_jobs_and_integrity_without_keys_writes_or_sweeping() {
    let scene = Scene::new();
    fs::create_dir_all(scene.root()).unwrap();
    let first = JobGuard::begin(&scene.root(), &scope(Uuid::new_v4())).unwrap();
    let abandoned_id = first.id();
    first.complete().unwrap();
    drop(first);
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute(
        "UPDATE job SET state = 'running', backup_id = NULL WHERE job_id = ?1",
        [abandoned_id.to_string()],
    )
    .unwrap();
    drop(conn);
    let abandoned = json(scene.run(&["job", "inspect", &abandoned_id.to_string()]));
    assert_eq!(abandoned["job"]["state"], "running");
    assert_eq!(abandoned["job"]["backup_id"], Value::Null);
    let backup_id = Uuid::new_v4();
    let running = JobGuard::begin(&scene.root(), &scope(backup_id)).unwrap();
    let running_id = running.id();
    fs::create_dir_all(scene.root().join("artifacts")).unwrap();
    let before = fs::read(scene.inventory()).unwrap();
    fs::set_permissions(scene.inventory(), fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(scene.root(), fs::Permissions::from_mode(0o500)).unwrap();

    let jobs = json(scene.run(&["job", "list"]));
    assert_eq!(jobs["audit_recorded"], false);
    let rows = jobs["jobs"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|row| row["job_id"] == abandoned_id.to_string() && row["state"] == "running")
    );
    assert!(rows.windows(2).all(
        |p| (p[0]["started_at_utc"].as_str(), p[0]["job_id"].as_str())
            <= (p[1]["started_at_utc"].as_str(), p[1]["job_id"].as_str())
    ));
    let current = json(scene.run(&["job", "inspect", &running_id.to_string()]));
    assert_eq!(current["audit_recorded"], false);
    assert_eq!(current["job"]["state"], "running");
    assert_eq!(current["job"]["backup_id"], backup_id.to_string());
    assert_eq!(current["job"]["operation"], "backup");
    assert_eq!(current["job"]["target_fingerprint"], Value::Null);
    assert_eq!(current["job"]["source_fingerprint"], SOURCE);
    let check = json(scene.run(&["inventory", "check"]));
    assert_eq!(check["valid"], true);
    assert_eq!(check["schema_version"], backup_inventory::SCHEMA_VERSION);
    assert_eq!(check["audit_recorded"], false);
    assert!(
        json(scene.run(&["inventory", "list"]))["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    error(
        scene.run(&["job", "inspect", &Uuid::new_v4().to_string()]),
        "JOB_NOT_FOUND",
    );
    assert_eq!(before, fs::read(scene.inventory()).unwrap());
    assert!(!scene.root().join("inventory.db-journal").exists());
    let copy = Scene::new();
    fs::create_dir_all(copy.root()).unwrap();
    fs::create_dir(copy.root().join("artifacts")).unwrap();
    fs::copy(scene.inventory(), copy.inventory()).unwrap();
    fs::set_permissions(copy.inventory(), fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(copy.root(), fs::Permissions::from_mode(0o500)).unwrap();
    assert_eq!(json(copy.run(&["inventory", "check"]))["valid"], true);
    assert!(
        json(copy.run(&["inventory", "list"]))["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        json(copy.run(&["job", "inspect", &running_id.to_string()]))["job"]["state"],
        "running"
    );
    assert_eq!(before, fs::read(copy.inventory()).unwrap());
    assert_eq!(fs::read_dir(copy.root()).unwrap().count(), 2);
    fs::set_permissions(copy.root(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(scene.root(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(scene.inventory(), fs::Permissions::from_mode(0o600)).unwrap();
    drop(running);
}

#[test]
fn missing_and_damaged_inventory_are_not_reported_as_missing_jobs() {
    let scene = Scene::new();
    error(
        scene.run(&["job", "inspect", &Uuid::new_v4().to_string()]),
        "INVENTORY_OPEN_FAILED",
    );
    assert!(!scene.root().exists());
    fs::create_dir_all(scene.root()).unwrap();
    fs::write(scene.inventory(), b"not a sqlite inventory").unwrap();
    error(scene.run(&["inventory", "check"]), "INVENTORY_OPEN_FAILED");
    assert_eq!(
        fs::read(scene.inventory()).unwrap(),
        b"not a sqlite inventory"
    );
}

#[test]
fn old_inventory_is_checked_without_migration_and_jobs_fail() {
    let scene = Scene::new();
    fs::create_dir_all(scene.root()).unwrap();
    // Use the actual v1 migration rather than inventing an older schema.
    let source = include_str!("../../backup-inventory/src/schema.rs");
    let sql = source
        .split("const SCHEMA_V1: &str = \"")
        .nth(1)
        .unwrap()
        .split("\n\";")
        .next()
        .unwrap();
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute_batch(sql).unwrap();
    conn.execute(
        "INSERT INTO meta (key,value) VALUES ('source_fingerprint',?1)",
        [SOURCE],
    )
    .unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    drop(conn);
    let before = fs::read(scene.inventory()).unwrap();
    assert_eq!(
        json(scene.run(&["inventory", "check"]))["schema_version"],
        1
    );
    error(scene.run(&["job", "list"]), "INVENTORY_READ_FAILED");
    fs::create_dir_all(scene.root().join("artifacts")).unwrap();
    assert!(
        json(scene.run(&["inventory", "list"]))["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!scene.run(&["inventory", "reconcile"]).status.success());
    assert_eq!(before, fs::read(scene.inventory()).unwrap());
    let conn = rusqlite::Connection::open_with_flags(
        scene.inventory(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 1);
}

#[test]
fn structural_check_reports_a_corrupt_index() {
    let scene = Scene::new();
    fs::create_dir_all(scene.root()).unwrap();
    let job = JobGuard::begin(&scene.root(), &scope(Uuid::new_v4())).unwrap();
    job.complete().unwrap();
    drop(job);
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute_batch(
        "CREATE INDEX test_corrupt ON job(state);\n\
         PRAGMA writable_schema=ON;\n\
         UPDATE sqlite_schema SET sql = 'CREATE INDEX test_corrupt ON job(updated_at_utc)' \
         WHERE name = 'test_corrupt';\n\
         PRAGMA writable_schema=OFF;",
    )
    .unwrap();
    drop(conn);
    let output = scene.run(&["inventory", "check"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("INVENTORY_CORRUPT"));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["valid"], false);
    assert!(!report["problems"].as_array().unwrap().is_empty());
    error(
        scene.run(&["job", "inspect", &Uuid::new_v4().to_string()]),
        "INVENTORY_READ_FAILED",
    );
}

#[test]
fn damaged_job_and_newer_schema_are_refused() {
    let scene = Scene::new();
    fs::create_dir_all(scene.root()).unwrap();
    let job = JobGuard::begin(&scene.root(), &scope(Uuid::new_v4())).unwrap();
    let id = job.id();
    job.complete().unwrap();
    drop(job);
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute(
        "UPDATE job SET state = 'invalid' WHERE job_id = ?1",
        [id.to_string()],
    )
    .unwrap();
    drop(conn);
    error(
        scene.run(&["job", "inspect", &id.to_string()]),
        "INVENTORY_READ_FAILED",
    );
    error(
        scene.run(&["job", "inspect", &Uuid::new_v4().to_string()]),
        "INVENTORY_READ_FAILED",
    );
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute(
        "UPDATE job SET state = 'complete', profile_fingerprint = 'not-a-fingerprint' WHERE job_id = ?1",
        [id.to_string()],
    ).unwrap();
    drop(conn);
    error(scene.run(&["job", "list"]), "INVENTORY_READ_FAILED");
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute(
        "UPDATE job SET profile_fingerprint = ?1, source_fingerprint = '1111111111111111' WHERE job_id = ?2",
        [PROFILE, &id.to_string()],
    ).unwrap();
    drop(conn);
    error(
        scene.run(&["job", "inspect", &id.to_string()]),
        "INVENTORY_READ_FAILED",
    );
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.pragma_update(None, "user_version", backup_inventory::SCHEMA_VERSION + 1)
        .unwrap();
    drop(conn);
    error(scene.run(&["inventory", "check"]), "INVENTORY_OPEN_FAILED");
}

fn protection_scene() -> (Scene, Uuid) {
    let scene = Scene::new();
    fs::create_dir_all(scene.root()).unwrap();
    let inventory =
        Inventory::open(&scene.inventory(), &Estate::new(SOURCE.into()).unwrap()).unwrap();
    let id = Uuid::new_v4();
    inventory
        .adopt(&ArtifactRow {
            backup_id: id,
            source_fingerprint: SOURCE.into(),
            profile_fingerprint: None,
            shape: Shape::PlaintextDev,
            signer_id: None,
            recipient_id: None,
            payload_sha256: None,
            manifest_sha256: None,
            recipient_suite: None,
            signature_suite: None,
            payload_bytes: None,
            manifest_bytes: None,
            completed_at_utc: None,
            state: State::Registered,
        })
        .unwrap();
    (scene, id)
}

#[test]
fn protection_commands_are_keyless_idempotent_and_report_unknown_transitions() {
    let (scene, id) = protection_scene();
    let before = Inventory::open_read_only_bound(&scene.inventory()).unwrap();
    let artifact = before.artifact(id).unwrap();
    let jobs = before.jobs().unwrap();
    let observations = before.verification_events(id).unwrap();
    drop(before);
    let first = scene.run(&["backup", "unprotect", &id.to_string()]);
    assert!(String::from_utf8_lossy(&first.stderr).contains("prior protection was unknown"));
    assert_eq!(
        json(first),
        serde_json::json!({"backup_id": id, "protection": "unprotected", "changed": true, "audit_recorded": true})
    );
    let report = json(scene.run(&["backup", "protect", &id.to_string()]));
    assert_eq!(
        report,
        serde_json::json!({"backup_id": id, "protection": "protected", "changed": true, "audit_recorded": true})
    );
    let contents = fs::read(scene.inventory()).unwrap();
    let repeated = json(scene.run(&["backup", "protect", &id.to_string()]));
    assert_eq!(repeated["changed"], false);
    assert_eq!(repeated["audit_recorded"], false);
    assert_eq!(fs::read(scene.inventory()).unwrap(), contents);
    let human = scene.run_output(&["backup", "unprotect", &id.to_string()], "human");
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains("protected -> unprotected"));
    let inventory = Inventory::open_read_only_bound(&scene.inventory()).unwrap();
    assert_eq!(inventory.artifact(id).unwrap(), artifact);
    assert_eq!(inventory.jobs().unwrap(), jobs);
    assert_eq!(inventory.verification_events(id).unwrap(), observations);
    assert_eq!(inventory.protection(id).unwrap(), Some(false));
    assert_eq!(
        inventory
            .audit_events()
            .unwrap()
            .iter()
            .filter(|e| matches!(
                e.action,
                backup_inventory::AuditAction::ArtifactProtected
                    | backup_inventory::AuditAction::ArtifactUnprotected
            ))
            .count(),
        3
    );
    assert!(!scene.root().join("artifacts").exists());
    assert!(!scene.root().join("staging").exists());
    assert!(!scene.root().join("scratch").exists());
    let raw = fs::read(scene.inventory()).unwrap();
    for token in [
        b"backupctl_fixture_a01".as_slice(),
        b"missing-identity",
        b"missing-recipient",
    ] {
        assert!(!raw.windows(token.len()).any(|w| w == token));
    }
}

#[test]
fn protection_refusals_leave_inventory_history_and_binding_unchanged() {
    let missing = Scene::new();
    error(
        missing.run(&["backup", "protect", &Uuid::new_v4().to_string()]),
        "RETENTION_INVENTORY_INVALID",
    );
    assert!(!missing.root().exists());
    fs::create_dir_all(missing.root()).unwrap();
    error(
        missing.run(&["backup", "protect", &Uuid::new_v4().to_string()]),
        "RETENTION_INVENTORY_INVALID",
    );
    assert!(!missing.inventory().exists());
    let (scene, id) = protection_scene();
    let original = fs::read(scene.inventory()).unwrap();
    let activity = ActivityLock::hold(&scene.root()).unwrap();
    error(
        scene.run(&["backup", "protect", &id.to_string()]),
        "RETENTION_BUSY",
    );
    assert_eq!(fs::read(scene.inventory()).unwrap(), original);
    drop(activity);
    let activity_path = scene.root().join("locks/activity.lock");
    let saved_activity = scene.root().join("saved-activity.lock");
    fs::rename(&activity_path, &saved_activity).unwrap();
    std::os::unix::fs::symlink(&saved_activity, &activity_path).unwrap();
    error(
        scene.run(&["backup", "protect", &id.to_string()]),
        "RETENTION_INVENTORY_INVALID",
    );
    assert_eq!(fs::read(scene.inventory()).unwrap(), original);
    fs::remove_file(&activity_path).unwrap();
    fs::rename(&saved_activity, &activity_path).unwrap();
    error(
        scene.run(&["backup", "protect", &Uuid::new_v4().to_string()]),
        "RETENTION_ARTIFACT_INVALID",
    );
    assert_eq!(fs::read(scene.inventory()).unwrap(), original);
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = scene.root().join(format!("{INVENTORY_FILE}{suffix}"));
        fs::write(&sidecar, b"do not remove").unwrap();
        error(
            scene.run(&["backup", "unprotect", &id.to_string()]),
            "RETENTION_INVENTORY_INVALID",
        );
        assert_eq!(fs::read(scene.inventory()).unwrap(), original);
        assert_eq!(fs::read(&sidecar).unwrap(), b"do not remove");
        fs::remove_file(sidecar).unwrap();
    }
    let saved = scene.root().join("saved.db");
    fs::rename(scene.inventory(), &saved).unwrap();
    std::os::unix::fs::symlink(&saved, scene.inventory()).unwrap();
    error(
        scene.run(&["backup", "protect", &id.to_string()]),
        "RETENTION_INVENTORY_INVALID",
    );
    assert_eq!(fs::read(&saved).unwrap(), original);
    fs::remove_file(scene.inventory()).unwrap();
    fs::rename(&saved, scene.inventory()).unwrap();
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.pragma_update(None, "user_version", backup_inventory::SCHEMA_VERSION + 1)
        .unwrap();
    drop(conn);
    let newer = fs::read(scene.inventory()).unwrap();
    error(
        scene.run(&["backup", "protect", &id.to_string()]),
        "RETENTION_INVENTORY_INVALID",
    );
    assert_eq!(fs::read(scene.inventory()).unwrap(), newer);
}

#[test]
fn protection_refuses_malformed_inventory_rows_before_changing_anything() {
    let (scene, id) = protection_scene();
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute(
        "UPDATE artifact SET source_fingerprint = '0000000000000000'",
        [],
    )
    .unwrap();
    drop(conn);
    let bad = fs::read(scene.inventory()).unwrap();
    error(
        scene.run(&["backup", "protect", &id.to_string()]),
        "RETENTION_INVENTORY_INVALID",
    );
    assert_eq!(fs::read(scene.inventory()).unwrap(), bad);
}

#[test]
fn protection_upgrades_v5_only_for_a_valid_request_and_rolls_back_failed_audit() {
    let (scene, id) = protection_scene();
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute_batch("ALTER TABLE artifact DROP COLUMN protected; PRAGMA user_version=5;")
        .unwrap();
    drop(conn);
    let old = fs::read(scene.inventory()).unwrap();
    assert_eq!(
        json(scene.run(&["inventory", "check"]))["schema_version"],
        5
    );
    error(
        scene.run(&["backup", "protect", &Uuid::new_v4().to_string()]),
        "RETENTION_ARTIFACT_INVALID",
    );
    assert_eq!(fs::read(scene.inventory()).unwrap(), old);
    let human = scene.run_output(&["backup", "unprotect", &id.to_string()], "human");
    assert!(
        human.status.success(),
        "{}",
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(String::from_utf8_lossy(&human.stdout).contains("unknown -> unprotected"));
    let inventory = Inventory::open_read_only_bound(&scene.inventory()).unwrap();
    assert_eq!(inventory.schema_version().unwrap(), 6);
    assert_eq!(inventory.protection(id).unwrap(), Some(false));
    let events = inventory.audit_events().unwrap();
    let artifact = inventory.artifact(id).unwrap();
    drop(inventory);
    let conn = rusqlite::Connection::open(scene.inventory()).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse_protection BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    drop(conn);
    error(
        scene.run(&["backup", "protect", &id.to_string()]),
        "RETENTION_INVENTORY_INVALID",
    );
    let inventory = Inventory::open_read_only_bound(&scene.inventory()).unwrap();
    assert_eq!(inventory.protection(id).unwrap(), Some(false));
    assert_eq!(inventory.audit_events().unwrap(), events);
    assert_eq!(inventory.artifact(id).unwrap(), artifact);
}
