use backup_inventory::{INVENTORY_FILE, JobGuard, JobScope};
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
        Command::new(env!("CARGO_BIN_EXE_backupctl"))
            .args([
                "--config",
                self.0.join("config.toml").to_str().unwrap(),
                "--output",
                "json",
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
    assert_eq!(current["job"]["operation"], Value::Null);
    assert_eq!(current["job"]["source_fingerprint"], SOURCE);
    let check = json(scene.run(&["inventory", "check"]));
    assert_eq!(check["valid"], true);
    assert_eq!(check["schema_version"], 2);
    assert_eq!(check["audit_recorded"], false);
    error(
        scene.run(&["job", "inspect", &Uuid::new_v4().to_string()]),
        "JOB_NOT_FOUND",
    );
    assert_eq!(before, fs::read(scene.inventory()).unwrap());
    assert!(!scene.root().join("inventory.db-journal").exists());
    let copy = Scene::new();
    fs::create_dir_all(copy.root()).unwrap();
    fs::copy(scene.inventory(), copy.inventory()).unwrap();
    fs::set_permissions(copy.inventory(), fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(copy.root(), fs::Permissions::from_mode(0o500)).unwrap();
    assert_eq!(json(copy.run(&["inventory", "check"]))["valid"], true);
    assert_eq!(
        json(copy.run(&["job", "inspect", &running_id.to_string()]))["job"]["state"],
        "running"
    );
    assert_eq!(before, fs::read(copy.inventory()).unwrap());
    assert_eq!(fs::read_dir(copy.root()).unwrap().count(), 1);
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
    conn.pragma_update(None, "user_version", 3).unwrap();
    drop(conn);
    error(scene.run(&["inventory", "check"]), "INVENTORY_OPEN_FAILED");
}
