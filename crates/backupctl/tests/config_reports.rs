//! Full-process input/authorization/report checks. No PostgreSQL, tools or keys are
//! available in these scenes: an accidental eager open must fail the positive controls.
use backup_inventory::{Estate, Inventory, JobGuard, JobScope};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Output};
use uuid::Uuid;

const SOURCE: &str = "0123456789abcdef";
const ID: &str = "72d41dd6-27e6-4eee-89a1-633ed978ee73";
struct Scene(PathBuf);
impl Scene {
    fn new() -> Self {
        // Versioned config deliberately refuses world/group-writable ancestry. Tests
        // need a protected service home, not a global temporary directory.
        let home = PathBuf::from(std::env::var_os("HOME").expect("protected service HOME"));
        let root = home.join(format!(".backupctl-h02-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn root(&self) -> PathBuf {
        self.0.join("store")
    }
    fn config(&self) -> PathBuf {
        self.0.join("config.toml")
    }
    fn write(&self, content: &str) {
        fs::write(self.config(), content).unwrap();
        fs::set_permissions(self.config(), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn v1(&self, role: &str, read_only: bool, production: bool) -> String {
        let mut text = format!(
            "config_version = 1\nmode = \"{}\"\naccess = \"{role}\"\nread_only = {read_only}\n[storage]\nroot = {:?}\n",
            if production { "production" } else { "fixture" },
            self.root()
        );
        if role == "reader" || role == "writer" {
            text += &format!(
                "[encryption]\nidentity_file = {:?}\n",
                self.0.join("missing-parent/identity")
            );
            if role == "writer" {
                text += &format!(
                    "recipient_file = {:?}\n",
                    self.0.join("missing-parent/recipient")
                );
            }
        }
        if role != "inventory" {
            text += &format!(
                "[signing]\nverifying_key_file = {:?}\n",
                self.0.join("missing-parent/verifier")
            );
            if role == "writer" {
                text += &format!(
                    "signing_key_file = {:?}\n",
                    self.0.join("missing-parent/signer")
                );
            }
        }
        text
    }
    fn run(&self, output: &str, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_backupctl"))
            .arg("--config")
            .arg(self.config())
            .args(["--output", output])
            .args(args)
            .output()
            .unwrap()
    }
    fn envelope(&self, args: &[&str], code: Option<&str>) -> Value {
        let output = self.run("json-v1", args);
        assert_eq!(
            output.status.code(),
            Some(if code.is_some() { 1 } else { 0 }),
            "stderr={} stdout={}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let mut fields: Vec<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort();
        assert_eq!(fields, ["data", "error", "format", "operation", "status"]);
        assert_eq!(value["format"], "backupctl-cli-report-v1");
        if let Some(code) = code {
            assert_eq!(value["error"]["code"], code, "{value}");
            assert!(value["error"]["message"].as_str().unwrap().len() <= 512);
            assert_eq!(value["status"], "error");
        } else {
            assert!(value["error"].is_null());
            assert_eq!(value["status"], "ok");
        }
        value
    }
}
impl Drop for Scene {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn commands() -> Vec<Vec<&'static str>> {
    vec![
        vec!["key", "generate"],
        vec!["key", "publish"],
        vec!["key", "status"],
        vec!["profile", "list"],
        vec!["profile", "validate", "app"],
        vec!["backup", "create", "--confirm-synthetic"],
        vec!["backup", "create", "--dry-run"],
        vec!["backup", "list"],
        vec!["backup", "inspect", ID],
        vec!["backup", "verify", ID, "--level", "signature"],
        vec!["backup", "verify", ID, "--level", "checksum", "--read-only"],
        vec!["backup", "verify", ID],
        vec!["backup", "protect", ID],
        vec!["backup", "unprotect", ID],
        vec!["backup", "prune", "--keep-last", "1"],
        vec!["backup", "prune", "run", ID, "--confirm-digest", "bad"],
        vec!["backup", "delete", ID],
        vec!["backup", "delete", "run", ID, "--confirm-digest", "bad"],
        vec![
            "restore",
            "plan",
            ID,
            "--target",
            "backupctl_fixture_target",
        ],
        vec![
            "restore",
            "run",
            ID,
            "--confirm-target",
            "backupctl_fixture_target",
        ],
        vec!["job", "list"],
        vec!["job", "inspect", ID],
        vec!["inventory", "check"],
        vec!["inventory", "list"],
        vec!["inventory", "verification", ID],
        vec!["inventory", "reconcile"],
        vec!["inventory", "recover"],
        vec!["inventory", "adopt", ID, "--source-fingerprint", SOURCE],
        vec![
            "inventory",
            "rebuild",
            "--source-fingerprint",
            SOURCE,
            "--dry-run",
        ],
        vec![
            "inventory",
            "rebuild",
            "--source-fingerprint",
            SOURCE,
            "--prepare-rebuild",
        ],
        vec![
            "inventory",
            "rebuild",
            "--source-fingerprint",
            SOURCE,
            "--confirm-rebuild",
            "--plan-id",
            ID,
        ],
    ]
}

#[test]
fn production_checks_all_custody_roles_but_every_other_command_is_gated() {
    let scene = Scene::new();
    for (role, read_only) in [
        ("writer", false),
        ("reader", false),
        ("reader", true),
        ("public", true),
        ("inventory", false),
        ("inventory", true),
    ] {
        scene.write(&scene.v1(role, read_only, true));
        let checked = scene.envelope(&["config", "check"], None);
        assert_eq!(
            checked["data"],
            json!({"valid":true,"config_version":1,"mode":"production","access":role,"read_only":read_only,"production_enabled":false})
        );
        for args in commands() {
            scene.envelope(&args, Some("PRODUCTION_NOT_ENABLED"));
        }
        let old = scene.run("json", &["config", "check"]);
        assert_eq!(old.status.code(), Some(1));
        assert!(old.stdout.is_empty());
        assert!(String::from_utf8_lossy(&old.stderr).contains("OUTPUT_FORMAT_UNSUPPORTED"));
        assert!(!scene.root().exists());
        assert_eq!(fs::read_dir(&scene.0).unwrap().count(), 1);
    }
}

#[test]
fn fixture_custody_read_only_and_availability_refuse_before_any_resource_open() {
    let scene = Scene::new();
    for (role, read_only) in [
        ("writer", false),
        ("reader", false),
        ("reader", true),
        ("public", true),
        ("inventory", false),
        ("inventory", true),
    ] {
        scene.write(&scene.v1(role, read_only, false));
        scene.envelope(&["config", "check"], None);
        for args in commands() {
            let private = role == "writer" || role == "reader";
            let maintenance = role != "public";
            let native = matches!(
                (args[0], args[1]),
                ("backup", "create") | ("profile", "validate") | ("restore", _)
            );
            let allowed = match (args[0], args[1]) {
                ("key", "status") | ("job", _) => true,
                ("key", _) => role == "writer",
                ("profile", _) | ("restore", _) => private,
                ("inventory", "check" | "list" | "verification") => true,
                ("inventory", _) | ("backup", "protect" | "unprotect") => maintenance,
                ("backup", "create") => role == "writer",
                ("backup", "list") => role != "inventory",
                ("backup", "verify") if args.contains(&"signature") => role != "inventory",
                ("backup", _) => private,
                _ => unreachable!(),
            };
            let snapshot = matches!(
                (args[0], args[1]),
                ("key", "status")
                    | ("profile", "list")
                    | ("job", _)
                    | ("inventory", "check" | "list" | "verification")
                    | ("backup", "list" | "inspect" | "verify")
            );
            if !allowed {
                scene.envelope(&args, Some("ACCESS_DENIED"));
            } else if read_only && !snapshot {
                scene.envelope(&args, Some("READ_ONLY"));
            } else if args == ["profile", "list"] {
                scene.envelope(&args, None);
            } else if args == ["key", "status"] && role == "inventory" {
                assert_eq!(scene.envelope(&args, None)["data"], json!({"keys":[]}));
            } else if args[0] == "key" {
                // New protected key commands require existing safe parent directories;
                // no missing material is invented or opened through the store.
                scene.envelope(&args, Some("KEY_UNSAFE"));
            } else if native && !read_only {
                scene.envelope(&args, Some("CONFIG_INVALID"));
            } else if read_only {
                scene.envelope(&args, Some("FILESYSTEM_UNSAFE"));
            } else if args[0] == "key"
                || matches!(args[1], "list" | "inspect" | "verify" | "prune" | "delete")
                    && args[0] == "backup"
            {
                scene.envelope(
                    &args,
                    Some(if args[1] == "list" {
                        "FILESYSTEM_UNSAFE"
                    } else {
                        "KEY_UNSAFE"
                    }),
                );
            }
            // Writable keyless commands are exercised separately with a real inventory.
        }
        assert!(!scene.root().exists());
        assert_eq!(fs::read_dir(&scene.0).unwrap().count(), 1);
    }
}

#[test]
fn writable_keyless_inventory_works_without_source_tools_or_configured_keys() {
    let scene = Scene::new();
    fs::create_dir(scene.root()).unwrap();
    fs::set_permissions(scene.root(), fs::Permissions::from_mode(0o700)).unwrap();
    let job = JobGuard::begin(
        &scene.root(),
        &JobScope {
            source_fingerprint: SOURCE.into(),
            profile_fingerprint: "fedcba9876543210".into(),
            backup_id: Uuid::new_v4(),
        },
    )
    .unwrap();
    let job_id = job.id();
    job.complete().unwrap();
    drop(job);
    for (role, snapshot) in [
        ("writer", false),
        ("reader", false),
        ("inventory", false),
        ("reader", true),
        ("public", true),
        ("inventory", true),
    ] {
        scene.write(&scene.v1(role, snapshot, false));
        let before = fs::read(scene.root().join("inventory.db")).unwrap();
        let check = scene.envelope(&["inventory", "check"], None);
        assert_eq!(check["data"]["valid"], true);
        assert_eq!(
            scene.envelope(&["job", "inspect", &job_id.to_string()], None)["data"]["job"]["state"],
            "complete"
        );
        assert_eq!(fs::read(scene.root().join("inventory.db")).unwrap(), before);
        assert!(!scene.0.join("missing-identity").exists());
    }
}

#[test]
fn legacy_success_data_is_preserved_inside_the_new_envelope() {
    let scene = Scene::new();
    let config = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/m1.example.toml");
    scene.write(&fs::read_to_string(config).unwrap());
    for args in [vec!["config", "check"], vec!["profile", "list"]] {
        let bare = scene.run("json", &args);
        assert!(bare.status.success());
        let bare: Value = serde_json::from_slice(&bare.stdout).unwrap();
        let envelope = scene.envelope(&args, None);
        assert_eq!(bare, envelope["data"]);
    }
}

#[test]
fn versioned_schema_is_closed_and_does_not_infer_mode_or_custody() {
    let scene = Scene::new();
    let base = scene.v1("inventory", false, false);
    let cases = [
        base.replace("config_version = 1\n", ""),
        base.replace("mode = \"fixture\"\n", ""),
        base.replace("read_only = false\n", ""),
        base.replace("config_version = 1", "config_version = \"1\""),
        format!("{base}extra = 1\n"),
        format!("{base}root = \"/extra\"\n"),
        base.replace("access = \"inventory\"", "access = \"unknown\""),
        base.replace("read_only = false", "read_only = false\nread_only = true"),
        base.replace("[storage]", "[storage]\nextra = 1"),
        base.replace("/store\"", "/../store\""),
    ];
    for text in cases {
        scene.write(&text);
        scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    }
    scene.write(&base.replace("config_version = 1", "config_version = 2"));
    scene.envelope(&["config", "check"], Some("CONFIG_VERSION_UNSUPPORTED"));
    for (role, read_only) in [("writer", true), ("public", false)] {
        scene.write(&scene.v1(role, read_only, false));
        scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    }
    let reader = scene.v1("reader", false, false);
    scene.write(&format!("{reader}signing_key_file = \"/missing-signer\"\n"));
    scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    scene.write(&format!(
        "{base}[encryption]\nidentity_file = \"/identity\"\n"
    ));
    scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    assert!(!scene.root().exists());
}

#[test]
fn local_auth_names_and_profile_checks_preserve_signed_fixture_guards() {
    let scene = Scene::new();
    let base = scene.v1("writer", false, false);
    let source = "[source]\nhost = \"/run/postgresql\"\nport = 5432\nuser = \"backup_user\"\ndatabase = \"backupctl_fixture_h02\"\nmaintenance_database = \"postgres\"\nauth = \"peer\"\n[tools]\nclient_bin_dir = \"/missing-tools\"\n[[profile]]\nname = \"app\"\ndatabase = \"backupctl_fixture_h02\"\nschemas = [\"app\"]\n";
    let valid = format!("{base}{source}");
    scene.write(&valid);
    scene.envelope(&["config", "check"], None);
    assert_eq!(
        scene.envelope(&["profile", "list"], None)["data"][0]["name"],
        "app"
    );
    for (from, to) in [
        ("/run/postgresql", "localhost"),
        ("/run/postgresql", "db.example.invalid"),
        ("backup_user", "postgresql://SECRET_SENTINEL"),
        ("backupctl_fixture_h02", "application_db"),
        ("5432", "0"),
        (
            "auth = \"peer\"",
            "auth = \"peer\"\npassword_file = \"/pass\"",
        ),
        ("name = \"app\"", "name = \"whole-database\""),
        ("schemas = [\"app\"]", "schemas = [\"app*\"]"),
        ("[tools]", "client_bin_dir = \"/legacy\"\n[tools]"),
    ] {
        scene.write(&valid.replace(from, to));
        scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    }
    let tcp = valid.replace("/run/postgresql", "127.0.0.1").replace(
        "auth = \"peer\"",
        "auth = \"scram-passfile\"\npassword_file = \"/missing-pass\"",
    );
    scene.write(&tcp);
    scene.envelope(&["config", "check"], None);
    scene.write(&tcp.replace("password_file = \"/missing-pass\"\n", ""));
    scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    let production = valid
        .replace("mode = \"fixture\"", "mode = \"production\"")
        .replace("backupctl_fixture_h02", "application_db");
    scene.write(&production);
    scene.envelope(&["config", "check"], None);
    scene.write(&format!("{production}mode = \"data-only\"\n"));
    scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    let profile: backup_domain::Profile =
        serde_json::from_value(json!({"name":"app","database":"application_db"})).unwrap();
    assert!(
        profile.validate().is_err(),
        "frozen signed reader must retain fixture guard"
    );
    assert!(!scene.root().exists());
}

#[test]
fn config_file_boundaries_refuse_unsafe_inputs_without_snippets_or_blocking() {
    let scene = Scene::new();
    let valid = scene.v1("inventory", false, false);
    scene.write(&valid);
    fs::set_permissions(scene.config(), fs::Permissions::from_mode(0o644)).unwrap();
    scene.envelope(&["config", "check"], Some("CREDENTIAL_UNSAFE"));
    scene.write(&valid);
    fs::set_permissions(&scene.0, fs::Permissions::from_mode(0o770)).unwrap();
    scene.envelope(&["config", "check"], Some("CREDENTIAL_UNSAFE"));
    fs::set_permissions(&scene.0, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(scene.config(), scene.0.join("real.toml")).unwrap();
    symlink(scene.0.join("real.toml"), scene.config()).unwrap();
    scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    fs::remove_file(scene.config()).unwrap();
    let name = std::ffi::CString::new(scene.config().as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: valid pathname; creates only this scene's disposable FIFO.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    fs::remove_file(scene.config()).unwrap();
    scene.write(&"SENSITIVE_SENTINEL".repeat(5000));
    scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    scene.write("secret = \"SENSITIVE_SENTINEL\"\ninvalid = [");
    let output = scene.run("json-v1", &["config", "check"]);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SENSITIVE_SENTINEL"));
    assert!(output.stderr.is_empty());
    assert!(!scene.root().exists());
}

#[test]
fn parsed_runtime_errors_have_an_envelope_but_clap_errors_keep_exit_two() {
    let output = Command::new(env!("CARGO_BIN_EXE_backupctl"))
        .args(["--output", "json-v1", "config", "check"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "CONFIG_INVALID");
    for args in [
        vec!["--output", "json-v1", "backup", "inspect", "not-a-uuid"],
        vec!["--output", "bad", "config", "check"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_backupctl"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn versioned_inventory_maintenance_and_protection_use_the_existing_keyless_services() {
    let scene = Scene::new();
    scene.write(&scene.v1("inventory", false, false));
    let id = Uuid::new_v4();
    let dir = scene.root().join("artifacts").join(id.to_string());
    fs::create_dir_all(&dir).unwrap();
    for path in [scene.root(), scene.root().join("artifacts"), dir.clone()] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(dir.join("complete"), []).unwrap();
    fs::write(dir.join("payload.dump"), b"abc").unwrap();
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec(&json!({
            "format":"m1-development-plaintext","id":id,"synthetic_only":true,
            "database":"backupctl_fixture_h02","source_major":16,"source_version":"16",
            "dump_client_version":"16","application_version":"test","archive_format":"custom",
            "compression":"gzip","created_unix_ms":1,"size_bytes":3,
            "sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "status":"complete","security_globals":false
        }))
        .unwrap(),
    )
    .unwrap();
    drop(
        Inventory::open(
            &scene.root().join("inventory.db"),
            &Estate::new(SOURCE.into()).unwrap(),
        )
        .unwrap(),
    );
    scene.envelope(
        &[
            "inventory",
            "adopt",
            &id.to_string(),
            "--source-fingerprint",
            SOURCE,
        ],
        None,
    );
    let protect = scene.envelope(&["backup", "protect", &id.to_string()], None);
    assert_eq!(protect["data"]["protection"], "protected");
    assert_eq!(protect["data"]["audit_recorded"], true);
    assert_eq!(
        scene.envelope(&["backup", "unprotect", &id.to_string()], None)["data"]["protection"],
        "unprotected"
    );
    scene.envelope(&["inventory", "reconcile"], None);
    scene.envelope(
        &[
            "inventory",
            "rebuild",
            "--source-fingerprint",
            SOURCE,
            "--dry-run",
        ],
        None,
    );
    scene.envelope(&["inventory", "recover"], None);
    let abandoned = scene
        .root()
        .join("scratch")
        .join(Uuid::new_v4().to_string());
    fs::create_dir(&abandoned).unwrap();
    fs::write(abandoned.join("plaintext"), b"synthetic leftover").unwrap();
    let recovered = scene.envelope(&["inventory", "recover"], None);
    assert_eq!(recovered["data"]["removed"], json!([abandoned]));
    let prepared = scene.envelope(
        &[
            "inventory",
            "rebuild",
            "--source-fingerprint",
            SOURCE,
            "--prepare-rebuild",
        ],
        None,
    );
    let plan_id = prepared["data"]["plan_id"].as_str().unwrap();
    let rebuilt = scene.envelope(
        &[
            "inventory",
            "rebuild",
            "--source-fingerprint",
            SOURCE,
            "--confirm-rebuild",
            "--plan-id",
            plan_id,
        ],
        None,
    );
    let previous = PathBuf::from(rebuilt["data"]["previous_inventory"].as_str().unwrap());
    assert_eq!(previous.parent(), Some(scene.root().as_path()));
    assert!(previous.is_file());
    scene.envelope(&["inventory", "check"], None);
    assert_eq!(fs::read(dir.join("payload.dump")).unwrap(), b"abc");
}

#[test]
fn versioned_resources_are_structural_and_filesystem_refusals_are_safe() {
    let scene = Scene::new();
    let base = scene.v1("inventory", false, false);
    for resource in [
        "max_payload_bytes = 0",
        "max_globals_bytes = 8388609",
        "max_stage_bytes = 0",
        "max_scratch_bytes = 0",
        "min_free_bytes = 1048575",
        "min_free_bytes = 1099511627777",
        "unknown = 1",
        "max_payload_bytes = 18446744073709551616",
    ] {
        scene.write(&format!("{base}[resources]\n{resource}\n"));
        scene.envelope(&["config", "check"], Some("CONFIG_INVALID"));
    }
    scene.write(&format!("{base}[resources]\nmax_payload_bytes = 1\n"));
    scene.envelope(&["config", "check"], None);
    assert!(!scene.root().exists());
    fs::create_dir(scene.root()).unwrap();
    fs::set_permissions(scene.root(), fs::Permissions::from_mode(0o750)).unwrap();
    scene.envelope(&["inventory", "check"], Some("FILESYSTEM_UNSAFE"));
    assert_eq!(fs::read_dir(scene.root()).unwrap().count(), 0);
    fs::set_permissions(scene.root(), fs::Permissions::from_mode(0o700)).unwrap();
    symlink(scene.0.join("absent"), scene.root().join("inventory.db")).unwrap();
    scene.envelope(&["inventory", "recover"], Some("FILESYSTEM_UNSAFE"));
    assert!(!scene.0.join("absent").exists());
    assert_eq!(fs::read_dir(scene.root()).unwrap().count(), 1);
}

#[test]
fn writable_discovery_needs_no_keys_tools_source_and_never_recovers_work() {
    let scene = Scene::new();
    fs::create_dir(scene.root()).unwrap();
    fs::set_permissions(scene.root(), fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = scene.root().join("scratch");
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    let abandoned = scratch.join(Uuid::new_v4().to_string());
    fs::create_dir(&abandoned).unwrap();
    fs::write(abandoned.join("sentinel"), b"owned work retained").unwrap();
    for role in ["reader", "writer"] {
        scene.write(&scene.v1(role, false, false));
        let listing = scene.envelope(&["backup", "list"], None);
        assert_eq!(listing["data"]["signed"], json!([]));
        assert_eq!(
            fs::read(abandoned.join("sentinel")).unwrap(),
            b"owned work retained"
        );
    }
    fs::rename(&scratch, scene.0.join("saved-scratch")).unwrap();
    symlink(scene.0.join("saved-scratch"), &scratch).unwrap();
    scene.envelope(&["backup", "list"], Some("FILESYSTEM_UNSAFE"));
}
