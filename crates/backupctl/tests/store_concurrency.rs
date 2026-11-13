//! Two real `backupctl` processes on one storage root, with the first one's working
//! directories examined while it is still using them.
//!
//! Every other concurrency test here calls a store or a guard from inside a single process.
//! These exist because the defect phase S closes was in *process startup*: constructing a store
//! emptied `staging/` and `scratch/` before any lock was taken, so any second command — including
//! the read-only `backup list` — removed files the first command was writing or reading, and a
//! duplicate `backup create` destroyed the very dump whose scope lock refused it. One process
//! cannot show that, because the purge ran before either command had claimed anything.
//!
//! What holds in their place is ADR 0004's ownership rule, seen from outside the tool: opening a
//! store removes nothing, an operation that uses a working directory holds the store's activity
//! claim for as long as the directory exists, and only a maintenance pass that won that claim
//! exclusively deletes — which is why the last scene here kills a dump and checks what the next
//! `backup create` does with the leftovers.
//!
//! The PostgreSQL tools are shell scripts in the configured `client_bin_dir`, which is the
//! boundary the adapter was built around, so the real command line runs end to end without a
//! cluster. The scripts are also the synchronization: a dump announces that its staged payload
//! is complete and then stops until the test releases it. Nothing here waits a guessed amount of
//! time — every step waits for the file that proves the state it is about to assert on.

use backup_inventory::{INVENTORY_FILE, Inventory, JobLock, JobRow, JobState};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// One line of the fake archive. `echo` is a shell builtin, so the tool's whole output needs
/// no external command and no environment: the adapter clears it.
const ARCHIVE_LINE: &str = "PGDMP-synthetic-staging-bytes";
const ARCHIVE_LINES: usize = 64;
/// The bytes a finished dump is expected to have staged, counting the newline each line adds.
const ARCHIVE_BYTES: u64 = (ARCHIVE_LINE.len() as u64 + 1) * ARCHIVE_LINES as u64;
/// How long a paused tool waits for the test before giving up. The scene's own commands release
/// within a second, so this only ever fires when a test panicked mid-scene; it stays well inside
/// the configured `timeout_seconds` so the tool's exit, not the CLI's watchdog, ends the run.
const RELEASE_POLLS: usize = 600;

/// A storage root, a `client_bin_dir` of shell scripts, and one configuration pointing at both.
struct Scene {
    base: PathBuf,
    root: PathBuf,
    config: PathBuf,
}

impl Scene {
    /// Builds the scene and, when asked for an encrypted store, generates its key files with the
    /// real `key generate`: which key files a store will open is that command's business, not a
    /// test's guess.
    ///
    /// `pause_dump` leaves the `pause-dump` marker in place, so the scene's first dump stops with
    /// its payload staged. A scene that later removes it gets an ordinary, completing dump.
    fn new(label: &str, encrypted: bool, pause_dump: bool) -> Self {
        require_pause_command();
        let base = std::env::temp_dir().join(format!("backupctl-s01-{label}-{}", Uuid::new_v4()));
        let bin = base.join("bin");
        let root = base.join("store");
        let config = base.join("config.toml");
        fs::create_dir_all(&bin).unwrap();
        write_tool(&bin, "psql", &psql_script());
        write_tool(&bin, "pg_dump", &dump_script(&base));
        write_tool(&bin, "pg_restore", &restore_script(&base));
        write_tool(&bin, "pg_dumpall", &refusing_script("pg_dumpall"));
        write_tool(&bin, "createdb", &refusing_script("createdb"));
        if pause_dump {
            fs::write(base.join("pause-dump"), b"").unwrap();
        }
        let keys = base.join("keys");
        let mut toml = format!(
            "export_globals = false\ntimeout_seconds = 120\n\n[source]\nhost = \"127.0.0.1\"\nport = 5432\nuser = \"postgres\"\ndatabase = \"backupctl_fixture_s01\"\nclient_bin_dir = \"{}\"\n\n[storage]\nroot = \"{}\"\n",
            bin.display(),
            root.display()
        );
        if encrypted {
            toml.push_str(&format!(
                "\n[encryption]\nidentity_file = \"{}/identity.key\"\nrecipient_file = \"{}/recipient.key\"\n",
                keys.display(),
                keys.display()
            ));
        }
        fs::write(&config, toml).unwrap();
        let scene = Self { base, root, config };
        if encrypted {
            let generated = scene.run(&["key", "generate"]);
            assert!(
                generated.status.success(),
                "`key generate` failed: {}",
                text(&generated)
            );
        }
        scene
    }

    fn marker(&self, name: &str) -> PathBuf {
        self.base.join(name)
    }

    /// One command line from this scene's configuration, with its output kept for the message
    /// an assertion quotes.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_backupctl"))
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .output()
            .expect("run backupctl")
    }

    /// The same command line as a live second process, with no pipe left for it to fill: what
    /// these scenes observe is what it does to the store while it runs, not what it prints.
    fn spawn(&self, args: &[&str]) -> Child {
        Command::new(env!("CARGO_BIN_EXE_backupctl"))
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn backupctl")
    }

    fn staging(&self) -> PathBuf {
        self.root.join("staging")
    }

    fn scratch(&self) -> PathBuf {
        self.root.join("scratch")
    }

    fn artifacts(&self) -> PathBuf {
        self.root.join("artifacts")
    }

    /// Ends every paused tool. Also happens on unwind, because a test that failed mid-scene must
    /// not leave a client tool spinning until its own deadline.
    fn release(&self) {
        fs::write(self.marker("release"), b"").unwrap();
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        self.release();
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// `/bin/sleep` is how a paused tool waits without burning a core. Rather than degrade into a
/// spin that changes what the scene measures, the scene states the dependency.
fn require_pause_command() {
    assert!(
        Path::new("/bin/sleep").is_file(),
        "these scenes pause a client tool with /bin/sleep; none is present on this host"
    );
}

fn write_tool(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The wait a paused tool loops in, as shell text. The tool stops at its own deadline if the
/// test never releases it, so a broken scene fails instead of hanging the suite.
fn release_loop() -> String {
    format!(
        "i=0\nwhile [ ! -f \"$RELEASE\" ]; do\n  i=$((i + 1))\n  if [ $i -gt {RELEASE_POLLS} ]; then exit 1; fi\n  /bin/sleep 0.05\ndone\n"
    )
}

/// The two catalog probes the whole-database path makes: the server version and the large object
/// count. Anything else is a query this scene never expected, and answered with nothing.
fn psql_script() -> String {
    "\
if [ \"$1\" = \"--version\" ]; then echo 'psql (PostgreSQL) 16.4'; exit 0; fi
for argument in \"$@\"; do
  case \"$argument\" in
    --command=*) query=${argument#--command=} ;;
  esac
done
case \"$query\" in
  'SHOW server_version_num') echo 160004; exit 0 ;;
  *pg_largeobject_metadata*) echo 0; exit 0 ;;
esac
exit 1
"
    .to_string()
}

/// Writes the archive to standard output, as `pg_dump` does when given no `--file`, and pauses with
/// it already staged while the scene's `pause-dump` marker exists. The marker is a file rather than
/// a built-in flag because one scene needs two dumps: the first held mid-write, the second run to
/// completion by the command that recovers from it.
fn dump_script(base: &Path) -> String {
    format!(
        "STARTED='{}'\nRELEASE='{}'\nPAUSE='{}'\nif [ \"$1\" = \"--version\" ]; then echo 'pg_dump (PostgreSQL) 16.4'; exit 0; fi\ni=0\nwhile [ $i -lt {ARCHIVE_LINES} ]; do\n  echo '{ARCHIVE_LINE}'\n  i=$((i + 1))\ndone\nif [ -f \"$PAUSE\" ]; then\n  : > \"$STARTED\"\n  {}fi\n",
        base.join("dump-started").display(),
        base.join("release").display(),
        base.join("pause-dump").display(),
        release_loop(),
    )
}

/// The table-of-contents listing. Pausing is switched on by the test writing `pause-toc`, because
/// a dump inspects its own staged archive too, and only the read that follows a decrypt is the
/// one that has to be in progress when the second command arrives.
fn restore_script(base: &Path) -> String {
    format!(
        "STARTED='{}'\nRELEASE='{}'\nPAUSE='{}'\nif [ \"$1\" = \"--version\" ]; then echo 'pg_restore (PostgreSQL) 16.4'; exit 0; fi\nif [ -f \"$PAUSE\" ]; then\n  : > \"$STARTED\"\n  {}fi\necho 'Table public.accounts'\n",
        base.join("toc-started").display(),
        base.join("release").display(),
        base.join("pause-toc").display(),
        release_loop(),
    )
}

/// A tool these scenes never reach: it answers the version probe that every backup runs and
/// refuses anything else, so an unexpected call fails visibly.
fn refusing_script(name: &str) -> String {
    format!(
        "if [ \"$1\" = \"--version\" ]; then echo '{name} (PostgreSQL) 16.4'; exit 0; fi\nexit 1\n"
    )
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    match fs::read_dir(dir) {
        Ok(read) => read
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .collect(),
        // A working directory that is gone entirely holds no entries, which is what the count
        // assertions below need to be able to say.
        Err(_) => Vec::new(),
    }
}

/// Waits for the file a paused tool writes to announce a state. This is the whole synchronization:
/// the scene proceeds once the fact is observable, never once a duration has passed.
fn wait_for(marker: &Path, context: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !marker.is_file() {
        if Instant::now() >= deadline {
            panic!("{context}: {} never appeared", marker.display());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Waits for the staged payload to hold everything the dump produced. The start marker only
/// proves the tool reached that line of its script; the size proves the store consumed the bytes
/// into the file a second command would go on to remove.
fn wait_for_bytes(path: &Path, context: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let size = fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
        if size == ARCHIVE_BYTES {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "{context}: {} holds {size} bytes, expected {}",
                path.display(),
                ARCHIVE_BYTES
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The one working directory a live command owns, before the competing command runs.
fn one_entry(dir: &Path, owner: &str) -> PathBuf {
    let found = entries(dir);
    assert_eq!(
        found.len(),
        1,
        "{} holds {} entries; expected the one belonging to {owner}",
        dir.display(),
        found.len()
    );
    found[0].clone()
}

/// `backup list` reads only published artifacts, so it is the plainest possible second command —
/// and it still removes the staging directory a backup is writing into.
#[test]
fn a_read_command_leaves_a_live_backups_staging_directory_alone() {
    let scene = Scene::new("staging-vs-list", false, true);
    let mut backup = scene.spawn(&["backup", "create", "--confirm-synthetic"]);
    wait_for(
        &scene.marker("dump-started"),
        "the dump never reported a staged payload",
    );
    let stage = one_entry(&scene.staging(), "the running backup");
    let payload = stage.join("payload.dump");
    wait_for_bytes(
        &payload,
        "the running backup never staged its whole archive",
    );

    let listing = scene.run(&["backup", "list"]);
    assert!(
        listing.status.success(),
        "`backup list` failed: {}",
        text(&listing)
    );

    assert!(
        stage.is_dir(),
        "`backup list` removed the staging directory {} while a backup was writing it",
        stage.display()
    );
    assert!(
        payload.is_file(),
        "`backup list` removed the staged payload {}",
        payload.display()
    );
    let kept = fs::read(&payload).unwrap();
    assert_eq!(
        kept,
        vec![ARCHIVE_LINE.to_string() + "\n"; ARCHIVE_LINES]
            .join("")
            .into_bytes(),
        "the staged payload changed while a read command ran"
    );

    scene.release();
    let finished = backup.wait().unwrap();
    assert!(
        finished.success(),
        "the backup whose staging directory a read command met exited {finished}"
    );
    let published = entries(&scene.artifacts());
    assert_eq!(
        published.len(),
        1,
        "the released backup published {} artifacts",
        published.len()
    );
    assert!(published[0].join("complete").is_file());
    assert!(
        entries(&scene.staging()).is_empty(),
        "staging still holds a finished backup's work"
    );
}

#[test]
fn reconciliation_refuses_while_a_backup_is_publishing() {
    let scene = Scene::new("reconcile-vs-backup", false, true);
    let mut backup = scene.spawn(&["backup", "create", "--confirm-synthetic"]);
    wait_for(
        &scene.marker("dump-started"),
        "backup did not reach its dump",
    );
    let stage = one_entry(&scene.staging(), "the running backup");
    let listing = scene.run(&["inventory", "list"]);
    assert!(listing.status.success(), "{}", text(&listing));
    let output = scene.run(&["inventory", "reconcile"]);
    assert!(
        !output.status.success(),
        "reconciliation must not race publication"
    );
    assert!(
        text(&output).contains("RECONCILE_BUSY"),
        "{}",
        text(&output)
    );
    assert!(stage.is_dir());
    scene.release();
    assert!(backup.wait().unwrap().success());
}

#[test]
fn restore_claims_survive_parent_death_while_native_restore_runs() {
    let scene = Scene::new("restore-ownership", false, false);
    let backup = scene.run(&["backup", "create", "--confirm-synthetic"]);
    assert!(backup.status.success(), "{}", text(&backup));
    let artifact = one_entry(&scene.artifacts(), "backup")
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let bin = scene.base.join("bin");
    write_tool(
        &bin,
        "psql",
        "if [ \"$1\" = \"--version\" ]; then echo 'psql (PostgreSQL) 16.4'; exit 0; fi\nfor argument in \"$@\"; do case \"$argument\" in --command=*) query=${argument#--command=} ;; esac; done\ncase \"$query\" in 'SHOW server_version_num') echo 160004; exit 0 ;; *pg_largeobject_metadata*) echo 0; exit 0 ;; *pg_database*) exit 0 ;; esac\nexit 1\n",
    );
    write_tool(
        &bin,
        "createdb",
        &format!(
            "if [ \"$1\" = \"--version\" ]; then echo 'createdb (PostgreSQL) 16.4'; exit 0; fi\nprintf x >> '{}'; exit 0\n",
            scene.marker("createdb-calls").display()
        ),
    );
    write_tool(
        &bin,
        "pg_restore",
        &format!(
            "if [ \"$1\" = \"--version\" ]; then echo 'pg_restore (PostgreSQL) 16.4'; exit 0; fi\nif [ \"$1\" = \"--list\" ]; then echo 'Table public.accounts'; exit 0; fi\nRELEASE='{}'\n: > '{}'\n{}",
            scene.marker("release").display(),
            scene.marker("restore-started").display(),
            release_loop()
        ),
    );
    let target = "backupctl_fixture_restore_a05";
    let plan = scene.run(&[
        "restore",
        "plan",
        &artifact,
        "--target",
        target,
        "--security",
        "portable",
    ]);
    assert!(plan.status.success(), "{}", text(&plan));
    let plan = one_entry(&scene.root.join("plans"), "restore plan")
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let mut first = scene.spawn(&["restore", "run", &plan, "--confirm-target", target]);
    wait_for(
        &scene.marker("restore-started"),
        "native restore never started",
    );
    let id = Uuid::parse_str(&artifact).unwrap();
    assert!(
        backup_inventory::ResourceLock::artifact(&scene.root, id, true)
            .unwrap()
            .is_none()
    );
    let duplicate = scene.run(&["restore", "run", &plan, "--confirm-target", target]);
    assert!(
        !duplicate.status.success() && text(&duplicate).contains("RESTORE_BUSY"),
        "{}",
        text(&duplicate)
    );
    assert_eq!(fs::read(scene.marker("createdb-calls")).unwrap(), b"x");
    let rows = job_rows(&scene);
    let restore_job = rows
        .iter()
        .find(|row| row.state == JobState::Running && row.backup_id == Some(id))
        .unwrap()
        .job_id;
    first.kill().unwrap();
    first.wait().unwrap();
    assert!(
        backup_inventory::ActivityLock::hold_maintenance(&scene.root)
            .unwrap()
            .is_none()
    );
    let duplicate = scene.run(&["restore", "run", &plan, "--confirm-target", target]);
    assert!(
        !duplicate.status.success() && text(&duplicate).contains("RESTORE_BUSY"),
        "{}",
        text(&duplicate)
    );
    assert_eq!(fs::read(scene.marker("createdb-calls")).unwrap(), b"x");
    assert!(
        backup_inventory::ResourceLock::artifact(&scene.root, id, true)
            .unwrap()
            .is_none()
    );
    let inventory = Inventory::open_bound(&scene.root.join(INVENTORY_FILE))
        .unwrap()
        .unwrap();
    assert!(inventory.sweep_interrupted(&scene.root).unwrap().is_empty());
    drop(inventory);
    scene.release();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if backup_inventory::ResourceLock::artifact(&scene.root, id, true)
            .unwrap()
            .is_some()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "native child retained artifact claim after exit"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let recovery = scene.run(&["backup", "create", "--confirm-synthetic"]);
    assert!(recovery.status.success(), "{}", text(&recovery));
    assert_eq!(
        job_rows(&scene)
            .iter()
            .find(|row| row.job_id == restore_job)
            .unwrap()
            .state,
        JobState::Interrupted
    );
    write_tool(
        &bin,
        "pg_restore",
        "if [ \"$1\" = \"--version\" ]; then echo 'pg_restore (PostgreSQL) 16.4'; exit 0; fi\nif [ \"$1\" = \"--list\" ]; then echo 'Table public.accounts'; exit 0; fi\nexit 1\n",
    );
    let failed = scene.run(&["restore", "run", &plan, "--confirm-target", target]);
    assert!(
        !failed.status.success() && text(&failed).contains("partially modified"),
        "{}",
        text(&failed)
    );
    assert_eq!(fs::read(scene.marker("createdb-calls")).unwrap(), b"xx");
    assert!(
        job_rows(&scene)
            .iter()
            .any(|row| row.backup_id == Some(id) && row.state == JobState::Failed)
    );
}

/// The duplicate backup is refused by the scope lock, and that refusal is the point of ADR 0003's
/// gate 9. The lock is still taken after the store opens, which is exactly where the startup purge
/// used to destroy the dump its own refusal protected: the duplicate ran its recovery pass before
/// losing the scope, and the live backup's shared activity claim is what stops that pass now.
/// Remove the scope lock and this scene fails on the refusal; let a maintenance claim succeed while
/// the store is busy and it fails on the survival.
#[test]
fn a_refused_duplicate_backup_leaves_a_live_backups_staging_directory_alone() {
    let scene = Scene::new("staging-vs-duplicate", false, true);
    let mut backup = scene.spawn(&["backup", "create", "--confirm-synthetic"]);
    wait_for(
        &scene.marker("dump-started"),
        "the dump never reported a staged payload",
    );
    let stage = one_entry(&scene.staging(), "the running backup");
    let payload = stage.join("payload.dump");
    wait_for_bytes(
        &payload,
        "the running backup never staged its whole archive",
    );

    let duplicate = scene.run(&["backup", "create", "--confirm-synthetic"]);
    let refusal = text(&duplicate);
    assert!(
        !duplicate.status.success(),
        "two backups of one scope ran at the same time: {refusal}"
    );
    assert!(
        refusal.contains("already running"),
        "the duplicate was refused for some reason other than the held scope: {refusal}"
    );

    assert!(
        stage.is_dir(),
        "a refused duplicate backup removed the staging directory {} of the backup it refused",
        stage.display()
    );
    assert!(
        payload.is_file(),
        "a refused duplicate backup removed the staged payload {}",
        payload.display()
    );

    scene.release();
    let finished = backup.wait().unwrap();
    assert!(
        finished.success(),
        "the backup a duplicate refused to run against exited {finished}"
    );
    assert_eq!(entries(&scene.artifacts()).len(), 1);
}

/// A verification decrypts into `scratch/` and hands the plaintext to `pg_restore`. The startup
/// purge that used to clear staging cleared that view out from under a tool that was reading it.
#[test]
fn a_read_command_leaves_a_live_verifications_scratch_directory_alone() {
    let scene = Scene::new("scratch-vs-list", true, false);
    let created = scene.run(&["backup", "create", "--confirm-synthetic"]);
    assert!(
        created.status.success(),
        "the fixture backup failed: {}",
        text(&created)
    );
    let published = entries(&scene.artifacts());
    assert_eq!(
        published.len(),
        1,
        "the fixture backup published {} artifacts",
        published.len()
    );
    let id = published[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    fs::write(scene.marker("pause-toc"), b"").unwrap();
    let mut verify = scene.spawn(&["backup", "verify", &id]);
    wait_for(
        &scene.marker("toc-started"),
        "the table-of-contents listing never started",
    );
    let view = one_entry(&scene.scratch(), "the running verification");
    let payload = view.join("payload.dump");
    assert_eq!(
        fs::read(&payload).unwrap().len() as u64,
        ARCHIVE_BYTES,
        "the scratch view of a running verification held something other than the whole archive"
    );

    let listing = scene.run(&["backup", "list"]);
    assert!(
        listing.status.success(),
        "`backup list` failed: {}",
        text(&listing)
    );
    assert!(
        view.is_dir(),
        "`backup list` removed the scratch directory {} while a verification was reading it",
        view.display()
    );
    assert!(
        payload.is_file(),
        "`backup list` removed the decrypted payload {}",
        payload.display()
    );

    scene.release();
    let finished = verify.wait().unwrap();
    assert!(
        finished.success(),
        "the verification whose scratch view a read command met exited {finished}"
    );
    assert!(
        entries(&scene.scratch()).is_empty(),
        "scratch still holds a finished verification's plaintext"
    );
}

/// The store's job rows, read the way the maintenance pass reads them: the estate comes off the
/// index itself, because recomputing it needs a live database to learn the server major and these
/// scenes have only shell scripts standing in for one.
fn job_rows(scene: &Scene) -> Vec<JobRow> {
    let inventory = Inventory::open_bound(&scene.root.join(INVENTORY_FILE))
        .unwrap()
        .expect("these scenes have run a backup, so the store has an index");
    inventory.jobs().unwrap()
}

/// A dump killed by `SIGKILL` runs no code on the way out: its staging directory stays where it
/// was, its job row stays `running`, and only the kernel gives back what it held. The next
/// `backup create` of the same scope is the command that finds out, and it has to find out *before*
/// claiming the scope — afterwards its own live row and the dead one are indistinguishable to a
/// lock probe, which is what ADR 0004's acquisition order is for.
#[test]
fn a_killed_backups_leftovers_are_recovered_by_the_next_backup_of_its_scope() {
    let scene = Scene::new("killed-then-restarted", false, true);
    let mut killed = scene.spawn(&["backup", "create", "--confirm-synthetic"]);
    wait_for(
        &scene.marker("dump-started"),
        "the dump never reported a staged payload",
    );
    let stage = one_entry(&scene.staging(), "the running backup");
    wait_for_bytes(
        &stage.join("payload.dump"),
        "the running backup never staged its whole archive",
    );
    let abandoned: Uuid = stage
        .file_name()
        .unwrap()
        .to_string_lossy()
        .parse()
        .unwrap();

    killed.kill().expect("kill the dump mid-write");
    let died = killed.wait().expect("reap the killed command");
    assert!(
        !died.success(),
        "a SIGKILLed backup ended successfully: {died}"
    );
    assert!(
        stage.is_dir(),
        "a killed process somehow cleaned up after itself"
    );
    let rows = job_rows(&scene);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].state, JobState::Running);
    assert_eq!(rows[0].backup_id, Some(abandoned));
    assert!(
        JobLock::is_free(
            &scene.root,
            &rows[0].source_fingerprint,
            &rows[0].profile_fingerprint
        )
        .unwrap(),
        "a killed process still held its scope lock"
    );

    fs::remove_file(scene.marker("pause-dump")).unwrap();
    let restarted = scene.run(&["backup", "create", "--confirm-synthetic"]);
    assert!(
        restarted.status.success(),
        "the backup that followed a killed one failed: {}",
        text(&restarted)
    );

    let rows = job_rows(&scene);
    assert_eq!(rows.len(), 2, "{rows:?}");
    let dead = rows
        .iter()
        .find(|row| row.backup_id == Some(abandoned))
        .expect("the killed job's row is gone from the index");
    assert_eq!(
        dead.state,
        JobState::Interrupted,
        "the next backup of the scope left a dead row claiming a dump is running; it reported: {}",
        text(&restarted)
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.state == JobState::Complete)
            .count(),
        1,
        "{rows:?}"
    );
    assert!(
        !stage.exists(),
        "the recovery pass left {} behind",
        stage.display()
    );
    assert!(
        entries(&scene.staging()).is_empty(),
        "staging still holds a directory after the recovery pass"
    );
    let published = entries(&scene.artifacts());
    assert_eq!(
        published.len(),
        1,
        "the killed dump left a published artifact behind, or the restart published nothing"
    );
    assert!(published[0].join("complete").is_file());
    assert_ne!(
        published[0].file_name().unwrap().to_string_lossy(),
        abandoned.to_string(),
        "the recovered backup republished the killed one's id"
    );
    // Both claims survived their holder: the scope lock file is still there, still unreleased
    // nothing, and the activity claim was not unlinked either.
    assert!(
        JobLock::path_for(
            &scene.root,
            &dead.source_fingerprint,
            &dead.profile_fingerprint
        )
        .is_file()
    );

    // And once is enough for each row: the next backup of the same scope runs against a clean
    // store, so it neither marks another job interrupted nor collects a leftover.
    let third = scene.run(&["backup", "create", "--confirm-synthetic"]);
    assert!(
        third.status.success(),
        "the third backup failed: {}",
        text(&third)
    );
    let rows = job_rows(&scene);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(
        rows.iter()
            .filter(|row| row.state == JobState::Interrupted)
            .count(),
        1,
        "{rows:?}"
    );
    assert_eq!(entries(&scene.artifacts()).len(), 2);
    assert!(entries(&scene.staging()).is_empty());
}

#[test]
fn retention_cli_previews_save_intent_without_keys_for_writing_or_native_tools() {
    let scene = signed_retention_scene("b03", 0);
    let keys = scene.base.join("keys");
    let ctl = |args: &[&str]| -> serde_json::Value {
        let mut flags = vec!["--output", "json"];
        flags.extend_from_slice(args);
        let output = scene.run(&flags);
        assert!(output.status.success(), "{}", text(&output));
        serde_json::from_slice(&output.stdout).unwrap()
    };
    for _ in 0..2 {
        let created = ctl(&["backup", "create", "--confirm-synthetic"]);
        let id = created["manifest"]["backup_id"].as_str().unwrap();
        ctl(&["backup", "verify", id, "--level", "archive"]);
    }
    let inventory = Inventory::open_read_only_bound(&scene.root.join(INVENTORY_FILE)).unwrap();
    let mut rows = inventory.artifacts().unwrap();
    rows.sort_by(|a, b| {
        b.completed_at_utc
            .cmp(&a.completed_at_utc)
            .then(a.backup_id.cmp(&b.backup_id))
    });
    let before = fs::read(scene.root.join(INVENTORY_FILE)).unwrap();
    fs::remove_file(keys.join("signing.key")).unwrap();
    fs::remove_file(keys.join("recipient.key")).unwrap();
    fs::rename(scene.base.join("bin"), scene.base.join("offline-bin")).unwrap();
    let preview = ctl(&["backup", "prune", "--keep-last", "1"]);
    assert_eq!(
        preview["candidates"],
        serde_json::json!([rows[1].backup_id])
    );
    assert_eq!(preview["retained"], serde_json::json!([rows[0].backup_id]));
    assert_eq!(preview["audit_recorded"], false);
    let mut fields = preview
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort();
    assert_eq!(
        fields,
        [
            "audit_recorded",
            "candidates",
            "digest",
            "excluded",
            "expires_unix_ms",
            "keep_last",
            "operation",
            "plan_id",
            "profile_fingerprint",
            "retained",
            "source_fingerprint"
        ]
    );
    assert!(
        scene
            .root
            .join("plans")
            .join(format!(
                "deletion-{}.json",
                preview["plan_id"].as_str().unwrap()
            ))
            .is_file()
    );
    let empty = ctl(&["backup", "prune", "--keep-last", "2"]);
    assert!(empty["plan_id"].is_null());
    assert!(empty["digest"].is_null());
    let delete = ctl(&["backup", "delete", &rows[0].backup_id.to_string()]);
    assert_eq!(delete["candidates"], serde_json::json!([rows[0].backup_id]));
    assert!(delete["keep_last"].is_null());
    let human = scene.run(&["backup", "prune", "--keep-last", "1"]);
    assert!(human.status.success(), "{}", text(&human));
    assert!(text(&human).contains("Local history only"));
    for args in [
        vec!["backup", "prune", "--keep-last", "0"],
        vec!["backup", "prune", "--keep-last", "-1"],
        vec!["backup", "prune", "--keep-last", "18446744073709551616"],
        vec!["backup", "delete", "run"],
        vec!["backup", "prune", "run"],
    ] {
        let output = scene.run(&args);
        assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    }
    let bad = scene.run(&["backup", "prune", "--keep-last", "1", "--profile", "absent"]);
    assert_eq!(bad.status.code(), Some(1));
    assert_eq!(before, fs::read(scene.root.join(INVENTORY_FILE)).unwrap());
    // Persisted stale open rows pin their exact dependency without an implicit sweep.
    let conn = rusqlite::Connection::open(scene.root.join(INVENTORY_FILE)).unwrap();
    let job = Uuid::new_v4().to_string();
    conn.execute("INSERT INTO job VALUES (?1,?2,?3,?4,'running','2026-11-13T00:00:00Z','2026-11-13T00:00:00Z')",rusqlite::params![job,rows[1].backup_id.to_string(),inventory.estate().source_fingerprint,rows[1].profile_fingerprint]).unwrap();
    conn.execute(
        "INSERT INTO job_operation VALUES (?1,'backup',NULL)",
        [&job],
    )
    .unwrap();
    let pinned = ctl(&["backup", "prune", "--keep-last", "1"]);
    assert_eq!(pinned["candidates"], serde_json::json!([]));
    assert!(
        pinned["excluded"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["reasons"] == serde_json::json!(["job_dependency"]))
    );
    let refusal = scene.run(&["backup", "delete", &rows[1].backup_id.to_string()]);
    assert!(text(&refusal).contains("RETENTION_JOB_DEPENDENCY"));
    conn.execute("DELETE FROM job_operation WHERE job_id=?1", [&job])
        .unwrap();
    let unknown = scene.run(&["backup", "prune", "--keep-last", "1"]);
    assert!(text(&unknown).contains("RETENTION_JOB_DEPENDENCY"));
    assert_eq!(
        inventory
            .job(Uuid::parse_str(&job).unwrap())
            .unwrap()
            .unwrap()
            .state,
        JobState::Running
    );
}

fn signed_retention_scene(label: &str, count: usize) -> Scene {
    let scene = Scene::new(label, false, false);
    let keys = scene.base.join("keys");
    let mut cfg = fs::read_to_string(&scene.config).unwrap();
    cfg.push_str(&format!("\n[encryption]\nidentity_file = '{0}/identity.key'\nrecipient_file = '{0}/recipient.key'\n[signing]\nsigning_key_file = '{0}/signing.key'\nverifying_key_file = '{0}/verifying.key'\n", keys.display()));
    fs::write(&scene.config, &cfg).unwrap();
    assert!(scene.run(&["key", "generate"]).status.success());

    for _ in 0..count {
        let created = ctl_json(&scene, &["backup", "create", "--confirm-synthetic"]);
        ctl_json(
            &scene,
            &[
                "backup",
                "verify",
                created["manifest"]["backup_id"].as_str().unwrap(),
                "--level",
                "archive",
            ],
        );
    }
    scene
}
fn ctl_json(scene: &Scene, args: &[&str]) -> serde_json::Value {
    let mut flags = vec!["--output", "json"];
    flags.extend_from_slice(args);
    let output = scene.run(&flags);
    assert!(output.status.success(), "{}", text(&output));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn confirmed_cli_run_and_repeated_receipt_preserve_json_contract_and_scope() {
    let scene = signed_retention_scene("b04-complete", 4);
    let preview = ctl_json(&scene, &["backup", "prune", "--keep-last", "2"]);
    let id = preview["plan_id"].as_str().unwrap();
    let digest = preview["digest"].as_str().unwrap();
    let index = scene.root.join(INVENTORY_FILE);
    let before = fs::read(&index).unwrap();
    let wrong = scene.run(&[
        "--output",
        "json",
        "backup",
        "prune",
        "run",
        id,
        "--confirm-digest",
        &digest[..16],
    ]);
    assert_eq!(wrong.status.code(), Some(1));
    assert!(wrong.stdout.is_empty());
    assert!(text(&wrong).contains("RETENTION_CONFIRMATION_MISMATCH"));
    assert_eq!(fs::read(&index).unwrap(), before);
    for args in [
        vec![
            "backup",
            "prune",
            "--keep-last",
            "1",
            "run",
            id,
            "--confirm-digest",
            digest,
        ],
        vec![
            "backup",
            "prune",
            "run",
            id,
            "--confirm-digest",
            digest,
            "--profile",
            "other",
        ],
        vec![
            "backup",
            "delete",
            "run",
            "../not-a-plan",
            "--confirm-digest",
            digest,
        ],
        vec![
            "backup",
            "delete",
            "run",
            "11111111-1111-1111-8111-111111111111",
            "--confirm-digest",
            digest,
        ],
        vec!["backup", "delete", "run", id],
    ] {
        let output = scene.run(&args);
        assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    }
    let result = ctl_json(
        &scene,
        &["backup", "prune", "run", id, "--confirm-digest", digest],
    );
    let mut fields = result
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "audit_recorded",
            "completed",
            "deleting",
            "digest",
            "job_id",
            "operation",
            "outcome",
            "pending",
            "plan_id"
        ]
    );
    assert_eq!(result["completed"], preview["candidates"]);
    assert_eq!(result["outcome"], "complete");
    assert_eq!(result["audit_recorded"], true);
    assert_eq!(entries(&scene.artifacts()).len(), 2);
    let job = ctl_json(
        &scene,
        &["job", "inspect", result["job_id"].as_str().unwrap()],
    );
    assert_eq!(job["job"]["operation"], "prune");
    assert_eq!(job["job"]["artifact_ids"].as_array().unwrap().len(), 4);
    let before = fs::read(&index).unwrap();
    let receipt = ctl_json(
        &scene,
        &["backup", "prune", "run", id, "--confirm-digest", digest],
    );
    assert_eq!(receipt["job_id"], result["job_id"]);
    assert_eq!(receipt["audit_recorded"], false);
    assert_eq!(fs::read(&index).unwrap(), before);
    let singleton = preview["retained"][0].as_str().unwrap();
    let deletion = ctl_json(&scene, &["backup", "delete", singleton]);
    let deleted = ctl_json(
        &scene,
        &[
            "backup",
            "delete",
            "run",
            deletion["plan_id"].as_str().unwrap(),
            "--confirm-digest",
            deletion["digest"].as_str().unwrap(),
        ],
    );
    assert_eq!(deleted["operation"], "delete");
    assert_eq!(deleted["completed"], serde_json::json!([singleton]));
    let refused = scene.run(&["backup", "delete", preview["retained"][1].as_str().unwrap()]);
    assert!(text(&refused).contains("RETENTION_LAST_VALID"));
}

#[test]
fn cli_partial_failure_prints_durable_partition_and_recovery_never_starts_pending_ids() {
    let scene = signed_retention_scene("b04-partial", 4);
    let index = scene.root.join(INVENTORY_FILE);
    let conn = rusqlite::Connection::open(&index).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse_deleted BEFORE INSERT ON audit_event WHEN NEW.action='artifact_deleted' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let preview = ctl_json(&scene, &["backup", "prune", "--keep-last", "1"]);
    let id = preview["plan_id"].as_str().unwrap();
    let digest = preview["digest"].as_str().unwrap();
    let output = scene.run(&[
        "--output",
        "json",
        "backup",
        "prune",
        "run",
        id,
        "--confirm-digest",
        digest,
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(text(&output).contains("DELETION_RECOVERY_REQUIRED"));
    let partial: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(partial["outcome"], "partial");
    assert_eq!(partial["completed"], serde_json::json!([]));
    assert_eq!(
        partial["deleting"],
        serde_json::json!([preview["candidates"][0]])
    );
    assert_eq!(
        partial["pending"],
        serde_json::json!(&preview["candidates"].as_array().unwrap()[1..])
    );
    assert_eq!(partial["audit_recorded"], true);
    let first = preview["candidates"][0].as_str().unwrap();
    assert!(!scene.artifacts().join(first).exists());
    let inventory = Inventory::open_read_only_bound(&index).unwrap();
    let job_id = Uuid::parse_str(partial["job_id"].as_str().unwrap()).unwrap();
    assert_eq!(
        inventory.job(job_id).unwrap().unwrap().state,
        JobState::Failed
    );
    assert_eq!(
        inventory
            .artifact(Uuid::parse_str(first).unwrap())
            .unwrap()
            .unwrap()
            .state,
        backup_inventory::State::Deleting
    );
    let before = fs::read(&index).unwrap();
    let again = scene.run(&[
        "--output",
        "json",
        "backup",
        "prune",
        "run",
        id,
        "--confirm-digest",
        digest,
    ]);
    assert_eq!(again.status.code(), Some(1));
    let again: serde_json::Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(again["deleting"], partial["deleting"]);
    assert_eq!(again["audit_recorded"], false);
    assert_eq!(fs::read(&index).unwrap(), before);
    conn.execute_batch("DROP TRIGGER refuse_deleted;").unwrap();
    drop(conn);
    fs::remove_dir_all(scene.base.join("keys")).unwrap();
    fs::remove_dir_all(scene.base.join("bin")).unwrap();
    let recovered = ctl_json(&scene, &["inventory", "recover"]);
    assert_eq!(recovered["deleted"], serde_json::json!([first]));
    assert_eq!(
        inventory.job(job_id).unwrap().unwrap().state,
        JobState::Failed
    );
    assert_eq!(entries(&scene.artifacts()).len(), 3);
    for pending in partial["pending"].as_array().unwrap() {
        assert!(
            scene
                .artifacts()
                .join(pending.as_str().unwrap())
                .join("complete")
                .is_file()
        );
    }
    let before = fs::read(&index).unwrap();
    assert_eq!(
        ctl_json(&scene, &["inventory", "recover"])["deleted"],
        serde_json::json!([])
    );
    assert_eq!(fs::read(&index).unwrap(), before);
}
