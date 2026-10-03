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
