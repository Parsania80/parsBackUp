#!/usr/bin/env bash
# M5a recovery/integrity through actual CLI startup and matching native PG16/17/18 tools.
# Requires Docker, Python 3, strace with syscall injection, and a non-root user.
# Only isolated synthetic fixture databases and temporary stores are modified.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl --locked --offline
python3 - <<'PY'
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

REPO = Path.cwd()
CLI = str(REPO / "target/debug/backupctl")
DATABASE = "backupctl_fixture_m1"
TARGET = "backupctl_fixture_m5a_restore"
SCHEMA = (REPO / "crates/backup-inventory/src/schema.rs").read_text()
CURRENT = int(re.search(r"pub const SCHEMA_VERSION: i64 = (\d+);", SCHEMA)[1])
assert os.geteuid() != 0, "run as a non-root user to prove read-only permissions"
assert shutil.which("strace"), "install strace with syscall delay injection support"


def run(args, *, ok=True, input=None, env=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True,
                            timeout=150, env=env)
    if (result.returncode == 0) != ok:
        raise AssertionError(f"unexpected exit {result.returncode}: {args}\n"
                             f"{result.stdout}\n{result.stderr}")
    return result


def wait_for(probe, label):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(0.1)
    raise AssertionError(f"timed out: {label}")


def sql_file(path, sql, parameters=()):
    with contextlib.closing(sqlite3.connect(path)) as db:
        with db:
            return db.execute(sql, parameters).fetchall()


def digest_tree(root):
    import hashlib
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


def lock_free(path):
    with path.open("r+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True


for major in (16, 17, 18):
    container = f"backupctl-m5a-{major}-{os.getpid()}"
    children = []
    with tempfile.TemporaryDirectory(prefix="backupctl-m5a-") as directory:
        base = Path(directory)
        root = base / "data"
        index = root / "inventory.db"
        bin_dir = base / "bin"
        bin_dir.mkdir()
        keys = base / "keys"

        def docker(*args, **kwargs):
            return run(["docker", "exec", "-i", container, *args], **kwargs)

        def pg(sql, database=DATABASE):
            return docker("psql", "-U", "postgres", "-XAt", "-v", "ON_ERROR_STOP=1",
                          "-d", database, "-c", sql).stdout.strip()

        def config(name, store=root, shape="signed", key_dir=keys):
            path = base / f"{name}.toml"
            text = f'''export_globals = false
timeout_seconds = 120
[source]
host = "127.0.0.1"
port = 5432
user = "postgres"
database = "{DATABASE}"
client_bin_dir = "{bin_dir}"
[storage]
root = "{store}"
'''
            if shape != "plain":
                text += f'''[encryption]
identity_file = "{key_dir}/identity.key"
recipient_file = "{key_dir}/recipient.key"
'''
            if shape == "signed":
                text += f'''[signing]
signing_key_file = "{key_dir}/signing.key"
verifying_key_file = "{key_dir}/verifying.key"
'''
            path.write_text(text)
            return path

        writer = config("writer")
        keyless = config("keyless", key_dir=base / "absent-keys")

        def command(*args, cfg=writer):
            return [CLI, "--config", str(cfg), "--output", "json", *args]

        def ctl(*args, cfg=writer, ok=True, env=None):
            result = run(command(*args, cfg=cfg), ok=ok, env=env)
            return json.loads(result.stdout) if ok else result

        def rejects(*args, cfg=writer, contains=None):
            result = ctl(*args, cfg=cfg, ok=False)
            if contains:
                assert contains in result.stderr, result.stderr
            return result

        def create(cfg=writer):
            result = ctl("backup", "create", "--confirm-synthetic", cfg=cfg)
            return result["manifest"]["backup_id"] if "manifest" in result else result["id"]

        def jobs():
            return ctl("job", "list", cfg=keyless)["jobs"]

        def job(job_id):
            return ctl("job", "inspect", job_id, cfg=keyless)["job"]

        def rebuild(*flags, cfg=keyless, source=None):
            return ctl("inventory", "rebuild", "--source-fingerprint", source or estate,
                       *flags, cfg=cfg)

        def restore_plan(artifact):
            return ctl("restore", "plan", artifact, "--target", TARGET,
                       "--security", "portable")["plan"]["id"]

        def spawn(args, *, env=None):
            log = (base / f"child-{len(children)}.log").open("w+")
            child = subprocess.Popen(args, stdout=log, stderr=log, start_new_session=True,
                                     env=env)
            children.append((child, log))
            return child

        try:
            run(["docker", "run", "--rm", "-d", "--name", container, "--network", "none",
                 "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-v", f"{base}:{base}",
                 f"docker.arvancloud.ir/library/postgres:{major}-bookworm"])
            wait_for(lambda: subprocess.run(
                ["docker", "exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5).returncode == 0, "PostgreSQL ready")
            docker("createdb", "-U", "postgres", DATABASE)
            docker("psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-d", DATABASE,
                   input=(REPO / "tests/fixtures/postgres/core.sql").read_text())
            pg("CREATE TABLE public.m5a_stream AS SELECT i, md5(i::text) AS value "
               "FROM generate_series(1,200000) i")

            # Forward real archive bytes, then back-pressure the still-running native dump.
            (base / "pause-dump.py").write_text(f'''import pathlib, sys, time
sys.stdout.buffer.write(sys.stdin.buffer.read(4096))
sys.stdout.buffer.flush()
pathlib.Path({str(base / 'dump-started')!r}).touch()
deadline = time.monotonic() + 120
while pathlib.Path({str(base / 'pause-dump')!r}).exists():
    if time.monotonic() > deadline:
        sys.exit("dump pause timed out")
    time.sleep(0.05)
import shutil
shutil.copyfileobj(sys.stdin.buffer, sys.stdout.buffer)
''')

            # createdb's test-only trigger blocks the real pg_restore inside PostgreSQL.
            pause_sql = base / "pause.sql"
            pause_sql.write_text('''CREATE FUNCTION public.m5a_pause() RETURNS event_trigger
LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(120); END $$;
CREATE EVENT TRIGGER m5a_pause ON ddl_command_start WHEN TAG IN ('CREATE SCHEMA')
EXECUTE FUNCTION public.m5a_pause();
''')
            for tool in ("pg_dump", "pg_dumpall", "pg_restore", "psql", "createdb"):
                wrapper = bin_dir / tool
                wrapper.write_text(f'''#!/usr/bin/env bash
set -euo pipefail
if [[ "{tool}" == createdb && -f {base}/pause-restore && "$*" != --version ]]; then
    docker exec -i {container} createdb "$@"
    docker exec -i {container} psql -U postgres -X -v ON_ERROR_STOP=1 -d "${{@: -1}}" -f {pause_sql}
elif [[ "{tool}" == pg_dump && -f {base}/pause-dump && "$*" != --version ]]; then
    docker exec -i {container} pg_dump "$@" | python3 {base}/pause-dump.py
else
    exec docker exec -i {container} {tool} "$@"
fi
''')
                wrapper.chmod(0o700)

            ctl("key", "generate")
            artifact = create()
            estate = ctl("inventory", "check", cfg=keyless)["source_fingerprint"]
            artifacts_before = digest_tree(root / "artifacts")
            print(f"PostgreSQL {major}: native fixture backup registered", flush=True)

            (base / "pause-dump").touch()
            backup = spawn(command("backup", "create", "--confirm-synthetic"))
            wait_for(lambda: (base / "dump-started").exists(), "native dump emitted archive bytes")
            running = [j for j in jobs() if j["state"] == "running"]
            assert len(running) == 1, running
            interrupted_backup = running[0]
            stage = root / "staging" / interrupted_backup["backup_id"]
            assert stage.is_dir()
            rejects("backup", "create", "--confirm-synthetic", contains="already running")
            assert job(interrupted_backup["job_id"])["state"] == "running"
            ctl("backup", "inspect", artifact)
            ctl("inventory", "list", cfg=keyless)
            assert stage.is_dir() and digest_tree(root / "artifacts") == artifacts_before
            os.killpg(backup.pid, signal.SIGKILL)
            backup.wait(timeout=10)
            pg("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='pg_dump'")
            (base / "pause-dump").unlink()
            assert stage.is_dir(), "SIGKILL unexpectedly cleaned up its stage"
            create()
            assert job(interrupted_backup["job_id"])["state"] == "interrupted"
            assert not stage.exists()
            assert not list((root / "scratch").iterdir())
            assert not (root / "artifacts" / interrupted_backup["backup_id"]).exists()
            print(f"PostgreSQL {major}: killed dump, duplicate/read safety and same-scope restart passed", flush=True)

            # A live native restore keeps inherited claims after its CLI parent dies.
            plan = restore_plan(artifact)
            (base / "pause-restore").touch()
            restore = spawn(command("restore", "run", plan, "--confirm-target", TARGET))
            wait_for(lambda: pg("SELECT count(*) FROM pg_stat_activity WHERE datname='" + TARGET +
                                "' AND application_name='pg_restore' AND wait_event='PgSleep'") == "1",
                     "native restore blocked in DDL trigger")
            (base / "pause-restore").unlink()
            restore_job = next(j for j in jobs() if j["operation"] == "restore" and j["state"] == "running")
            artifact_lock = root / "locks" / f"artifact-{artifact}.lock"
            target_lock = root / "locks" / f"target-{restore_job['target_fingerprint']}.lock"
            assert not lock_free(artifact_lock) and not lock_free(target_lock)
            rejects("restore", "run", plan, "--confirm-target", TARGET, contains="RESTORE_BUSY")
            ctl("backup", "inspect", artifact)
            os.kill(restore.pid, signal.SIGKILL)
            restore.wait(timeout=10)
            assert not lock_free(artifact_lock) and not lock_free(target_lock)
            rejects("restore", "run", plan, "--confirm-target", TARGET, contains="RESTORE_BUSY")
            create()  # Real CLI recovery must not sweep a still-live restore child.
            assert job(restore_job["job_id"])["state"] == "running"
            pg("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='" + TARGET +
               "' AND application_name='pg_restore'")
            wait_for(lambda: lock_free(artifact_lock) and lock_free(target_lock), "native restore claims released")
            create()
            assert job(restore_job["job_id"])["state"] == "interrupted"
            assert pg(f"SELECT count(*) FROM pg_database WHERE datname='{TARGET}'") == "1"
            # The drill owns this partial fixture; production recovery deliberately keeps it.
            docker("dropdb", "-U", "postgres", TARGET)
            plan = restore_plan(artifact)
            ctl("restore", "run", plan, "--confirm-target", TARGET)
            docker("psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-d", TARGET,
                   input=(REPO / "tests/fixtures/postgres/assertions.sql").read_text())
            assert pg("SELECT count(*) FROM public.m5a_stream", TARGET) == "200000"
            assert any(j["operation"] == "restore" and j["state"] == "complete" for j in jobs())
            print(f"PostgreSQL {major}: killed native restore, inherited claims, recovery and validated restore passed", flush=True)

            # Refuse registration only after the authoritative artifact is complete.
            sql_file(index, "CREATE TRIGGER m5a_fail BEFORE INSERT ON artifact BEGIN "
                     "SELECT RAISE(ABORT, 'm5a registration failure'); END")
            before = set(p.name for p in (root / "artifacts").iterdir())
            rejects("backup", "create", "--confirm-synthetic", contains="published and restorable")
            published = set(p.name for p in (root / "artifacts").iterdir()) - before
            assert len(published) == 1
            orphan = published.pop()
            assert (root / "artifacts" / orphan / "complete").is_file()
            assert not sql_file(index, "SELECT 1 FROM artifact WHERE backup_id=?", (orphan,))
            assert next(j for j in jobs() if j["backup_id"] == orphan)["state"] == "failed"
            sql_file(index, "DROP TRIGGER m5a_fail")
            ctl("inventory", "adopt", orphan, "--source-fingerprint", estate, cfg=keyless)
            ctl("backup", "verify", orphan, "--level", "archive")
            print(f"PostgreSQL {major}: publication/registration failure and explicit adoption passed", flush=True)

            # Real native writers create all three shapes in one directory.
            create(config("plain", shape="plain"))
            create(config("unsigned", shape="unsigned"))
            entries = ctl("inventory", "list", cfg=keyless)["entries"]
            assert {e["shape"] for e in entries} == {"v1-signed", "age-unsigned", "plaintext-dev"}
            public = root / "artifacts" / artifact / "public.json"
            saved_header = public.read_bytes()
            public.write_text('{"version":')
            before_db = index.read_bytes()
            entries = ctl("inventory", "list", cfg=keyless)["entries"]
            assert next(e for e in entries if e["backup_id"] == artifact)["status"] == "conflict"
            rejects("inventory", "rebuild", "--source-fingerprint", estate, "--prepare-rebuild",
                    cfg=keyless, contains="artifact scan contains")
            assert index.read_bytes() == before_db
            public.write_bytes(saved_header)
            wrong = "0" * 16 if estate != "0" * 16 else "1" * 16
            rejects("inventory", "adopt", artifact, "--source-fingerprint", wrong,
                    cfg=keyless, contains="refusing to merge two estates")
            wrong_plan = rebuild("--prepare-rebuild", source=wrong)["plan_id"]
            rejects("inventory", "rebuild", "--source-fingerprint", wrong, "--confirm-rebuild",
                    "--plan-id", wrong_plan, cfg=keyless, contains="estate mismatch")
            assert index.read_bytes() == before_db

            # Keyless loss/rebuild, stale-plan refusal, unknown facts and history loss.
            saved_index = base / "inventory-saved.db"
            shutil.copyfile(index, saved_index)
            original_jobs = jobs()
            original_ids = {e["backup_id"] for e in ctl("inventory", "list", cfg=keyless)["entries"]}
            index.unlink()
            preview = rebuild("--dry-run")
            assert not index.exists() and preview["lost_history"] == ["jobs", "audit", "protection", "verification"]
            prepared = rebuild("--prepare-rebuild")["plan_id"]
            public.write_bytes(saved_header + b"\n")
            rejects("inventory", "rebuild", "--source-fingerprint", estate, "--confirm-rebuild",
                    "--plan-id", prepared, cfg=keyless, contains="stale")
            assert not index.exists()
            public.write_bytes(saved_header)
            prepared = rebuild("--prepare-rebuild")["plan_id"]
            rebuilt = rebuild("--confirm-rebuild", "--plan-id", prepared)
            assert rebuilt["rebuilt"] and rebuilt["previous_inventory"] is None
            assert {e["backup_id"] for e in rebuilt["entries"]} == original_ids
            assert jobs() == []
            rows = sql_file(index, "SELECT profile_fingerprint,completed_at_utc FROM artifact")
            assert len(rows) == len(entries) and all(row == (None, None) for row in rows)
            assert sql_file(index, "SELECT count(*) FROM provisional_artifact")[0][0] == len(rows)
            ctl("backup", "verify", artifact, "--level", "archive")
            assert sql_file(index, "SELECT profile_fingerprint FROM artifact WHERE backup_id=?", (artifact,))[0][0]
            print(f"PostgreSQL {major}: mixed shapes, malformed header, wrong estate and keyless rebuild passed", flush=True)

            # Discover syscall ordinals from this build, then delay each successful boundary
            # and SIGKILL before userspace continues. No production failpoint is needed.
            def crash_store(label):
                store = base / label
                store.mkdir(mode=0o700)
                shutil.copytree(root / "artifacts", store / "artifacts", copy_function=os.link)
                shutil.copyfile(saved_index, store / "inventory.db")
                return store, config(label, store=store, key_dir=base / "absent-keys")

            traced_syscalls = "openat,fsync,link,linkat,rename,renameat,renameat2"
            baseline_root, baseline_cfg = crash_store("rebuild-baseline")
            prepared = rebuild("--prepare-rebuild", cfg=baseline_cfg)["plan_id"]
            trace = base / "rebuild-baseline.trace"
            run(["strace", "-yy", "-e", f"trace={traced_syscalls}", "-o", str(trace),
                 *command("inventory", "rebuild", "--source-fingerprint", estate,
                          "--confirm-rebuild", "--plan-id", prepared, cfg=baseline_cfg)])
            ordinals, checkpoints = {}, {}
            phase = None
            for line in trace.read_text().splitlines():
                match = re.match(r"(\w+)\(", line)
                if not match:
                    continue
                syscall = match[1]
                ordinals[syscall] = ordinals.get(syscall, 0) + 1
                checkpoint = None
                if syscall == "openat" and ".inventory-rebuild-" in line and "O_EXCL" in line:
                    checkpoint = "stage-create"
                elif syscall == "fsync" and ".inventory-rebuild-" in line and ".db>" in line:
                    checkpoint = "stage-sync"  # The final one is after SQLite closes.
                elif syscall in ("link", "linkat") and "inventory.db.previous-" in line:
                    checkpoint = phase = "old-link"
                elif syscall.startswith("rename") and ".inventory-rebuild-" in line:
                    checkpoint = phase = "replacement"
                elif syscall == "fsync" and f"<{baseline_root}>" in line:
                    checkpoint = {"old-link": "old-dir-sync", "replacement": "replacement-dir-sync"}.get(phase)
                if checkpoint:
                    checkpoints[checkpoint] = (syscall, ordinals[syscall])
            assert set(checkpoints) == {"stage-create", "stage-sync", "old-link", "old-dir-sync",
                                        "replacement", "replacement-dir-sync"}, checkpoints
            authoritative = saved_index.read_bytes()
            for checkpoint, (syscall, ordinal) in checkpoints.items():
                crash_root, crash_cfg = crash_store(f"crash-{checkpoint}")
                prepared = rebuild("--prepare-rebuild", cfg=crash_cfg)["plan_id"]
                trace = base / f"{checkpoint}.trace"
                child = spawn(["strace", "-yy", "-e", f"trace={traced_syscalls}",
                               "-e", f"inject={syscall}:delay_exit=60s:when={ordinal}", "-o", str(trace),
                               *command("inventory", "rebuild", "--source-fingerprint", estate,
                                        "--confirm-rebuild", "--plan-id", prepared, cfg=crash_cfg)])
                wait_for(lambda: trace.exists() and "(DELAYED)" in trace.read_text(), checkpoint)
                delayed = next(line for line in trace.read_text().splitlines() if "(DELAYED)" in line)
                assert " = 0 " in delayed or (checkpoint == "stage-create" and "O_EXCL" in delayed), delayed
                expected_path = {
                    "stage-create": ".inventory-rebuild-", "stage-sync": ".db>",
                    "old-link": "inventory.db.previous-", "old-dir-sync": f"<{crash_root}>",
                    "replacement": ".inventory-rebuild-", "replacement-dir-sync": f"<{crash_root}>",
                }[checkpoint]
                assert expected_path in delayed, delayed
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
                installed = checkpoint in ("replacement", "replacement-dir-sync")
                assert ((crash_root / "inventory.db").read_bytes() != authoritative) == installed
                assert ctl("inventory", "check", cfg=crash_cfg)["valid"]
                assert ctl("job", "list", cfg=crash_cfg)["jobs"] == ([] if installed else original_jobs)
                previous = list(crash_root.glob("inventory.db.previous-*"))
                assert len(previous) == (0 if checkpoint in ("stage-create", "stage-sync") else 1)
                assert all(p.read_bytes() == authoritative for p in previous)
                # A fresh explicit rebuild remains possible after every interruption.
                prepared = rebuild("--prepare-rebuild", cfg=crash_cfg)["plan_id"]
                rebuild("--confirm-rebuild", "--plan-id", prepared, cfg=crash_cfg)
                assert ctl("inventory", "check", cfg=crash_cfg)["valid"]
            print(f"PostgreSQL {major}: six rebuild filesystem crash boundaries passed", flush=True)

            # Freeze real v1 and v2 migrations from the production migration source.
            for old_version in (1, 2):
                old_root = base / f"old-{old_version}"
                old_root.mkdir(mode=0o700)
                old_index = old_root / "inventory.db"
                with contextlib.closing(sqlite3.connect(old_index)) as db:
                    for version in range(1, old_version + 1):
                        migration = SCHEMA.split(f'const SCHEMA_V{version}: &str = "', 1)[1].split('\n";', 1)[0]
                        db.executescript(migration)
                    db.execute("INSERT INTO meta VALUES ('source_fingerprint', ?)", (estate,))
                    # Keep populated v1 facts across all subsequent migration steps.
                    db.execute("INSERT INTO artifact (backup_id,source_fingerprint,shape,state) "
                               "VALUES (?,?, 'plaintext-dev','missing')", (artifact, estate))
                    db.execute(f"PRAGMA user_version={old_version}")
                    db.commit()
                old_index.chmod(0o600)
                old_cfg = config(f"old-{old_version}", store=old_root)
                original = old_index.read_bytes()
                assert ctl("inventory", "check", cfg=old_cfg)["schema_version"] == old_version
                assert old_index.read_bytes() == original
                create(old_cfg)  # Actual startup upgrades before creating its new job.
                assert ctl("inventory", "check", cfg=old_cfg)["schema_version"] == CURRENT
                assert sql_file(old_index, "SELECT state FROM artifact WHERE backup_id=?", (artifact,)) == [("missing",)]
                assert len(ctl("job", "list", cfg=old_cfg)["jobs"]) == 1

            # A newer schema is never migrated/replaced, including confirmed rebuild.
            sql_file(index, f"PRAGMA user_version={CURRENT + 1}")
            newer = index.read_bytes()
            rejects("inventory", "check", cfg=keyless, contains="INVENTORY_OPEN_FAILED")
            rejects("backup", "create", "--confirm-synthetic", contains="schema version")
            prepared = rebuild("--prepare-rebuild")["plan_id"]
            rejects("inventory", "rebuild", "--source-fingerprint", estate, "--confirm-rebuild",
                    "--plan-id", prepared, cfg=keyless, contains="newer")
            assert index.read_bytes() == newer
            sql_file(index, f"PRAGMA user_version={CURRENT}")

            # Restore the genuinely populated pre-rebuild file, then damage an index.
            shutil.copyfile(saved_index, index)
            assert jobs() and sql_file(index, "SELECT count(*) FROM artifact")[0][0] > 0
            sql_file(index, "CREATE INDEX m5a_corrupt ON job(state)")
            page_size = sql_file(index, "PRAGMA page_size")[0][0]
            page = sql_file(index, "SELECT rootpage FROM sqlite_schema WHERE name='m5a_corrupt'")[0][0]
            damaged = bytearray(index.read_bytes())
            offset = page * page_size - 512
            assert any(damaged[offset:offset + 512]), "corruption positive control was already zero"
            damaged[offset:offset + 512] = bytes(512)
            index.write_bytes(damaged)
            assert sql_file(index, "SELECT count(*) FROM job NOT INDEXED")[0][0] > 0
            corrupt = index.read_bytes()
            result = rejects("inventory", "check", cfg=keyless, contains="INVENTORY_CORRUPT")
            report = json.loads(result.stdout)
            assert report["valid"] is False and report["problems"]
            assert any("page" in p.lower() or "row" in p.lower() for p in report["problems"]), report
            assert index.read_bytes() == corrupt
            prepared = rebuild("--prepare-rebuild")["plan_id"]
            rebuilt = rebuild("--confirm-rebuild", "--plan-id", prepared)
            assert Path(rebuilt["previous_inventory"]).read_bytes() == corrupt
            assert ctl("inventory", "check", cfg=keyless)["valid"]

            # One current SQLite file is sufficient; no keys, tools, artifact tree or journal.
            copy_root = base / "readonly-copy"
            copy_root.mkdir(mode=0o700)
            copy_index = copy_root / "inventory.db"
            shutil.copyfile(saved_index, copy_index)
            copy_cfg = config("readonly", store=copy_root, key_dir=base / "absent-keys")
            copy_cfg.write_text(copy_cfg.read_text().replace(str(bin_dir), str(base / "absent-tools")))
            copy_index.chmod(0o400)
            copy_root.chmod(0o500)
            original = digest_tree(copy_root)
            assert ctl("inventory", "check", cfg=copy_cfg)["valid"]
            copied_jobs = ctl("job", "list", cfg=copy_cfg)["jobs"]
            assert copied_jobs == original_jobs and copied_jobs
            ctl("job", "inspect", copied_jobs[0]["job_id"], cfg=copy_cfg)
            assert digest_tree(copy_root) == original and len(list(copy_root.iterdir())) == 1
            copy_root.chmod(0o700)
            print(f"PostgreSQL {major}: v1/v2 upgrades, newer-schema refusal, populated corruption/rebuild and read-only copy passed", flush=True)
        finally:
            # Kill CLI process groups, then stop the isolated server and its docker-exec children.
            for child, log in children:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
                log.seek(0)
                if sys.exc_info()[0] is not None or child.returncode not in (0, -signal.SIGKILL):
                    print(log.read(), flush=True)
                log.close()
            run(["docker", "rm", "-f", container])
print("M5a: PostgreSQL 16/17/18 recovery and integrity drill passed", flush=True)
PY
