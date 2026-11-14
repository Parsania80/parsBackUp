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
PRIVATE_PROFILE = "m5a-private-profile"
PRIVATE_SCOPE = "m5a_private_scope"
FAKE_CREDENTIAL = "m5a-fake-credential-never-real"
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
        captures = []
        secrets = {"fake-credential": FAKE_CREDENTIAL.encode()}
        metadata = {"database": DATABASE.encode(), "host": b"127.0.0.1",
                    "profile": PRIVATE_PROFILE.encode(), "scope": PRIVATE_SCOPE.encode(),
                    "target": TARGET.encode()}
        password_file = base / "pgpass"
        password_file.write_text(f"127.0.0.1:5432:{DATABASE}:postgres:{FAKE_CREDENTIAL}\n")
        password_file.chmod(0o600)

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
password_file = "{password_file}"
[storage]
root = "{store}"
[[profile]]
name = "{PRIVATE_PROFILE}"
database = "{DATABASE}"
large_objects = true
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

        def command(*args, cfg=writer, output="json"):
            return [CLI, "--config", str(cfg), "--output", output, *args]

        def capture(args, output, result):
            captures.append((args, output, result.stdout.encode(), result.stderr.encode()))
            return result

        def ctl(*args, cfg=writer, ok=True, env=None):
            result = capture(args, "json", run(command(*args, cfg=cfg), ok=ok, env=env))
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

        def restore_plan(artifact, target=TARGET):
            # This drill deliberately restores an old snapshot. Review the local warning,
            # then explicitly bind it in the newly saved plan; runtime authenticates again.
            listing = ctl("backup", "list")
            acknowledgement = ["--acknowledge-older-snapshot"] if any(
                w["artifact_id"] == artifact for w in listing["rollback_warnings"]) else []
            return ctl("restore", "plan", artifact, "--target", target,
                       "--security", "portable", *acknowledgement)["plan"]["id"]

        def spawn(args, *, env=None):
            log = (base / f"child-{len(children)}.log").open("w+")
            child = subprocess.Popen(args, stdout=log, stderr=log, start_new_session=True,
                                     env=env)
            children.append((child, log))
            return child

        def hits(blob, tokens):
            return {label for label, token in tokens.items() if token in blob}

        def scan_inventory():
            scanned = []
            for path in base.rglob("*"):
                if path.is_file() and "inventory" in path.name and ".db" in path.name:
                    found = hits(path.read_bytes(), {**secrets, **metadata})
                    assert not found, f"inventory metadata leak in {path.name}: {sorted(found)}"
                    scanned.append(path)
            assert scanned, "inventory scan examined no files"

        def history():
            return {table: sql_file(index, f"SELECT * FROM {table} ORDER BY 1")
                    for table in ("job", "job_operation", "audit_event", "verification_event")}

        def trace_write(*args, ok=True, cfg=writer, fsync_ordinal=1):
            trace = base / "live-journal.trace"
            trace.unlink(missing_ok=True)
            child = subprocess.Popen(
                ["strace", "-yy", "-e", "trace=fsync", "-e",
                 f"inject=fsync:delay_exit=2s:when={fsync_ordinal}", "-o", str(trace), *command(*args, cfg=cfg)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                wait_for(lambda: trace.exists() and "(DELAYED)" in trace.read_text(), "live SQLite journal")
                delayed = next(line for line in trace.read_text().splitlines() if "(DELAYED)" in line)
                assert ".db-journal>" in delayed, delayed
                journal = Path(re.search(r"<([^>]+\.db-journal)>", delayed)[1])
                assert journal.is_file() and journal.stat().st_size > 512
                scan_inventory()
                assert hits(journal.read_bytes() + b"\n".join(secrets.values()), secrets) == set(secrets)
                stdout, stderr = child.communicate(timeout=150)
                result = subprocess.CompletedProcess(child.args, child.returncode, stdout, stderr)
                capture(args, "json", result)
                assert (result.returncode == 0) == ok, stderr
                scan_inventory()
                return json.loads(stdout) if ok else result
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.communicate(timeout=10)

        def check_reports(artifact):
            # Keyless reports must not inherit the metadata authenticated detail commands expose.
            requests = [("job", "list"), ("inventory", "check"), ("inventory", "list"),
                        ("inventory", "verification", artifact),
                        ("inventory", "rebuild", "--source-fingerprint", estate, "--dry-run")]
            requests += [("job", "inspect", j["job_id"]) for j in jobs()]
            for args in requests:
                for output in ("json", "human"):
                    result = capture(args, output, run(command(*args, cfg=keyless, output=output)))
                    assert not hits((result.stdout + result.stderr).encode(), {**secrets, **metadata}), args
            for output in ("json", "human"):
                for args in [("backup", "inspect", artifact), ("key", "status")]:
                    capture(args, output, run(command(*args, output=output)))
            for args, output, stdout, stderr in captures:
                assert not hits(stdout + stderr, secrets), f"secret in {output} {args[:2]}"
            scan_inventory()

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
            pg(f"CREATE SCHEMA {PRIVATE_SCOPE}; CREATE TABLE {PRIVATE_SCOPE}.entries (id int)")

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
if [[ -f {base}/fail-preflight && "$*" == --version ]]; then
    cat {base}/native-secret >&2; exit 1
elif [[ -f {base}/fail-{tool} && "$*" != --version && "$1" != --list ]]; then
    cat {base}/native-secret >&2; exit 1
elif [[ "{tool}" == createdb && -f {base}/pause-restore && "$*" != --version ]]; then
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
            for name in ("identity", "signing"):
                seed = (keys / f"{name}.key").read_text().splitlines()[1]
                secrets[f"{name}-hex"] = seed.encode()
                secrets[f"{name}-raw"] = bytes.fromhex(seed)
                if name == "signing":
                    for number, component in enumerate((seed[:64], seed[64:])):
                        secrets[f"signing-component-{number}-hex"] = component.encode()
                        secrets[f"signing-component-{number}-raw"] = bytes.fromhex(component)
            (base / "native-secret").write_bytes(b"\n".join([*secrets.values(), *metadata.values()]))
            artifact = create()
            estate = ctl("inventory", "check", cfg=keyless)["source_fingerprint"]
            assert sql_file(index, "SELECT protected FROM artifact WHERE backup_id=?", (artifact,)) == [(0,)]
            protected_files = digest_tree(root / "artifacts")
            protection = trace_write("backup", "protect", artifact, cfg=keyless)
            assert protection == {"backup_id": artifact, "protection": "protected", "changed": True, "audit_recorded": True}
            before = history()
            assert ctl("backup", "protect", artifact, cfg=keyless)["changed"] is False
            assert history() == before
            assert trace_write("backup", "unprotect", artifact, cfg=keyless)["protection"] == "unprotected"
            assert digest_tree(root / "artifacts") == protected_files
            scan_inventory()
            # A populated SQLite copy proves every sentinel is detectable by the byte scan.
            control = base / "positive-control.db"
            shutil.copyfile(index, control)
            with contextlib.closing(sqlite3.connect(control)) as db:
                db.execute("CREATE TABLE privacy_control (value BLOB)")
                db.executemany("INSERT INTO privacy_control VALUES (?)", [(v,) for v in [*secrets.values(), *metadata.values()]])
                db.commit()
            assert hits(control.read_bytes(), {**secrets, **metadata}) == set(secrets) | set(metadata)
            print(f"PostgreSQL {major}: raw SQLite privacy positive control detected all sentinels", flush=True)

            before = history()
            invalid = base / "invalid-config.toml"
            invalid.write_text(writer.read_text() + f'\nunrecognized_secret = "{FAKE_CREDENTIAL}"\n')
            for output in ("json", "human"):
                args = ("config", "check")
                report = capture(args, output, run(command(*args, cfg=invalid, output=output), ok=False))
                assert "invalid configuration" in report.stderr
            assert history() == before, "configuration refusal invented history"
            (base / "fail-preflight").touch()
            rejects("backup", "create", "--confirm-synthetic", contains="output withheld")
            (base / "fail-preflight").unlink()
            assert history() == before, "preflight refusal invented history"
            (base / "fail-pg_dump").touch()
            failure = trace_write("backup", "create", "--confirm-synthetic", ok=False)
            (base / "fail-pg_dump").unlink()
            assert "output withheld" in failure.stderr
            failed = next(j for j in jobs() if j["job_id"] not in {r[0] for r in before["job"]})
            assert failed["state"] == "failed"
            assert sql_file(index, "SELECT action FROM audit_event WHERE job_id=? ORDER BY event_id",
                            (failed["job_id"],)) == [("job_started",), ("job_failed",)]
            assert not (root / "artifacts" / failed["backup_id"]).exists()
            profiled = trace_write("backup", "create", "--confirm-synthetic", "--profile", PRIVATE_PROFILE)["manifest"]["backup_id"]
            assert PRIVATE_PROFILE.encode() in captures[-1][2], "authenticated create report control was absent"
            args = ("backup", "create", "--confirm-synthetic", "--profile", PRIVATE_PROFILE)
            report = capture(args, "human", run(command(*args, output="human")))
            assert PRIVATE_PROFILE in report.stdout
            (base / "fail-pg_dump").touch()
            report = capture(args, "human", run(command(*args, output="human"), ok=False))
            (base / "fail-pg_dump").unlink()
            assert "output withheld" in report.stderr
            check_reports(profiled)

            # B03 previews authenticate current bytes and bind existing archive observations.
            whole = [artifact, create(), create()]
            for known in [*whole, profiled]:
                ctl("backup", "verify", known, "--level", "archive")
            # B05: real authenticated publication, cross-profile local warning and explicit
            # plan acknowledgement. Keep mutations in this block out of B03's frozen snapshot.
            high_water = sql_file(index, "SELECT backup_id,completed_at_utc FROM completion_high_water")[0]
            before_db = index.read_bytes()
            listed = ctl("backup", "list")
            assert set(listed) == {"signed", "unsigned", "rollback_warnings", "rollback_unknown"}
            warning = next(w for w in listed["rollback_warnings"] if w["artifact_id"] == artifact)
            assert warning["high_water"] == {"artifact_id": high_water[0], "completed_at_utc": high_water[1]}
            assert warning["completed_at_utc"] < high_water[1] and listed["rollback_unknown"] == []
            human = capture(("backup", "list"), "human", run(command("backup", "list", output="human")))
            assert "WARNING: older snapshot" in human.stdout
            assert index.read_bytes() == before_db
            plan_files = digest_tree(root / "plans")
            rejects("restore", "plan", artifact, "--target", TARGET, "--security", "portable",
                    contains="OLDER_SNAPSHOT_ACK_REQUIRED")
            assert digest_tree(root / "plans") == plan_files
            acknowledged = ctl("restore", "plan", artifact, "--target", TARGET, "--security", "portable",
                               "--acknowledge-older-snapshot")["plan"]
            assert acknowledged["format"] == "m5b-restore-plan-v2"
            assert acknowledged["rollback"]["acknowledged"] is True
            assert acknowledged["rollback"]["high_water"] == warning["high_water"]
            # Wait for the timestamp boundary explicitly; equal-second completions are ties.
            import calendar
            boundary = calendar.timegm(time.strptime(high_water[1], "%Y-%m-%dT%H:%M:%SZ")) + 1
            wait_for(lambda: time.time() >= boundary, "new authenticated completion second")
            ctl("backup", "create", "--confirm-synthetic", "--profile", PRIVATE_PROFILE)
            rejects("restore", "run", acknowledged["id"], "--confirm-target", TARGET,
                    contains="OLDER_SNAPSHOT_REPLAN_REQUIRED")
            assert pg(f"SELECT count(*) FROM pg_database WHERE datname='{TARGET}'") == "0"
            scan_inventory()
            print(f"PostgreSQL {major}: B05 authenticated history/list warnings/bound acknowledgement/stale refusal passed", flush=True)
            reader_cfg = config("retention-reader")
            reader_cfg.write_text(reader_cfg.read_text().replace(
                f'signing_key_file = "{keys}/signing.key"\n', "").replace(
                str(bin_dir), str(base / "absent-tools")))
            frozen_db = index.read_bytes()
            frozen_files = digest_tree(root / "artifacts")
            order = [r[0] for r in sql_file(index,
                "SELECT backup_id FROM artifact WHERE backup_id IN (?,?,?) "
                "ORDER BY completed_at_utc DESC, backup_id", whole)]
            preview = ctl("backup", "prune", "--keep-last", "2", cfg=reader_cfg)
            assert preview["candidates"] == [order[2]] and preview["retained"] == sorted(order[:2])
            assert preview["audit_recorded"] is False
            plan_path = root / "plans" / f'deletion-{preview["plan_id"]}.json'
            envelope = json.loads(plan_path.read_text())
            assert plan_path.stat().st_mode & 0o777 == 0o600
            import hashlib
            assert hashlib.sha256(json.dumps(envelope["plan"], separators=(",", ":")).encode()).hexdigest() == preview["digest"] == envelope["digest"]
            assert envelope["plan"]["inventory_sha256"] == hashlib.sha256(frozen_db).hexdigest()
            for member in envelope["plan"]["candidates"] + envelope["plan"]["retained"]:
                assert member["verification_event_id"] == sql_file(index,
                    "SELECT MAX(event_id) FROM verification_event WHERE backup_id=? AND level='archive' AND outcome='success' AND current=1", (member["backup_id"],))[0][0]
            assert index.read_bytes() == frozen_db and digest_tree(root / "artifacts") == frozen_files
            empty = ctl("backup", "prune", "--keep-last", "3", cfg=reader_cfg)
            assert empty["candidates"] == [] and all(empty[k] is None for k in ("plan_id", "digest", "expires_unix_ms"))
            ctl("backup", "protect", order[2], cfg=keyless)
            protected = ctl("backup", "prune", "--keep-last", "1", cfg=reader_cfg)
            assert protected["candidates"] == [order[1]] and protected["retained"] == sorted((order[0], order[2]))
            ctl("backup", "unprotect", order[2], cfg=keyless)
            explicit = ctl("backup", "delete", order[0], cfg=reader_cfg)
            assert explicit["candidates"] == [order[0]] and explicit["retained"] == sorted(order[1:])
            rejects("backup", "delete", profiled, cfg=reader_cfg, contains="RETENTION_LAST_VALID")
            # Reusing the same profile name intentionally groups changed historical selections.
            changed_cfg = config("changed-profile")
            changed_cfg.write_text(changed_cfg.read_text().replace("large_objects = true", 'large_objects = true\nmode = "data-only"'))
            changed = ctl("backup", "create", "--confirm-synthetic", "--profile", PRIVATE_PROFILE, cfg=changed_cfg)["manifest"]["backup_id"]
            ctl("backup", "verify", changed, "--level", "archive", cfg=changed_cfg)
            scoped = ctl("backup", "prune", "--keep-last", "1", "--profile", PRIVATE_PROFILE, cfg=reader_cfg)
            assert set(scoped["candidates"] + scoped["retained"]) == {profiled, changed}
            assert len(scoped["candidates"]) == len(scoped["retained"]) == 1
            for path in (root / "plans").glob("deletion-*.json"):
                assert not hits(path.read_bytes(), {**secrets, **metadata}), "private metadata in retention plan"
            print(f"PostgreSQL {major}: retention preview, exact saved plan, profile boundary and plan privacy passed", flush=True)
            # B04 runs on isolated copies; the later recovery drill keeps its original history.
            deletion_root = base / "b04-complete-store"
            shutil.copytree(root, deletion_root)
            deletion_cfg = config("b04-complete", store=deletion_root)
            deletion_plan = ctl("backup", "prune", "--keep-last", "2", cfg=deletion_cfg)
            candidate = deletion_plan["candidates"][0]
            result = trace_write("backup", "prune", "run", deletion_plan["plan_id"],
                                 "--confirm-digest", deletion_plan["digest"], cfg=deletion_cfg)
            assert result["completed"] == [candidate] and result["outcome"] == "complete"
            deletion_index = deletion_root / "inventory.db"
            assert not (deletion_root / "artifacts" / candidate).exists()
            assert sql_file(deletion_index, "SELECT state FROM artifact WHERE backup_id=?", (candidate,)) == [("deleted",)]
            assert sql_file(deletion_index, "SELECT DISTINCT current FROM verification_event WHERE backup_id=?", (candidate,)) == [(0,)]
            before_receipt = deletion_index.read_bytes()
            receipt = ctl("backup", "prune", "run", deletion_plan["plan_id"],
                          "--confirm-digest", deletion_plan["digest"], cfg=deletion_cfg)
            assert receipt["job_id"] == result["job_id"] and receipt["audit_recorded"] is False
            assert deletion_index.read_bytes() == before_receipt
            for retained in deletion_plan["retained"]:
                ctl("backup", "verify", retained, "--level", "archive", "--read-only", cfg=deletion_cfg)
            partial_root = base / "b04-partial-store"
            shutil.copytree(root, partial_root)
            partial_cfg = config("b04-partial", store=partial_root)
            partial_keyless = config("b04-partial-keyless", store=partial_root, key_dir=base / "absent-keys")
            partial_index = partial_root / "inventory.db"
            with contextlib.closing(sqlite3.connect(partial_index)) as db:
                db.execute("CREATE TRIGGER refuse_deleted BEFORE INSERT ON audit_event WHEN NEW.action='artifact_deleted' BEGIN SELECT RAISE(ABORT,'injected'); END")
                db.commit()
            partial_plan = ctl("backup", "prune", "--keep-last", "1", cfg=partial_cfg)
            failed = rejects("backup", "prune", "run", partial_plan["plan_id"],
                             "--confirm-digest", partial_plan["digest"], cfg=partial_cfg,
                             contains="DELETION_RECOVERY_REQUIRED")
            partition = json.loads(failed.stdout)
            started, pending = partial_plan["candidates"]
            assert partition["completed"] == [] and partition["deleting"] == [started] and partition["pending"] == [pending]
            assert partition["outcome"] == "partial" and failed.returncode == 1
            with contextlib.closing(sqlite3.connect(partial_index)) as db:
                db.execute("DROP TRIGGER refuse_deleted")
                db.commit()
            recovered = ctl("inventory", "recover", cfg=partial_keyless)
            assert recovered["deleted"] == [started]
            assert (partial_root / "artifacts" / pending / "complete").is_file()
            assert sql_file(partial_index, "SELECT state FROM job WHERE job_id=?", (partition["job_id"],)) == [("failed",)]
            after = rejects("backup", "prune", "run", partial_plan["plan_id"],
                            "--confirm-digest", partial_plan["digest"], cfg=partial_keyless,
                            contains="DELETION_RECOVERY_REQUIRED")
            after = json.loads(after.stdout)
            assert after["completed"] == [started] and after["pending"] == [pending] and after["audit_recorded"] is False
            for store in (deletion_root, partial_root):
                for path in (store / "plans").glob("deletion-*.json"):
                    assert not hits(path.read_bytes(), {**secrets, **metadata}), "private metadata in executed plan"
            scan_inventory()
            print(f"PostgreSQL {major}: exact confirmed deletion, live journal privacy, partial JSON and keyless started-only recovery passed", flush=True)
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
            before = history()
            rejects("backup", "create", "--confirm-synthetic", contains="already running")
            assert history() == before, "duplicate startup invented history"
            rejects("backup", "protect", artifact, cfg=keyless, contains="RETENTION_BUSY")
            assert history() == before, "busy protection invented history"
            rejects("backup", "prune", "--keep-last", "1", contains="RETENTION_BUSY")
            rejects("backup", "delete", artifact, contains="RETENTION_BUSY")
            assert history() == before, "busy retention invented history"
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
            failed_target = TARGET + "_failure"
            failed_plan = restore_plan(artifact, failed_target)
            before = history()
            (base / "fail-pg_restore").touch()
            failure = trace_write("restore", "run", failed_plan, "--confirm-target", failed_target, ok=False)
            (base / "fail-pg_restore").unlink()
            assert "output withheld" in failure.stderr
            failed = next(j for j in jobs() if j["job_id"] not in {r[0] for r in before["job"]})
            assert failed["operation"] == "restore" and failed["state"] == "failed"
            assert sql_file(index, "SELECT action FROM audit_event WHERE job_id=? ORDER BY event_id",
                            (failed["job_id"],)) == [("job_started",), ("job_failed",)]
            assert pg(f"SELECT count(*) FROM pg_database WHERE datname='{failed_target}'") == "1"
            plan = restore_plan(artifact)
            before = history()
            rejects("restore", "run", plan, "--confirm-target", TARGET + "_wrong", contains="confirmation target")
            assert history() == before, "confirmation refusal invented history"
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
            before = history()
            rejects("restore", "run", plan, "--confirm-target", TARGET, contains="RESTORE_BUSY")
            assert history() == before, "target-lock refusal invented history"
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
            trace_write("restore", "run", plan, "--confirm-target", TARGET)
            docker("psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-d", TARGET,
                   input=(REPO / "tests/fixtures/postgres/assertions.sql").read_text())
            assert pg("SELECT count(*) FROM public.m5a_stream", TARGET) == "200000"
            assert any(j["operation"] == "restore" and j["state"] == "complete" for j in jobs())
            completed = [j for j in jobs() if j["operation"] == "restore" and j["state"] == "complete"]
            assert len(completed) == 1
            assert sql_file(index, "SELECT action FROM audit_event WHERE job_id=? ORDER BY event_id",
                            (completed[0]["job_id"],)) == [("job_started",), ("job_completed",)]
            check_reports(artifact)
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
            trace_write("backup", "verify", orphan, "--level", "archive")
            check_reports(orphan)
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
            assert not index.exists() and preview["lost_history"] == ["jobs", "audit", "protection", "verification", "rollback"]
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
            assert all(row == (None,) for row in sql_file(index, "SELECT protected FROM artifact"))
            assert sql_file(index, "SELECT * FROM completion_high_water") == []
            assert artifact in ctl("backup", "list")["rollback_unknown"]
            assert sql_file(index, "SELECT count(*) FROM provisional_artifact")[0][0] == len(rows)
            ctl("backup", "verify", artifact, "--level", "archive")
            assert sql_file(index, "SELECT backup_id FROM completion_high_water") == [(artifact,)]
            assert sql_file(index, "SELECT profile_fingerprint FROM artifact WHERE backup_id=?", (artifact,))[0][0]
            assert sql_file(index, "SELECT protected FROM artifact WHERE backup_id=?", (artifact,)) == [(None,)]
            rejects("backup", "prune", "--keep-last", "1", contains="RETENTION_PROTECTION_UNKNOWN")
            check_reports(artifact)
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
            journal_ordinal = 0
            last_journal = None
            for line in (base / "rebuild-baseline.trace").read_text().splitlines():
                if line.startswith("fsync("):
                    journal_ordinal += 1
                    if ".db-journal>" in line:
                        last_journal = journal_ordinal
            assert last_journal is not None
            journal_root, journal_cfg = crash_store("journal-rebuild")
            prepared = rebuild("--prepare-rebuild", cfg=journal_cfg)["plan_id"]
            trace_write("inventory", "rebuild", "--source-fingerprint", estate, "--confirm-rebuild",
                        "--plan-id", prepared, cfg=journal_cfg, fsync_ordinal=last_journal)
            assert ctl("inventory", "check", cfg=journal_cfg)["valid"]
            assert ctl("job", "list", cfg=journal_cfg)["jobs"] == []
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
            scan_inventory()
            for args, output, stdout, stderr in captures:
                assert not hits(stdout + stderr, secrets), f"secret in {output} {args[:2]}"
            for _, log in children:
                log.flush()
                log.seek(0)
                assert not hits(log.read().encode(), secrets), "secret in spawned CLI output"
            print(f"PostgreSQL {major}: metadata/seed scans, live journals and honest audit timing passed", flush=True)
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
