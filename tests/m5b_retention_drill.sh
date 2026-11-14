#!/usr/bin/env bash
# B06: real signed archives, competing CLI processes and marker-first crash recovery.
# Requires Docker, Python 3, strace delay injection and cached PostgreSQL images.
# Only isolated synthetic fixture databases and temporary stores are modified.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl --locked --offline
python3 - <<'PY'
import contextlib
import fcntl
import hashlib
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
import uuid

REPO = Path.cwd()
CLI = str(REPO / "target/debug/backupctl")
DATABASE = "backupctl_fixture_m5b"
TARGET = "backupctl_fixture_m5b_restore"
PROFILE = "m5b-private-profile"
FAKE_PASSWORD = "m5b-fake-password-never-real"
assert os.geteuid() != 0, "run as a non-root user"
assert shutil.which("strace"), "strace with syscall delay injection is required"


def run(args, *, ok=True, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=150)
    assert (result.returncode == 0) == ok, (args, result.returncode, result.stdout, result.stderr)
    return result


def wait_for(probe, label):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out: {label}")


def sql(root, statement, parameters=()):
    with contextlib.closing(sqlite3.connect(root / "inventory.db")) as db:
        with db:
            return db.execute(statement, parameters).fetchall()


def tree(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


for major in (16, 17, 18):
    container = f"backupctl-m5b-{major}-{os.getpid()}"
    children = []
    with tempfile.TemporaryDirectory(prefix="backupctl-m5b-") as directory:
        base = Path(directory)
        seed = base / "seed"
        keys = base / "keys"
        bin_dir = base / "bin"
        bin_dir.mkdir()
        password = base / "pgpass"
        password.write_text(f"127.0.0.1:5432:{DATABASE}:postgres:{FAKE_PASSWORD}\n")
        password.chmod(0o600)
        captures = []

        def config(label, root, *, keyless=False, plain=False, no_tools=False):
            path = base / f"{label}.toml"
            key_dir = base / "absent-keys" if keyless else keys
            tools = base / "absent-tools" if no_tools else bin_dir
            text = f'''export_globals = false
timeout_seconds = 120
[source]
host = "127.0.0.1"
port = 5432
user = "postgres"
database = "{DATABASE}"
client_bin_dir = "{tools}"
password_file = "{password}"
[storage]
root = "{root}"
[[profile]]
name = "{PROFILE}"
database = "{DATABASE}"
large_objects = true
'''
            if not plain:
                text += f'''[encryption]
identity_file = "{key_dir}/identity.key"
recipient_file = "{key_dir}/recipient.key"
[signing]
signing_key_file = "{key_dir}/signing.key"
verifying_key_file = "{key_dir}/verifying.key"
'''
            path.write_text(text)
            return path

        writer = config("writer", seed)

        def command(cfg, *args):
            return [CLI, "--config", str(cfg), "--output", "json", *args]

        def ctl(cfg, *args, ok=True):
            result = run(command(cfg, *args), ok=ok)
            captures.append((result.stdout + result.stderr).encode())
            return json.loads(result.stdout) if ok else result

        def reject(cfg, *args, code):
            result = ctl(cfg, *args, ok=False)
            assert code in result.stderr, result.stderr
            return result

        def clone(label):
            root = base / label
            shutil.copytree(seed, root)
            return root, config(label, root)

        def preview(cfg, n=1):
            return ctl(cfg, "backup", "prune", "--keep-last", str(n))

        def create(cfg, *flags):
            result = ctl(cfg, "backup", "create", "--confirm-synthetic", *flags)
            return result["manifest"]["backup_id"] if "manifest" in result else result["id"]

        def execute(cfg, plan, *, ok=True):
            return ctl(cfg, *execution(plan), ok=ok)

        def execution(plan):
            return ("backup", plan["operation"], "run", plan["plan_id"],
                    "--confirm-digest", plan["digest"])

        def artifacts(root):
            return tree(root / "artifacts")

        def unchanged_refusal(root, cfg, args, code):
            before = (root / "inventory.db").read_bytes(), artifacts(root), tree(root / "plans")
            reject(cfg, *args, code=code)
            assert before == ((root / "inventory.db").read_bytes(), artifacts(root), tree(root / "plans"))

        def spawn(args):
            log = (base / f"child-{len(children)}.log").open("w+")
            child = subprocess.Popen(args, stdout=log, stderr=log, start_new_session=True)
            children.append((child, log))
            return child

        def kill(child):
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)

        def pg(query, database=DATABASE):
            return run(["docker", "exec", container, "psql", "-U", "postgres", "-XAt",
                        "-v", "ON_ERROR_STOP=1", "-d", database, "-c", query]).stdout.strip()

        def plan_restore(cfg, artifact):
            listing = ctl(cfg, "backup", "list")
            ack = ["--acknowledge-older-snapshot"] if any(
                w["artifact_id"] == artifact for w in listing["rollback_warnings"]) else []
            return ctl(cfg, "restore", "plan", artifact, "--target", TARGET,
                       "--security", "portable", *ack)["plan"]["id"]

        try:
            run(["docker", "run", "--rm", "-d", "--name", container, "--network", "none",
                 "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-v", f"{base}:{base}",
                 f"docker.arvancloud.ir/library/postgres:{major}-bookworm"])
            wait_for(lambda: subprocess.run(
                ["docker", "exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5).returncode == 0,
                "PostgreSQL ready")
            run(["docker", "exec", container, "createdb", "-U", "postgres", DATABASE])
            run(["docker", "exec", "-i", container, "psql", "-U", "postgres", "-X",
                 "-v", "ON_ERROR_STOP=1", "-d", DATABASE],
                input=(REPO / "tests/fixtures/postgres/core.sql").read_text().replace("backupctl_fixture_m1", DATABASE))
            for tool in ("pg_dump", "pg_dumpall", "pg_restore", "psql", "createdb"):
                wrapper = bin_dir / tool
                wrapper.write_text(f'''#!/usr/bin/env bash
set -euo pipefail
if [[ "{tool}" == pg_restore && "$*" != --version && "$1" != --list && -f {base}/pause-restore ]]; then
    touch {base}/restore-started
    for ((i=0; i<2400; i++)); do
        [[ -f {base}/pause-restore ]] || exec docker exec -i {container} {tool} "$@"
        sleep 0.05
    done
    exit 1
fi
exec docker exec -i {container} {tool} "$@"
''')
                wrapper.chmod(0o700)
            ctl(writer, "key", "generate")
            ids = []
            for _ in range(4):
                artifact = create(writer)
                ids.append(artifact)
                ctl(writer, "backup", "verify", artifact, "--level", "archive")
            profiled = create(writer, "--profile", PROFILE)
            ctl(writer, "backup", "verify", profiled, "--level", "archive")
            estate = ctl(writer, "inventory", "check")["source_fingerprint"]
            order = [r[0] for r in sql(seed, "SELECT backup_id FROM artifact WHERE backup_id != ? "
                                     "ORDER BY completed_at_utc DESC, backup_id", (profiled,))]
            assert set(order) == set(ids)

            root, cfg = clone("exact")
            ctl(cfg, "backup", "protect", order[-1])
            protected = artifacts(root)
            ctl(cfg, "inventory", "reconcile")
            ctl(cfg, "backup", "verify", order[-1], "--level", "archive")
            assert sql(root, "SELECT protected FROM artifact WHERE backup_id=?", (order[-1],)) == [(1,)]
            assert artifacts(root) == protected
            plan = preview(cfg)
            assert plan["candidates"] == sorted(order[1:-1])
            assert plan["retained"] == sorted([order[0], order[-1]])
            exclusions = {e["backup_id"]: e["reasons"] for e in plan["excluded"]}
            assert "protected" in exclusions[order[-1]] and "keep_last" in exclusions[order[0]]
            assert "outside_scope" in exclusions[profiled]
            unchanged_refusal(root, cfg, ("backup", "delete", order[-1]), "RETENTION_PROTECTED")
            unchanged_refusal(root, cfg, ("backup", "delete", profiled), "RETENTION_LAST_VALID")
            result = execute(cfg, plan)
            assert result["outcome"] == "complete" and result["completed"] == plan["candidates"]
            assert result["deleting"] == result["pending"] == []
            assert {p.name for p in (root / "artifacts").iterdir()} == set(plan["retained"]) | {profiled}
            before = (root / "inventory.db").read_bytes()
            receipt = execute(cfg, plan)
            assert receipt == {**result, "audit_recorded": False}
            assert (root / "inventory.db").read_bytes() == before
            for artifact in plan["retained"]:
                ctl(cfg, "backup", "verify", artifact, "--level", "archive", "--read-only")
            # Returned complete files cannot revive an existing tombstone.
            deleted = plan["candidates"][0]
            shutil.copytree(seed / "artifacts" / deleted, root / "artifacts" / deleted)
            reject(cfg, "backup", "inspect", deleted, code="deleted")
            ctl(cfg, "inventory", "reconcile")
            unchanged_refusal(root, cfg, ("inventory", "adopt", deleted, "--source-fingerprint", estate),
                              "artifact is absent, registered, incomplete, or invalid")
            assert sql(root, "SELECT state FROM artifact WHERE backup_id=?", (deleted,)) == [("deleted",)]
            assert sql(root, "SELECT DISTINCT current FROM verification_event WHERE backup_id=?", (deleted,)) == [(0,)]
            assert sql(root, "SELECT count(*) FROM audit_event WHERE action='artifact_deleted'")[0][0] == len(plan["candidates"])
            # Explicit single-copy deletion shares the executor but has its own CLI operation.
            root, cfg = clone("singleton-delete")
            single = ctl(cfg, "backup", "delete", order[0])
            assert single["candidates"] == [order[0]] and single["retained"] == sorted(order[1:])
            result = execute(cfg, single)
            assert result["operation"] == "delete" and result["outcome"] == "complete"
            assert result["completed"] == [order[0]] and result["deleting"] == result["pending"] == []
            assert {p.name for p in (root / "artifacts").iterdir()} == set(order[1:]) | {profiled}
            job = ctl(cfg, "job", "inspect", result["job_id"])["job"]
            assert job["operation"] == "delete" and job["artifact_ids"] == sorted(order)
            ctl(cfg, "backup", "verify", order[1], "--level", "archive", "--read-only")
            print(f"PostgreSQL {major}: exact confirmed sets, protection/refresh, profile/quota/last-copy exclusions, survivor archives and tombstones passed", flush=True)

            # Persisted stale jobs are fixture setup, not simulated deletion execution.
            root, cfg = clone("stale-job")
            job = str(uuid.uuid4())
            row = sql(root, "SELECT source_fingerprint,profile_fingerprint FROM artifact WHERE backup_id=?", (order[-1],))[0]
            sql(root, "INSERT INTO job VALUES (?,?,?,?,'running','2026-11-14T00:00:00Z','2026-11-14T00:00:00Z')",
                (job, order[-1], *row))
            sql(root, "INSERT INTO job_operation VALUES (?,'backup',NULL)", (job,))
            plan = preview(cfg)
            assert any(e["backup_id"] == order[-1] and "job_dependency" in e["reasons"] for e in plan["excluded"])
            unchanged_refusal(root, cfg, ("backup", "delete", order[-1]), "RETENTION_JOB_DEPENDENCY")
            sql(root, "DELETE FROM job_operation WHERE job_id=?", (job,))
            unchanged_refusal(root, cfg, ("backup", "prune", "--keep-last", "1"), "RETENTION_JOB_DEPENDENCY")

            root, cfg = clone("fact-exclusions")
            sql(root, "UPDATE artifact SET completed_at_utc=NULL WHERE backup_id=?", (order[-1],))
            sql(root, "UPDATE verification_event SET current=0 WHERE backup_id=?", (order[-2],))
            plan = preview(cfg)
            exclusions = {e["backup_id"]: e["reasons"] for e in plan["excluded"]}
            assert "unknown_time" in exclusions[order[-1]]
            assert "verification_required" in exclusions[order[-2]]
            sql(root, "UPDATE artifact SET profile_fingerprint=NULL WHERE backup_id=?", (order[-1],))
            assert any("unknown_profile" in e["reasons"] for e in preview(cfg)["excluded"])
            for state in ("missing", "conflict"):
                sql(root, "UPDATE artifact SET state=? WHERE backup_id=?", (state, order[-1]))
                assert any(state in e["reasons"] for e in preview(cfg)["excluded"])
            root, cfg = clone("unregistered")
            sql(root, "DELETE FROM artifact WHERE backup_id=?", (order[-1],))
            assert any(e["backup_id"] == order[-1] and "unregistered" in e["reasons"] for e in preview(cfg)["excluded"])
            plain_cfg = config("plain-writer", root, plain=True)
            unsigned = create(plain_cfg)
            assert unsigned not in preview(cfg)["candidates"] + preview(cfg)["retained"]
            assert any(e["backup_id"] == unsigned for e in preview(cfg)["excluded"])
            ctl(cfg, "inventory", "adopt", unsigned, "--source-fingerprint", estate)
            assert any(e["backup_id"] == unsigned and "unsigned" in e["reasons"] for e in preview(cfg)["excluded"])

            root, cfg = clone("rebuild")
            no_keys = config("rebuild-keyless", root, keyless=True, no_tools=True)
            unchanged_refusal(root, no_keys, ("backup", "prune", "--keep-last", "1"), "RETENTION_ARTIFACT_INVALID")
            prepared = ctl(no_keys, "inventory", "rebuild", "--source-fingerprint", estate, "--prepare-rebuild")
            rebuilt = ctl(no_keys, "inventory", "rebuild", "--source-fingerprint", estate,
                          "--confirm-rebuild", "--plan-id", prepared["plan_id"])
            assert "rollback" in rebuilt["lost_history"]
            unchanged_refusal(root, cfg, ("backup", "prune", "--keep-last", "1"), "RETENTION_SCOPE_UNKNOWN")
            for artifact in ids:
                ctl(cfg, "backup", "verify", artifact, "--level", "archive")
            unchanged_refusal(root, cfg, ("backup", "prune", "--keep-last", "1"), "RETENTION_PROTECTION_UNKNOWN")
            assert sql(root, "SELECT DISTINCT protected FROM artifact") == [(None,)]

            for damage in ("missing", "corrupt"):
                root, cfg = clone(f"witness-{damage}")
                plan = preview(cfg)
                witness = root / "artifacts" / plan["retained"][0] / "payload.age"
                if damage == "missing":
                    shutil.rmtree(witness.parent)
                else:
                    body = bytearray(witness.read_bytes())
                    body[-1] ^= 1
                    witness.write_bytes(body)
                unchanged_refusal(root, cfg, execution(plan), "RETENTION_PLAN_STALE")
            root, cfg = clone("use-held")
            lock = root / "locks" / f"artifact-{order[-1]}.lock"
            with lock.open("r+") as held:
                fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
                unchanged_refusal(root, cfg, ("backup", "delete", order[-1]), "RETENTION_BUSY")
            print(f"PostgreSQL {major}: job/use and invalid/unknown exclusions, keyless rebuild and damaged retained witnesses passed", flush=True)

            # Identical copies retain the same plan/SQLite bytes; discover syscall positions.
            template, template_cfg = clone("crash-template")
            restore_id = plan_restore(template_cfg, order[0])
            plan = preview(template_cfg)
            first, *pending = plan["candidates"]
            assert len(pending) == 2
            def crash_copy(label):
                root = base / label
                shutil.copytree(template, root)
                return root, config(label, root)

            trace_calls = "close,unlink,unlinkat,fsync"
            root, cfg = crash_copy("trace-baseline")
            trace = base / "baseline.trace"
            run(["strace", "-yy", "-e", f"trace={trace_calls}", "-o", str(trace),
                 *command(cfg, *execution(plan))])
            ordinals, checkpoints = {}, {}
            phase = None
            last_content_close = None
            for line in trace.read_text().splitlines():
                match = re.match(r"(\w+)\(", line)
                if not match:
                    continue
                call = match[1]
                ordinals[call] = ordinals.get(call, 0) + 1
                point = None
                if call == "close" and f"/artifacts/{first}/" in line and phase is None:
                    last_content_close = call, ordinals[call]
                if call == "unlinkat" and f"/artifacts/{first}>" in line:
                    if '"complete"' in line:
                        assert last_content_close is not None
                        checkpoints["intent-before-marker"] = last_content_close
                        point = phase = "marker-unlink"
                    else:
                        assert phase in ("marker-sync", "content-unlink"), line
                        if phase == "marker-sync":
                            point = "content-unlink"
                        phase = "content-unlink"
                elif call == "fsync" and f"/artifacts/{first}>" in line:
                    point = phase = {"marker-unlink": "marker-sync", "content-unlink": "contents-sync"}.get(phase)
                elif call == "unlinkat" and f'"{first}", AT_REMOVEDIR' in line:
                    assert phase == "contents-sync", line
                    point = phase = "directory-unlink"
                elif call == "fsync" and f"<{root}/artifacts>" in line and phase == "directory-unlink":
                    point = phase = "parent-sync"
                elif call == "unlink" and "inventory.db-journal" in line and phase == "parent-sync":
                    point = phase = "tombstone-commit"
                if point:
                    assert " = 0" in line, line
                    checkpoints[point] = call, ordinals[call]
            assert set(checkpoints) == {"intent-before-marker", "marker-unlink", "marker-sync", "content-unlink",
                                        "contents-sync", "directory-unlink", "parent-sync", "tombstone-commit"}, checkpoints

            def paused(root, cfg, label):
                call, ordinal = checkpoints[label]
                trace = base / f"{root.name}.trace"
                child = spawn(["strace", "-yy", "-e", f"trace={trace_calls}", "-e",
                               f"inject={call}:delay_exit=60s:when={ordinal}", "-o", str(trace),
                               *command(cfg, *execution(plan))])
                wait_for(lambda: trace.exists() and "(DELAYED)" in trace.read_text(), label)
                delayed = next(s for s in trace.read_text().splitlines() if "(DELAYED)" in s)
                assert " = 0 " in delayed and str(root) in delayed, delayed
                if label == "tombstone-commit":
                    assert "inventory.db-journal" in delayed, delayed
                elif label == "intent-before-marker":
                    assert delayed.startswith("close(") and f"/artifacts/{first}/" in delayed, delayed
                elif label == "marker-unlink":
                    assert '"complete"' in delayed and first in delayed, delayed
                elif label in ("marker-sync", "content-unlink", "contents-sync"):
                    assert first in delayed, delayed
                elif label == "directory-unlink":
                    assert first in delayed and "AT_REMOVEDIR" in delayed, delayed
                observed = root
                if label == "tombstone-commit":
                    # SQLite still holds its write lock while unlink's return is delayed.
                    # The removed journal is the durable commit point; inspect a quiet copy.
                    observed = base / f"{root.name}-committed-copy"
                    observed.mkdir()
                    shutil.copyfile(root / "inventory.db", observed / "inventory.db")
                state = "deleted" if label == "tombstone-commit" else "deleting"
                assert sql(observed, "SELECT state FROM artifact WHERE backup_id=?", (first,)) == [(state,)]
                assert (root / "artifacts" / first / "complete").exists() == (label == "intent-before-marker")
                deleted_events = sql(observed, "SELECT 1 FROM audit_event WHERE action='artifact_deleted' AND backup_id=?", (first,))
                assert len(deleted_events) == (1 if label == "tombstone-commit" else 0)
                return child

            for label in checkpoints:
                root, cfg = crash_copy(f"crash-{label}")
                untouched = {a: tree(root / "artifacts" / a) for a in pending + plan["retained"]}
                child = paused(root, cfg, label)
                if label == "marker-sync":
                    # The loser cannot start, even using the same confirmed plan.
                    unchanged_refusal(root, cfg, execution(plan), "RETENTION_BUSY")
                    before = (root / "inventory.db").read_bytes(), artifacts(root)
                    rejected = ctl(cfg, "restore", "run", restore_id, "--confirm-target", TARGET, ok=False)
                    assert "clearing this store" in rejected.stderr, rejected.stderr
                    assert before == ((root / "inventory.db").read_bytes(), artifacts(root))
                    assert pg(f"SELECT count(*) FROM pg_database WHERE datname='{TARGET}'", "postgres") == "0"
                kill(child)
                # Reads are observational; lifecycle state refuses use before explicit recovery.
                before = (root / "inventory.db").read_bytes(), artifacts(root)
                ctl(cfg, "inventory", "list")
                ctl(cfg, "backup", "inspect", first, ok=False)
                assert before == ((root / "inventory.db").read_bytes(), artifacts(root))
                no_keys = config(f"recover-{label}", root, keyless=True, no_tools=True)
                recovered = ctl(no_keys, "inventory", "recover")
                assert recovered["deleted"] == ([] if label == "tombstone-commit" else [first])
                assert not (root / "artifacts" / first).exists()
                assert all(tree(root / "artifacts" / a) == h for a, h in untouched.items())
                assert sql(root, "SELECT state FROM artifact WHERE backup_id=?", (first,)) == [("deleted",)]
                assert sql(root, "SELECT DISTINCT current FROM verification_event WHERE backup_id=?", (first,)) == [(0,)]
                deletion_job = sql(root, "SELECT job_id FROM deletion_job WHERE plan_id=?", (plan["plan_id"],))[0][0]
                assert sql(root, "SELECT state FROM job WHERE job_id=?", (deletion_job,)) == [("interrupted",)]
                assert not sql(root, "SELECT 1 FROM audit_event WHERE job_id=? AND action='job_completed'", (deletion_job,))
                before = (root / "inventory.db").read_bytes()
                partial = execute(cfg, plan, ok=False)
                report = json.loads(partial.stdout)
                assert report["completed"] == [first] and report["deleting"] == [] and report["pending"] == pending
                assert not report["audit_recorded"] and "DELETION_RECOVERY_REQUIRED" in partial.stderr
                assert ctl(no_keys, "inventory", "recover")["deleted"] == []
                assert (root / "inventory.db").read_bytes() == before
            print(f"PostgreSQL {major}: competing deleter/restore refused; eight real intent/marker/content/directory/tombstone crash boundaries and started-only keyless recovery passed", flush=True)

            for damage in ("missing-plan", "changed-plan", "extra-file", "changed-bytes"):
                root, cfg = crash_copy(f"recovery-{damage}")
                child = paused(root, cfg, "marker-sync")
                kill(child)
                saved = root / "plans" / f'deletion-{plan["plan_id"]}.json'
                if damage == "missing-plan":
                    saved.unlink()
                elif damage == "changed-plan":
                    body = json.loads(saved.read_text())
                    body["digest"] = "0" * 64
                    saved.write_text(json.dumps(body))
                elif damage == "extra-file":
                    (root / "artifacts" / first / "unexpected").write_text("unplanned")
                else:
                    payload = root / "artifacts" / first / "payload.age"
                    body = bytearray(payload.read_bytes())
                    body[-1] ^= 1
                    payload.write_bytes(body)
                before = artifacts(root)
                reject(config(f"unsafe-{damage}", root, keyless=True, no_tools=True),
                       "inventory", "recover", code="DELETION_RECOVERY_REQUIRED")
                assert artifacts(root) == before
                assert all((root / "artifacts" / a / "complete").is_file() for a in pending)

            # A handled post-unlink audit failure reports its precise durable partition.
            root, cfg = crash_copy("handled-failure")
            sql(root, "CREATE TRIGGER refuse_deleted BEFORE INSERT ON audit_event WHEN NEW.action='artifact_deleted' BEGIN SELECT RAISE(ABORT,'injected'); END")
            # Trigger creation changes the inventory, so obtain new confirmed intent.
            partial_plan = preview(cfg)
            result = json.loads(execute(cfg, partial_plan, ok=False).stdout)
            assert result["completed"] == [] and result["deleting"] == [first] and result["pending"] == pending
            assert sorted(result["completed"] + result["deleting"] + result["pending"]) == partial_plan["candidates"]
            assert result["audit_recorded"] and result["outcome"] == "partial"
            sql(root, "DROP TRIGGER refuse_deleted")
            assert ctl(config("handled-keyless", root, keyless=True, no_tools=True), "inventory", "recover")["deleted"] == [first]
            assert sql(root, "SELECT state FROM job WHERE job_id=?", (result["job_id"],)) == [("failed",)]

            root, cfg = crash_copy("restore-wins")
            (base / "pause-restore").touch()
            child = spawn(command(cfg, "restore", "run", restore_id, "--confirm-target", TARGET))
            wait_for(lambda: (base / "restore-started").exists(), "native restore held")
            unchanged_refusal(root, cfg, execution(plan), "RETENTION_BUSY")
            (base / "pause-restore").unlink()
            assert child.wait(timeout=150) == 0
            assert pg("SELECT count(*) FROM app.accounts", TARGET) == pg("SELECT count(*) FROM app.accounts")
            print(f"PostgreSQL {major}: unsafe recovery evidence, honest partial JSON and reverse native restore/delete contention passed", flush=True)

            secrets = [FAKE_PASSWORD.encode()]
            for name in ("identity", "signing"):
                value = (keys / f"{name}.key").read_text().splitlines()[1]
                secrets += [value.encode(), bytes.fromhex(value)]
                if name == "signing":
                    for part in (value[:64], value[64:]):
                        secrets += [part.encode(), bytes.fromhex(part)]
            metadata = [DATABASE.encode(), TARGET.encode(), PROFILE.encode(), b"127.0.0.1"]
            tokens = secrets + metadata
            def private_hits(blob):
                return {i for i, token in enumerate(tokens) if token in blob}
            for path in base.rglob("*"):
                if path.is_file() and ("inventory.db" in path.name or path.name.startswith("deletion-")):
                    assert not private_hits(path.read_bytes()), path
            assert all(not any(token in output for token in secrets) for output in captures)
            for _, log in children:
                log.flush()
                log.seek(0)
                output = log.read().encode()
                assert not any(token in output for token in secrets), "secret in child output"
            # A populated SQLite positive control exercises the same scanner as real ledgers.
            positive = base / "privacy-positive.db"
            shutil.copyfile(seed / "inventory.db", positive)
            with contextlib.closing(sqlite3.connect(positive)) as db:
                db.execute("CREATE TABLE privacy_control (value BLOB)")
                db.executemany("INSERT INTO privacy_control VALUES (?)", [(v,) for v in tokens])
                db.commit()
            assert private_hits(positive.read_bytes()) == set(range(len(tokens)))
            print(f"PostgreSQL {major}: raw ledger/plan and captured report privacy checks passed", flush=True)
        finally:
            for child, log in children:
                if child.poll() is None:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
                log.seek(0)
                if sys.exc_info()[0] is not None:
                    print(log.read(), flush=True)
                log.close()
            run(["docker", "rm", "-f", container])
print("M5b: PostgreSQL 16/17/18 destructive/race/crash retention drill passed", flush=True)
PY
