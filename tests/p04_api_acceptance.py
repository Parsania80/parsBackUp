"""End-to-end fixture acceptance with live OpenAPI response validation."""

import hashlib
import json
import re
import sqlite3
import sys
import time
import uuid

sys.dont_write_bytecode = True
from jsonschema import Draft202012Validator, FormatChecker

from p02_worker_drill import CANCEL_TARGET, CRASH_TARGET, PARTIAL_TARGET, ROOT, TARGET, eventually, private, run
from p03_http_drill import browser_session, http_fixture, listening, start_supervised

CLI = ROOT / "target/debug/backupctl"
BACKUP = {"profile_id": None, "confirm_synthetic": True}
NATIVE_DIAGNOSTIC = "P04_NATIVE_PRIVATE_DIAGNOSTIC"


class Contract:
    def __init__(self, forbidden):
        spec = json.loads((ROOT / "docs/api/openapi-v1.json").read_text())
        self.forbidden = [*forbidden, NATIVE_DIAGNOSTIC]
        self.paths = []
        self.responses = set()
        for path, operations in spec["paths"].items():
            pattern = re.sub(r"\{[^}]+\}", "[^/]+", path)
            self.paths.append((re.compile(pattern), operations))
        self.components = spec["components"]
        self.schemas = {}

    def __call__(self, method, path, status, response):
        method = method.lower()
        path = path.partition("?")[0]
        route, operations = next((pattern.pattern, operations) for pattern, operations in self.paths
                                 if pattern.fullmatch(path) and method in operations)
        schema = self.schemas.get((route, method, status))
        if schema is None:
            definition = operations[method]["responses"][str(status)]
            if "$ref" in definition:
                definition = self.components["responses"][definition["$ref"].rsplit("/", 1)[1]]
            schema = Draft202012Validator(
                dict(definition["content"]["application/json"]["schema"], components=self.components),
                format_checker=FormatChecker(),
            )
            self.schemas[route, method, status] = schema
        schema.validate(response)
        assert not any(value in json.dumps(response) for value in self.forbidden), "private data in response"
        self.responses.add((route, method, status))


def post(client, path, actor, payload, status, *, code=None, key=None, retry=False):
    return client.request("POST", path, status, actor=actor, body=payload, code=code,
                          headers={"Idempotency-Key": key or str(uuid.uuid4())}, retry=retry)[0]


def operation(client, path, actor, payload, state="succeeded"):
    return client.finish(client.submit(path, actor, payload), actor, state)


def plan(client, actor, artifact, target):
    return operation(client, "/restore-plans", actor, {
        "artifact_id": artifact, "target_database": target, "security": "portable",
        "sections": "full", "acknowledge_older_snapshot": False, "confirm_synthetic": True,
    })["result"]["intent"]


def restore_request(intent, target):
    return {"intent_id": intent["id"], "confirm_digest": intent["digest"],
            "confirm_target": target, "confirm_synthetic": True}


def read_intent(client, actor, intent):
    return client.request("GET", f"/intents/{intent['id']}", 200, actor=actor, retry=True)[0]


def sql(container, statement, db="postgres"):
    return run("docker", "exec", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
               "-d", db, "-Atc", statement).stdout.strip()


def target_exists(container, name):
    assert name in (TARGET, PARTIAL_TARGET, CANCEL_TARGET, CRASH_TARGET)
    return sql(container, f"SELECT count(*) FROM pg_database WHERE datname='{name}'") == "1"


def cli_reader(base, *args):
    result = run(str(CLI), "--config", str(base / "reader.toml"), "--output", "json-v1", *args)
    return json.loads(result.stdout)["data"]


def change_actor(base, actor_id, active):
    registry = base / "registry.json"
    data = json.loads(registry.read_text())
    entry = next(entry for entry in data["credentials"] if entry["actor_id"] == actor_id)
    entry["active"] = active
    update = registry.with_suffix(".next")
    private(update, json.dumps(data))
    update.replace(registry)


def expire_intent(base, intent):
    # Age a real plan in the isolated fixture instead of changing the host clock.
    # Keep the canonical binding internally valid while moving its time window.
    with sqlite3.connect(base / "state/control.sqlite") as db:
        raw = db.execute("SELECT binding FROM intents WHERE id=?", [intent["id"]]).fetchone()[0]
        binding = json.loads(raw)
        binding["expires_unix_ms"] = int(time.time() * 1000) - 1
        binding["created_unix_ms"] = binding["expires_unix_ms"] - 900_000
        raw = json.dumps(binding, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(b"backupctl-api-intent-v1\0" + raw.encode()).hexdigest()
        db.execute("UPDATE intents SET binding=?,digest=? WHERE id=?", (raw, digest, intent["id"]))
    return dict(intent, digest=digest)


def confirmation_and_equivalence(base, client, container, admin, other):
    first = operation(client, "/backups", admin, BACKUP)["result"]["artifact_id"]
    newest = operation(client, "/backups", admin, BACKUP)["result"]["artifact_id"]
    for artifact in [first, newest]:
        inspected = operation(client, "/inspections", admin, {"artifact_id": artifact})["result"]
        manifest = cli_reader(base, "backup", "inspect", artifact)
        assert inspected["artifact_id"] == manifest["backup_id"]
        assert inspected["database"] == manifest["profile_snapshot"]["database"]
        assert inspected["source_major"] == manifest["source_server_major"]
        verified = operation(client, "/verifications", admin, {
            "artifact_id": artifact, "level": "archive",
        })["result"]
        cli_verified = cli_reader(base, "backup", "verify", artifact, "--level", "archive")
        assert verified["artifact_id"] == cli_verified["artifact_id"]
        assert verified["level"] == cli_verified["level"]
        assert verified["inventory_recorded"] == cli_verified["audit_recorded"] is True

    intent = plan(client, admin, newest, TARGET)
    request = restore_request(intent, TARGET)
    post(client, "/restores", other, request, 404, code="NOT_FOUND")
    post(client, "/restores", admin, dict(request, confirm_target=PARTIAL_TARGET), 409,
         code="INTENT_CONFLICT", retry=True)
    post(client, "/restores", admin, dict(request, confirm_digest="0" * 64), 409,
         code="INTENT_CONFLICT", retry=True)
    assert read_intent(client, admin, intent)["consumed_by_job_id"] is None
    assert not target_exists(container, TARGET)
    expired = expire_intent(base, plan(client, admin, newest, TARGET))
    post(client, "/restores", admin, restore_request(expired, TARGET), 410,
         code="INTENT_EXPIRED", retry=True)
    assert read_intent(client, admin, expired)["consumed_by_job_id"] is None

    key = str(uuid.uuid4())
    job = client.finish(client.submit("/restores", admin, request, key), admin)
    assert job["core_job_id"] and job["result"]["artifact_id"] == newest
    assert post(client, "/restores", admin, request, 200, key=key, retry=True)["id"] == job["id"]
    post(client, "/restores", admin, request, 409, code="INTENT_CONFLICT", retry=True)
    assert sql(container, "SELECT n FROM sample", TARGET) == "42"
    print("API/core inspection and archive verification agree. Restore ownership, digest, target, expiry and replay passed.")
    return first, newest


def partial_outcomes(base, client, container, admin, other, first, newest):
    intent = plan(client, admin, newest, PARTIAL_TARGET)
    (base / "tool-mode").write_text("restore-fail")
    try:
        receipt = operation(client, "/restores", admin, restore_request(intent, PARTIAL_TARGET), "partial")
    finally:
        (base / "tool-mode").unlink()
    assert receipt["effects"] == "database_may_be_modified"
    assert receipt["core_job_id"] and receipt["error"]["code"] == "OPERATION_FAILED"
    assert target_exists(container, PARTIAL_TARGET)
    assert sql(container, "SELECT to_regclass('public.sample') IS NULL", PARTIAL_TARGET) == "t"

    intent = plan(client, admin, newest, CANCEL_TARGET)
    (base / "tool-mode").write_text("restore-cancel")
    job = client.submit("/restores", admin, restore_request(intent, CANCEL_TARGET))
    eventually(lambda: (base / "native-started").exists())
    assert target_exists(container, CANCEL_TARGET)
    cancel(client, other, job)
    receipt = client.finish(job, admin, "partial")
    assert receipt["effects"] == "database_may_be_modified"
    assert receipt["core_job_id"] and receipt["error"]["code"] == "OPERATION_CANCELLED"
    assert target_exists(container, CANCEL_TARGET)
    clear_barrier(base)

    # Reject the final deletion audit after the fixture's core actually unlinks
    # the candidate. This is the same post-unlink failure used by the core drill.
    inventory = base / "store/inventory.db"
    with sqlite3.connect(inventory) as db:
        db.execute("CREATE TRIGGER p04_refuse_deleted BEFORE INSERT ON audit_event "
                   "WHEN NEW.action='artifact_deleted' BEGIN SELECT RAISE(ABORT,'p04-fixture'); END")
    intent = operation(client, "/retention-previews", admin, {
        "operation": "delete", "artifact_id": first,
    })["result"]["intent"]
    request = {"intent_id": intent["id"], "confirm_digest": intent["digest"]}
    post(client, "/retention-runs", other, request, 404, code="NOT_FOUND")
    post(client, "/retention-runs", admin, dict(request, confirm_digest="0" * 64), 409,
         code="INTENT_CONFLICT", retry=True)
    assert (base / "store/artifacts" / first / "complete").exists()
    assert read_intent(client, admin, intent)["consumed_by_job_id"] is None
    key = str(uuid.uuid4())
    receipt = client.finish(client.submit("/retention-runs", admin, request, key), admin, "partial")
    assert receipt["effects"] == "artifacts_may_be_deleted" and receipt["core_job_id"]
    result = receipt["result"]
    assert result["completed"] == [] and result["deleting"] == [first] and result["pending"] == []
    assert result["audit_recorded"]
    assert not (base / "store/artifacts" / first / "complete").exists()
    assert (base / "store/artifacts" / newest / "complete").exists()
    assert post(client, "/retention-runs", admin, request, 200, key=key, retry=True) == receipt
    post(client, "/retention-runs", admin, request, 409, code="INTENT_CONFLICT", retry=True)

    with sqlite3.connect(inventory) as db:
        db.execute("DROP TRIGGER p04_refuse_deleted")
    recovery = cli_reader(base, "inventory", "recover")
    assert first in recovery["deleted"]
    print("Partial restore and partial deletion receipts match actual effects. Native details were redacted.")


def failed_verification(base, client, admin, artifact):
    payload = base / "store/artifacts" / artifact / "payload.age"
    original = payload.read_bytes()
    changed = bytearray(original)
    changed[-1] ^= 1
    payload.write_bytes(changed)
    try:
        job = operation(client, "/verifications", admin,
                        {"artifact_id": artifact, "level": "signature"}, "failed")
        assert job["effects"] == "inventory_may_be_modified"
        assert job["error"]["code"] == "OPERATION_FAILED"
        with sqlite3.connect(base / "store/inventory.db") as db:
            outcome = db.execute("SELECT outcome FROM verification_event WHERE backup_id=? "
                                 "AND level='signature' ORDER BY event_id DESC LIMIT 1",
                                 [artifact]).fetchone()
            assert outcome == ("failure",), outcome
    finally:
        payload.write_bytes(original)
    operation(client, "/verifications", admin, {"artifact_id": artifact, "level": "archive"})
    print("Failed verification reports the persisted failure observation.")


def cancel(client, actor, job):
    return post(client, f"/jobs/{job['id']}/cancel", actor, {}, 200, retry=True)


def held_backup(base, client, actor):
    (base / "tool-mode").write_text("cancel")
    job = client.submit("/backups", actor, BACKUP)
    eventually(lambda: (base / "native-started").exists())
    return job


def clear_barrier(base):
    (base / "tool-mode").unlink()
    (base / "native-started").unlink()


def queue_and_revocation(base, client, admin, other, backup):
    token, actor_id = backup
    active = held_backup(base, client, admin)
    revoked = client.submit("/backups", token, BACKUP)
    queued = [client.submit("/backups", admin, BACKUP) for _ in range(15)]
    post(client, "/backups", other, BACKUP, 429, code="QUEUE_FULL")
    assert client.request("GET", "/health", 200, actor=other)[0]["queue_depth"] == 16
    _, cookie = browser_session(client, token)
    change_actor(base, actor_id, False)
    client.request("GET", "/health", 401, actor=token, code="AUTH_REQUIRED")
    client.request("GET", "/session", 401, code="AUTH_REQUIRED", headers={"Cookie": cookie.split(";", 1)[0]})
    for job in queued:
        assert cancel(client, other, job)["state"] == "cancelled"
    clear_barrier(base)
    cancel(client, other, active)
    client.finish(active, other, "cancelled")
    job = client.finish(revoked, other, "failed")
    assert job["error"]["code"] == "ACCESS_DENIED" and job["effects"] == "none"
    assert job["core_job_id"] is None
    print("HTTP queue cap, queued cancellation and revocation before dispatch passed.")


def crash_and_replay(base, client, unit, container, admin, other, artifact):
    intent = plan(client, admin, artifact, CRASH_TARGET)
    request = restore_request(intent, CRASH_TARGET)
    key = str(uuid.uuid4())
    _, session = browser_session(client, other)
    active = held_backup(base, client, other)
    queued = client.submit("/restores", admin, request, key)
    assert read_intent(client, admin, intent)["consumed_by_job_id"] == queued["id"]
    run("systemctl", "--user", "kill", "--kill-whom=main", "--signal=KILL", unit)
    eventually(lambda: run("systemctl", "--user", "show", "-p", "LoadState", "--value",
                           unit, check=False).stdout.strip() == "not-found")
    clear_barrier(base)
    start_supervised(unit, base / "api.toml")
    listening(client, admin)
    result = client.finish(active, other, "interrupted")
    assert result["effects"] == "unknown"
    replay = post(client, "/restores", admin, request, 200, key=key, retry=True)
    assert replay["id"] == queued["id"] and replay["state"] == "interrupted" and replay["effects"] == "none"
    post(client, "/restores", admin, request, 409, code="INTENT_CONFLICT", retry=True)
    client.request("GET", "/session", 401, code="AUTH_REQUIRED", headers={"Cookie": session.split(";", 1)[0]})
    assert not target_exists(container, CRASH_TARGET)
    assert read_intent(client, admin, intent)["consumed_by_job_id"] == queued["id"]
    print("Abrupt service exit preserved interrupted receipts and consumed intent without replay.")


def main():
    roles = ("admin", "admin-other", "backup")
    with http_fixture(".parsbackup-p04-", roles) as (base, client, unit, container, actors):
        admin, other = (actors[name][0] for name in roles[:2])
        checker = Contract([str(base), *(token for token, _ in actors.values())])
        client.check_response = checker
        start_supervised(unit, base / "api.toml")
        listening(client, admin)
        first, newest = confirmation_and_equivalence(base, client, container, admin, other)
        partial_outcomes(base, client, container, admin, other, first, newest)
        failed_verification(base, client, admin, newest)
        queue_and_revocation(base, client, admin, other, actors["backup"])
        crash_and_replay(base, client, unit, container, admin, other, newest)
        assert len(checker.responses) >= 20
        print(f"OpenAPI validated {len(checker.responses)} distinct live route/method/status combinations.")


if __name__ == "__main__":
    main()
