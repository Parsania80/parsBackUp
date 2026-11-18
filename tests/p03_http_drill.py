"""Exercise the public v1 contract on loopback with the P02 PostgreSQL fixture."""

import base64
from contextlib import contextmanager
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
from p02_worker_drill import ROOT, TARGET, eventually, private, run, setup, tool_host

BINARY = ROOT / "target/debug/backup-api"
API = "/api/v1"


class Client:
    def __init__(self, port):
        self.port = port
        self.origin = f"http://127.0.0.1:{port}"
        self.check_response = None

    def connect(self):
        return HTTPConnection("127.0.0.1", self.port, timeout=8)

    def request(self, method, path, expected, *, actor=None, body=None, headers=None,
                code=None, retry=False):
        fields = {}
        if actor:
            fields["Authorization"] = f"Bearer {actor}"
        if body is not None:
            fields["Content-Type"] = "application/json"
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
        fields.update(headers or {})
        statuses = (expected,) if isinstance(expected, int) else expected
        for _ in range(30):
            conn = self.connect()
            try:
                conn.request(method, API + path, body=body, headers=fields)
                res = conn.getresponse()
                status, response_headers = res.status, dict(res.getheaders())
                response = json.loads(res.read())
            finally:
                conn.close()
            if status == 429 and retry:
                time.sleep(1.05)
                continue
            assert status in statuses, (method, path, status, response.get("error"))
            assert response_headers["cache-control"] == "no-store"
            assert response["api_version"] == "backupctl-api-v1"
            assert uuid.UUID(response["request_id"]).version == 4
            if code is not None:
                assert response["error"]["code"] == code, (method, path, response["error"])
                assert "data" not in response
            else:
                assert "error" not in response
            if self.check_response:
                self.check_response(method, API + path, status, response)
            return response.get("data"), response_headers
        raise AssertionError("actor rate limit never cleared")

    def submit(self, path, actor, body, key=None):
        key = key or str(uuid.uuid4())
        job, headers = self.request("POST", path, 202, actor=actor, body=body,
                                    headers={"Idempotency-Key": key}, retry=True)
        assert headers["location"] == job["url"]
        assert headers["retry-after"] == "2"
        return job

    def finish(self, job, actor, state="succeeded"):
        def finished():
            nonlocal job
            job, _ = self.request("GET", "/jobs/" + job["id"], 200, actor=actor, retry=True)
            return job["state"] not in ("queued", "running", "cancel_requested")

        eventually(finished)
        assert job["state"] == state, (job["operation"], job["state"], job["error"])
        return job


def credentials(base, roles=("admin", "viewer", "backup")):
    registry = {"format": "api-credentials-v1", "credentials": []}
    actors = {}
    for name in roles:
        role = name.split("-", 1)[0]
        secret = secrets.token_bytes(32)
        actor = str(uuid.uuid4())
        token = base64.urlsafe_b64encode(secret).decode().rstrip("=")
        registry["credentials"].append({
            "actor_id": actor, "credential_id": str(uuid.uuid4()), "revision": 1,
            "active": True, "roles": [role], "token_sha256": hashlib.sha256(secret).hexdigest(),
        })
        actors[name] = (token, actor)
    private(base / "registry.json", json.dumps(registry))
    return actors


def listening(client, token):
    def probe():
        try:
            client.request("GET", "/health", 200, actor=token, retry=True)
        except OSError:
            return False
        return True
    eventually(probe)


@contextmanager
def local_process(base):
    with subprocess.Popen([str(BINARY), "--read-only", str(base / "api.toml")],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as process:
        try:
            yield
        finally:
            if process.poll() is None:
                process.terminate()
            _, error = process.communicate(timeout=15)
            assert process.returncode == 0, (process.returncode, error.decode())


def browser_session(client, token, *, host=None):
    headers = {"Origin": client.origin}
    if host:
        headers["Host"] = host
    view, headers = client.request("POST", "/session", 201, body={"token": token}, headers=headers)
    session = headers["set-cookie"]
    assert all(x in session for x in ("HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=28800"))
    assert "Domain=" not in session
    return view, session


def read_only_drill(base, client, admin, viewer):
    with local_process(base):
        listening(client, admin)
        _, headers = client.request("GET", "/health", 401, code="AUTH_REQUIRED")
        assert headers["www-authenticate"] == "Bearer"
        client.request("GET", "/health", 403, actor=admin, headers={"Host": "invalid.test"}, code="ACCESS_DENIED")
        client.request("GET", "/health", 403, actor=admin, headers={"Origin": "https://invalid.test"}, code="ACCESS_DENIED")
        client.request("GET", "/metrics", 403, actor=viewer, code="ACCESS_DENIED")
        health, _ = client.request("GET", "/health", 200, actor=admin)
        assert health == {"ready": True, "mode": "fixture", "production_enabled": False,
                          "job_admission": False, "containment_verified": False, "queue_depth": 0}
        client.request("POST", "/backups", 503, actor=admin, code="CONTAINMENT_UNAVAILABLE",
                       headers={"Idempotency-Key": str(uuid.uuid4())},
                       body={"profile_id": None, "confirm_synthetic": True})
        assert client.request("GET", "/artifacts", 200, actor=viewer)[0] == {"items": [], "next_after": None}
        assert not (base / "store").exists()
        client.request("POST", "/session", 403, body={"token": viewer}, code="ACCESS_DENIED")
        view, cookie_header = browser_session(client, viewer)
        assert cookie_header.startswith("backupctl-dev=") and "Secure" not in cookie_header
        cookie = cookie_header.split(";", 1)[0]
        cookie_only = {"Cookie": cookie}
        logged_in = client.request("GET", "/session", 200, headers=cookie_only)[0]
        assert logged_in == view
        token = cookie.split("=", 1)[1]
        with sqlite3.connect(base / "state/control.sqlite") as db:
            assert db.execute("PRAGMA user_version").fetchone() == (2,)
            assert db.execute("SELECT token_sha256 FROM sessions").fetchone() == (
                hashlib.sha256(base64.urlsafe_b64decode(token + "=")).hexdigest(),)
        client.request("GET", "/session", 400, actor=viewer, headers=cookie_only, code="INVALID_REQUEST")
        client.request("DELETE", "/session", 403, headers=dict(cookie_only, Origin=client.origin), code="ACCESS_DENIED")
        revoked, headers = client.request("DELETE", "/session", 200, headers={
            "Cookie": cookie, "Origin": client.origin, "X-CSRF-Token": view["csrf_token"]})
        assert revoked == {"revoked": True} and "Max-Age=0" in headers["set-cookie"]
        client.request("GET", "/session", 401, headers=cookie_only, code="AUTH_REQUIRED")
        _, old = browser_session(client, viewer)
        for _ in range(3):
            browser_session(client, viewer)
        _, limited = client.request("POST", "/session", 429, body={"token": viewer},
                                    headers={"Origin": client.origin, "X-Forwarded-For": "192.0.2.1"},
                                    code="RATE_LIMIT")
        assert limited["retry-after"] == "1"
    with local_process(base):
        listening(client, admin)
        client.request("GET", "/session", 401, headers={"Cookie": old.split(";", 1)[0]}, code="AUTH_REQUIRED")
    print("Read-only mode, session custody, Origin/CSRF, logout and restart passed")


def proxy_cookie_drill(base, client, viewer):
    path = base / "api.toml"
    original = path.read_text()
    proxy_host = "fixture.example.test"
    proxy_origin = f"https://{proxy_host}"
    private(path, original.replace(client.origin, proxy_origin)
            .replace("development_http = true", "development_http = false"))
    try:
        with local_process(base):
            def probe():
                try:
                    client.request("GET", "/health", 200, actor=viewer, headers={"Host": proxy_host})
                except OSError:
                    return False
                return True
            eventually(probe)
            client.request("GET", "/health", 403, actor=viewer, code="ACCESS_DENIED")
            _, headers = client.request("POST", "/session", 201, body={"token": viewer},
                                        headers={"Host": proxy_host, "Origin": proxy_origin})
            cookie = headers["set-cookie"]
            assert cookie.startswith("__Host-backupctl=") and "; Secure" in cookie
    finally:
        private(path, original)
    print("HTTPS proxy Host and Secure cookie policy passed")


def supervised_drill(client, admin, viewer, backup, base):
    health, _ = client.request("GET", "/health", 200, actor=admin)
    assert health["ready"] and health["job_admission"] and health["containment_verified"]
    writer = base / "writer.toml"
    original = writer.read_text()
    private(writer, original + "\n# Change the default binding revision.\n")
    try:
        health, _ = client.request("GET", "/health", 200, actor=admin)
        assert not health["ready"] and not health["job_admission"]
        assert health["containment_verified"] and health["queue_depth"] == 0
        client.request("POST", "/backups", 409, actor=admin, code="CONFIG_CHANGED",
                       headers={"Idempotency-Key": str(uuid.uuid4())},
                       body={"profile_id": None, "confirm_synthetic": True})
    finally:
        private(writer, original)
    health, _ = client.request("GET", "/health", 200, actor=admin)
    assert health["ready"] and health["job_admission"]
    profiles, _ = client.request("GET", "/profiles", 200, actor=backup)
    assert profiles["items"][0]["operations"] == ["backup", "inspection", "verification"]
    client.request("GET", "/jobs?limit=2&limit=3", 400, actor=admin, code="INVALID_REQUEST")
    client.request("GET", "/jobs?unexpected=abc", 400, actor=admin, code="INVALID_REQUEST")
    key = str(uuid.uuid4())
    head = {"Idempotency-Key": key}
    request = {"profile_id": None, "confirm_synthetic": True}
    client.request("POST", "/backups", 403, actor=viewer, body=request, headers=head, code="ACCESS_DENIED")
    client.request("POST", "/backups", 413, actor=admin, body=b" " * 16385, headers=head, code="BODY_TOO_LARGE")
    client.request("POST", "/backups", 415, actor=admin, body=request,
                   headers=dict(head, **{"Content-Encoding": "gzip"}), code="UNSUPPORTED_MEDIA")
    client.request("POST", "/backups", 400, actor=admin, headers=head,
                   body=b'{"profile_id":null,"confirm_synthetic":true,"confirm_synthetic":true}', code="INVALID_REQUEST")
    client.request("POST", "/backups", 400, actor=admin, headers=head,
                   body=dict(request, connection="unused"), code="INVALID_REQUEST")
    first = client.submit("/backups", admin, request, key)
    client.request("POST", "/backups", 409, actor=admin, headers=head,
                   body=dict(request, profile_id="different"), code="IDEMPOTENCY_CONFLICT")
    first = client.finish(first, admin)
    artifact_id = first["result"]["artifact_id"]
    replay, _ = client.request("POST", "/backups", 200, actor=admin, body=request, headers=head, retry=True)
    assert replay["id"] == first["id"]
    client.request("GET", "/jobs/" + first["id"], 404, actor=backup, code="NOT_FOUND")
    second = client.finish(client.submit("/backups", backup, request), backup)
    retained = second["result"]["artifact_id"]
    jobs, _ = client.request("GET", "/jobs", 200, actor=backup)
    assert [j["id"] for j in jobs["items"]] == [second["id"]]
    jobs, _ = client.request("GET", "/jobs?limit=1", 200, actor=admin)
    assert jobs["next_after"] == jobs["items"][0]["id"]
    artifacts, _ = client.request("GET", "/artifacts?limit=1", 200, actor=viewer)
    cursor = artifacts["next_after"]
    assert cursor == artifacts["items"][0]["artifact_id"]
    following, _ = client.request("GET", f"/artifacts?after={cursor}", 200, actor=viewer)
    assert {cursor, following["items"][0]["artifact_id"]} == {artifact_id, retained}
    one, _ = client.request("GET", "/artifacts/" + artifact_id, 200, actor=viewer)
    assert one == {"artifact_id": artifact_id, "format": "signed-artifact-v1", "header_status": "unverified"}
    inspected = client.finish(client.submit("/inspections", admin, {"artifact_id": artifact_id}), admin)
    assert inspected["result"]["source_major"] == 17
    unsigned = base / "store/artifacts" / str(uuid.uuid4())
    unsigned.mkdir(mode=0o700)
    (unsigned / "complete").touch()
    for i in range(4096):
        (unsigned.parent / f"overflow-{i}").touch()
    client.request("GET", "/artifacts", 503, actor=viewer, code="DISCOVERY_LIMIT")
    for path in unsigned.parent.glob("overflow-*"):
        path.unlink()
    (unsigned / "complete").unlink()
    unsigned.rmdir()
    for artifact in (artifact_id, retained):
        verified = client.finish(client.submit("/verifications", admin,
                                              {"artifact_id": artifact, "level": "archive"}), admin)
        assert verified["result"]["passed"]
    plan = client.finish(client.submit("/restore-plans", admin, {
        "artifact_id": retained, "target_database": TARGET, "security": "portable", "sections": "full",
        "acknowledge_older_snapshot": False, "confirm_synthetic": True,
    }), admin)["result"]["intent"]
    fetched, _ = client.request("GET", "/intents/" + plan["id"], 200, actor=admin, retry=True)
    assert fetched == plan
    client.request("GET", "/intents/" + plan["id"], 404, actor=backup, code="NOT_FOUND")
    restored = client.finish(client.submit("/restores", admin, {
        "intent_id": plan["id"], "confirm_digest": plan["digest"], "confirm_target": TARGET,
        "confirm_synthetic": True,
    }), admin)
    assert restored["result"]["target_database"] == TARGET
    protection = client.finish(client.submit("/artifact-protections", admin, {
        "artifact_id": retained, "protected": True, "reason": "Fixture retained copy",
    }), admin)
    assert protection["result"]["protected"]
    preview = client.finish(client.submit("/retention-previews", admin, {
        "operation": "delete", "artifact_id": artifact_id,
    }), admin)["result"]["intent"]
    deleted = client.finish(client.submit("/retention-runs", admin, {
        "intent_id": preview["id"], "confirm_digest": preview["digest"],
    }), admin)
    assert deleted["result"]["completed"] == [artifact_id]
    client.request("GET", "/artifacts/" + artifact_id, 404, actor=viewer, code="NOT_FOUND")
    view, header = browser_session(client, admin)
    cookie = header.split(";", 1)[0]
    (base / "tool-mode").write_text("cancel")
    pending = client.submit("/backups", admin, request)
    eventually(lambda: (base / "native-started").exists())
    client.request("POST", "/jobs/" + pending["id"] + "/cancel", 403, body={}, code="ACCESS_DENIED",
                   headers={"Cookie": cookie, "Origin": client.origin, "Idempotency-Key": str(uuid.uuid4())})
    client.request("POST", "/jobs/" + pending["id"] + "/cancel", 200, body={}, retry=True,
                   headers={"Cookie": cookie, "Origin": client.origin,
                            "X-CSRF-Token": view["csrf_token"], "Idempotency-Key": str(uuid.uuid4())})
    client.finish(pending, admin, "cancelled")
    counters, _ = client.request("GET", "/metrics", 200, actor=admin, retry=True)
    assert counters["accepted_total"] == 11 and counters["cancelled_total"] == 1
    assert counters["succeeded_total"] == 10 and counters["rejected_total"] >= 8
    print("Supervised HTTP job submission, permissions, paging, restore, retention and CSRF cancellation passed")


def start_supervised(unit, config):
    settings = {"Type", "UMask", "TimeoutStopSec", "KillMode", "KillSignal", "FinalKillSignal",
                "SendSIGKILL", "Delegate", "Restart", "NoNewPrivileges", "TasksMax", "MemoryMax"}
    properties = [f"--property={line}" for line in (ROOT / "deploy/systemd/backup-api.service")
                  .read_text().splitlines() if line.partition("=")[0] in settings]
    assert len(settings) == len(properties)
    run("systemd-run", "--user", "--collect", f"--unit={unit}", *properties,
        str(BINARY), "--supervise", str(config))


@contextmanager
def http_fixture(prefix, roles=("admin", "viewer", "backup")):
    unit = f"parsbackup-p02-{os.getpid()}.service"
    container = unit.removesuffix(".service")
    tools = Path("/opt") / f"{container}-{uuid.uuid4().hex}"
    assert not tools.exists()
    with tempfile.TemporaryDirectory(prefix=prefix, dir=Path.home()) as directory:
        base = Path(directory)
        try:
            setup(base, container, tools)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            client = Client(port)
            config = base / "api.toml"
            private(config, config.read_text().replace("127.0.0.1:8090", f"127.0.0.1:{port}"))
            actors = credentials(base, roles)
            yield base, client, unit, container, actors
        finally:
            run("systemctl", "--user", "stop", unit, check=False)
            run("docker", "rm", "-f", "-v", container, check=False)
            tool_host("cleanup", tools)


def main():
    with http_fixture(".parsbackup-p03-") as (base, client, unit, container, actors):
        admin, viewer, backup = (actors[role][0] for role in ["admin", "viewer", "backup"])
        read_only_drill(base, client, admin, viewer)
        proxy_cookie_drill(base, client, viewer)
        start_supervised(unit, base / "api.toml")
        listening(client, admin)
        supervised_drill(client, admin, viewer, backup, base)
        result = run("docker", "exec", container, "psql", "-U", "postgres", "-d", TARGET,
                     "-Atc", "SELECT n FROM sample")
        assert result.stdout.strip() == "42"
        run("systemctl", "--user", "stop", unit)
        # Recreate the v1 layout around real P02-compatible job and intent rows.
        with sqlite3.connect(base / "state/control.sqlite") as db:
            db.executescript("DROP TABLE sessions; DROP INDEX jobs_actor_page; PRAGMA user_version=1;")
        with local_process(base):
            listening(client, admin)
            metrics, _ = client.request("GET", "/metrics", 200, actor=admin)
            assert metrics["accepted_total"] == 11 and metrics["cancelled_total"] == 1
            with sqlite3.connect(base / "state/control.sqlite") as db:
                assert db.execute("PRAGMA user_version").fetchone() == (2,)
        print("Control schema migration preserved existing jobs")


if __name__ == "__main__":
    main()
