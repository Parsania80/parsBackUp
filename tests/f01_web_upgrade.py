"""Accept the fixture web packages on a disposable Debian 13 systemd target."""

import argparse
import base64
import hashlib
from http.client import HTTPSConnection
import json
from pathlib import Path
import re
import secrets
import ssl
import sys
import uuid

sys.dont_write_bytecode = True
from p02_worker_drill import ROOT, eventually, run
from p03_http_drill import Client, browser_session
from p04_api_acceptance import BACKUP, operation, plan, restore_request


class TlsClient(Client):
    def __init__(self, port, certificate):
        super().__init__(port)
        self.origin = f"https://127.0.0.1:{port}"
        self.context = ssl.create_default_context(cadata=certificate)

    def connect(self):
        return HTTPSConnection("127.0.0.1", self.port, context=self.context, timeout=8)

    def get_file(self, path, status):
        conn = self.connect()
        try:
            conn.request("GET", path)
            response = conn.getresponse()
            assert response.status == status, (path, response.status)
            return response.read(), dict(response.getheaders())
        finally:
            conn.close()


SOURCE = "backupctl_fixture_web"
BEFORE = "backupctl_fixture_web_before"
AFTER = "backupctl_fixture_web_after"
API = "backup-api.service"


def facts(ex):
    # No raw control records, credentials, or artifact paths are persisted as evidence.
    script = """
import hashlib, pathlib
paths = [pathlib.Path(p) for p in
         ('/etc/backupctl', '/etc/nginx/tls', '/var/lib/backupctl', '/var/lib/backup-api')]
h = hashlib.sha256()
files = [pathlib.Path('/etc/nginx/conf.d/backupctl-web.conf')]
for root in paths:
    files.extend([root, *sorted(root.rglob('*'))])
for p in files:
    st = p.stat()
    h.update(repr((str(p), st.st_uid, st.st_gid, st.st_mode)).encode())
    if p.is_file():
        h.update(hashlib.sha256(p.read_bytes()).digest())
print(h.hexdigest())
"""
    return ex("python3", "-", content=script).stdout.strip()


def install_fixture(ex, origin):
    def put(path, body, owner="backupctl"):
        ex("install", "-m", "600", "-o", owner, "-g", owner, "/dev/null", path)
        ex("tee", path, content=body)

    password = secrets.token_urlsafe(32)
    ex("pg_ctlcluster", "17", "main", "start")
    ex("runuser", "-u", "postgres", "--", "psql", "-Xq", "-v", "ON_ERROR_STOP=1",
       content=rf"""
CREATE ROLE web_fixture LOGIN CREATEDB PASSWORD '{password}';
CREATE DATABASE {SOURCE} OWNER web_fixture;
\c {SOURCE}
SET ROLE web_fixture;
CREATE TABLE sample(n integer PRIMARY KEY);
INSERT INTO sample VALUES (42);
""")
    put("/etc/backupctl/credentials/passfile", "".join(
        f"127.0.0.1:5432:{db}:web_fixture:{password}\n" for db in (SOURCE, "postgres", BEFORE, AFTER)))
    writer = (ROOT / "deploy/writer.example.toml").read_text().replace(
        "backupctl_fixture_example", SOURCE).replace("backup_reader", "web_fixture")
    put("/etc/backupctl/profiles/web-writer.toml", writer)
    reader = re.sub(r"^(recipient_file|signing_key_file) = .*\n", "", writer, flags=re.M)
    put("/etc/backupctl/profiles/web-reader.toml", reader.replace('access = "writer"', 'access = "reader"'))
    ex("runuser", "-u", "backupctl", "--", "/usr/bin/backupctl",
       "--config", "/etc/backupctl/profiles/web-writer.toml", "key", "generate")
    raw = secrets.token_bytes(32)
    token = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    put("/etc/backupctl/credentials/web-registry.json", json.dumps({
        "format": "api-credentials-v1", "credentials": [{
            "actor_id": str(uuid.uuid4()), "credential_id": str(uuid.uuid4()),
            "revision": 1, "active": True, "roles": ["admin"],
            "token_sha256": hashlib.sha256(raw).hexdigest(),
        }],
    }))
    put("/etc/backupctl/api.toml", f"""
format = "api-config-v1"
listen = "127.0.0.1:8090"
public_origin = "{origin}"
development_http = false
control_database = "/var/lib/backup-api/control.sqlite"
credential_registry = "/etc/backupctl/credentials/web-registry.json"
[[profiles]]
id = "default"
display_name = "F01 packaged web fixture"
writer_config = "/etc/backupctl/profiles/web-writer.toml"
reader_config = "/etc/backupctl/profiles/web-reader.toml"
operations = ["backup", "inspection", "verification", "restore_plan", "restore"]
""")
    return token


def start_tls(ex):
    ex("install", "-d", "-m", "700", "/etc/nginx/tls")
    crt, key = (f"/etc/nginx/tls/backupctl-web.{suffix}" for suffix in ("crt", "key"))
    ex("openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
       "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
       "-keyout", key, "-out", crt)
    ex("chmod", "600", key)
    sample = "/usr/share/backupctl-web/examples/backupctl-web.conf"
    site = "/etc/nginx/conf.d/backupctl-web.conf"
    # Bind to the container interface for Docker's random loopback-only host port.
    ex("tee", site, content=ex("sed", "s/listen 127.0.0.1:8443/listen 8443/", sample).stdout)
    ex("rm", "-f", "/etc/nginx/sites-enabled/default")
    ex("nginx", "-t")
    ex("systemctl", "reload-or-restart", "nginx")
    return ex("cat", crt).stdout


def index_assets(client):
    html, headers = client.get_file("/", 200)
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "no-cache" in headers["Cache-Control"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assets = set(re.findall(rb'''(?:src|href)="(/assets/[^"]+)"''', html))
    assert assets and any(path.endswith(b".js") for path in assets)
    for path in assets:
        client.get_file(path.decode(), 200)
    return assets


def verify_upgrade(ex, client, token, initial, updated):
    def start():
        ex("systemctl", "daemon-reload")
        ex("systemctl", "start", API)

        def ready():
            try:
                view, _ = client.request("GET", "/health", 200, actor=token)
                return view["job_admission"] and not view["production_enabled"]
            except (OSError, ValueError):
                return False

        eventually(ready)
        assert ex("stat", "-c", "%U:%G:%a", "/var/lib/backup-api").stdout.strip() == "backupctl:backupctl:700"

    def sql(db, statement):
        return ex("runuser", "-u", "postgres", "--", "psql", "-XAt", "-v", "ON_ERROR_STOP=1",
                  "-d", db, "-c", statement).stdout.strip()

    start()
    before_assets = index_assets(client)
    client.request("GET", "/health", 403, actor=token, headers={"Host": "unexpected.invalid"},
                   code="ACCESS_DENIED")
    _, cookie = browser_session(client, token)
    assert cookie.startswith("__Host-backupctl=") and "; Secure" in cookie
    session = {"Cookie": cookie.split(";", 1)[0]}
    client.request("GET", "/session", 200, headers=session)

    key = str(uuid.uuid4())
    backup = client.finish(client.submit("/backups", token, BACKUP, key), token)
    artifact = backup["result"]["artifact_id"]
    assert operation(client, "/verifications", token, {"artifact_id": artifact, "level": "archive"})[
        "result"]["inventory_recorded"]
    intent = plan(client, token, artifact, BEFORE)
    restored = operation(client, "/restores", token, restore_request(intent, BEFORE))
    assert sql(BEFORE, "SELECT n FROM sample") == "42"
    print("Clean install: packaged Nginx site and systemd API verified and restored a signed backup.", flush=True)

    ex("systemctl", "stop", API)
    before = facts(ex)
    ex("dpkg", "-i", f"/packages/{updated.name}")
    assert facts(ex) == before, "Package upgrade changed operator files or durable state"
    version = ex("dpkg-query", "-W", "-f=${Version}", "backupctl-web").stdout
    assert updated.name == f"backupctl-web_{version}_amd64.deb" and updated.name != initial.name
    assert ex("systemctl", "is-active", API, check=False).returncode != 0
    assert ex("systemctl", "is-active", "nginx").stdout.strip() == "active"
    start()
    after_assets = index_assets(client)
    assert after_assets.isdisjoint(before_assets)
    for path in before_assets:
        client.get_file(path.decode(), 404)
    client.request("GET", "/session", 401, headers=session, code="AUTH_REQUIRED")
    retry, _ = client.request("POST", "/backups", 200, actor=token, body=BACKUP,
                              headers={"Idempotency-Key": key}, retry=True)
    assert retry == backup
    assert client.request("GET", f"/jobs/{restored['id']}", 200, actor=token)[0] == restored
    saved, _ = client.request("GET", f"/intents/{intent['id']}", 200, actor=token)
    assert saved["consumed_by_job_id"] == restored["id"]
    client.request("POST", "/restores", 409, actor=token, body=restore_request(intent, BEFORE),
                   headers={"Idempotency-Key": str(uuid.uuid4())}, code="INTENT_CONFLICT", retry=True)
    assert sql(BEFORE, "SELECT n FROM sample") == "42"
    assert sql("postgres", f"SELECT count(*) FROM pg_database WHERE datname='{AFTER}'") == "0"
    result = run("node", str(ROOT / "ui/scripts/release-acceptance.mjs"), content=json.dumps({
        "origin": client.origin, "token": token, "artifact": artifact, "target": AFTER,
    }), check=False, timeout=90)
    assert result.returncode == 0, result.stderr
    assert sql(AFTER, "SELECT n FROM sample") == "42"
    print(result.stdout, end="")
    print(f"Upgrade to {version}: new assets, old session revoked, original jobs, receipt, consumed intent, "
          "artifact and restored row preserved. The console restored the pre-upgrade archive to a second database.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("initial_web", type=Path)
    parser.add_argument("updated_web", type=Path)
    parser.add_argument("--image", default="backupctl-f01-web:debian13")
    args = parser.parse_args()
    cli, initial, updated = (p.resolve(strict=True) for p in (args.cli, args.initial_web, args.updated_web))
    assert cli.parent == initial.parent == updated.parent, "Place all packages in one directory"
    name = f"parsbackup-f01-web-{uuid.uuid4().hex[:12]}"
    run("docker", "run", "--pull=never", "-d", "--name", name, "--privileged",
        "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/run/lock", "-p", "127.0.0.1::8443",
        "-v", f"{cli.parent}:/packages:ro", args.image)

    def ex(*cmd, content=None, check=True):
        result = run("docker", "exec", "-i", name, *cmd, content=content, check=False)
        if check and result.returncode:
            diagnostic = result.stderr if content is None else "fixture stdin withheld"
            raise AssertionError(f"{cmd[:3]}: exit {result.returncode}: {diagnostic}")
        return result

    try:
        eventually(lambda: ex("systemctl", "is-system-running", check=False).stdout.strip()
                   in ("running", "degraded"))
        assert ex("cat", "/proc/1/comm").stdout.strip() == "systemd"
        assert ex("test", "!", "-e", "/var/lib/backup-api").returncode == 0
        ex("dpkg", "-i", f"/packages/{cli.name}", f"/packages/{initial.name}")
        ex("systemctl", "daemon-reload")
        ex("systemd-analyze", "verify", "/usr/lib/systemd/system/backup-api.service")
        assert ex("systemctl", "is-active", API, check=False).returncode != 0
        assert ex("test", "!", "-e", "/var/lib/backup-api").returncode == 0
        assert ex("test", "!", "-e", "/etc/backupctl/api.toml").returncode == 0
        assert ex("test", "!", "-e", "/etc/nginx/conf.d/backupctl-web.conf").returncode == 0
        address = run("docker", "port", name, "8443/tcp").stdout.strip()
        assert address.startswith("127.0.0.1:")
        client = TlsClient(int(address.rsplit(":", 1)[1]), start_tls(ex))
        token = install_fixture(ex, client.origin)
        print(ex("cat", "/etc/debian_version").stdout.strip(), ex("nginx", "-v").stderr.strip(),
              ex("pg_lsclusters", "--no-header").stdout.split()[0], flush=True)
        verify_upgrade(ex, client, token, initial, updated)
    finally:
        run("docker", "rm", "-f", "-v", name, check=False)


if __name__ == "__main__":
    main()
