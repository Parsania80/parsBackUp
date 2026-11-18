"""Drive the built fixture console through the real, supervised API."""

from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
import ssl
import sys
from threading import Thread
from urllib.parse import urlsplit
import uuid

sys.dont_write_bytecode = True
from p02_worker_drill import ROOT, SOURCE, TARGET, eventually, private, run
from p03_http_drill import http_fixture, start_supervised

DIST = (ROOT / "ui/dist").resolve()
REQUEST_HEADERS = {"host", "origin", "cookie", "content-type", "x-csrf-token", "idempotency-key"}
RESPONSE_HEADERS = {"cache-control", "content-type", "location", "retry-after",
                    "set-cookie", "www-authenticate"}


@contextmanager
def https_console(base, api_port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            if path.startswith("/api/v1/"):
                self.forward()
                return
            file = DIST / "index.html" if path == "/" else (DIST / path.lstrip("/")).resolve()
            if not file.is_relative_to(DIST) or not file.is_file():
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(file)[0] or "application/octet-stream")
            self.send_header("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(file.read_bytes())

        def forward(self):
            if not self.path.startswith("/api/v1/"):
                self.send_error(404)
                return
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= 16384 or self.headers.get("Transfer-Encoding"):
                self.send_error(413)
                return
            conn = HTTPConnection("127.0.0.1", api_port, timeout=10)
            try:
                conn.request(self.command, self.path, body=self.rfile.read(size) if size else None,
                             headers={k: v for k, v in self.headers.items() if k.lower() in REQUEST_HEADERS})
                response = conn.getresponse()
                body = response.read()
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() in RESPONSE_HEADERS:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                conn.close()

        do_POST = do_DELETE = forward

    key, cert = base / "https.key", base / "https.pem"
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
        "-keyout", str(key), "-out", str(cert))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            yield f"https://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            thread.join()


def main():
    assert (DIST / "index.html").is_file(), "Build ui/dist before running the drill"
    roles = ("admin-setup", "admin", "viewer", "backup")
    with http_fixture(".parsbackup-u02-", roles=roles) as (base, client, unit, container, actors):
        with https_console(base, client.port) as origin:
            config = base / "api.toml"
            private(config, config.read_text().replace(f'public_origin = "{client.origin}"',
                                                      f'public_origin = "{origin}"')
                    .replace("development_http = true", "development_http = false"))
            configure_profiles(base)
            start_supervised(unit, config)
            artifact, cancellable = prepare_jobs(base, client, urlsplit(origin).netloc, actors["admin-setup"][0])
            result = run("node", str(ROOT / "ui/scripts/browser-smoke.mjs"), content=json.dumps({
                "origin": origin, "token": actors["admin"][0], "viewer": actors["viewer"][0],
                "artifact": artifact, "target": TARGET, "cancellable": cancellable,
                "screenshot": os.environ.get("PARSBACKUP_U02_SCREENSHOT"),
                "backupToken": actors["backup"][0],
                "profileScreenshot": os.environ.get("PARSBACKUP_U03_SCREENSHOT"),
            }), timeout=120, check=False)
            print(result.stdout, end="")
            assert result.returncode == 0, result.stderr
            restored = run("docker", "exec", container, "psql", "-U", "postgres", "-d", TARGET,
                           "-Atc", "SELECT n FROM sample")
            assert restored.stdout.strip() == "42"
            print("PostgreSQL fixture confirmed the restored row")


def configure_profiles(base, daily_name="Daily fixture"):
    core_profile = f'''
[[profile]]
name = "sample-only"
database = "{SOURCE}"
tables = ["public.sample"]
'''
    for name in ("writer.toml", "reader.toml"):
        path = base / name
        private(path, path.read_text() + core_profile)
    config = base / "api.toml"
    private(config, config.read_text() + f'''
[[profiles]]
id = "daily"
display_name = {json.dumps(daily_name)}
reader_config = "{base}/reader.toml"
writer_config = "{base}/writer.toml"
core_profile = "sample-only"
operations = ["backup"]

[[profiles]]
id = "prune-only"
display_name = "Prune fixture"
reader_config = "{base}/reader.toml"
core_profile = "sample-only"
operations = ["retention_preview"]
''')


def prepare_jobs(base, client, host, token):
    def request(method, path, status, headers=None, body=None):
        return client.request(method, path, status, actor=token, body=body,
                              headers={"Host": host, **(headers or {})}, retry=True)[0]

    def ready():
        try:
            return request("GET", "/health", 200)["job_admission"]
        except OSError:
            return False

    eventually(ready)

    def backup():
        return request("POST", "/backups", 202, {"Idempotency-Key": str(uuid.uuid4())},
                       {"profile_id": None, "confirm_synthetic": True})

    job = backup()
    path = "/jobs/" + job["id"]

    def done():
        nonlocal job
        job = request("GET", path, 200)
        return job["state"] not in ("queued", "running")

    eventually(done)
    assert job["state"] == "succeeded", job["error"]
    mode = base / "tool-mode"
    private(mode, "cancel")
    cancellable = backup()
    eventually((base / "native-started").is_file)
    # pg_dump has already read the mode and signalled its pause.
    mode.unlink()
    return job["result"]["artifact_id"], cancellable["id"]


if __name__ == "__main__":
    main()
