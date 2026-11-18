"""Run keyboard, accessibility and recovery checks on the supervised console."""

import json
import os
import sqlite3
import sys
import time
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
from p02_worker_drill import PARTIAL_TARGET, ROOT, TARGET, eventually, private, run
from p03_http_drill import Client, http_fixture, listening, start_supervised
from p04_api_acceptance import BACKUP, clear_barrier, held_backup, operation, plan, restore_request, sql
from u02_console_drill import DIST, configure_profiles, https_console

LITERAL_NAME = '<em>Daily fixture</em> & "QA"'


class ProxiedClient(Client):
    def __init__(self, port, origin):
        super().__init__(port)
        self.host = urlsplit(origin).netloc

    def request(self, method, path, expected, *, headers=None, **options):
        return super().request(method, path, expected, headers={"Host": self.host, **(headers or {})}, **options)


def recovery_receipts(base, client, unit, container, token):
    artifact = operation(client, "/backups", token, BACKUP)["result"]["artifact_id"]
    intent = plan(client, token, artifact, PARTIAL_TARGET)
    mode = base / "tool-mode"
    private(mode, "restore-fail")
    try:
        partial = operation(client, "/restores", token, restore_request(intent, PARTIAL_TARGET), "partial")
    finally:
        mode.unlink()
    assert partial["effects"] == "database_may_be_modified"
    assert sql(container, "SELECT to_regclass('public.sample') IS NULL", PARTIAL_TARGET) == "t"

    held = held_backup(base, client, token)
    run("systemctl", "--user", "kill", "--kill-whom=main", "--signal=KILL", unit)
    eventually(lambda: run("systemctl", "--user", "show", "-p", "LoadState", "--value",
                           unit, check=False).stdout.strip() == "not-found")
    clear_barrier(base)
    start_supervised(unit, base / "api.toml")
    listening(client, token)
    interrupted = client.finish(held, token, "interrupted")
    assert interrupted["effects"] == "unknown"
    return artifact, partial["id"], interrupted["id"]


def expired_session(base, client, origin, token):
    _, headers = client.request("POST", "/session", 201, body={"token": token},
                                headers={"Origin": origin}, retry=True)
    expired = int(time.time() * 1000) - 1000
    with sqlite3.connect(base / "state/control.sqlite") as db:
        # This fixture has exactly one session after restart.
        assert db.execute("UPDATE sessions SET created=?,expires=?",
                          (expired - 28_800_000, expired)).rowcount == 1
    cookie = headers["set-cookie"].split(";", 1)[0]
    client.request("GET", "/session", 401, headers={"Cookie": cookie}, code="AUTH_REQUIRED")
    return cookie.split("=", 1)[1]


def browser(data):
    result = run("node", str(ROOT / "ui/scripts/browser-acceptance.mjs"),
                 content=json.dumps(data), check=False, timeout=120)
    print(result.stdout, end="")
    assert result.returncode == 0, result.stderr


def main():
    assert (DIST / "index.html").is_file(), "Build ui/dist before running acceptance"
    roles = ("admin-setup", "admin")
    with http_fixture(".parsbackup-u04-", roles=roles) as (base, listener, unit, container, actors):
        with https_console(base, listener.port) as origin:
            client = ProxiedClient(listener.port, origin)
            config = base / "api.toml"
            private(config, config.read_text().replace(f'public_origin = "{listener.origin}"',
                                                      f'public_origin = "{origin}"')
                    .replace("development_http = true", "development_http = false"))
            configure_profiles(base, LITERAL_NAME)
            start_supervised(unit, config)
            setup_token = actors["admin-setup"][0]
            token = actors["admin"][0]
            listening(client, setup_token)
            artifact, partial, interrupted = recovery_receipts(base, client, unit, container, setup_token)
            expired = expired_session(base, client, origin, token)
            browser({"origin": origin, "token": token, "expired": expired, "artifact": artifact,
                     "partial": partial, "interrupted": interrupted, "target": TARGET, "literal": LITERAL_NAME,
                     "screenshotDir": os.environ.get("PARSBACKUP_U04_SCREENSHOTS")})
            assert sql(container, "SELECT n FROM sample", TARGET) == "42"
            print("Verified live partial effects, interruption and keyboard-restored PostgreSQL row")
            writer = base / "writer.toml"
            original = writer.read_text()
            try:
                private(writer, original + "\n# U04 changes the default admission binding.\n")
                browser({"origin": origin, "token": token, "unavailable": True})
            finally:
                private(writer, original)


if __name__ == "__main__":
    main()
