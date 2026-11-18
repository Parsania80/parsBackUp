"""Opt-in P02 drill with a local Docker fixture and real user systemd service."""

import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "docker.arvancloud.ir/library/postgres:17-bookworm"
SOURCE = "backupctl_fixture_p02"
TARGET = "backupctl_fixture_p02_restore"
PARTIAL_TARGET = "backupctl_fixture_p04_partial"
CANCEL_TARGET = "backupctl_fixture_p04_cancel"
CRASH_TARGET = "backupctl_fixture_p04_crash"


# Protected native adapters require ELF tools and clear the environment.
NATIVE_FIXTURE = r"""
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char mode[16] = {0};
    FILE *file = fopen(BASE "/tool-mode", "r");
    if (file) {
        if (!fgets(mode, sizeof mode, file)) return 4;
        fclose(file);
    }
    int version = argc == 2 && !strcmp(argv[1], "--version");
    if (!strcmp(TOOL, "pg_restore")) {
        for (int i = 1; i < argc; ++i) {
            if (strncmp(argv[i], "--dbname=", 9)) continue;
            if (!strcmp(mode, "restore-fail")) {
                fputs("P04_NATIVE_PRIVATE_DIAGNOSTIC\n", stderr);
                return 13;
            }
            if (!strcmp(mode, "restore-cancel")) {
                int started = open(BASE "/native-started", O_WRONLY | O_CREAT, 0600);
                if (started < 0) return 14;
                close(started);
                sleep(60);
            }
        }
    }
    if (!strcmp(TOOL, "pg_dump") && !version && !strcmp(mode, "cancel")) {
        int started = open(BASE "/native-started", O_WRONLY | O_CREAT, 0600);
        if (started < 0) return 5;
        close(started);
        sleep(60);
    }
    if (!strcmp(TOOL, "pg_dump") && !version && !strcmp(mode, "orphan")) {
        int ready[2];
        if (pipe(ready)) return 6;
        pid_t pid = fork();
        if (pid < 0) return 7;
        if (pid == 0) {
            if (setsid() < 0 || signal(SIGTERM, SIG_IGN) == SIG_ERR) _exit(8);
            close(0); close(1); close(2);
            close(ready[0]);
            FILE *marker = fopen(BASE "/orphan-pid", "w");
            if (!marker || fprintf(marker, "%d\n", getpid()) < 0 || fclose(marker)) _exit(9);
            if (write(ready[1], "x", 1) != 1) _exit(10);
            close(ready[1]);
            sleep(90);
            _exit(0);
        }
        close(ready[1]);
        char byte;
        if (read(ready[0], &byte, 1) != 1) return 11;
        close(ready[0]);
    }
    argv[0] = TOOL_ROOT "/" TOOL ".real";
    execv(argv[0], argv);
    return 12;
}
"""


def run(*args, content=None, check=True, timeout=120):
    return subprocess.run(args, input=content, text=True, capture_output=True,
                          check=check, timeout=timeout)


def private(path, text):
    path.write_text(text)
    path.chmod(0o600)


def eventually(predicate):
    for _ in range(150):
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("fixture did not reach its expected state")


def setup(base, container, installed_tools):
    # This secret is disposable synthetic fixture data, never included in evidence.
    password = secrets.token_hex(24)
    run("docker", "run", "-d", "--name", container, "--pull=never", "--tmpfs",
        "/var/lib/postgresql/data:rw", "-p", "127.0.0.1::5432",
        "-e", f"POSTGRES_PASSWORD={password}", "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
        "-e", f"POSTGRES_DB={SOURCE}", IMAGE)
    eventually(lambda: run("docker", "exec", container, "pg_isready", "-h",
                           "127.0.0.1", "-U", "postgres", check=False).returncode == 0)
    port = run("docker", "port", container, "5432/tcp").stdout.strip().rsplit(":", 1)[1]
    run("docker", "exec", "-i", container, "psql", "-U", "postgres", "-d", SOURCE,
        "-v", "ON_ERROR_STOP=1", content="CREATE TABLE sample (n int); INSERT INTO sample VALUES (42);")
    private(base / "passfile", "".join(
        f"127.0.0.1:{port}:{database}:postgres:{password}\n"
        for database in [SOURCE, TARGET, PARTIAL_TARGET, CANCEL_TARGET, CRASH_TARGET, "postgres"]))
    tools = base / "tools"
    tools.mkdir(mode=0o755)
    for tool in ["psql", "pg_dump", "pg_dumpall", "pg_restore", "createdb"]:
        run("docker", "cp", f"{container}:/usr/lib/postgresql/17/bin/{tool}", str(tools / tool))
        run(str(tools / tool), "--version")
    # Both readiness markers are written by the actual native invocation. The
    # orphan closes the inherited pipes so the worker can finish before checking.
    wrapper = base / "native-fixture.c"
    for tool in ["pg_dump", "pg_restore"]:
        binary = tools / tool
        binary.rename(tools / f"{tool}.real")
        wrapper.write_text(f"#define BASE {json.dumps(str(base))}\n"
                           f"#define TOOL_ROOT {json.dumps(str(installed_tools))}\n"
                           f"#define TOOL {json.dumps(tool)}\n" + NATIVE_FIXTURE)
        run("cc", "-Wall", "-Wextra", "-Werror", "-O2", str(wrapper), "-o", str(binary))
        binary.chmod(0o755)
    # The protected core requires root-owned native tools and ancestors.
    tool_host("install", installed_tools, tools)
    for name in ["keys", "state"]:
        (base / name).mkdir(mode=0o700)
    common = f"""config_version = 1
mode = "fixture"
read_only = false
access = "{{access}}"
[storage]
root = "{base}/store"
[source]
host = "127.0.0.1"
port = {port}
user = "postgres"
database = "{SOURCE}"
maintenance_database = "postgres"
auth = "scram-passfile"
password_file = "{base}/passfile"
[tools]
client_bin_dir = "{installed_tools}"
[encryption]
identity_file = "{base}/keys/identity"
{{recipient}}
[signing]
verifying_key_file = "{base}/keys/verifier"
{{signer}}
"""
    private(base / "writer.toml", common.format(
        access="writer", recipient=f'recipient_file = "{base}/keys/recipient"',
        signer=f'signing_key_file = "{base}/keys/signer"'))
    private(base / "reader.toml", common.format(access="reader", recipient="", signer=""))
    run(str(ROOT / "target/debug/backupctl"), "--config", str(base / "writer.toml"),
        "key", "generate")
    actor = {"actor_id": str(uuid.uuid4()), "credential_id": str(uuid.uuid4()), "revision": 1}
    private(base / "actor.json", json.dumps(actor))
    registry = {"format": "api-credentials-v1", "credentials": [
        dict(actor, active=True, roles=["admin"],
             token_sha256=hashlib.sha256(secrets.token_bytes(32)).hexdigest())]}
    private(base / "registry.json", json.dumps(registry))
    private(base / "api.toml", f"""format = "api-config-v1"
listen = "127.0.0.1:8090"
public_origin = "http://127.0.0.1:8090"
development_http = true
control_database = "{base}/state/control.sqlite"
credential_registry = "{base}/registry.json"
[[profiles]]
id = "default"
display_name = "P02 fixture"
writer_config = "{base}/writer.toml"
reader_config = "{base}/reader.toml"
operations = ["backup", "inspection", "verification", "restore_plan", "restore",
              "retention_preview", "retention_run", "artifact_protection"]
""")


TOOL_NAMES = ("psql", "pg_dump", "pg_dumpall", "pg_restore", "createdb", "pg_dump.real",
              "pg_restore.real")


def tool_host(action, destination, source=None):
    assert destination.parent == Path("/opt")
    assert destination.name.startswith("parsbackup-p02-") and destination.name.count("-") == 3
    mount = ["--mount", "type=bind,src=/opt,dst=/host-opt"]
    path = f"/host-opt/{destination.name}"
    if action == "install":
        mount += ["--mount", f"type=bind,src={source},dst=/fixture-tools,readonly"]
        program = 'dir=$1; shift; mkdir -m 755 "$dir"; for tool; do install -m 755 "/fixture-tools/$tool" "$dir/$tool"; done'
    else:
        program = 'dir=$1; shift; test -d "$dir" || exit 0; for tool; do if test -f "$dir/$tool"; then unlink "$dir/$tool"; fi; done; rmdir "$dir"'
    result = run("docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
               "--cap-drop=ALL", "--security-opt=no-new-privileges", *mount, "--entrypoint",
               "/bin/sh", IMAGE, "-eu", "-c", program, "p02-tools", path, *TOOL_NAMES, check=False)
    assert result.returncode == 0, result.stderr


def orphan_stopped(base):
    pid = (base / "orphan-pid").read_text().strip()
    stat = Path("/proc") / pid / "stat"
    try:
        fields = stat.read_text().rsplit(")", 1)[1].split()
    except FileNotFoundError:
        return True
    return fields[0] == "Z"


def main():
    test_binary = str(Path(sys.argv[1]).resolve(strict=True))
    unit = f"parsbackup-p02-{os.getpid()}.service"
    container = unit.removesuffix(".service")
    installed_tools = Path("/opt") / f"{container}-{uuid.uuid4().hex}"
    assert not installed_tools.exists()
    with tempfile.TemporaryDirectory(prefix=".parsbackup-p02-", dir=Path.home()) as directory:
        base = Path(directory)
        try:
            setup(base, container, installed_tools)
            unmanaged = run(str(ROOT / "target/debug/backup-api"), "--supervise",
                            str(base / "api.toml"), check=False)
            assert unmanaged.returncode != 0 and "CONTAINMENT_UNAVAILABLE" in unmanaged.stderr
            assert not (base / "state/control.sqlite").exists()
            # Apply the actual unit's process ownership and resource settings.
            # Identity/paths/sandbox mount policy belong to the system deployment.
            settings = {
                "Type", "UMask", "TimeoutStopSec", "KillMode", "KillSignal", "FinalKillSignal",
                "SendSIGKILL", "Delegate", "Restart", "NoNewPrivileges", "LimitCORE",
                "LimitNOFILE", "TasksMax", "MemoryMax",
            }
            deployment = (ROOT / "deploy/systemd/backup-api.service").read_text()
            properties = [
                f"--property={line}" for line in deployment.splitlines()
                if line.partition("=")[0] in settings]
            assert len(properties) == len(settings)
            service = ("systemd-run", "--user", "--wait", "--pipe", "--collect",
                       f"--unit={unit}", *properties, f"--setenv=P02_FIXTURE={base}",
                       test_binary, "--ignored", "--exact", "supervised_worker", "--nocapture")
            first = run(*service, check=False)
            print(first.stdout + first.stderr, end="")
            assert first.returncode != 0 and "BACKUP_API_CONTAINMENT_LOST" in first.stderr
            eventually(lambda: orphan_stopped(base))
            # The collected unit may remain registered for one manager iteration.
            eventually(lambda: run("systemctl", "--user", "show", "-p", "LoadState", "--value",
                                   unit, check=False).stdout.strip() == "not-found")
            second = run(*service, check=False)
            print(second.stdout + second.stderr, end="")
            assert second.returncode == 0, "same-unit restart failed"
            result = run("docker", "exec", container, "psql", "-U", "postgres", "-d", TARGET,
                         "-Atc", "SELECT n FROM sample")
            assert result.stdout.strip() == "42"
            print("P02 queue/retry/restore/delete/cancel, escaped descendant termination and restart pass")
        finally:
            run("systemctl", "--user", "stop", unit, check=False)
            run("docker", "rm", "-f", "-v", container, check=False)
            tool_host("cleanup", installed_tools)


if __name__ == "__main__":
    main()
