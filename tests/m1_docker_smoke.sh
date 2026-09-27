#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl

container_name=""
test_root=""
cleanup() {
    if [[ -n "$container_name" ]]; then
        docker stop "$container_name" >/dev/null 2>&1 || true
    fi
    if [[ -n "$test_root" ]]; then
        rm -rf "$test_root"
    fi
}
trap cleanup EXIT

for major in 16 17 18; do
    test_root=$(mktemp -d /tmp/backupctl-m1-smoke-XXXXXXXX)
    container_name="backupctl-m1-smoke-${major}-$$"
    docker run --rm -d --name "$container_name" --network none \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        -v "$test_root:$test_root" \
        "docker.arvancloud.ir/library/postgres:${major}-bookworm" >/dev/null
    ready=0
    for _ in $(seq 1 40); do
        if docker exec "$container_name" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.25
    done
    if [[ "$ready" != 1 ]]; then
        echo "PostgreSQL $major did not become ready" >&2
        exit 1
    fi

    docker exec "$container_name" createdb -U postgres backupctl_fixture_m1
    docker exec -i "$container_name" psql -U postgres -X -v ON_ERROR_STOP=1 \
        -d backupctl_fixture_m1 < tests/fixtures/postgres/core.sql >/dev/null

    mkdir -p "$test_root/bin"
    for tool in pg_dump pg_dumpall pg_restore psql createdb; do
        printf '#!/bin/sh\nexec /usr/bin/docker exec %s %s "$@"\n' \
            "$container_name" "$tool" > "$test_root/bin/$tool"
        chmod 700 "$test_root/bin/$tool"
    done
    cat > "$test_root/config.toml" <<CONFIG
[source]
host = "127.0.0.1"
port = 5432
user = "postgres"
database = "backupctl_fixture_m1"
client_bin_dir = "$test_root/bin"

[storage]
root = "$test_root/data"
CONFIG
    target/debug/backupctl --config "$test_root/config.toml" config check >/dev/null
    target/debug/backupctl --config "$test_root/config.toml" --output json \
        backup create --confirm-synthetic > "$test_root/created.json"
    backup_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$test_root/created.json")
    target/debug/backupctl --config "$test_root/config.toml" --output json \
        backup list > "$test_root/list.json"
    target/debug/backupctl --config "$test_root/config.toml" --output json \
        backup inspect "$backup_id" > "$test_root/inspect.json"
    python3 - "$test_root" "$backup_id" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
backup_id = sys.argv[2]
listed = json.loads((root / 'list.json').read_text())
inspected = json.loads((root / 'inspect.json').read_text())
assert len(listed) == 1 and listed[0]['id'] == backup_id
assert inspected['id'] == backup_id and inspected['synthetic_only']
PY
    docker exec "$container_name" createdb -U postgres backupctl_fixture_restored
    docker exec "$container_name" pg_restore -U postgres --exit-on-error \
        -d backupctl_fixture_restored "$test_root/data/artifacts/$backup_id/payload.dump"
    docker exec -i "$container_name" psql -U postgres -X -v ON_ERROR_STOP=1 \
        -d backupctl_fixture_restored < tests/fixtures/postgres/assertions.sql >/dev/null
    if [[ "$major" == 16 ]]; then
        if target/debug/backupctl --config "$test_root/config.toml" backup create > /dev/null 2>&1; then
            echo "synthetic confirmation guard failed" >&2
            exit 1
        fi
        mkdir -p "$test_root/badbin"
        cp "$test_root/bin/psql" "$test_root/bin/pg_restore" "$test_root/bin/pg_dumpall" "$test_root/bin/createdb" "$test_root/badbin/"
        cat > "$test_root/bad.toml" <<CONFIG
timeout_seconds = 1

[source]
host = "127.0.0.1"
port = 5432
user = "postgres"
database = "backupctl_fixture_m1"
client_bin_dir = "$test_root/badbin"

[storage]
root = "$test_root/data"
CONFIG
        # The first failing tool simulates a write error after preflight.
        cat > "$test_root/badbin/pg_dump" <<BAD
#!/bin/sh
if [ "\$1" = "--version" ]; then
    exec /usr/bin/docker exec "$container_name" pg_dump "\$@"
fi
printf 'simulated no space left on device\n' >&2
exit 7
BAD
        chmod 700 "$test_root/badbin/pg_dump"
        if target/debug/backupctl --config "$test_root/bad.toml" backup create --confirm-synthetic > /dev/null 2>&1; then
            echo "write-error backup was incorrectly accepted" >&2
            exit 1
        fi
        # A successful process with no archive must also be rejected.
        cat > "$test_root/badbin/pg_dump" <<BAD
#!/bin/sh
if [ "\$1" = "--version" ]; then
    exec /usr/bin/docker exec "$container_name" pg_dump "\$@"
fi
exit 0
BAD
        if target/debug/backupctl --config "$test_root/bad.toml" backup create --confirm-synthetic > /dev/null 2>&1; then
            echo "empty backup was incorrectly accepted" >&2
            exit 1
        fi
        # The adapter must stop a hung process at the configured timeout.
        cat > "$test_root/badbin/pg_dump" <<BAD
#!/bin/sh
if [ "\$1" = "--version" ]; then
    exec /usr/bin/docker exec "$container_name" pg_dump "\$@"
fi
exec /bin/sleep 3
BAD
        if target/debug/backupctl --config "$test_root/bad.toml" backup create --confirm-synthetic > /dev/null 2>&1; then
            echo "timed-out backup was incorrectly accepted" >&2
            exit 1
        fi
        # A mismatched client major must fail before staging a dump.
        cat > "$test_root/badbin/pg_dump" <<BAD
#!/bin/sh
if [ "\$1" = "--version" ]; then
    printf 'pg_dump (PostgreSQL) 15.0\n'
    exit 0
fi
exit 7
BAD
        if target/debug/backupctl --config "$test_root/bad.toml" backup create --confirm-synthetic > /dev/null 2>&1; then
            echo "client version mismatch was incorrectly accepted" >&2
            exit 1
        fi
        # A mistakenly pasted value must not be repeated in parse errors.
        cp "$test_root/config.toml" "$test_root/invalid.toml"
        printf 'password = "%s"\n' "$backup_id" >> "$test_root/invalid.toml"
        if target/debug/backupctl --config "$test_root/invalid.toml" config check > /dev/null 2> "$test_root/invalid.err"; then
            echo "unknown credential field was incorrectly accepted" >&2
            exit 1
        fi
        if grep -q "$backup_id" "$test_root/invalid.err"; then
            echo "configuration error leaked a field value" >&2
            exit 1
        fi
        artifact_count=$(find "$test_root/data/artifacts" -mindepth 1 -maxdepth 1 -type d | wc -l)
        stage_count=$(find "$test_root/data/staging" -mindepth 1 -maxdepth 1 -type d | wc -l)
        if [[ "$artifact_count" != 1 || "$stage_count" != 0 ]]; then
            echo "failed jobs published or leaked staging artifacts" >&2
            exit 1
        fi
        echo "PostgreSQL 16: confirmation, write-error, empty-output, timeout, version, and redaction guards passed"
    fi
    echo "PostgreSQL $major: backup, list, inspect, and independent restore passed"
    cleanup
    container_name=""
    test_root=""
done
