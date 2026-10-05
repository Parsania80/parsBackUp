#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl

source_name=""
target_name=""
sacrifice_name=""
test_root=""
cleanup() {
    for name in "$source_name" "$target_name" "$sacrifice_name"; do
        if [[ -n "$name" ]]; then
            docker stop "$name" >/dev/null 2>&1 || true
        fi
    done
    if [[ -n "$test_root" ]]; then
        rm -rf "$test_root"
    fi
}
trap cleanup EXIT

make_wrappers() {
    local container="$1" dir="$2" port="$3"
    mkdir -p "$dir"
    for tool in pg_dump pg_dumpall pg_restore psql createdb; do
        if [[ -n "$port" ]]; then
            # --version must be passed alone: some tools reject connection
            # options combined with it.
            printf '#!/bin/sh\nfor a in "$@"; do [ "$a" = "--version" ] && exec /usr/bin/docker exec %s %s --version; done\nexec /usr/bin/docker exec -i %s %s -h 127.0.0.1 -p %s "$@"\n' \
                "$container" "$tool" "$container" "$tool" "$port" > "$dir/$tool"
        else
            printf '#!/bin/sh\nexec /usr/bin/docker exec -i %s %s "$@"\n' \
                "$container" "$tool" > "$dir/$tool"
        fi
        chmod 700 "$dir/$tool"
    done
}

wait_ready() {
    local container="$1" port="$2"
    local args=(-h 127.0.0.1 -U postgres)
    if [[ -n "$port" ]]; then
        args+=(-p "$port")
    fi
    for _ in $(seq 1 80); do
        if docker exec "$container" pg_isready "${args[@]}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

for major in 16 17 18; do
    test_root=$(mktemp -d /tmp/backupctl-m2-smoke-XXXXXXXX)
    source_name="backupctl-m2-source-${major}-$$"
    target_name="backupctl-m2-target-${major}-$$"
    target_port=$((54320 + major))

    docker run --rm -d --name "$source_name" --network none \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        -v "$test_root:$test_root" \
        "docker.arvancloud.ir/library/postgres:${major}-bookworm" >/dev/null
    # The target simulates a freshly rebuilt host after loss of the original.
    # It mounts the shared test root so artifact paths resolve identically.
    docker run --rm -d --name "$target_name" --network host \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        -v "$test_root:$test_root" \
        "docker.arvancloud.ir/library/postgres:${major}-bookworm" \
        -p "$target_port" >/dev/null
    wait_ready "$source_name" "" || { echo "source $major not ready" >&2; exit 1; }
    wait_ready "$target_name" "$target_port" || { echo "target $major not ready" >&2; exit 1; }

    src_sql() {
        docker exec -i "$source_name" psql -U postgres -X -v ON_ERROR_STOP=1 "$@"
    }
    dst_sql() {
        docker exec -i "$target_name" psql -U postgres -h 127.0.0.1 -p "$target_port" \
            -X -v ON_ERROR_STOP=1 "$@"
    }

    docker exec "$source_name" createdb -U postgres backupctl_fixture_m1
    src_sql -d backupctl_fixture_m1 < tests/fixtures/postgres/core.sql >/dev/null
    # Native pg_dumpall exports must preserve quoted identifiers and role settings.
    src_sql -d backupctl_fixture_m1 >/dev/null <<'SQL'
CREATE ROLE "backupctl_fixture Mixed Case" LOGIN;
CREATE ROLE "backupctl_fixture;semi" NOLOGIN;
CREATE ROLE "backupctl_fixture ""quote""" NOLOGIN;
CREATE ROLE "backupctl_fixture
line" NOLOGIN;
ALTER ROLE "backupctl_fixture Mixed Case" SET application_name TO 'semi;--colon';
GRANT "backupctl_fixture;semi" TO "backupctl_fixture Mixed Case";
SQL
    # Placeholder on the rebuilt cluster so plans can probe its catalogs; the
    # restores below only ever write into fresh target databases.
    docker exec "$target_name" createdb -U postgres -h 127.0.0.1 -p "$target_port" backupctl_fixture_m1

    make_wrappers "$source_name" "$test_root/bin" ""
    make_wrappers "$target_name" "$test_root/bin_target" "$target_port"
    cat > "$test_root/config.toml" <<CONFIG
export_globals = true

[source]
host = "127.0.0.1"
port = 5432
user = "postgres"
database = "backupctl_fixture_m1"
client_bin_dir = "$test_root/bin"

[storage]
root = "$test_root/data"
CONFIG
    cat > "$test_root/config_target.toml" <<CONFIG
[source]
host = "127.0.0.1"
port = $target_port
user = "postgres"
database = "backupctl_fixture_m1"
client_bin_dir = "$test_root/bin_target"

[storage]
root = "$test_root/data"
CONFIG
    ctl() { target/debug/backupctl --config "$test_root/config.toml" "$@"; }
    ctlt() { target/debug/backupctl --config "$test_root/config_target.toml" "$@"; }

    # --- backup with security metadata --------------------------------------
    ctl --output json backup create --confirm-synthetic > "$test_root/created.json"
    backup_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$test_root/created.json")
    artifact_dir="$test_root/data/artifacts/$backup_id"

    # Test 10: password material never enters artifacts or CLI output.
    if grep -qr "fake-verifier-for-tests-only" "$test_root/data" "$test_root"/*.json "$test_root"/*.err 2>/dev/null; then
        echo "password material found in stored data or CLI output" >&2
        exit 1
    fi
    if grep -qiE "PASSWORD[[:space:]]+'" "$artifact_dir/globals.sql"; then
        echo "globals export included password verifiers" >&2
        exit 1
    fi
    if grep -qr "SCRAM-SHA-256" "$test_root/data"; then
        echo "SCRAM verifier found in the artifact store" >&2
        exit 1
    fi

    # Checksum and archive verification levels.
    ctl --output json backup verify "$backup_id" --level checksum > /dev/null
    ctl --output json backup verify "$backup_id" --level archive > /dev/null

    # Tests 8/9: DR onto a cluster where the roles still exist is refused.
    if ctl restore plan "$backup_id" --target backupctl_fixture_dr --security dr \
        > "$test_root/exists.err" 2>&1; then
        echo "DR plan was accepted while fixture roles already exist" >&2
        exit 1
    fi
    grep -q "already exist" "$test_root/exists.err"

    # M1 compatibility: the native-restore path must still round-trip.
    docker exec "$source_name" createdb -U postgres backupctl_fixture_native
    docker exec "$source_name" pg_restore -U postgres --exit-on-error \
        -d backupctl_fixture_native "$artifact_dir/payload.dump"
    src_sql -d backupctl_fixture_native < tests/fixtures/postgres/assertions.sql >/dev/null
    src_sql -d postgres -c 'DROP DATABASE backupctl_fixture_native;' >/dev/null

    # --- test 5: portable restore onto the role-less rebuilt cluster --------
    # PostgreSQL prerequisite: skipping ownership leaves objects with the
    # restoring role, so portable needs no source roles at all.
    ctlt restore plan "$backup_id" --target backupctl_fixture_portable --security portable \
        --output json > "$test_root/plan2.json"
    plan2_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$test_root/plan2.json")
    python3 - "$test_root/data/plans/$plan2_id.json" <<'PY'
import json
import sys
stored = json.load(open(sys.argv[1]))
assert stored["security"] == {"roles": False, "ownership": False, "privileges": False}
PY
    ctlt restore run "$plan2_id" --confirm-target backupctl_fixture_portable >/dev/null
    dst_sql -d backupctl_fixture_portable < tests/fixtures/postgres/assertions.sql >/dev/null
    portable_owner=$(dst_sql -tA -d backupctl_fixture_portable \
        -c "SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = 'app'")
    if [[ "$portable_owner" != "postgres" ]]; then
        echo "portable restore applied ownership despite policy (owner: $portable_owner)" >&2
        exit 1
    fi
    if dst_sql -tA -d backupctl_fixture_portable -c "SELECT 1 FROM pg_roles WHERE rolname = 'backupctl_fixture_alice'" | grep -q 1; then
        echo "portable restore created roles despite policy" >&2
        exit 1
    fi

    # --- tests 1-4, 6, 7, 11: DR onto the rebuilt cluster --------------------
    ctlt restore plan "$backup_id" --target backupctl_fixture_dr --security dr \
        --output json > "$test_root/plan.json"
    plan_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$test_root/plan.json")
    # Test 6: the persisted plan records exactly the selected security policy.
    python3 - "$test_root/plan.json" "$test_root/data/plans/$plan_id.json" <<'PY'
import json
import sys
plan = json.load(open(sys.argv[1]))["plan"]
stored = json.load(open(sys.argv[2]))
assert plan["security"] == {"roles": True, "ownership": True, "privileges": True}
assert stored["security"] == plan["security"]
assert stored["id"] == plan["id"] and stored["artifact_id"] == plan["artifact_id"]
assert stored["expires_unix_ms"] > stored["created_unix_ms"]
PY

    # Test 7: an expired plan can never execute.
    plan_file="$test_root/data/plans/$plan_id.json"
    python3 - "$plan_file" <<'PY'
import json
import sys
path = sys.argv[1]
plan = json.load(open(path))
plan["expires_unix_ms"] = 1
json.dump(plan, open(path, "w"))
PY
    if ctlt restore run "$plan_id" --confirm-target backupctl_fixture_dr > /dev/null 2>&1; then
        echo "expired restore plan was executed" >&2
        exit 1
    fi
    rm "$plan_file"
    ctlt restore plan "$backup_id" --target backupctl_fixture_dr --security dr \
        --output json > "$test_root/plan.json"
    plan_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$test_root/plan.json")

    # A mismatched confirmation target must be refused.
    if ctlt restore run "$plan_id" --confirm-target backupctl_fixture_wrong > /dev/null 2>&1; then
        echo "restore accepted a mismatched confirmation target" >&2
        exit 1
    fi

    ctlt restore run "$plan_id" --confirm-target backupctl_fixture_dr >/dev/null
    # Tests 1-4 and 11: the rebuilt cluster regained its security model.
    dst_sql -d backupctl_fixture_dr < tests/fixtures/postgres/assertions.sql >/dev/null
    dst_sql -d backupctl_fixture_dr < tests/fixtures/postgres/security-assertions.sql >/dev/null
    dst_sql -d backupctl_fixture_dr >/dev/null <<'SQL'
DO $$
BEGIN
    IF (SELECT count(*) FROM pg_roles WHERE rolname = ANY(ARRAY[
        'backupctl_fixture Mixed Case', 'backupctl_fixture;semi',
        'backupctl_fixture "quote"', E'backupctl_fixture\nline'])) <> 4 THEN
        RAISE EXCEPTION 'DR restore lost a quoted role name';
    END IF;
    IF NOT pg_has_role('backupctl_fixture Mixed Case', 'backupctl_fixture;semi', 'MEMBER') THEN
        RAISE EXCEPTION 'DR restore lost quoted role membership';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'backupctl_fixture Mixed Case'
        AND rolconfig @> ARRAY['application_name=semi;--colon']) THEN
        RAISE EXCEPTION 'DR restore lost a quoted role setting';
    END IF;
END
$$;
SQL
    # After DR the roles exist, so a second DR plan is refused (test 9 again).
    if ctlt restore plan "$backup_id" --target backupctl_fixture_dr2 --security dr \
        > "$test_root/twice.err" 2>&1; then
        echo "second DR plan accepted on a cluster with restored roles" >&2
        exit 1
    fi
    grep -q "already exist" "$test_root/twice.err"
    # The artifact is now marked restore-tested.
    ctl --output json backup inspect "$backup_id" > "$test_root/inspect.json"
    python3 - "$test_root/inspect.json" <<'PY'
import json
import sys
manifest = json.load(open(sys.argv[1]))
assert manifest["security_globals"] is True
assert manifest["verification_level"] == "restore-tested"
PY

    # A DR plan over an artifact without security metadata is refused.
    sed 's/export_globals = true/export_globals = false/' "$test_root/config.toml" > "$test_root/plain.toml"
    target/debug/backupctl --config "$test_root/plain.toml" --output json \
        backup create --confirm-synthetic > "$test_root/plain.json"
    plain_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$test_root/plain.json")
    plain_globals="$test_root/data/artifacts/$plain_id/globals.sql"
    if [[ -e "$plain_globals" ]]; then
        echo "export_globals=false backup still wrote a globals file" >&2
        exit 1
    fi
    if target/debug/backupctl --config "$test_root/plain.toml" \
        restore plan "$plain_id" --target backupctl_fixture_dr3 --security dr > /dev/null 2>&1; then
        echo "DR plan was accepted for an artifact without globals" >&2
        exit 1
    fi
    # Its portable restore still works (security metadata is optional there).
    target/debug/backupctl --config "$test_root/config_target.toml" \
        restore plan "$plain_id" --target backupctl_fixture_portable2 --security portable \
        --output json > "$test_root/plan3.json"
    plan3_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$test_root/plan3.json")
    ctlt restore run "$plan3_id" --confirm-target backupctl_fixture_portable2 >/dev/null
    dst_sql -d backupctl_fixture_portable2 < tests/fixtures/postgres/assertions.sql >/dev/null

    # Corruption must be caught by verification before any restore runs.
    printf 'corrupt' | dd of="$artifact_dir/payload.dump" bs=1 seek=100 conv=notrunc status=none
    if ctl backup verify "$backup_id" --level checksum > /dev/null 2>&1; then
        echo "corrupted payload passed checksum verification" >&2
        exit 1
    fi
    if ctl restore plan "$backup_id" --target backupctl_fixture_bad --security portable > /dev/null 2>&1; then
        echo "restore was planned over a corrupted artifact" >&2
        exit 1
    fi

    if [[ "$major" == 16 ]]; then
        # Forged security metadata must be rejected before any execution:
        # the manifest digest binding makes a tampered globals file fatal at
        # plan time, so a malicious or accidental edit can never reach psql.
        sacrifice_name="backupctl-m2-sacrifice-$$"
        sacrifice_port=54999
        docker run --rm -d --name "$sacrifice_name" --network host \
            -e POSTGRES_HOST_AUTH_METHOD=trust \
            -v "$test_root:$test_root" \
            "docker.arvancloud.ir/library/postgres:${major}-bookworm" \
            -p "$sacrifice_port" >/dev/null
        wait_ready "$sacrifice_name" "$sacrifice_port" || { echo "sacrifice not ready" >&2; exit 1; }
        docker exec "$sacrifice_name" createdb -U postgres -h 127.0.0.1 -p "$sacrifice_port" backupctl_fixture_m1
        make_wrappers "$sacrifice_name" "$test_root/bin_sacrifice" "$sacrifice_port"
        cat > "$test_root/config_sacrifice.toml" <<CONFIG
export_globals = true

[source]
host = "127.0.0.1"
port = $sacrifice_port
user = "postgres"
database = "backupctl_fixture_m1"
client_bin_dir = "$test_root/bin_sacrifice"

[storage]
root = "$test_root/data_sacrifice"
CONFIG
        ctl_s() { target/debug/backupctl --config "$test_root/config_sacrifice.toml" "$@"; }
        ctl_s --output json backup create --confirm-synthetic > "$test_root/s_created.json"
        s_backup_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$test_root/s_created.json")
        s_globals="$test_root/data_sacrifice/artifacts/$s_backup_id/globals.sql"
        printf 'GRANT pg_write_server_files TO backupctl_fixture_bob;\n' >> "$s_globals"
        if ctl_s restore plan "$s_backup_id" --target backupctl_fixture_sx --security dr \
            > "$test_root/tamper.err" 2>&1; then
            echo "plan accepted an artifact with a tampered globals file" >&2
            exit 1
        fi
        grep -q "globals checksum" "$test_root/tamper.err"
        if ctl_s backup verify "$s_backup_id" --level checksum > /dev/null 2>&1; then
            echo "tampered globals passed checksum verification" >&2
            exit 1
        fi
        echo "PostgreSQL 16: globals tamper detection and DR refusal checks passed"
    fi
    echo "PostgreSQL $major: DR security restore, portable restore, plan expiry/binding, and verification passed"
    cleanup
    source_name=""
    target_name=""
    sacrifice_name=""
    test_root=""
done
