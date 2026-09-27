#!/usr/bin/env bash
# M3: typed profiles, catalog-resolved selection, and section-limited restores.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl

source_name=""
test_root=""
cleanup() {
    if [[ -n "$source_name" ]]; then
        docker stop "$source_name" >/dev/null 2>&1 || true
    fi
    if [[ -n "$test_root" ]]; then
        rm -rf "$test_root"
    fi
}
trap cleanup EXIT

make_wrappers() {
    local container="$1" dir="$2"
    mkdir -p "$dir"
    for tool in pg_dump pg_dumpall pg_restore psql createdb; do
        printf '#!/bin/sh\nfor a in "$@"; do [ "$a" = "--version" ] && exec /usr/bin/docker exec %s %s --version; done\nexec /usr/bin/docker exec -i %s %s "$@"\n' \
            "$container" "$tool" "$container" "$tool" > "$dir/$tool"
        chmod 700 "$dir/$tool"
    done
}

fail() {
    echo "PostgreSQL $1: $2" >&2
    exit 1
}

for major in 16 17 18; do
    test_root=$(mktemp -d /tmp/backupctl-m3-smoke-XXXXXXXX)
    source_name="backupctl-m3-source-${major}-$$"

    docker run --rm -d --name "$source_name" --network none \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        -v "$test_root:$test_root" \
        "docker.arvancloud.ir/library/postgres:${major}-bookworm" >/dev/null
    for _ in $(seq 1 80); do
        docker exec "$source_name" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break
        sleep 0.25
    done

    src_sql() {
        docker exec -i "$source_name" psql -U postgres -X -v ON_ERROR_STOP=1 "$@"
    }
    # A single-row probe: empty or unexpected output must fail the run.
    expect_count() {
        local database="$1" statement="$2" want="$3" got
        got=$(src_sql -tA -d "$database" -c "$statement" | tr -d '[:space:]')
        if [[ "$got" != "$want" ]]; then
            fail "$major" "expected $want from $statement, got '$got'"
        fi
    }

    docker exec "$source_name" createdb -U postgres backupctl_fixture_m1
    src_sql -d backupctl_fixture_m1 < tests/fixtures/postgres/core.sql >/dev/null

    make_wrappers "$source_name" "$test_root/bin"
    cat > "$test_root/config.toml" <<CONFIG
export_globals = false
timeout_seconds = 120

[source]
host = "127.0.0.1"
port = 5432
user = "postgres"
database = "backupctl_fixture_m1"
client_bin_dir = "$test_root/bin"

[storage]
root = "$test_root/data"

[[profile]]
name = "whole"
database = "backupctl_fixture_m1"
large_objects = true

[[profile]]
name = "whole-strict"
database = "backupctl_fixture_m1"

[[profile]]
name = "app-aux"
database = "backupctl_fixture_m1"
schemas = ["app", "aux"]

[[profile]]
name = "app-aux-los"
database = "backupctl_fixture_m1"
schemas = ["app", "aux"]
large_objects = true

[[profile]]
name = "app-aux-schema"
database = "backupctl_fixture_m1"
mode = "schema-only"
schemas = ["app", "aux"]

[[profile]]
name = "aux-only"
database = "backupctl_fixture_m1"
schemas = ["aux"]

[[profile]]
name = "events"
database = "backupctl_fixture_m1"
tables = ["app.partitioned_events"]

[[profile]]
name = "child-only"
database = "backupctl_fixture_m1"
tables = ["app.partitioned_events_2026"]

[[profile]]
name = "counters-only"
database = "backupctl_fixture_m1"
tables = ["app.counters"]

[[profile]]
name = "view-only"
database = "backupctl_fixture_m1"
tables = ["app.account_emails"]

[[profile]]
name = "accounts-only"
database = "backupctl_fixture_m1"
tables = ["app.accounts"]

[[profile]]
name = "nowhere"
database = "backupctl_fixture_m1"
schemas = ["nosuch"]

[[profile]]
name = "no-hstore"
database = "backupctl_fixture_m1"
schemas = ["app", "aux"]
exclude_extensions = ["hstore"]
CONFIG
    ctl() { target/debug/backupctl --config "$test_root/config.toml" "$@"; }

    # --- profiles are listed and checked against the live catalog ------------
    ctl profile list | grep -q "profile: app-aux"
    ctl --output json profile list > "$test_root/profiles.json"
    python3 - "$test_root/profiles.json" <<'PY'
import json
import sys
profiles = json.load(open(sys.argv[1]))
names = [item["name"] for item in profiles]
assert "app-aux" in names and "no-hstore" in names, names
assert all(item["database"] == "backupctl_fixture_m1" for item in profiles)
PY

    # --- large objects cannot be silently dropped or over-collected ---------
    # A filtered profile that omits them would archive a database whose stored
    # large objects go missing.
    if ctl profile validate app-aux > "$test_root/lo.err" 2>&1; then
        fail "$major" "a filtered profile excluding large objects was accepted"
    fi
    grep -q "large objects" "$test_root/lo.err"
    # Taking them is all-or-nothing, so a filtered profile cannot promise a
    # subset of them either.
    if ctl profile validate app-aux-los > "$test_root/lo-all.err" 2>&1; then
        fail "$major" "a filtered profile requesting all large objects was accepted"
    fi
    grep -q "every large object" "$test_root/lo-all.err"
    # A whole-database profile may exclude them only explicitly.
    if ctl profile validate whole-strict > "$test_root/lo-whole.err" 2>&1; then
        fail "$major" "a whole-database profile excluding large objects was accepted"
    fi
    grep -q "large objects" "$test_root/lo-whole.err"
    # The over-scope refusal must name the alternative, not just fail.
    ctl profile validate whole > "$test_root/whole.txt"
    grep -q "scope: whole database" "$test_root/whole.txt"

    # From here on the fixture is large-object free so selective scenarios work.
    src_sql -d backupctl_fixture_m1 \
        -c "DELETE FROM app.documents; SELECT lo_unlink(oid) FROM pg_catalog.pg_largeobject_metadata;" \
        >/dev/null

    # Zero-match selections fail instead of writing an empty archive.
    if ctl profile validate nowhere > "$test_root/zero.err" 2>&1; then
        fail "$major" "a profile selecting a nonexistent schema was accepted"
    fi
    grep -q "match nothing" "$test_root/zero.err"

    # --- out-of-scope dependencies fail closed -------------------------------
    for probe in "aux-only:foreign key target" \
        "child-only:parent relation" \
        "counters-only:sequence default" \
        "view-only:view base relation" \
        "accounts-only:column type"; do
        name=${probe%%:*}
        kind=${probe##*:}
        if ctl profile validate "$name" > "$test_root/$name.err" 2>&1; then
            fail "$major" "profile $name was accepted despite depending outside its selection"
        fi
        grep -q "$kind" "$test_root/$name.err" ||
            fail "$major" "profile $name did not report $kind: $(cat "$test_root/$name.err")"
    done
    # The safe direction of the same cross-schema reference stays accepted:
    # app-aux holds both sides of aux.orders -> app.accounts.
    ctl profile validate app-aux > "$test_root/app-aux.txt"
    grep -q "schemas: app, aux" "$test_root/app-aux.txt"

    # Partition families are expanded to exact names before pg_dump runs.
    ctl profile validate events > "$test_root/events.txt"
    grep -q "app.partitioned_events, app.partitioned_events_2025, app.partitioned_events_2026" \
        "$test_root/events.txt"

    # --- dry run reports scope and writes nothing ----------------------------
    ctl backup create --profile app-aux --dry-run > "$test_root/dry.txt"
    if [[ -n "$(ls -A "$test_root/data/artifacts")" ]]; then
        fail "$major" "--dry-run published an artifact"
    fi
    ctl --output json backup create --profile events --dry-run > "$test_root/dry.json"
    python3 - "$test_root/dry.json" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1]))
assert report["profile"] == "events"
assert len(report["selection"]["resolved_tables"]) == 3, report["selection"]
assert report["selection"]["resolved_schemas"] == []
PY
    if [[ -n "$(ls -A "$test_root/data/artifacts")" ]]; then
        fail "$major" "--dry-run published an artifact"
    fi

    # --- --exclude-extension is a 17+ capability -----------------------------
    if [[ "$major" -lt 17 ]]; then
        if ctl backup create --profile no-hstore --confirm-synthetic > "$test_root/ext.err" 2>&1; then
            fail "$major" "pg_dump 16 was asked to exclude extensions"
        fi
        grep -q "PostgreSQL 17" "$test_root/ext.err"
    else
        ctl --output json backup create --profile no-hstore --confirm-synthetic > /dev/null
    fi

    # --- a selective artifact records its exact resolved scope --------------
    ctl --output json backup create --profile app-aux --confirm-synthetic \
        > "$test_root/created.json"
    backup_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$test_root/created.json")
    python3 - "$test_root/created.json" <<'PY'
import json
import sys
manifest = json.load(open(sys.argv[1]))
scope = manifest["scope"]
assert manifest["format"] == "m1-development-plaintext"
assert scope["profile"] == "app-aux"
assert scope["whole_database"] is False
assert scope["requested_schemas"] == ["app", "aux"]
assert scope["resolved_schemas"] == ["app", "aux"]
assert scope["resolved_tables"] == []
assert scope["large_objects"] is False
assert len(manifest["toc_sha256"]) == 64
PY
    artifact_dir="$test_root/data/artifacts/$backup_id"
    ctl backup verify "$backup_id" --level archive > /dev/null

    # Table-selected artifacts record the expanded family as their scope.
    ctl --output json backup create --profile events --confirm-synthetic > "$test_root/events.json"
    events_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$test_root/events.json")
    python3 - "$test_root/events.json" <<'PY'
import json
import sys
manifest = json.load(open(sys.argv[1]))
assert manifest["scope"]["requested_tables"] == ["app.partitioned_events"]
assert manifest["scope"]["resolved_tables"] == [
    "app.partitioned_events",
    "app.partitioned_events_2025",
    "app.partitioned_events_2026",
], manifest["scope"]
PY
    # The recorded table of contents is what the archive-level check proves, so
    # a manifest rewritten to a different digest must fail against the same
    # untouched payload.
    manifest_path="$artifact_dir/manifest.json"
    python3 - "$manifest_path" <<'PY'
import json
import sys
path = sys.argv[1]
manifest = json.load(open(path))
manifest["toc_sha256"] = "d" * 64
json.dump(manifest, open(path, "w"))
PY
    if ctl backup verify "$backup_id" --level archive > "$test_root/toc.err" 2>&1; then
        fail "$major" "archive verification ignored the recorded table of contents"
    fi
    grep -q "table of contents" "$test_root/toc.err"
    python3 - "$manifest_path" "$test_root/created.json" <<'PY'
import json
import sys
manifest = json.load(open(sys.argv[1]))
manifest["toc_sha256"] = json.load(open(sys.argv[2]))["toc_sha256"]
json.dump(manifest, open(sys.argv[1], "w"))
PY
    ctl backup verify "$backup_id" --level archive > /dev/null

    # --- section-limited restore --------------------------------------------
    # Data alone cannot exist in a database that has not been created yet.
    if ctl restore plan "$backup_id" --target backupctl_fixture_sec --security portable \
        --section data > "$test_root/sec.err" 2>&1; then
        fail "$major" "a data-only restore into a new database was planned"
    fi
    grep -q "pre-data" "$test_root/sec.err"
    if ctl restore plan "$backup_id" --target backupctl_fixture_sec --security dr \
        --section pre-data > "$test_root/sec-dr.err" 2>&1; then
        fail "$major" "a partial restore was allowed to claim role security"
    fi
    grep -q "cannot reconstruct" "$test_root/sec-dr.err"

    ctl --output json restore plan "$backup_id" --target backupctl_fixture_sec \
        --security portable --section pre-data > "$test_root/plan-sec.json"
    plan_sec=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$test_root/plan-sec.json")
    python3 - "$test_root/plan-sec.json" "$test_root/data/plans/$plan_sec.json" <<'PY'
import json
import sys
plan = json.load(open(sys.argv[1]))["plan"]
stored = json.load(open(sys.argv[2]))
assert plan["sections"] == {"pre_data": True, "data": False, "post_data": False}
assert stored["sections"] == plan["sections"]
assert stored["artifact_scope"] == "app-aux"
PY
    ctl restore run "$plan_sec" --confirm-target backupctl_fixture_sec > "$test_root/sec-run.txt"
    grep -q "verification level: none" "$test_root/sec-run.txt"
    grep -q "does not prove the artifact restores completely" "$test_root/sec-run.txt"
    expect_count backupctl_fixture_sec "SELECT count(*) FROM app.accounts" 0
    ctl --output json backup inspect "$backup_id" > "$test_root/inspect.json"
    python3 - "$test_root/inspect.json" <<'PY'
import json
import sys
assert json.load(open(sys.argv[1]))["verification_level"] is None
PY

    # --- full selective restore proves the artifact -------------------------
    ctl --output json restore plan "$backup_id" --target backupctl_fixture_full \
        --security portable > "$test_root/plan-full.json"
    plan_full=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$test_root/plan-full.json")
    ctl restore run "$plan_full" --confirm-target backupctl_fixture_full > /dev/null
    src_sql -d backupctl_fixture_full < tests/fixtures/postgres/selective-assertions.sql >/dev/null
    # A structure-only selection must not carry rows from the source.
    expect_count backupctl_fixture_full "SELECT count(*) FROM aux.orders" 2
    ctl --output json backup inspect "$backup_id" > "$test_root/inspect.json"
    python3 - "$test_root/inspect.json" <<'PY'
import json
import sys
assert json.load(open(sys.argv[1]))["verification_level"] == "restore-tested"
PY

    # A schema-only profile must contain structure and no rows.
    ctl --output json backup create --profile app-aux-schema --confirm-synthetic \
        > "$test_root/schema.json"
    schema_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$test_root/schema.json")
    ctl --output json restore plan "$schema_id" --target backupctl_fixture_schemaonly \
        --security portable > "$test_root/plan-schema.json"
    plan_schema=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$test_root/plan-schema.json")
    ctl restore run "$plan_schema" --confirm-target backupctl_fixture_schemaonly > /dev/null
    expect_count backupctl_fixture_schemaonly "SELECT count(*) FROM app.accounts" 0
    expect_count backupctl_fixture_schemaonly \
        "SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND conrelid = 'aux.orders'::regclass" 1

    # A table-selected artifact restores its whole partition family.
    ctl --output json restore plan "$events_id" --target backupctl_fixture_events \
        --security portable > "$test_root/plan-events.json"
    plan_events=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$test_root/plan-events.json")
    ctl restore run "$plan_events" --confirm-target backupctl_fixture_events > /dev/null
    expect_count backupctl_fixture_events "SELECT count(*) FROM app.partitioned_events" 2
    # Family expansion is what makes that restore complete: the parent alone
    # would have carried no child partitions.
    expect_count backupctl_fixture_events \
        "SELECT count(*) FROM pg_class WHERE relname = 'partitioned_events_2026'" 1

    echo "PostgreSQL $major: profiles, resolved scope, dependency refusal, section restore, and TOC binding passed"
    docker stop "$source_name" >/dev/null 2>&1 || true
    source_name=""
    rm -rf "$test_root"
    test_root=""
done
