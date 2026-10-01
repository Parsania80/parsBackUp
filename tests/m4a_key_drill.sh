#!/usr/bin/env bash
# M4a: the key-loss recovery and rotation drill against real PostgreSQL tools.
#
# This runs the procedure in docs/security/key-lifecycle.md step by step, so the
# document is a tested procedure rather than an intention. It answers the two
# questions an operator actually asks at 3 a.m.: can I still restore the backup I
# took before the rotation, and what exactly happens if a key file is gone.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl

source_name=""
target_name=""
test_root=""
cleanup() {
    for name in "$source_name" "$target_name"; do
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
    local container="$1" dir="$2" port="$3" logdir="$4"
    mkdir -p "$dir" "$logdir"
    for tool in pg_dump pg_dumpall pg_restore psql createdb; do
        {
            echo '#!/bin/sh'
            echo "log=\"$logdir/$tool.log\""
            cat <<'LOG'
printf 'argv %s\n' "$*" >> "$log"
for a in "$@"; do
    case "$a" in
        /*) if [ -f "$a" ]; then
                printf 'file %s %s\n' "$a" "$(head -c 5 "$a" | od -An -tx1 | tr -d ' \n')" >> "$log"
            else
                printf 'file %s absent\n' "$a" >> "$log"
            fi ;;
    esac
done
LOG
            if [[ -n "$port" ]]; then
                printf 'for a in "$@"; do [ "$a" = "--version" ] && exec /usr/bin/docker exec %s %s --version; done\n' \
                    "$container" "$tool"
                printf 'exec /usr/bin/docker exec -i %s %s -h 127.0.0.1 -p %s "$@"\n' \
                    "$container" "$tool" "$port"
            else
                printf 'exec /usr/bin/docker exec -i %s %s "$@"\n' "$container" "$tool"
            fi
        } > "$dir/$tool"
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

# Every file argument a tool was handed must be a PGDMP archive under `prefix`; a
# check that saw no read at all proves nothing, so it fails.
assert_reads() {
    local logdir="$1" prefix="$2" label="$3"
    python3 - "$logdir" "$prefix" "$label" <<'PY'
import os
import sys

logdir, prefix, label = sys.argv[1:4]
pgdmp = "5047444d50"
seen = []
for name in sorted(os.listdir(logdir)):
    for line in open(os.path.join(logdir, name)):
        if not line.startswith("file "):
            continue
        _, path, digest = line.split()
        seen.append(path)
        if digest != pgdmp:
            sys.exit(f"{label}: {name} was handed {path}, which is not an archive ({digest})")
        if not path.startswith(prefix):
            sys.exit(f"{label}: {name} read {path}, outside {prefix}")
if not seen:
    sys.exit(f"{label}: no tool read an archive, so the check proved nothing")
print(f"{label}: {len(seen)} tool read(s), all plaintext under {prefix}")
PY
}

rejects() {
    local label="$1"
    shift
    if "$@" > "$test_root/reject.out" 2>&1; then
        echo "$label was accepted" >&2
        cat "$test_root/reject.out" >&2
        return 1
    fi
}

recipient_of() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["identity"]["recipient"])' "$1"
}

for major in 16 17 18; do
    test_root=$(mktemp -d /tmp/backupctl-m4a-drill-XXXXXXXX)
    source_name="backupctl-m4a-drill-source-${major}-$$"
    target_name="backupctl-m4a-drill-target-${major}-$$"
    target_port=$((54320 + major))

    docker run --rm -d --name "$source_name" --network none \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        -v "$test_root:$test_root" \
        "docker.arvancloud.ir/library/postgres:${major}-bookworm" >/dev/null
    docker run --rm -d --name "$target_name" --network host \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        -v "$test_root:$test_root" \
        "docker.arvancloud.ir/library/postgres:${major}-bookworm" \
        -p "$target_port" >/dev/null
    wait_ready "$source_name" "" || { echo "source $major not ready" >&2; exit 1; }
    wait_ready "$target_name" "$target_port" || { echo "target $major not ready" >&2; exit 1; }

    src_sql() { docker exec -i "$source_name" psql -U postgres -X -v ON_ERROR_STOP=1 "$@"; }
    dst_sql() {
        docker exec -i "$target_name" psql -U postgres -h 127.0.0.1 -p "$target_port" \
            -X -v ON_ERROR_STOP=1 "$@"
    }

    docker exec "$source_name" createdb -U postgres backupctl_fixture_m1
    src_sql -d backupctl_fixture_m1 < tests/fixtures/postgres/core.sql >/dev/null
    # The placeholder lets a target-cluster configuration probe its catalogs.
    docker exec "$target_name" createdb -U postgres -h 127.0.0.1 -p "$target_port" backupctl_fixture_m1

    make_wrappers "$source_name" "$test_root/bin" "" "$test_root/log_src"
    make_wrappers "$target_name" "$test_root/bin_target" "$target_port" "$test_root/log_tgt"

    # One writer per configuration shape: `key generate` and `key status` act on
    # the configured paths and nothing else, so a generation IS a configuration.
    write_config() {
        local out="$1" keys="$2" cluster="$3"
        local port=5432 bin="$test_root/bin"
        if [[ "$cluster" == target ]]; then
            port=$target_port
            bin="$test_root/bin_target"
        fi
        cat > "$out" <<CONFIG
export_globals = true

[source]
host = "127.0.0.1"
port = $port
user = "postgres"
database = "backupctl_fixture_m1"
client_bin_dir = "$bin"

[storage]
root = "$test_root/data"

[encryption]
identity_file = "$keys/identity.key"
recipient_file = "$keys/recipient.key"
CONFIG
    }
    write_config "$test_root/gen1.toml" "$test_root/keys/gen1" source
    write_config "$test_root/gen2.toml" "$test_root/keys/gen2" source
    write_config "$test_root/gen1-target.toml" "$test_root/keys/gen1" target
    write_config "$test_root/gen2-target.toml" "$test_root/keys/gen2" target
    write_config "$test_root/vault.toml" "$test_root/vault/gen1" target
    # The same store with the identity directory emptied: what total key loss looks like.
    write_config "$test_root/lost.toml" "$test_root/keys/nothing" target

    gen1() { target/debug/backupctl --config "$test_root/gen1.toml" "$@"; }
    gen2() { target/debug/backupctl --config "$test_root/gen2.toml" "$@"; }
    gen1t() { target/debug/backupctl --config "$test_root/gen1-target.toml" "$@"; }
    gen2t() { target/debug/backupctl --config "$test_root/gen2-target.toml" "$@"; }
    vault() { target/debug/backupctl --config "$test_root/vault.toml" "$@"; }
    lost() { target/debug/backupctl --config "$test_root/lost.toml" "$@"; }
    plan_id() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$1"; }
    backup_id() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$1"; }

    # --- 1. generation 1 exists, and its artifacts are readable -----------------
    gen1 --output json key generate > "$test_root/gen1-keys.json"
    # Captured now, because by step 8 both copies of this key file are gone by design.
    seed1=$(sed -n '2p' "$test_root/keys/gen1/identity.key")
    gen1 --output json backup create --confirm-synthetic > "$test_root/gen1-backup.json"
    first=$(backup_id "$test_root/gen1-backup.json")
    gen1 backup verify "$first" --level archive >/dev/null

    # --- 2. the offline copy is taken before anything is rotated ----------------
    # An operator keeps this copy somewhere the storage host cannot drag it back to;
    # here it is a directory the drill treats as that separate place.
    mkdir -p "$test_root/vault/gen1"
    chmod 700 "$test_root/vault/gen1"
    cp -p "$test_root/keys/gen1/identity.key" "$test_root/vault/gen1/identity.key"
    cp -p "$test_root/keys/gen1/recipient.key" "$test_root/vault/gen1/recipient.key"
    stat -c '%a' "$test_root/vault/gen1/identity.key" | grep -q '^600$'

    # --- 3. rotation cannot destroy the generation it replaces ------------------
    # A rotation is a new key directory plus a new configuration, because generation
    # refuses an occupied path before writing either half. There is no command that
    # silently makes yesterday's backups unreadable.
    rejects "key generate over an existing identity" gen1 key generate
    grep -q "refusing to overwrite the existing key file" "$test_root/reject.out"
    gen2 --output json key generate > "$test_root/gen2-keys.json"
    seed2=$(sed -n '2p' "$test_root/keys/gen2/identity.key")
    recipient1=$(recipient_of "$test_root/gen1-keys.json")
    recipient2=$(recipient_of "$test_root/gen2-keys.json")
    if [[ "$recipient1" == "$recipient2" ]]; then
        echo "the rotated pair reported the recipient of the generation it replaced" >&2
        exit 1
    fi

    # --- 4. the new generation writes, and the two cannot read each other -------
    gen2 --output json backup create --confirm-synthetic > "$test_root/gen2-backup.json"
    second=$(backup_id "$test_root/gen2-backup.json")
    gen2 backup verify "$second" --level archive >/dev/null
    # Both artifacts sit in one store, so the only difference between them is the
    # recipient in each age header. Each generation opens its own and refuses the
    # other's; this is the consequence an operator accepts when rotating.
    rejects "generation 2 reading a generation 1 artifact" gen2 backup verify "$first" \
        --level archive
    grep -qiE "age|decrypt|identity" "$test_root/reject.out"
    rejects "generation 1 reading a generation 2 artifact" gen1 backup verify "$second" \
        --level archive
    grep -qiE "age|decrypt|identity" "$test_root/reject.out"

    # --- 5. the live generation 1 key is lost -----------------------------------
    # Restoring an old generation must need only the offline copy, so the live file
    # goes first and the store becomes unable to read its own older artifacts.
    rm "$test_root/keys/gen1/identity.key"
    rejects "any command after the live identity disappears" gen1t backup inspect "$first"
    grep -q "identity key file" "$test_root/reject.out"
    if [[ -n "$(ls -A "$test_root/data/staging")" || -n "$(ls -A "$test_root/data/scratch")" ]]; then
        echo "a refused read left work in staging or scratch:" >&2
        ls -R "$test_root/data/staging" "$test_root/data/scratch" >&2
        exit 1
    fi

    # --- 6. recovery from the offline copy, with the mode pitfall ---------------
    # A careless copy lands world-readable, which the store refuses: a key another
    # local user can read is not a secret. Fixing the mode is part of the procedure.
    cp "$test_root/vault/gen1/identity.key" "$test_root/keys/gen1/identity.key"
    chmod 644 "$test_root/keys/gen1/identity.key"
    rejects "a recovered identity left world-readable" gen1t backup inspect "$first"
    grep -q "must be mode 0600 or stricter" "$test_root/reject.out"
    chmod 600 "$test_root/keys/gen1/identity.key"
    gen1t --output json key status >/dev/null
    gen1t backup verify "$first" --level archive >/dev/null

    # The restore an operator actually wants: the old artifact, into a new cluster,
    # configured only by the generation's own file.
    rm "$test_root/keys/gen1/identity.key"
    vault restore plan "$first" --target backupctl_fixture_drill_old --security portable \
        --output json > "$test_root/old-plan.json"
    rm -f "$test_root"/log_tgt/pg_restore.log
    vault restore run "$(plan_id "$test_root/old-plan.json")" \
        --confirm-target backupctl_fixture_drill_old >/dev/null
    assert_reads "$test_root/log_tgt" "$test_root/data/scratch/" "old-generation restore"
    dst_sql -d backupctl_fixture_drill_old < tests/fixtures/postgres/assertions.sql >/dev/null

    # --- 7. total key loss is unrecoverable, and the bytes prove it -------------
    # The last step is the honest one. The artifact is not corrupted and not lost;
    # it is inert. The manifest is read directly here because no CLI command through
    # this configuration can reach the store any more.
    rm -rf "$test_root/vault/gen1"
    rejects "restore of a generation with no identity anywhere" lost backup inspect "$first"
    grep -q "identity key file" "$test_root/reject.out"
    python3 - "$test_root/data/artifacts/$first" <<'PY'
import hashlib
import json
import os
import sys

directory = sys.argv[1]
manifest = json.load(open(os.path.join(directory, "manifest.json")))
raw = open(os.path.join(directory, "payload.age"), "rb").read()
assert len(raw) > 0, "the ciphertext itself is gone"
assert hashlib.sha256(raw).hexdigest() == manifest["sha256"], (
    "total key loss also damaged the artifact, so this drill proved the wrong thing"
)
assert manifest["recipient_suite"] == "mlkem768x25519-v0"
print(
    "generation 1 artifact intact at {} bytes, and unreadable without its identity".format(
        len(raw)
    )
)
PY
    # The current generation is untouched by the loss, which is the point of keeping
    # one pair per generation rather than rewriting a shared key.
    gen2 backup verify "$second" --level archive >/dev/null
    gen2t restore plan "$second" --target backupctl_fixture_drill_new --security portable \
        --output json > "$test_root/new-plan.json"
    gen2t restore run "$(plan_id "$test_root/new-plan.json")" \
        --confirm-target backupctl_fixture_drill_new >/dev/null
    dst_sql -d backupctl_fixture_drill_new < tests/fixtures/postgres/assertions.sql >/dev/null

    # --- 8. an identity the operator supplied becomes usable --------------------
    # The seed below is written by hand, not generated here: publishing derives the
    # public half from it and must leave the identity file byte-identical, because a
    # rewritten seed is exactly what orphans every artifact sealed under it.
    mkdir -p "$test_root/keys/custom"
    custom_seed=$(printf 'backupctl key drill custom seed' | sha256sum | cut -c1-64)
    printf '!backupctl-mlkem768x25519-v0\n%s\n' "$custom_seed" > "$test_root/keys/custom/identity.key"
    chmod 600 "$test_root/keys/custom/identity.key"
    write_config "$test_root/custom.toml" "$test_root/keys/custom" source
    write_config "$test_root/custom-target.toml" "$test_root/keys/custom" target
    ctl_custom() { target/debug/backupctl --config "$test_root/custom.toml" "$@"; }
    rejects "status for an identity with no published half" ctl_custom key status
    grep -q "inspect recipient key file" "$test_root/reject.out"
    custom_before=$(sha256sum "$test_root/keys/custom/identity.key" | cut -d' ' -f1)
    ctl_custom --output json key publish > "$test_root/custom-publish.json"
    custom_after=$(sha256sum "$test_root/keys/custom/identity.key" | cut -d' ' -f1)
    if [[ "$custom_before" != "$custom_after" ]]; then
        echo "key publish altered the identity file it was only supposed to read" >&2
        exit 1
    fi
    stat -c '%a' "$test_root/keys/custom/recipient.key" | grep -q '^644$'
    rejects "key publish over an existing recipient" ctl_custom key publish
    grep -q "refusing to overwrite the existing key file" "$test_root/reject.out"
    # The pair is usable as a generation: write, verify, and restore under a key this
    # CLI never generated.
    ctl_custom --output json backup create --confirm-synthetic > "$test_root/custom-backup.json"
    custom=$(backup_id "$test_root/custom-backup.json")
    ctl_custom backup verify "$custom" --level archive >/dev/null
    target/debug/backupctl --config "$test_root/custom-target.toml" restore plan "$custom" \
        --target backupctl_fixture_drill_custom --security portable \
        --output json > "$test_root/custom-plan.json"
    target/debug/backupctl --config "$test_root/custom-target.toml" restore run \
        "$(plan_id "$test_root/custom-plan.json")" --confirm-target backupctl_fixture_drill_custom \
        >/dev/null
    dst_sql -d backupctl_fixture_drill_custom < tests/fixtures/postgres/assertions.sql >/dev/null
    if [[ "$(recipient_of "$test_root/custom-publish.json")" == "$recipient2" ]]; then
        echo "a hand-written seed derived the recipient of a generated pair" >&2
        exit 1
    fi

    # --- 9. nothing secret reached the store or the terminal --------------------
    for needle in "$seed1" "$seed2" "$custom_seed" backupctl_fixture_alice SCRAM-SHA-256 \
        fake-verifier-for-tests-only; do
        if grep -qr "$needle" "$test_root/data" "$test_root"/*.json "$test_root"/*.out \
            2>/dev/null; then
            echo "secret material ($needle) reached the store or CLI output" >&2
            exit 1
        fi
    done
    for dir in staging scratch; do
        if [[ -n "$(ls -A "$test_root/data/$dir")" ]]; then
            echo "the drill left work in $dir" >&2
            exit 1
        fi
    done

    echo "PostgreSQL $major: rotation, cross-generation refusal, key loss, offline recovery, total-loss inertness, and an operator-supplied identity verified"
    cleanup
    source_name=""
    target_name=""
    test_root=""
done
