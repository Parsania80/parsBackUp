#!/usr/bin/env bash
# M4a: the encrypted write and read path against real PostgreSQL tools.
#
# What the crate tests cannot prove is that a live `pg_dump` stream, a live
# `pg_restore`, and a live `psql` never meet anything but plaintext at the tool
# boundary, and that the published store never holds plaintext at all. Every
# client tool here is a wrapper that records each file argument it was handed, so
# the reads are evidence rather than an assumption.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl

# A PostgreSQL custom archive starts with these five bytes; an age stream starts
# with those. As hex they are what the tool wrappers log.
PGDMP_HEX=5047444d50
AGE_HEX=6167652d65

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

# Each wrapper appends two kinds of line to its own log before exec'ing the real
# tool: the argv it received, and one line per absolute file argument with the
# first five bytes of that file in hex. Reading the header is what tells a
# decrypted archive apart from an age stream that reached a tool by mistake.
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
                # --version must be passed alone: some tools reject connection
                # options combined with it.
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

# Every file argument a tool was handed must be a PGDMP archive under `prefix`.
# For the encrypted store that prefix is the scratch view and nothing else; for the
# plaintext control it is the store tree, where staging and artifacts are both
# expected to hold readable archives. A check that saw no read at all proves
# nothing, so it fails.
assert_reads() {
    local logdir="$1" prefix="$2" label="$3"
    python3 - "$logdir" "$prefix" "$label" "$PGDMP_HEX" <<'PY'
import os
import sys

logdir, prefix, label, pgdmp = sys.argv[1:5]
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

# Rewrites the payload digest and size a manifest records, so a replaced or
# truncated payload passes the checksum level and only authenticated decryption
# can catch it. That is the difference between "the hash matches" and "the file
# is ours".
patch_manifest() {
    python3 - "$1" "$2" <<'PY'
import hashlib
import json
import sys

manifest_path, payload = sys.argv[1], sys.argv[2]
raw = open(payload, "rb").read()
manifest = json.load(open(manifest_path))
manifest["sha256"] = hashlib.sha256(raw).hexdigest()
manifest["size_bytes"] = len(raw)
json.dump(manifest, open(manifest_path, "w"), indent=2)
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

for major in 16 17 18; do
    test_root=$(mktemp -d /tmp/backupctl-m4a-smoke-XXXXXXXX)
    source_name="backupctl-m4a-source-${major}-$$"
    target_name="backupctl-m4a-target-${major}-$$"
    target_port=$((54320 + major))

    docker run --rm -d --name "$source_name" --network none \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        -v "$test_root:$test_root" \
        "docker.arvancloud.ir/library/postgres:${major}-bookworm" >/dev/null
    # The target simulates a freshly rebuilt host that has never seen these roles.
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
    docker exec "$target_name" createdb -U postgres -h 127.0.0.1 -p "$target_port" backupctl_fixture_m1

    make_wrappers "$source_name" "$test_root/bin" "" "$test_root/log_src"
    make_wrappers "$target_name" "$test_root/bin_target" "$target_port" "$test_root/log_tgt"
    # A third client directory with its own log, for the keyless store that must
    # read straight out of artifacts/.
    make_wrappers "$source_name" "$test_root/bin_plain" "" "$test_root/log_plain"

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

[encryption]
identity_file = "$test_root/keys/identity.key"
recipient_file = "$test_root/keys/recipient.key"
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

[encryption]
identity_file = "$test_root/keys/identity.key"
recipient_file = "$test_root/keys/recipient.key"
CONFIG
    # A second generation, so a configuration can pair one identity with a
    # stranger's recipient.
    sed "s|$test_root/keys/|$test_root/keys2/|g; s|root = \"$test_root/data\"|root = \"$test_root/data_foreign\"|" \
        "$test_root/config.toml" > "$test_root/config_pair2.toml"
    sed "s|$test_root/keys/recipient.key|$test_root/keys2/recipient.key|" \
        "$test_root/config.toml" > "$test_root/config_mismatch.toml"
    # Key files inside the artifact store: an encrypted archive next to the
    # identity that opens it is a plaintext archive with extra steps.
    sed "s|$test_root/keys/identity.key|$test_root/data/identity.key|" \
        "$test_root/config.toml" > "$test_root/config_inside.toml"
    # The same database with no [encryption] block at all, into its own store root.
    # The whole block goes, header included, so TOML parsing sees no empty table.
    sed "/^\[encryption\]/,\$d" "$test_root/config.toml" |
        sed "s|client_bin_dir = \"$test_root/bin\"|client_bin_dir = \"$test_root/bin_plain\"|; s|root = \"$test_root/data\"|root = \"$test_root/data_plain\"|" \
        > "$test_root/config_plain.toml"

    ctl() { target/debug/backupctl --config "$test_root/config.toml" "$@"; }
    ctlt() { target/debug/backupctl --config "$test_root/config_target.toml" "$@"; }
    json_of() {
        python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
    }

    # --- 1. the key pair is created, confirmed, and never overwritten ----------
    # Nothing exists yet, so a status request must name the missing file rather than
    # invent a key.
    rejects "key status before generation" target/debug/backupctl \
        --config "$test_root/config.toml" key status
    grep -q "identity key file" "$test_root/reject.out"
    # Key files inside the store are refused before anything is written.
    rejects "key generate inside the store" target/debug/backupctl \
        --config "$test_root/config_inside.toml" key generate
    grep -q "must live outside the artifact store" "$test_root/reject.out"
    if [[ -e "$test_root/data/identity.key" ]]; then
        echo "key generate wrote a key inside the store despite refusing" >&2
        exit 1
    fi
    # The real pair: the parent directory does not exist yet, which is the normal
    # first run.
    ctl --output json key generate > "$test_root/keygen.json"
    stat -c '%a' "$test_root/keys" | grep -q '^700$'
    ctl key generate > "$test_root/second_generate.out" 2>&1 || true
    grep -q "refusing to overwrite the existing key file" "$test_root/second_generate.out"
    ctl --output json key status > "$test_root/keystatus.json"
    python3 - "$test_root/keystatus.json" "$test_root/keygen.json" <<'PY'
import json
import sys

status = json.load(open(sys.argv[1]))
generated = json.load(open(sys.argv[2]))
identity, recipient = status["identity"], status["recipient"]
assert identity["suite"] == "mlkem768x25519-v0", identity["suite"]
assert identity["mode"] == "0600", identity["mode"]
assert recipient["mode"] == "0644", recipient["mode"]
assert identity["recipient"] == recipient["recipient"], "the two files carry different keys"
assert len(identity["recipient"]) == 2432, len(identity["recipient"])
assert identity["path"] == generated["identity"]["path"]
PY
    target/debug/backupctl --config "$test_root/config_pair2.toml" key generate >/dev/null
    if target/debug/backupctl --config "$test_root/config_mismatch.toml" \
        key status > "$test_root/mismatch.out" 2>&1; then
        echo "a mismatched identity/recipient pair was reported as usable" >&2
        exit 1
    fi
    grep -q "is not the recipient of identity key file" "$test_root/mismatch.out"

    # The seed is the only secret in the pair, so it must appear in no CLI output
    # and no stored byte. Every later step appends to the files grepped at step 3.
    seed=$(sed -n '2p' "$test_root/keys/identity.key")
    if [[ ${#seed} -ne 64 ]]; then
        echo "the identity key file did not hold a 64-character seed" >&2
        exit 1
    fi

    # --- 2. a backup writes ciphertext and nothing else ------------------------
    ctl --output json backup create --confirm-synthetic > "$test_root/created.json"
    backup_id=$(json_of "$test_root/created.json" id)
    artifact_dir="$test_root/data/artifacts/$backup_id"
    python3 - "$test_root/created.json" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1]))
assert manifest["format"] == "m4a-development-age", manifest["format"]
assert manifest["recipient_suite"] == "mlkem768x25519-v0"
# Both sizes belong in the manifest: the store holds the ciphertext, and the
# plaintext size is the bound a decrypt is allowed to expand to.
assert manifest["payload_plaintext_bytes"] > 0
assert manifest["size_bytes"] > manifest["payload_plaintext_bytes"], "age does not compress"
PY
    find "$artifact_dir" -maxdepth 1 -mindepth 1 -printf '%f\n' | sort > "$test_root/files.txt"
    if ! diff -q "$test_root/files.txt" \
        <(printf 'complete\nglobals.age\nmanifest.json\npayload.age\n') >/dev/null; then
        echo "an encrypted artifact holds more than ciphertext, manifest, and marker:" >&2
        cat "$test_root/files.txt" >&2
        exit 1
    fi
    if [[ "$(head -c 5 "$artifact_dir/payload.age" | od -An -tx1 | tr -d ' \n')" != "$AGE_HEX" ]]; then
        echo "payload.age is not an age stream" >&2
        exit 1
    fi
    # pg_dump must never be given an output file: the pipe is the whole design.
    if grep -h '^argv ' "$test_root"/log_src/pg_dump*.log | grep -qF -- '--file'; then
        echo "a dump tool was given --file, so PostgreSQL wrote a plaintext file" >&2
        exit 1
    fi
    ctl backup inspect "$backup_id" > "$test_root/inspect.out"
    grep -q "recipient suite: mlkem768x25519-v0" "$test_root/inspect.out"

    # --- 3. no plaintext anywhere in the store ---------------------------------
    # backupctl_fixture_alice is a role name the globals export carries verbatim, so
    # it is the needle a sealed archive must not contain. Step 9 shows the same grep
    # finding it in a keyless store, which is what makes its silence here evidence.
    if grep -qr "backupctl_fixture_alice" "$test_root/data"; then
        echo "role metadata was found in plaintext inside the encrypted store:" >&2
        grep -rl "backupctl_fixture_alice" "$test_root/data" >&2
        exit 1
    fi
    for needle in fake-verifier-for-tests-only SCRAM-SHA-256 "$seed"; do
        if grep -qr "$needle" "$test_root/data" "$test_root"/*.json "$test_root"/*.out 2>/dev/null; then
            echo "secret material ($needle) reached the store or CLI output" >&2
            exit 1
        fi
    done
    for dir in staging scratch; do
        if [[ -n "$(ls -A "$test_root/data/$dir")" ]]; then
            echo "a finished backup left work in $dir" >&2
            exit 1
        fi
    done

    # --- 4. verification decrypts only into scratch ----------------------------
    # Checksum level hashes ciphertext, so it must not need a scratch file at all.
    rm -f "$test_root"/log_src/pg_restore.log
    ctl --output json backup verify "$backup_id" --level checksum >/dev/null
    if [[ -e "$test_root/log_src/pg_restore.log" ]] || [[ -n "$(ls -A "$test_root/data/scratch")" ]]; then
        echo "checksum verification decrypted the payload it only needed to hash" >&2
        exit 1
    fi
    ctl --output json backup verify "$backup_id" --level archive >/dev/null
    assert_reads "$test_root/log_src" "$test_root/data/scratch/" "archive verification"
    if [[ -n "$(ls -A "$test_root/data/scratch")" ]]; then
        echo "archive verification left decrypted plaintext in scratch" >&2
        exit 1
    fi

    # --- 5. DR restore plays the ciphertext back into a new cluster ------------
    ctlt restore plan "$backup_id" --target backupctl_fixture_m4a --security dr \
        --output json > "$test_root/plan.json"
    plan_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$test_root/plan.json")
    rm -f "$test_root"/log_tgt/pg_restore.log
    ctlt restore run "$plan_id" --confirm-target backupctl_fixture_m4a >/dev/null
    assert_reads "$test_root/log_tgt" "$test_root/data/scratch/" "DR restore"
    for dir in staging scratch; do
        if [[ -n "$(ls -A "$test_root/data/$dir")" ]]; then
            echo "a finished restore left decrypted plaintext in $dir" >&2
            exit 1
        fi
    done
    if grep -qr "backupctl_fixture_alice" "$test_root/data"; then
        echo "a restore wrote plaintext into the encrypted store" >&2
        exit 1
    fi
    dst_sql -d backupctl_fixture_m4a < tests/fixtures/postgres/assertions.sql >/dev/null
    dst_sql -d backupctl_fixture_m4a < tests/fixtures/postgres/security-assertions.sql >/dev/null
    ctl --output json backup inspect "$backup_id" > "$test_root/after.json"
    python3 - "$test_root/after.json" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1]))
assert manifest["verification_level"] == "restore-tested"
assert manifest["format"] == "m4a-development-age"
assert manifest["recipient_suite"] == "mlkem768x25519-v0"
PY
    # Marking the artifact restore-tested must not disturb its ciphertext.
    if [[ "$(head -c 5 "$artifact_dir/payload.age" | od -An -tx1 | tr -d ' \n')" != "$AGE_HEX" ]]; then
        echo "the payload stopped being an age stream after a restore" >&2
        exit 1
    fi

    # --- 6. a bit flip is caught by the digest before age even runs ------------
    ctl --output json backup create --confirm-synthetic > "$test_root/flip.json"
    flip_id=$(json_of "$test_root/flip.json" id)
    printf 'X' | dd of="$test_root/data/artifacts/$flip_id/payload.age" bs=1 seek=3000 \
        conv=notrunc status=none
    rejects "checksum verify of a flipped payload" ctl backup verify "$flip_id" --level checksum
    grep -q "payload checksum or size mismatch" "$test_root/reject.out"
    rejects "restore plan over a flipped payload" ctlt restore plan "$flip_id" \
        --target backupctl_fixture_m4a_flip --security portable

    # --- 7. ciphertext from a stranger's recipient is refused -------------------
    # An age stream is bound to the recipient its header was wrapped to, so a payload
    # published by a different key pair cannot be opened by this identity even after its
    # manifest digest was rewritten to match the bytes exactly. Detecting a swap between
    # two artifacts of the SAME recipient is deliberately not claimed here: age
    # authenticates a stream, not which of this deployment's backups it came from, and
    # that is what M4b signing adds.
    target/debug/backupctl --config "$test_root/config_pair2.toml" --output json \
        backup create --confirm-synthetic > "$test_root/foreign.json"
    foreign_id=$(json_of "$test_root/foreign.json" id)
    ctl --output json backup create --confirm-synthetic > "$test_root/victim.json"
    victim_id=$(json_of "$test_root/victim.json" id)
    victim_dir="$test_root/data/artifacts/$victim_id"
    cp "$test_root/data_foreign/artifacts/$foreign_id/payload.age" "$victim_dir/payload.age"
    patch_manifest "$victim_dir/manifest.json" "$victim_dir/payload.age"
    # The digest agrees with the file now, so the checksum level passes: that level
    # proves the hash matches, not that the bytes are ours.
    ctl --output json backup verify "$victim_id" --level checksum >/dev/null
    rejects "archive verification of a foreign recipient's payload" ctl backup verify \
        "$victim_id" --level archive
    grep -qiE "age|decrypt|identity" "$test_root/reject.out"
    # Planning only hashes, so it accepts the forgery; the run is where decryption
    # refuses it. The target database is created before the payload is decrypted, so an
    # empty database is the documented outcome and replayed objects would not be.
    ctlt restore plan "$victim_id" --target backupctl_fixture_m4a_forged --security portable \
        --output json > "$test_root/forged.json"
    forged_plan=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan"]["id"])' "$test_root/forged.json")
    rejects "restore run over a foreign recipient's payload" ctlt restore run "$forged_plan" \
        --confirm-target backupctl_fixture_m4a_forged
    if [[ "$(dst_sql -tA -d postgres -c \
        "SELECT 1 FROM pg_database WHERE datname = 'backupctl_fixture_m4a_forged'")" == "1" ]]; then
        replayed=$(dst_sql -tA -d backupctl_fixture_m4a_forged \
            -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'app'")
        if [[ "$replayed" != "0" ]]; then
            echo "foreign ciphertext replayed $replayed objects into the target" >&2
            exit 1
        fi
    fi

    # --- 8. truncation is refused even with a matching digest -----------------
    # age authenticates the whole stream, so a shorter file that hashes correctly is
    # still not a backup.
    ctl --output json backup create --confirm-synthetic > "$test_root/short.json"
    short_id=$(json_of "$test_root/short.json" id)
    short_payload="$test_root/data/artifacts/$short_id/payload.age"
    size=$(stat -c '%s' "$short_payload")
    truncate -s $((size - 64)) "$short_payload"
    patch_manifest "$test_root/data/artifacts/$short_id/manifest.json" "$short_payload"
    ctl --output json backup verify "$short_id" --level checksum >/dev/null
    rejects "archive verification of a truncated payload" ctl backup verify "$short_id" \
        --level archive

    # --- 9. without key files the same tool writes the M1 plaintext layout -----
    # This is the control for steps 3 and 4: the same greps and the same wrappers must
    # find plaintext in a keyless store, which is what makes their silence above
    # evidence rather than an accident of configuration.
    target/debug/backupctl --config "$test_root/config_plain.toml" --output json \
        backup create --confirm-synthetic > "$test_root/plain.json"
    plain_id=$(json_of "$test_root/plain.json" id)
    plain_dir="$test_root/data_plain/artifacts/$plain_id"
    python3 - "$test_root/plain.json" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1]))
assert manifest["format"] == "m1-development-plaintext", manifest["format"]
assert manifest["recipient_suite"] is None
assert manifest["payload_plaintext_bytes"] is None
PY
    if [[ ! -e "$plain_dir/payload.dump" || ! -e "$plain_dir/globals.sql" ]]; then
        echo "a keyless store did not write the plaintext layout" >&2
        exit 1
    fi
    if [[ -e "$plain_dir/payload.age" ]]; then
        echo "a keyless store wrote an age payload" >&2
        exit 1
    fi
    if ! grep -q "backupctl_fixture_alice" "$plain_dir/globals.sql"; then
        echo "the plaintext store lacks the role metadata the encrypted store sealed" >&2
        exit 1
    fi
    if [[ -e "$test_root/data_plain/scratch" ]]; then
        echo "a keyless store created a scratch directory" >&2
        exit 1
    fi
    # A plaintext store hands its tools a real file from its own tree: staging during
    # the dump, the artifact afterwards. That is what the encrypted store gives up.
    target/debug/backupctl --config "$test_root/config_plain.toml" \
        backup verify "$plain_id" --level archive >/dev/null
    assert_reads "$test_root/log_plain" "$test_root/data_plain/" "plaintext archive verification"

    echo "PostgreSQL $major: hybrid age write path, scratch-only decryption, DR restore, and bit-flip/foreign-recipient/truncation refusal passed"
    cleanup
    source_name=""
    target_name=""
    test_root=""
done
