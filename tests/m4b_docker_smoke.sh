#!/usr/bin/env bash
# M4b: signed artifact v1 against real PostgreSQL tools, on PostgreSQL 16, 17 and 18.
#
# The crate tests prove the bytes; this proves the operation. Three things can only be
# observed here: that a live `pg_dump` stream becomes a v1 directory whose signature is
# checked before a single byte is decrypted, that a disaster-recovery host holding an
# identity and a verifying key — and deliberately no signing secret — can verify, plan and
# restore that artifact, and that stock `rage` still refuses the hybrid stream our writer
# produces. Every client tool is a wrapper logging each absolute file argument it was handed
# together with that file's first five bytes, so the reads are evidence, not an assumption.
#
# The DR cluster answers at the same host and port the manifest claims, on purpose:
# `source_fingerprint` binds engine, major, host, port and database name. Both phases of a
# pass therefore share one `[source]` block and one port, with the source container stopped
# before the DR container takes its place. That makes step 9 a DR rehearsal rather than a
# second connection to the same server, and step 10 the proof that a configuration naming a
# different database is refused before anything is created.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl

# A PostgreSQL custom archive starts with these five bytes; an age stream starts with those.
PGDMP_HEX=5047444d50
AGE_HEX=6167652d65
HYBRID_SIGNATURE_BYTES=3373
RECIPIENT_SUITE=mlkem768x25519-v0
SIGNATURE_SUITE='ed25519+ml-dsa-65'
SIGNING_MARKER='!backupctl-ed25519mldsa65-v0'
IDENTITY_MARKER='!backupctl-mlkem768x25519-v0'

# The stock-rage divergence is a tested contract, so a missing `rage` fails this run instead
# of silently skipping the step that states it.
rage_bin=$(command -v rage || true)
[[ -n "$rage_bin" ]] || rage_bin="$HOME/.cargo/bin/rage"
[[ -x "$rage_bin" ]] || {
    echo "the stock-rage assertion needs rage on PATH (cargo install age --locked)" >&2
    exit 1
}
rage_keygen="$(dirname "$rage_bin")/rage-keygen"
[[ -x "$rage_keygen" ]] || {
    echo "rage-keygen not found beside $rage_bin" >&2
    exit 1
}

source_name=""
dr_name=""
test_root=""
cleanup() {
    for name in "$source_name" "$dr_name"; do
        if [[ -n "$name" ]]; then
            docker stop "$name" >/dev/null 2>&1 || true
        fi
    done
    if [[ -n "$test_root" ]]; then
        rm -rf "$test_root"
    fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# The connection flags come from the configuration (--host/--port), so a wrapper only has to
# put the tool in the right container. Both clusters serve the same port, at different times,
# which is what lets one [source] block describe both.
make_wrappers() {
    local container="$1" dir="$2" logdir="$3"
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
            printf 'exec /usr/bin/docker exec -i %s %s "$@"\n' "$container" "$tool"
        } > "$dir/$tool"
        chmod 700 "$dir/$tool"
    done
}

wait_ready() {
    local container="$1" port="$2"
    for _ in $(seq 1 80); do
        if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres -p "$port" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

# Every file argument a tool was handed must be a PGDMP archive under `prefix`; a check that
# saw no read at all proves nothing, so it fails.
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

# A digest over every tool log, so "this level ran no PostgreSQL tool" is a comparison rather
# than an absence of evidence.
log_state() {
    find "$1" -type f -name '*.log' -print0 | sort -z | xargs -0 -r sha256sum
}

# The same over an artifact directory: a signed v1 is immutable, so a restore that proves it
# replays must leave every byte of it exactly where it was.
dir_state() {
    local dir="$1" file
    while IFS= read -r file; do
        sha256sum "$dir/$file"
    done < <(find "$dir" -maxdepth 1 -type f -printf '%f\n' | sort) | sha256sum
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

# Rewrites the payload digest and size `public.json` records, so replaced or truncated
# ciphertext is exactly what the discovery file now describes. This is the attacker M4a could
# not stop: it holds the recipient, can seal its own bytes, and can edit every plaintext field
# beside them. Only a signature over the digests, made by a key that is not in the store,
# tells it apart.
patch_public() {
    python3 - "$1" <<'PY'
import hashlib
import json
import os
import sys

directory = sys.argv[1]
path = os.path.join(directory, "payload.age")
raw = open(path, "rb").read()
header_path = os.path.join(directory, "public.json")
header = json.load(open(header_path))
header["payload_sha256"] = hashlib.sha256(raw).hexdigest()
header["payload_ciphertext_bytes"] = len(raw)
json.dump(header, open(header_path, "w"))
PY
}

# Edits one field of one artifact's public.json, for the cases where the header alone lies.
# The third argument says which JSON type to write, because a digest is digits too.
edit_public() {
    python3 - "$1" "$2" "$3" "$4" <<'PY'
import json
import sys

directory, field, value, kind = sys.argv[1:5]
path = f"{directory}/public.json"
header = json.load(open(path))
header[field] = int(value) if kind == "int" else value
json.dump(header, open(path, "w"))
PY
}

get_json() {
    python3 - "$1" "$2" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1]))
for part in sys.argv[2].split("."):
    document = document[int(part)] if part.isdigit() else document[part]
print(document)
PY
}

json_count() {
    python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))[sys.argv[2]]))' "$1" "$2"
}

for major in 16 17 18; do
    test_root=$(mktemp -d /tmp/backupctl-m4b-smoke-XXXXXXXX)
    source_name="backupctl-m4b-source-${major}-$$"
    dr_name="backupctl-m4b-dr-${major}-$$"
    port=$((54320 + major))
    fixture_db=backupctl_fixture_m1
    dr_db=backupctl_fixture_m4b_dr
    probe_db=backupctl_fixture_m4b_probe

    docker run --rm -d --name "$source_name" --network host \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        -v "$test_root:$test_root" \
        "docker.arvancloud.ir/library/postgres:${major}-bookworm" -p "$port" >/dev/null
    wait_ready "$source_name" "$port" || fail "source $major not ready"

    src_sql() {
        docker exec -i "$source_name" psql -U postgres -h 127.0.0.1 -p "$port" \
            -X -v ON_ERROR_STOP=1 "$@"
    }
    dr_sql() {
        docker exec -i "$dr_name" psql -U postgres -h 127.0.0.1 -p "$port" \
            -X -v ON_ERROR_STOP=1 "$@"
    }

    docker exec -i "$source_name" createdb -U postgres -h 127.0.0.1 -p "$port" "$fixture_db"
    src_sql -d "$fixture_db" < tests/fixtures/postgres/core.sql >/dev/null

    make_wrappers "$source_name" "$test_root/bin" "$test_root/log_src"

    # A generation is a configuration here, as it was in M4a: `key generate`, `key publish`
    # and `key status` act on the paths in the file and nothing else. The fifth argument is
    # the key directory and the sixth which host shape the [signing] block describes:
    # `both` for a writer (secret plus public half), `verify` for a DR host (public half
    # only), `none` for a store that signs nothing.
    write_config() {
        local out="$1" database="$2" bin="$3" root="$4" keys="$5" shape="$6"
        {
            echo 'export_globals = true'
            echo
            cat <<SOURCE
[source]
host = "127.0.0.1"
port = $port
user = "postgres"
database = "$database"
client_bin_dir = "$bin"
SOURCE
            echo
            cat <<STORAGE
[storage]
root = "$root"
STORAGE
            echo
            cat <<CRYPTO
[encryption]
identity_file = "$keys/identity.key"
recipient_file = "$keys/recipient.key"
CRYPTO
            if [[ "$shape" != none ]]; then
                echo
                if [[ "$shape" == both ]]; then
                    cat <<SIGNING
[signing]
signing_key_file = "$keys/signing.key"
verifying_key_file = "$keys/verifying.key"
SIGNING
                else
                    cat <<SIGNING
[signing]
verifying_key_file = "$keys/verifying.key"
SIGNING
                fi
            fi
        } > "$out"
    }
    write_config "$test_root/write.toml" "$fixture_db" "$test_root/bin" \
        "$test_root/data" "$test_root/keys/gen1" both
    write_config "$test_root/foreign.toml" "$fixture_db" "$test_root/bin" \
        "$test_root/data_foreign" "$test_root/keys/gen2" both
    write_config "$test_root/dr.toml" "$fixture_db" "$test_root/bin" \
        "$test_root/data" "$test_root/keys/gen1" verify

    ctl() { target/debug/backupctl --config "$test_root/write.toml" "$@"; }
    dctl() { target/debug/backupctl --config "$test_root/dr.toml" "$@"; }
    fctl() { target/debug/backupctl --config "$test_root/foreign.toml" "$@"; }
    plan_id() { get_json "$1" "plan.id"; }
    backup_id() { get_json "$1" "manifest.backup_id"; }
    artifact_dir() { echo "$test_root/data/artifacts/$1"; }

    # --- 1. four key files, and the refusals that keep them honest --------------
    # A [signing] block with nothing to seal under is a contradiction, not a store that is
    # half configured: the signature is made over two ciphertext files.
    sed '/^\[encryption\]/,/^$/d' "$test_root/write.toml" > "$test_root/noenc.toml"
    rejects "a [signing] block with no [encryption] block" \
        target/debug/backupctl --config "$test_root/noenc.toml" key generate
    grep -qF "a [signing] block requires an [encryption] block" "$test_root/reject.out"
    # Same rule for both key families, and each names its own family in the refusal.
    sed "s|$test_root/keys/gen1/identity.key|$test_root/data/keys/identity.key|" \
        "$test_root/write.toml" > "$test_root/inside_enc.toml"
    rejects "an identity file inside the artifact store" \
        target/debug/backupctl --config "$test_root/inside_enc.toml" key generate
    grep -q "encryption key files must live outside the artifact store" "$test_root/reject.out"
    sed "s|$test_root/keys/gen1/signing.key|$test_root/data/keys/signing.key|" \
        "$test_root/write.toml" > "$test_root/inside_sig.toml"
    rejects "a signing file inside the artifact store" \
        target/debug/backupctl --config "$test_root/inside_sig.toml" key generate
    grep -q "signing key files must live outside the artifact store" "$test_root/reject.out"
    # Two roles, one file: the contract keeps them apart and so does the configuration.
    sed "s|$test_root/keys/gen1/signing.key|$test_root/keys/gen1/identity.key|" \
        "$test_root/write.toml" > "$test_root/same.toml"
    rejects "a signing key file that is also the identity" \
        target/debug/backupctl --config "$test_root/same.toml" key generate
    grep -q "must not name the same file" "$test_root/reject.out"

    ctl --output json key generate > "$test_root/keygen.json"
    stat -c '%a' "$test_root/keys/gen1" | grep -q '^700$'
    stat -c '%a' "$test_root/keys/gen1/signing.key" | grep -q '^600$'
    stat -c '%a' "$test_root/keys/gen1/verifying.key" | grep -q '^644$'
    # Refusing an occupied path is what keeps a rotation from orphaning a generation.
    rejects "key generate over an existing signing key" ctl key generate
    grep -q "refusing to overwrite the existing key file" "$test_root/reject.out"
    python3 - "$test_root/keygen.json" "$SIGNATURE_SUITE" "$RECIPIENT_SUITE" <<'PY'
import json
import re
import sys

report = json.load(open(sys.argv[1]))
signature_suite, recipient_suite = sys.argv[2:4]
rows = report["signing"]
assert len(rows) == 2, f"a writer reports both halves, got {len(rows)}"
signing, verifying = rows
assert signing["role"] == "signing" and verifying["role"] == "verifying", rows
assert signing["mode"] == "0600", signing["mode"]
assert verifying["mode"] == "0644", verifying["mode"]
for row in rows:
    assert row["suite"] == signature_suite, row["suite"]
    assert re.fullmatch(r"[0-9a-f]{16}", row["signer"]), row["signer"]
assert signing["signer"] == verifying["signer"], "the two halves are not one key"
assert report["identity"]["suite"] == recipient_suite
assert report["identity"]["recipient"] == report["recipient"]["recipient"]
PY
    recipient_hex=$(get_json "$test_root/keygen.json" "identity.recipient")
    signer_line=$(get_json "$test_root/keygen.json" "signing.0.signer")
    [[ ${#recipient_hex} -eq 2432 ]] || fail "recipient hex line is ${#recipient_hex} characters"
    [[ ${#signer_line} -eq 16 ]] || fail "signer id is ${#signer_line} characters"
    # A key command prints public facts. The two seeds below are the only secrets in these
    # four files, so step 10 greps every byte this pass produced for them.
    identity_seed=$(sed -n '2p' "$test_root/keys/gen1/identity.key")
    signing_seed=$(sed -n '2p' "$test_root/keys/gen1/signing.key")
    [[ ${#identity_seed} -eq 64 ]] || fail "identity key held ${#identity_seed} hex characters"
    [[ ${#signing_seed} -eq 128 ]] || fail "signing key held ${#signing_seed} hex characters"
    head -n 1 "$test_root/keys/gen1/signing.key" | grep -q "^$SIGNING_MARKER$"
    # `key status` on a writer reports all four files in one call, which is what an operator
    # checks before a first backup: this host can seal, publish, and verify. The report is
    # written to a file and asserted field by field, because a key command that leaked a seed
    # would leak it in exactly this shape of output.
    ctl --output json key status > "$test_root/status.json"
    if grep -q -e "$identity_seed" -e "$signing_seed" "$test_root/status.json"; then
        fail "key status printed a seed"
    fi
    python3 - "$test_root/status.json" "$test_root/keygen.json" <<'PY'
import json
import sys

status, generated = (json.load(open(path)) for path in sys.argv[1:3])
rows = status["signing"]
assert len(rows) == 2, f"a writer reports both signing halves, got {len(rows)}"
assert {row["role"] for row in rows} == {"signing", "verifying"}, rows
by_role = {row["role"]: row for row in rows}
assert by_role["signing"]["mode"] == "0600", by_role["signing"]
assert by_role["verifying"]["mode"] == "0644", by_role["verifying"]
for row in rows:
    assert row["suite"] == generated["signing"][0]["suite"], row
    assert row["signer"] == generated["signing"][0]["signer"], row
assert status["identity"]["recipient"] == generated["identity"]["recipient"]
assert status["recipient"]["recipient"] == generated["recipient"]["recipient"]
assert status["identity"]["path"].endswith("identity.key"), status["identity"]
assert by_role["signing"]["path"].endswith("signing.key"), by_role["signing"]
PY

    # --- 2. the write is v1, and only v1 files are on disk ----------------------
    grep -q '"shape":"signed artifact v1"' \
        <(target/debug/backupctl --config "$test_root/write.toml" --output json config check)
    ctl --output json backup create --confirm-synthetic > "$test_root/first.json"
    first=$(backup_id "$test_root/first.json")
    first_dir=$(artifact_dir "$first")
    python3 - "$test_root/first.json" "$fixture_db" "$major" <<'PY'
import json
import re
import sys

created = json.load(open(sys.argv[1]))
database, major = sys.argv[2], int(sys.argv[3])
header, manifest = created["public"], created["manifest"]
assert header["format_version"] == 1 and manifest["format_version"] == 1
assert header["backup_id"] == manifest["backup_id"]
assert header["recipient_suite"] == "mlkem768x25519-v0"
assert header["signature_suite"] == "ed25519+ml-dsa-65"
assert manifest["engine"] == "postgresql"
assert manifest["source_server_major"] == major
# A dump that named no profile records the reserved synthetic snapshot, so a v1 manifest never
# has an empty scope field to guess at.
assert manifest["profile_snapshot"]["name"] == "whole-database"
assert manifest["profile_snapshot"]["database"] == database
assert manifest["profile_snapshot"]["large_objects"] is True
assert manifest["resolved_selection"]["whole_database"] is True
assert manifest["globals_policy"] == "exported"
assert manifest["verification_level"] == "none"
# The table of contents is recorded at write time, because the manifest is signed and an
# archive check performed later could not be written into it afterwards.
assert manifest["archive_toc_sha256"] is not None
assert re.fullmatch(r"[0-9a-f]{16}", manifest["source_fingerprint"])
assert re.fullmatch(r"[0-9a-f]{64}", header["payload_sha256"])
assert manifest["payload_ciphertext_bytes"] == header["payload_ciphertext_bytes"] > 0
assert manifest["archive_plaintext_bytes"] > 0
# age does not compress, and the store holds only ciphertext.
assert header["payload_ciphertext_bytes"] > manifest["archive_plaintext_bytes"]
PY
    find "$first_dir" -maxdepth 1 -mindepth 1 -printf '%f\n' | sort > "$test_root/files.txt"
    if ! diff -q "$test_root/files.txt" \
        <(printf 'complete\nglobals.age\nmanifest.age\npayload.age\npublic.json\nsignature.hybrid\n') \
        >/dev/null; then
        echo "a v1 artifact is not exactly its six files:" >&2
        cat "$test_root/files.txt" >&2
        exit 1
    fi
    [[ "$(stat -c '%s' "$first_dir/signature.hybrid")" -eq $HYBRID_SIGNATURE_BYTES ]] ||
        fail "signature.hybrid is $(stat -c '%s' "$first_dir/signature.hybrid") bytes"
    for name in payload.age globals.age manifest.age; do
        [[ "$(head -c 5 "$first_dir/$name" | od -An -tx1 | tr -d ' \n')" == "$AGE_HEX" ]] ||
            fail "$name is not an age stream"
    done
    if [[ -e "$first_dir/payload.dump" || -e "$first_dir/globals.sql" ||
        -e "$first_dir/manifest.json" ]]; then
        fail "a v1 artifact also holds a development-layout file"
    fi
    # Signing changed the sink, not the pipe: a dump tool must still never name an output file.
    if grep -h '^argv ' "$test_root"/log_src/pg_dump*.log | grep -qF -- '--file'; then
        fail "a dump tool was given --file, so PostgreSQL wrote a plaintext file"
    fi
    ctl backup inspect "$first" > "$test_root/inspect.out"
    grep -q "format: signed artifact v1" "$test_root/inspect.out"
    grep -q "signed: $SIGNATURE_SUITE by signer $signer_line" "$test_root/inspect.out"
    grep -q "source fingerprint:" "$test_root/inspect.out"
    grep -q "table of contents: [0-9a-f]" "$test_root/inspect.out"

    # --- 3. no plaintext, no secret, no leftovers -------------------------------
    # A magic scan over every byte of the store: M4a could only make this claim about tool
    # arguments, because a v1 store holds no readable archive at all.
    python3 - "$test_root/data" <<'PY'
import os
import sys

needle = b"PGDMP"
hits = []
for base, _, files in os.walk(sys.argv[1]):
    for name in sorted(files):
        path = os.path.join(base, name)
        if needle in open(path, "rb").read():
            hits.append(path)
if hits:
    sys.exit("plaintext archive bytes inside the signed store: " + ", ".join(hits))
print(f"no PGDMP magic anywhere under {sys.argv[1]}")
PY
    for needle in backupctl_fixture_alice SCRAM-SHA-256 fake-verifier-for-tests-only \
        "$identity_seed" "$signing_seed"; do
        if grep -qr -- "$needle" "$test_root/data" "$test_root"/*.json "$test_root"/*.out 2>/dev/null; then
            echo "secret or plaintext material ($needle) reached the store or CLI output:" >&2
            grep -rl -- "$needle" "$test_root/data" "$test_root"/*.json "$test_root"/*.out >&2
            exit 1
        fi
    done
    for dir in staging scratch; do
        if [[ -n "$(ls -A "$test_root/data/$dir")" ]]; then
            fail "a finished backup left work in $dir"
        fi
    done

    # --- 4. the three levels, and what each is allowed to touch -----------------
    # Signature level is the DR host's whole toolkit: recompute both ciphertext digests,
    # verify the detached signature, decrypt nothing.
    reads_before=$(log_state "$test_root/log_src")
    ctl --output json backup verify "$first" --level signature > "$test_root/v-sig.json"
    [[ "$(log_state "$test_root/log_src")" == "$reads_before" ]] ||
        fail "signature-level verification ran a PostgreSQL tool"
    [[ -z "$(ls -A "$test_root/data/scratch")" ]] ||
        fail "signature-level verification decrypted into scratch"
    python3 - "$test_root/v-sig.json" "$test_root/first.json" <<'PY'
import json
import sys

report, created = (json.load(open(path)) for path in sys.argv[1:3])
header = created["public"]
assert report["level"] == "signature", report["level"]
assert report["payload_sha256"] == header["payload_sha256"]
assert report["payload_size_bytes"] == header["payload_ciphertext_bytes"]
# The globals digest lives inside the encrypted manifest, so a reader that decrypts nothing
# cannot report it. That absence is the level's meaning, not a gap in the report.
assert report["globals_sha256"] is None and report["globals_size_bytes"] is None
origin = report["origin"]
assert origin["signer_id"] == header["signer_id"]
assert origin["recipient_id"] == header["recipient_id"]
assert origin["signature_suite"] == header["signature_suite"]
PY
    grep -q "nothing was decrypted to produce this report" \
        <(ctl backup verify "$first" --level signature)

    # Checksum level decrypts the manifest (never the payload) to read authenticated digests,
    # so it reports globals and still runs no tool.
    reads_before=$(log_state "$test_root/log_src")
    ctl --output json backup verify "$first" --level checksum > "$test_root/v-sum.json"
    [[ "$(log_state "$test_root/log_src")" == "$reads_before" ]] ||
        fail "checksum-level verification ran a PostgreSQL tool"
    [[ -z "$(ls -A "$test_root/data/scratch")" ]] ||
        fail "checksum-level verification decrypted the payload"
    python3 - "$test_root/v-sum.json" "$test_root/v-sig.json" <<'PY'
import json
import sys

checksum, signature = (json.load(open(path)) for path in sys.argv[1:3])
assert checksum["globals_sha256"] is not None, "no globals digest from the signed manifest"
assert checksum["payload_sha256"] == signature["payload_sha256"]
assert checksum["origin"] == signature["origin"]
PY

    rm -f "$test_root"/log_src/pg_restore.log
    ctl --output json backup verify "$first" --level archive > "$test_root/v-arc.json"
    assert_reads "$test_root/log_src" "$test_root/data/scratch/" "archive verification"
    [[ -z "$(ls -A "$test_root/data/scratch")" ]] ||
        fail "archive verification left decrypted plaintext in scratch"
    grep -q '"level": "archive"' "$test_root/v-arc.json"

    # Listing needs no key at all; inspect needs the decryption identity. The DR-shape store
    # is the one asked to list, because that is the host with the least material.
    dctl --output json backup list > "$test_root/list.json"
    python3 - "$test_root/list.json" "$test_root/first.json" <<'PY'
import json
import sys

listing, created = (json.load(open(path)) for path in sys.argv[1:3])
assert [row["backup_id"] for row in listing["signed"]] == [created["manifest"]["backup_id"]]
assert listing["unsigned"] == []
assert listing["signed"][0]["payload_sha256"] == created["public"]["payload_sha256"]
PY
    grep -q "signed v1 (signer $signer_line)" <(dctl backup list)

    # --- 5. stock rage refuses what our writer produced ------------------------
    # The stanza tags are the whole reason, so they are pinned at CLI level before the binary
    # is asked to disagree: exactly one hybrid recipient, age's noise stanza beside it, and no
    # classical X25519 line a downgraded reader could fall back to.
    python3 - "$first_dir/payload.age" "$RECIPIENT_SUITE" <<'PY'
import sys

path, suite = sys.argv[1:3]
tag = suite.rsplit("-", 1)[0].encode()
raw = open(path, "rb").read()
magic = b"age-encryption.org/v1"
if not raw.startswith(magic):
    sys.exit(f"payload.age does not open with the age header: {raw[:32]!r}")
# The header block ends at the first empty line; everything after it is body, whose
# base64 lines can never be mistaken for stanza lines but are not worth scanning.
header = raw.partition(b"\n\n")[0]
stanzas = []
for line in header.splitlines():
    if line.startswith(b"-> "):
        parts = line[3:].split()
        if parts:
            stanzas.append(parts[0])
if stanzas.count(tag) != 1:
    sys.exit(f"payload.age carries {stanzas}, expected exactly one {tag!r} stanza")
foreign = [s for s in stanzas if s != tag and not s.endswith(b"-grease")]
if foreign:
    sys.exit(f"payload.age shares its header with {foreign}")
print(
    f"payload.age header: one {tag.decode()} recipient, "
    f"{len(stanzas) - 1} grease stanza(s), no classical recipient"
)
PY
    # The control first: rage round-trips its own X25519 recipient in this environment, so a
    # refusal below is about our recipient type, not a broken binary or an unreadable file.
    mkdir -p "$test_root/rage"
    "$rage_keygen" -o "$test_root/rage/control.agekey" >/dev/null 2>&1
    control_pub=$("$rage_keygen" -y "$test_root/rage/control.agekey")
    printf 'backupctl m4b interop control\n' > "$test_root/rage/plain.txt"
    "$rage_bin" -r "$control_pub" -o "$test_root/rage/control.age" "$test_root/rage/plain.txt"
    "$rage_bin" -d -i "$test_root/rage/control.agekey" -o "$test_root/rage/back.txt" \
        "$test_root/rage/control.age"
    cmp -s "$test_root/rage/plain.txt" "$test_root/rage/back.txt" ||
        fail "rage could not round-trip its own recipient, so the divergence check proves nothing"
    for name in payload.age globals.age manifest.age; do
        if "$rage_bin" -d -i "$test_root/rage/control.agekey" -o "$test_root/rage/leak.out" \
            "$first_dir/$name" > "$test_root/rage/$name.out" 2>&1; then
            echo "stock rage decrypted our $name; the hybrid recipient is not a divergence" >&2
            exit 1
        fi
        if [[ -e "$test_root/rage/leak.out" ]]; then
            fail "rage wrote output while refusing $name"
        fi
        printf 'rage refuses %s: %s\n' "$name" "$(head -n 1 "$test_root/rage/$name.out")"
    done

    # --- 6. a forgery that edits every plaintext field it can reach ------------
    # Two more artifacts from the SAME recipient and the SAME signer, so anything this section
    # detects is detection the signature alone added: age could not tell these files apart.
    for label in a b; do
        ctl --output json backup create --confirm-synthetic > "$test_root/$label.json"
    done
    pair_a=$(backup_id "$test_root/a.json")
    pair_b=$(backup_id "$test_root/b.json")
    dir_a=$(artifact_dir "$pair_a")
    dir_b=$(artifact_dir "$pair_b")
    cp -r "$dir_a" "$test_root/pristine_a"
    restore_a() {
        rm -rf "$dir_a"
        cp -r "$test_root/pristine_a" "$dir_a"
    }
    first_state=$(dir_state "$first_dir")

    # For each case: every level refuses, the refusal names the signature rather than a parse
    # error, and a restore plan refuses too — with no target database created behind it.
    refuses_everywhere() {
        local label="$1" directory="$2" expected="$3" id
        id=$(basename "$directory")
        for level in signature checksum archive; do
            rejects "$label at --level $level" ctl backup verify "$id" --level "$level"
            grep -qiE "$expected" "$test_root/reject.out" ||
                fail "$label at $level refused for the wrong reason: $(cat "$test_root/reject.out")"
        done
        rejects "$label at restore plan" dctl restore plan "$id" \
            --target backupctl_fixture_m4b_forged --security portable
        grep -qiE "$expected" "$test_root/reject.out"
        if [[ "$(src_sql -tA -d postgres -c \
            "SELECT 1 FROM pg_database WHERE datname = 'backupctl_fixture_m4b_forged'")" == "1" ]]; then
            fail "$label: a restore plan created a target database before refusing the artifact"
        fi
        restore_a
    }

    # 6.1 the swap M4a documented as undetectable: donor ciphertext, header rewritten to
    # describe it exactly. Every hash now agrees with the files; only the origin can disagree.
    cp "$dir_b/payload.age" "$dir_a/payload.age"
    patch_public "$dir_a"
    refuses_everywhere "a swapped payload" "$dir_a" \
        "does not verify|signature check failed"

    # 6.2 truncation, with the digest rewritten to match the shorter file.
    size=$(stat -c '%s' "$dir_a/payload.age")
    truncate -s $((size - 64)) "$dir_a/payload.age"
    patch_public "$dir_a"
    refuses_everywhere "a truncated payload" "$dir_a" "does not verify|signature check failed"

    # 6.3 untouched ciphertext and a header that lies about it: caught one step earlier, as a
    # disagreement between public.json and the file on disk.
    edit_public "$dir_a" payload_sha256 "$(printf '0%.0s' {1..64})" str
    rejects "a public.json that lies about the payload" ctl backup verify "$pair_a" \
        --level signature
    grep -q "payload.age is not the ciphertext public.json describes" "$test_root/reject.out"
    restore_a

    # 6.4 another artifact's signature. Right length, parses, and the tuple does not match —
    # which is the whole point of a detached signature over digests.
    cp "$dir_b/signature.hybrid" "$dir_a/signature.hybrid"
    refuses_everywhere "a signature copied from another artifact" "$dir_a" \
        "does not verify|signature check failed"

    # 6.5 one byte of the signature itself.
    printf '\x01' | dd of="$dir_a/signature.hybrid" bs=1 seek=100 conv=notrunc status=none
    refuses_everywhere "a mutated signature" "$dir_a" "does not verify|signature check failed"

    # 6.6 a signature one byte short: the hybrid signature is a fixed 3373-byte type, so a
    # truncated file is not a signature at all.
    truncate -s $((HYBRID_SIGNATURE_BYTES - 1)) "$dir_a/signature.hybrid"
    rejects "a signature one byte short" ctl backup verify "$pair_a" --level signature
    grep -qiE "signature" "$test_root/reject.out"
    restore_a

    # 6.7 the completion marker gone: an incomplete directory is not an artifact. A missing
    # file reaches the store as a bare stat failure, so this asserts the refusal and the io
    # error behind it; naming the marker in that message is a documentation item, not a claim
    # this pass can make.
    rm "$dir_a/complete"
    rejects "an artifact without its completion marker" ctl backup verify "$pair_a" \
        --level signature
    grep -qiE "no such file|not a directory" "$test_root/reject.out"
    restore_a

    # 6.8 a symlink in place of the payload.
    mv "$dir_a/payload.age" "$dir_a/payload.real"
    ln -s "$dir_a/payload.real" "$dir_a/payload.age"
    rejects "a symlinked payload" ctl backup verify "$pair_a" --level signature
    grep -q "expected a regular non-symlink file" "$test_root/reject.out"
    restore_a

    # 6.9 public.json replaced by another artifact's: the directory name is the identity, and
    # the discovery record cannot overrule it.
    cp "$dir_b/public.json" "$dir_a/public.json"
    rejects "a public.json naming a different backup id" ctl backup verify "$pair_a" \
        --level signature
    grep -q "found under directory" "$test_root/reject.out"
    restore_a

    # 6.10 an unknown field, an oversized file, and an unknown format version: all three are
    # refused by the bounded parser, not by anything downstream of it.
    edit_public "$dir_a" surprise 1 int
    rejects "public.json with an unknown field" ctl backup verify "$pair_a" --level signature
    grep -q "invalid public.json" "$test_root/reject.out"
    restore_a
    printf '%*s' 5000 '' >> "$dir_a/public.json"
    rejects "an oversized public.json" ctl backup verify "$pair_a" --level signature
    grep -q "over the 4096 byte cap" "$test_root/reject.out"
    restore_a
    edit_public "$dir_a" format_version 2 int
    rejects "public.json claiming format version 2" ctl backup verify "$pair_a" \
        --level signature
    grep -q "unknown public.json format version 2" "$test_root/reject.out"
    restore_a

    # 6.11 the recorded suite downgraded to classical-only, in public.json and nowhere else.
    # What this pins is where the truth of an artifact lives: signature.hybrid covers the
    # backup id and the two ciphertext digests, so a suite claim in the discovery file is not
    # authenticated by it and --level signature still passes. The lie is caught one step later,
    # against the signed manifest — which is the record a reader actually trusts.
    edit_public "$dir_a" signature_suite ed25519 str
    if ! ctl --output json backup verify "$pair_a" --level signature \
        > "$test_root/downgrade.json" 2>&1; then
        cat "$test_root/downgrade.json" >&2
        fail "a downgraded suite was refused at signature level, contrary to the contract"
    fi
    grep -q '"signature_suite": "ed25519"' "$test_root/downgrade.json"
    rejects "a downgraded suite, read against the signed manifest" ctl backup verify "$pair_a" \
        --level checksum
    grep -q "disagree on signature_suite" "$test_root/reject.out"
    restore_a

    # 6.12 a byte flip inside the encrypted manifest: its digest is inside the signature, so
    # an attacker who holds the identity still cannot edit a signed manifest.
    python3 - "$dir_a/manifest.age" <<'PY'
import sys

path = sys.argv[1]
raw = bytearray(open(path, "rb").read())
raw[200] ^= 0x01
open(path, "wb").write(raw)
PY
    rejects "a flipped byte inside manifest.age" ctl backup verify "$pair_a" --level signature
    grep -q "manifest.age is not the ciphertext public.json describes" "$test_root/reject.out"
    restore_a
    [[ "$(dir_state "$first_dir")" == "$first_state" ]] ||
        fail "a tampering pass against another artifact disturbed the intact one"

    # --- 7. another generation's key, and an operator's own seed ----------------
    # An artifact from a different signing pair is intact, well-formed, and verifiable — by
    # someone else. The store reports it instead of hiding it, and refuses it.
    fctl --output json key generate > /dev/null
    fctl --output json backup create --confirm-synthetic > "$test_root/foreign.json"
    foreign=$(backup_id "$test_root/foreign.json")
    cp -r "$test_root/data_foreign/artifacts/$foreign" "$test_root/data/artifacts/"
    rejects "an artifact signed by a stranger's key" ctl backup verify "$foreign" \
        --level signature
    grep -q "origin signature of artifact" "$test_root/reject.out"
    dctl --output json backup list > "$test_root/list2.json"
    [[ "$(json_count "$test_root/list2.json" signed)" -eq 4 ]] ||
        fail "a signed store hid the foreign artifact: $(cat "$test_root/list2.json")"
    rejects "a restore plan over a stranger's artifact" dctl restore plan "$foreign" \
        --target backupctl_fixture_m4b_foreign --security portable
    grep -q "origin signature of artifact" "$test_root/reject.out"
    rm -rf "$test_root/data/artifacts/$foreign"

    # A hand-written signing seed: publish derives the public halves, reads the seeds it is
    # given, and must leave them byte-for-byte untouched. Rewriting a seed is the one edit
    # that makes every artifact signed under it unverifiable by the key a reader holds.
    mkdir -p "$test_root/keys/custom"
    custom_identity=$(printf 'backupctl m4b custom identity seed' | sha256sum | cut -c1-64)
    custom_signing=$(printf '%s%s' \
        "$(printf 'backupctl m4b custom ed25519 half' | sha256sum | cut -c1-64)" \
        "$(printf 'backupctl m4b custom mldsa65 half' | sha256sum | cut -c1-64)")
    printf '%s\n%s\n' "$IDENTITY_MARKER" "$custom_identity" \
        > "$test_root/keys/custom/identity.key"
    printf '%s\n%s\n' "$SIGNING_MARKER" "$custom_signing" \
        > "$test_root/keys/custom/signing.key"
    chmod 600 "$test_root/keys/custom/identity.key" "$test_root/keys/custom/signing.key"
    write_config "$test_root/custom.toml" "$fixture_db" "$test_root/bin" \
        "$test_root/data_custom" "$test_root/keys/custom" both
    cctl() { target/debug/backupctl --config "$test_root/custom.toml" "$@"; }
    rejects "key status before the public halves exist" cctl key status
    grep -qiE "recipient key file|verifying key file" "$test_root/reject.out"
    custom_before=$(cat "$test_root/keys/custom/identity.key" \
        "$test_root/keys/custom/signing.key" | sha256sum)
    cctl --output json key publish > "$test_root/custom-publish.json"
    custom_after=$(cat "$test_root/keys/custom/identity.key" \
        "$test_root/keys/custom/signing.key" | sha256sum)
    [[ "$custom_before" == "$custom_after" ]] ||
        fail "key publish rewrote a seed it was only supposed to read"
    stat -c '%a' "$test_root/keys/custom/verifying.key" | grep -q '^644$'
    rejects "key publish over an existing verifying file" cctl key publish
    grep -q "refusing to overwrite the existing key file" "$test_root/reject.out"
    # The published pair is a usable generation: it writes a v1 artifact that its own
    # verifying key authenticates and no other generation's trusts.
    cctl --output json backup create --confirm-synthetic > "$test_root/custom.json"
    custom=$(backup_id "$test_root/custom.json")
    cctl backup verify "$custom" --level signature >/dev/null
    # The human path names the format it wrote: an operator must not be told "development
    # backup" while the store holds signed artifact v1 bytes. A second artifact in this store
    # is harmless, since no assertion here counts the contents of data_custom.
    cctl backup create --confirm-synthetic > "$test_root/custom-human.out"
    grep -q "created signed artifact v1" "$test_root/custom-human.out"
    custom_signer=$(get_json "$test_root/custom-publish.json" "signing.0.signer")
    [[ "$custom_signer" == "$(get_json "$test_root/custom.json" "public.signer_id")" ]] ||
        fail "the published verifying key is not the key the artifact was signed with"
    if [[ "$custom_signer" == "$signer_line" ]]; then
        fail "a hand-written signing seed derived the signer id of a generated pair"
    fi
    cp -r "$test_root/data_custom/artifacts/$custom" "$test_root/data/artifacts/"
    rejects "the generated pair trusting a custom-key artifact" ctl backup verify "$custom" \
        --level signature
    grep -q "origin signature of artifact" "$test_root/reject.out"
    rm -rf "$test_root/data/artifacts/$custom"
    # The tampered artifacts of step 6 are not evidence the DR host should still be carrying.
    for id in "$pair_a" "$pair_b"; do
        rm -rf "$(artifact_dir "$id")"
    done

    # --- 8. the DR host: no signing secret, and a rebuilt cluster ---------------
    # The source container stops and the DR container takes its port, so the address the
    # manifest describes is the address the operator configures — and the roles this restore
    # applies are roles a fresh cluster has never seen.
    docker stop "$source_name" >/dev/null
    source_name=""
    docker run --rm -d --name "$dr_name" --network host \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        -v "$test_root:$test_root" \
        "docker.arvancloud.ir/library/postgres:${major}-bookworm" -p "$port" >/dev/null
    wait_ready "$dr_name" "$port" || fail "DR cluster $major not ready"
    docker exec -i "$dr_name" createdb -U postgres -h 127.0.0.1 -p "$port" "$fixture_db"
    docker exec -i "$dr_name" createdb -U postgres -h 127.0.0.1 -p "$port" "$probe_db"
    make_wrappers "$dr_name" "$test_root/bin_dr" "$test_root/log_dr"
    # Same [source] block, same keys, different client directory: the configuration is what
    # moved, not the credentials.
    write_config "$test_root/dr.toml" "$fixture_db" "$test_root/bin_dr" \
        "$test_root/data" "$test_root/keys/gen1" verify

    # The shape is the claim: one signing row, the verifying half, and no secret here to lose.
    dctl --output json key status > "$test_root/dr-status.json"
    python3 - "$test_root/dr-status.json" "$test_root/keygen.json" <<'PY'
import json
import sys

report, writer = (json.load(open(path)) for path in sys.argv[1:3])
assert len(report["signing"]) == 1, report["signing"]
verifying = report["signing"][0]
assert verifying["role"] == "verifying", verifying
assert verifying["signer"] == writer["signing"][0]["signer"]
PY
    # A verify-only configuration cannot be talked into minting a signing secret: the age
    # pair is generated, and the signing half of the command refuses before it touches a
    # path. That boundary is the whole meaning of the omitted `signing_key_file`.
    write_config "$test_root/drfresh.toml" "$fixture_db" "$test_root/bin_dr" \
        "$test_root/data_drfresh" "$test_root/keys/gen3" verify
    rejects "key generate on a host configured to verify only" \
        target/debug/backupctl --config "$test_root/drfresh.toml" key generate
    grep -q "configures no signing_key_file" "$test_root/reject.out"
    [[ -e "$test_root/keys/gen3/identity.key" ]] ||
        fail "the refusal stopped the encryption pair it was asked to generate too"
    [[ ! -e "$test_root/keys/gen3/signing.key" ]] ||
        fail "a verify-only host was given a signing secret anyway"
    # Producing an artifact is refused because this store holds no recipient, which is the
    # readable consequence of a DR host having nothing to sign or seal with.
    rejects "a backup on the DR host" dctl backup create --confirm-synthetic
    grep -qiE "no recipient file|cannot seal" "$test_root/reject.out"
    # Signature level on the DR host reports the same origin the writer reported, with no
    # signing key in reach.
    dctl --output json backup verify "$first" --level signature > "$test_root/dr-sig.json"
    python3 - "$test_root/dr-sig.json" "$test_root/v-sig.json" <<'PY'
import json
import sys

dr, writer = (json.load(open(path)) for path in sys.argv[1:3])
assert dr == writer, f"the DR host reported a different origin: {dr} vs {writer}"
PY
    # Without a verifying key this host can prove nothing about any artifact, which is why the
    # DR store loads it up front instead of discovering the gap mid-restore.
    mv "$test_root/keys/gen1/verifying.key" "$test_root/verifying.key.out"
    rejects "verification with no verifying key" dctl backup verify "$first" --level signature
    grep -qiE "verifying key file" "$test_root/reject.out"
    rejects "a restore plan with no verifying key" dctl restore plan "$first" \
        --target backupctl_fixture_m4b_noverify --security dr
    mv "$test_root/verifying.key.out" "$test_root/keys/gen1/verifying.key"

    first_digest=$(dir_state "$first_dir")
    dctl restore plan "$first" --target "$dr_db" --security dr --output json \
        > "$test_root/plan.json"
    python3 - "$test_root/plan.json" "$fixture_db" "$major" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
database, major = sys.argv[2], int(sys.argv[3])
plan = report["plan"]
assert plan["artifact_scope"] == "whole-database", plan["artifact_scope"]
assert plan["artifact_database"] == database
assert plan["source_major"] == major
assert plan["security"]["roles"] is True
PY
    rm -f "$test_root"/log_dr/pg_restore.log
    dctl --output json restore run "$(plan_id "$test_root/plan.json")" \
        --confirm-target "$dr_db" > "$test_root/run.json"
    assert_reads "$test_root/log_dr" "$test_root/data/scratch/" "DR restore"
    python3 - "$test_root/run.json" <<'PY'
import json
import sys

executed = json.load(open(sys.argv[1]))
# The artifact is signed, so the run that proves it replays cannot raise the level the
# artifact itself records: that would need this host to hold a signing key.
assert executed["recorded_in_artifact"] is False, executed
assert executed["verification_level"] == "none", executed
PY
    dr_sql -d "$dr_db" < tests/fixtures/postgres/assertions.sql >/dev/null
    dr_sql -d "$dr_db" < tests/fixtures/postgres/security-assertions.sql >/dev/null
    [[ "$(dir_state "$first_dir")" == "$first_digest" ]] ||
        fail "a DR restore rewrote a signed artifact"
    grep -q "verification: none" <(dctl backup inspect "$first")
    for dir in staging scratch; do
        if [[ -n "$(ls -A "$test_root/data/$dir")" ]]; then
            fail "a finished restore left decrypted plaintext in $dir"
        fi
    done
    if grep -qr "backupctl_fixture_alice" "$test_root/data"; then
        fail "a restore wrote plaintext into the signed store"
    fi

    # --- 9. a source the manifest does not describe is refused ------------------
    # Same server, same port, a different database: the fingerprint is the only difference,
    # and a plan has to stop on it before it creates anything.
    write_config "$test_root/probe.toml" "$probe_db" "$test_root/bin_dr" \
        "$test_root/data" "$test_root/keys/gen1" verify
    rejects "a plan whose configured database is not the one that was dumped" \
        target/debug/backupctl --config "$test_root/probe.toml" restore plan "$first" \
        --target backupctl_fixture_m4b_wrongsource --security portable
    grep -q "dumped from a different source than the configured one" "$test_root/reject.out"
    if [[ "$(dr_sql -tA -d postgres -c \
        "SELECT 1 FROM pg_database WHERE datname = 'backupctl_fixture_m4b_wrongsource'")" == "1" ]]; then
        fail "the fingerprint refusal came after its target database was created"
    fi

    # --- 10. nothing secret anywhere this pass produced -------------------------
    for needle in "$identity_seed" "$signing_seed" "$custom_identity" "$custom_signing" \
        backupctl_fixture_alice SCRAM-SHA-256 fake-verifier-for-tests-only; do
        if grep -qr -- "$needle" "$test_root/data" "$test_root/data_foreign" \
            "$test_root/data_custom" "$test_root"/*.json "$test_root"/*.out 2>/dev/null; then
            echo "secret material ($needle) reached a store or CLI output:" >&2
            grep -rl -- "$needle" "$test_root/data" "$test_root/data_foreign" \
                "$test_root/data_custom" "$test_root"/*.json "$test_root"/*.out >&2
            exit 1
        fi
    done

    echo "PostgreSQL $major: v1 write, three levels with their exact reach, rage divergence, twelve forgery cases, foreign-key refusal, operator-supplied seed, DR restore without a signing key, and source binding passed"
    cleanup
    source_name=""
    dr_name=""
    test_root=""
done
