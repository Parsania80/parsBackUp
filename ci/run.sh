#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
mode=${1:-}
suite=${2:-}
export RUSTUP_TOOLCHAIN=1.97.1
export CARGO_NET_OFFLINE=true
export LC_ALL=C
case "$mode:$suite" in
    fast:|package:|native:*) ;;
    *) echo 'usage: ci/run.sh fast|package|native SUITE' >&2; exit 2 ;;
esac
if [[ $mode == native ]]; then
    python3 - "$suite" <<'PY'
import json,sys
assert sys.argv[1] in json.load(open('ci/inputs.json'))['native_suites'], 'unknown native suite'
PY
fi
mkdir -p target/ci-logs
label=$mode${suite:+-$suite}
# No credentials, raw fixture directories or private key material enter evidence archives.
python3 - "$label" <<'PY'
import hashlib,json,subprocess,sys
from pathlib import Path
paths=set(subprocess.check_output(['git','ls-files','-z']).decode().split('\0'))-{''}
paths.update(subprocess.check_output(['git','ls-files','--others','--exclude-standard','-z']).decode().split('\0'))
paths.discard('')
Path(f'target/ci-logs/{sys.argv[1]}-inputs.json').write_text(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in sorted(paths) if Path(p).is_file()},sort_keys=True,indent=2)+'\n')
PY
set +e
(
    set -e
    case "$mode" in
        fast)
            cargo fmt --all --check
            cargo clippy --workspace --all-targets --locked --offline -- -D warnings
            cargo test --workspace --locked --offline
            cargo build -p backupctl --locked --offline
            python3 ci/check.py
            target/ci-tools/actionlint -color -shellcheck= -pyflakes= .github/workflows/*.yml
            ;;
        native) bash "tests/$suite.sh" ;;
        package) bash tests/h03_package_drill.sh --reuse-images ;;
    esac
) 2>&1 | tee "target/ci-logs/$label.log"
status=${PIPESTATUS[0]}
set -e
python3 - "$label" <<'PY'
import hashlib,json,sys
from pathlib import Path
record=json.loads(Path(f'target/ci-logs/{sys.argv[1]}-inputs.json').read_text())
for path,digest in record.items():
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest, f'input changed during verification: {path}'
print(f'{len(record)} verification source inputs unchanged')
PY
exit "$status"
