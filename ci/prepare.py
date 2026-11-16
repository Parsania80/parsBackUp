"""Explicit provisioning for CI; no production credentials or deployment."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT/'ci/inputs.json').read_text())


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


mode = sys.argv[1] if len(sys.argv) == 2 else ''
if mode == 'lint':
    tools = ROOT/'target/ci-tools'
    tools.mkdir(parents=True, exist_ok=True)
    run('go', 'install', 'github.com/rhysd/actionlint/cmd/actionlint@'+PINS['actionlint'],
        env={**os.environ, 'GOBIN': str(tools), 'GOTOOLCHAIN': 'local'})
elif mode in ('native', 'package'):
    assert os.geteuid() != 0, 'run drills as a non-root user with access to Docker'
    for image in PINS['images']:
        if (mode == 'native') != ('/postgres:' in image['tag']):
            continue
        run('docker', 'pull', '--platform', 'linux/amd64', image['reference'])
        run('docker', 'tag', image['reference'], image['tag'])
    if mode == 'package':
        for tag, suffix, build_tools in [('ubuntu24', '/ubuntu:24.04', 'gcc libc6-dev binutils dpkg-dev'),
                                         ('debian13', '/debian:13-slim', '')]:
            base = next(i['reference'] for i in PINS['images'] if i['tag'].endswith(suffix))
            run('docker', 'build', '--build-arg', f'BASE={base}', '--build-arg', f'BUILD_TOOLS={build_tools}',
                '-t', f'backupctl-h03-test:{tag}', '-f', str(ROOT/'tests/h03/Dockerfile'), str(ROOT))
else:
    raise SystemExit('usage: python3 ci/prepare.py lint|native|package')
