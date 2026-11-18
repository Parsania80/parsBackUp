"""Dependency-free reference/syntax checks plus real CLI envelope examples."""
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
pins = json.loads(Path('ci/inputs.json').read_text())
assert tomllib.loads(Path('rust-toolchain.toml').read_text())['toolchain']['channel'] == pins['rust']
assert len(set(pins['native_suites'])) == len(pins['native_suites'])
for suite in pins['native_suites']:
    assert re.fullmatch(r'[a-z0-9_]+', suite) and Path(f'tests/{suite}.sh').is_file()
for image in pins['images']:
    assert re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}', image['reference'])
for workflow in Path('.github/workflows').glob('*.yml'):
    text = workflow.read_text()
    for action, revision in re.findall(r'uses:\s*([^@\s]+)@([^\s]+)', text):
        assert pins['actions'][action] == revision, (workflow, action)
    assert 'persist-credentials: false' in text and 'contents: read' in text
    assert not any(x in text for x in ('pull_request_target', 'self-hosted', 'secrets.', 'write-all'))
    assert 'cargo fetch --locked' in text and pins['rust'] in text
native = Path('.github/workflows/native.yml').read_text()
assert set(re.findall(r'^          - (\w+)$', native, re.M)) == set(pins['native_suites'])
assert pins['rage'] in native
files = [Path('README.md'), Path('project.md')]
files += sorted(Path('docs/development').glob('h0[1234]-*.md'))
files += sorted(Path('docs/operations').glob('*.md'))
files += [Path('docs/development/v01-validation.md'), Path('docs/security/v01-review.md')]
files += [Path('docs/backup-format/manifest-v2-family.md'), Path('docs/development/v01-w1-offline-dispatch.md')]
files += [Path('docs/development/v01-w2-restore-plan-compatibility.md')]
files += [Path('docs/development/p01-api-contract.md')]
files += [Path('docs/development/u01-ui-design.md')]
files += [Path('docs/security/api-v1-review.md')]
subprocess.run(['python3', 'ci/check_api.py'], check=True)
links = 0
for file in files:
    text = file.read_text()
    clean = re.sub(r'```.*?```', '', text, flags=re.S)
    for dest in re.findall(r'\[[^\]]*\]\(([^\s)]+)\)', clean):
        if '://' in dest or dest.startswith('mailto:'):
            continue
        path, _, fragment = urllib.parse.unquote(dest).partition('#')
        target = (file.parent/path).resolve() if path else file.resolve()
        assert target.exists(), (file, dest)
        if fragment and target.suffix == '.md':
            headings = re.findall(r'^#{1,6}\s+(.+?)\s*#*$', target.read_text(), re.M)
            slugs = [re.sub(r'[^\w\- ]', '', h.lower()).replace(' ', '-') for h in headings]
            assert fragment in slugs, (file, dest)
        links += 1
    for language, body in re.findall(r'```(toml|json)\n(.*?)\n```', text, re.S):
        tomllib.loads(body) if language == 'toml' else json.loads(body)
for file in Path('config').glob('*.toml'):
    tomllib.loads(file.read_text())
tomllib.loads(Path('deploy/writer.example.toml').read_text())
blocks = 0
for file in sorted(Path('tests').glob('*.sh')) + [Path('ci/run.sh'), Path('deploy/build-deb.sh')]:
    subprocess.run(['bash', '-n', str(file)], check=True)
    for index, code in enumerate(re.findall(r"<<'PY'[^\n]*\n(.*?)^PY$", file.read_text(), re.S | re.M)):
        compile(code, f'{file}:python-{index}', 'exec')
        blocks += 1
for file in Path('deploy/debian').iterdir():
    subprocess.run(['sh', '-n', str(file)], check=True)
for file in sorted(Path('ci').glob('*.py')) + [
    Path('tests/h03/package_drill.py'),
    Path('tests/p02_worker_drill.py'),
    Path('tests/p03_http_drill.py'),
    Path('tests/p04_api_acceptance.py'),
    Path('tests/u02_console_drill.py'),
    Path('tests/u04_browser_acceptance.py'),
]:
    code = file.read_text()
    compile(code, str(file), 'exec')
    if file.name == 'package_drill.py':
        for node in ast.walk(ast.parse(code)):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'probe' for t in node.targets):
                compile(node.value.value, 'h03-sandbox-probe', 'exec')
# These are actual documented command envelopes, not an implementation-mirroring unit test.
examples = [json.loads(s) for s in re.findall(r'```json\n(.*?)\n```', Path('docs/operations/cli-reference.md').read_text(), re.S)]
with tempfile.TemporaryDirectory(prefix='.backupctl-h04-reports-', dir=Path.home()) as directory:
    base = Path(directory)
    config = base/'inventory.toml'
    fixture = f'config_version=1\nmode="fixture"\naccess="inventory"\nread_only=true\n[storage]\nroot="{base}/absent-store"\n'
    for expected, mode, command, status in [(examples[0], 'fixture', ['config', 'check'], 0),
                                             (examples[1], 'production', ['job', 'list'], 1)]:
        config.write_text(fixture.replace('mode="fixture"', f'mode="{mode}"'))
        config.chmod(0o600)
        result = subprocess.run(['target/debug/backupctl', '--config', str(config), '--output', 'json-v1', *command], capture_output=True, text=True)
        assert result.returncode == status and not result.stderr, result
        assert json.loads(result.stdout) == expected, result.stdout
        assert not (base/'absent-store').exists()
subprocess.run(['git', 'diff', '--check'], check=True)
print(f'{links} local reference targets/fragments, TOML/JSON, {blocks} embedded Python blocks, standalone/script syntax, pins and two real CLI examples pass')
