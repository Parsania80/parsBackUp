"""Connect the accepted fixture package, HTTP API and console on one artifact."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
from p02_worker_drill import ROOT, TARGET, private, run
from p03_http_drill import http_fixture, listening, start_supervised
from p04_api_acceptance import operation, sql, target_exists
from u02_console_drill import DIST, https_console
from u04_browser_acceptance import ProxiedClient


def main():
    assert (DIST / 'index.html').is_file(), 'Build ui/dist before running acceptance'
    packages = ROOT / 'target/packages'
    package = packages / 'backupctl_0.1.0~fixture.1_amd64.deb'
    expected = (packages / 'SHA256SUMS').read_text().splitlines()
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    assert f'{digest}  {package.name}' in expected, 'Run the fixture package drill first'
    with tempfile.TemporaryDirectory(prefix='f01-packaged-cli-') as extracted:
        run('dpkg-deb', '-x', str(package), extracted)
        cli = Path(extracted) / 'usr/bin/backupctl'
        with http_fixture('.parsbackup-f01-', roles=('admin',)) as (base, listener, unit, container, actors):
            created = run(str(cli), '--config', str(base / 'writer.toml'), '--output', 'json-v1',
                          'backup', 'create', '--confirm-synthetic')
            artifact = json.loads(created.stdout)['data']['manifest']['backup_id']
            with https_console(base, listener.port) as origin:
                config = base / 'api.toml'
                private(config, config.read_text().replace(f'public_origin = "{listener.origin}"',
                                                          f'public_origin = "{origin}"')
                        .replace('development_http = true', 'development_http = false'))
                client = ProxiedClient(listener.port, origin)
                start_supervised(unit, config)
                token = actors['admin'][0]
                listening(client, token)
                verified = operation(client, '/verifications', token, {
                    'artifact_id': artifact, 'level': 'archive',
                })['result']
                assert verified['artifact_id'] == artifact and verified['inventory_recorded'] is True
                assert not target_exists(container, TARGET)
                result = run('node', str(ROOT / 'ui/scripts/release-acceptance.mjs'),
                             content=json.dumps(dict(origin=origin, token=token, artifact=artifact, target=TARGET)),
                             check=False, timeout=90)
                assert result.returncode == 0, result.stderr
                assert sql(container, 'SELECT n FROM sample', TARGET) == '42'
    print(f'Package {digest}: packaged CLI backup, HTTP archive verification and HTTPS console restore of row 42 passed')


if __name__ == '__main__':
    main()
