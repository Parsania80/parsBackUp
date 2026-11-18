"""Isolated package/system-manager acceptance; never installs host services."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
IMAGES = [('ubuntu24', 'docker.arvancloud.ir/library/ubuntu:24.04', 16),
          ('debian13', 'docker.arvancloud.ir/library/debian:13-slim', 17)]


def run(args, *, content=None, ok=True, timeout=180):
    p = subprocess.run(args, input=content, text=True, capture_output=True, timeout=timeout)
    if ok and p.returncode:
        raise AssertionError(f'{args[:7]}: exit {p.returncode}\n{p.stdout}\n{p.stderr}')
    return p


def wait(predicate, label, seconds=30):
    end = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < end, label
        time.sleep(.1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reuse-images', action='store_true', help='use already prepared test images')
    parser.add_argument('--work', type=Path, help='reuse this drill\'s existing private build directory')
    args = parser.parse_args()
    if not args.reuse_images:
        for tag, base, _ in IMAGES:
            subprocess.run(['docker', 'build', '--build-arg', f'BASE={base}',
                            '--build-arg', 'BUILD_TOOLS=' if tag == 'debian13' else 'BUILD_TOOLS=gcc libc6-dev binutils dpkg-dev', '-t',
                            f'backupctl-h03-test:{tag}', '-f', str(ROOT/'tests/h03/Dockerfile'), str(ROOT)], check=True)
    for tag, _, _ in IMAGES:
        run(['docker', 'image', 'inspect', f'backupctl-h03-test:{tag}'])
    work = args.work or Path(tempfile.mkdtemp(prefix='.backupctl-h03-drill-', dir=Path.home()))
    assert work.is_dir() and work.parent == Path.home() and work.name.startswith('.backupctl-h03-drill-')
    assert work.stat().st_uid == os.getuid() and work.stat().st_mode & 0o077 == 0
    uid, gid = os.getuid(), os.getgid()
    toolchain = Path(run(['rustup', 'which', 'rustc']).stdout.strip()).parent.parent
    cargo_home = work/'cargo'
    cargo_home.mkdir(exist_ok=True)
    if not (cargo_home/'registry').exists():
        # Resolved inside the build container, intentionally dangling on the host.
        (cargo_home/'registry').unlink(missing_ok=True)
        (cargo_home/'registry').symlink_to('/registry')
    mounts = ['-v', f'{ROOT}:/src:ro', '-v', f'{work}:/work']
    build = ['docker', 'run', '--pull=never', '--rm', '--network', 'none', '--user', f'{uid}:{gid}', *mounts,
             '-v', f'{toolchain}:/toolchain:ro', '-v', f'{Path.home()/".cargo/registry"}:/registry:ro',
             '-w', '/src', '-e', 'CARGO_HOME=/work/cargo', '-e', 'CARGO_TARGET_DIR=/work/target',
             '-e', 'RUSTC=/toolchain/bin/rustc', '-e', 'PATH=/toolchain/bin:/usr/bin:/bin',
             '-e', 'SOURCE_DATE_EPOCH='+run(['git', '-C', str(ROOT), 'show', '-s', '--format=%ct', 'HEAD']).stdout.strip(),
             'backupctl-h03-test:ubuntu24']
    containers = []
    completed = False
    try:
        subprocess.run([*build, 'cargo', 'build', '--release', '-p', 'backupctl', '--locked', '--offline'], check=True)
        for out, version in [('packages', '0.1.0~fixture.1'), ('repeat', '0.1.0~fixture.1'), ('upgrade', '0.1.0~fixture.2')]:
            subprocess.run([*build, 'bash', 'deploy/build-deb.sh', '/work/target/release/backupctl',
                            f'/work/{out}', version], check=True)
        package = 'backupctl_0.1.0~fixture.1_amd64.deb'
        upgrade = 'backupctl_0.1.0~fixture.2_amd64.deb'
        digest = hashlib.sha256((work/'packages'/package).read_bytes()).hexdigest()
        assert digest == hashlib.sha256((work/'repeat'/package).read_bytes()).hexdigest(), 'packaging is not repeatable'
        print(f'Ubuntu-built shared package sha256={digest}; repeated archive bytes match', flush=True)
        offline = ('test ! -d /run/systemd/system; '
                   f'dpkg -i /work/packages/{package}; '
                   'test ! -e /etc/systemd/system/timers.target.wants/backupctl-backup@offline.timer; '
                   'systemctl --no-reload enable backupctl-backup@offline.timer; '
                   'dpkg --remove backupctl; dpkg --purge backupctl; '
                   'test ! -e /etc/systemd/system/timers.target.wants/backupctl-backup@offline.timer; '
                   'test ! -L /etc/systemd/system/timers.target.wants/backupctl-backup@offline.timer; '
                   'test -d /var/lib/backupctl; id backupctl')
        run(['docker', 'run', '--pull=never', '--rm', '--network', 'none', '-v', f'{work}:/work:ro',
             'backupctl-h03-test:ubuntu24', 'sh', '-ec', offline])
        print('Offline install/remove/purge without a running system manager passed', flush=True)
        for tag, _, major in IMAGES:
            name = f'backupctl-h03-{tag}-{os.getpid()}'
            containers.append(name)
            run(['docker', 'run', '--pull=never', '-d', '--name', name, '--privileged', '--cgroupns=private',
                 '--network', 'none', '--tmpfs', '/run', '--tmpfs', '/run/lock', *mounts,
                 f'backupctl-h03-test:{tag}'])

            def ex(*cmd, content=None, ok=True, user=None, timeout=180):
                options = ['--user', user] if user else []
                return run(['docker', 'exec', '-i', *options, name, *cmd], content=content, ok=ok, timeout=timeout)

            def py(code):
                return ex('python3', '-', content=code).stdout.strip()

            def put(path, text, service=False, mode=0o600):
                py(f'import pathlib,os,pwd; p=pathlib.Path({path!r}); p.parent.mkdir(parents=True,exist_ok=True); p.write_text({text!r}); p.chmod({mode}); '
                   + (f'u=pwd.getpwnam("backupctl"); os.chown(p,u.pw_uid,u.pw_gid)' if service else ''))

            def ctl(*cmd, ok=True):
                return ex('systemctl', *cmd, ok=ok)

            wait(lambda: ctl('is-system-running', ok=False).stdout.strip() in ('running', 'degraded'), 'systemd boot')
            assert ex('cat', '/proc/1/comm').stdout.strip() == 'systemd'
            assert ex('readlink', '/proc/1/ns/cgroup').stdout.strip() != os.readlink('/proc/self/ns/cgroup'), 'requires private cgroup namespace'
            assert ex('cat', '/proc/1/cgroup').stdout.strip() in ('0::/', '0::/init.scope')
            print(tag, ex('systemctl', '--version').stdout.splitlines()[0], ex('ldd', '--version').stdout.splitlines()[0], flush=True)
            ex('dpkg', '-i', f'/work/packages/{package}')
            units = {path for path in ex('dpkg-query', '-L', 'backupctl').stdout.splitlines()
                     if path.startswith('/usr/lib/systemd/system/')}
            assert units == {'/usr/lib/systemd/system/backupctl-backup@.service',
                             '/usr/lib/systemd/system/backupctl-backup@.timer'}, units
            ex('systemd-analyze', 'verify', '/usr/lib/systemd/system/backupctl-backup@.service', '/usr/lib/systemd/system/backupctl-backup@.timer')
            unit = 'backupctl-backup@daily.service'
            timer = 'backupctl-backup@daily.timer'
            assert ctl('is-enabled', timer, ok=False).returncode != 0
            assert ctl('is-active', timer, ok=False).returncode != 0
            assert py('from pathlib import Path; print(len(list(Path("/etc/backupctl/profiles").iterdir())))') == '0'
            ex('sh', '/var/lib/dpkg/info/backupctl.postinst', 'configure')
            # Existing unsafe directories must fail without silently repairing custody.
            ex('chmod', '755', '/var/lib/backupctl')
            assert ex('sh', '/var/lib/dpkg/info/backupctl.postinst', 'configure', ok=False).returncode != 0
            assert ex('stat', '-c', '%a', '/var/lib/backupctl').stdout.strip() == '755'
            ex('chmod', '700', '/var/lib/backupctl')
            ex('mv', '/var/lib/backupctl', '/var/lib/backupctl.saved')
            ex('ln', '-s', '/tmp', '/var/lib/backupctl')
            assert ex('sh', '/var/lib/dpkg/info/backupctl.postinst', 'configure', ok=False).returncode != 0
            ex('rm', '/var/lib/backupctl')
            ex('mv', '/var/lib/backupctl.saved', '/var/lib/backupctl')
            ex('pg_ctlcluster', str(major), 'main', 'start')

            def sql(statement, database='postgres'):
                return ex('runuser', '-u', 'postgres', '--', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-d', database, '-c', statement).stdout.strip()

            source, target = 'backupctl_fixture_package', 'backupctl_fixture_package_recovered'
            sql("CREATE ROLE backupctl LOGIN SUPERUSER PASSWORD 'package-fixture'")
            sql(f"CREATE DATABASE {source}")
            sql("CREATE TABLE evidence(id integer PRIMARY KEY,note text); INSERT INTO evidence VALUES (1,'package recovery');", source)
            cfg = (ROOT/'deploy/writer.example.toml').read_text().replace('backupctl_fixture_example', source).replace('backup_reader', 'backupctl').replace('/postgresql/17/', f'/postgresql/{major}/')
            put('/etc/backupctl/profiles/daily.toml', cfg, True)
            put('/etc/backupctl/credentials/passfile', ''.join(f'127.0.0.1:5432:{db}:backupctl:package-fixture\n' for db in (source, 'postgres', target)), True)

            def cli(*cmd, config='daily', ok=True):
                p = ex('/usr/bin/backupctl', '--config', f'/etc/backupctl/profiles/{config}.toml', '--output', 'json-v1', *cmd, user='backupctl', ok=ok)
                assert not p.stderr, p.stderr
                return json.loads(p.stdout)

            assert cli('config', 'check')['status'] == 'ok'
            cli('key', 'generate')
            # Exercise actual sandbox permissions independently from unit directive text.
            probe = '''import os,pathlib,json,time,signal,sys
state=pathlib.Path('/var/lib/backupctl')
assert os.getuid()!=0
old=os.umask(0o077); assert old==0o077
assert pathlib.Path('/etc/backupctl/credentials/passfile').read_text()
for path in ['/etc/backupctl/credentials/passfile','/etc/backupctl/keys/signer','/usr/bin/backupctl']:
    try: open(path,'a').close()
    except (PermissionError,OSError): pass
    else: raise AssertionError('sandbox allowed write: '+path)
assert not os.access('/root',os.R_OK)
status=pathlib.Path('/proc/self/status').read_text()
assert 'NoNewPrivs:\\t1' in status and 'CapEff:\\t0000000000000000' in status
if len(sys.argv)>1:
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    child=os.fork()
    if child==0:
        os.setsid(); signal.signal(signal.SIGTERM,signal.SIG_IGN)
        (state/'escaped').write_text(str(os.getpid()))
        while True: time.sleep(1)
    (state/'parent').write_text(str(os.getpid()))
    while True: time.sleep(1)
(state/'sandbox-passed').write_text('ok')
'''
            put('/etc/backupctl/probe.py', probe, mode=0o644)
            dropin = f'/etc/systemd/system/{unit}.d/acceptance.conf'

            def override(body):
                put(dropin, '[Service]\n'+body, mode=0o644)
                ctl('daemon-reload')
                ctl('reset-failed', unit, ok=False)

            override('ExecStart=\nExecStart=/usr/bin/python3 /etc/backupctl/probe.py\n')
            ctl('start', unit)
            assert ex('cat', '/var/lib/backupctl/sandbox-passed').stdout == 'ok'
            # Escaping a process group/session cannot escape the service cgroup.
            for termination in ('stop', 'main-kill', 'deadline'):
                ex('rm', '-f', '/var/lib/backupctl/escaped', '/var/lib/backupctl/parent')
                deadline = '30s' if termination == 'stop' else '3s'
                override(f'ExecStart=\nExecStart=/usr/bin/python3 /etc/backupctl/probe.py hold\nTimeoutStartSec={deadline}\nTimeoutStopSec=1s\n')
                ctl('start', '--no-block', unit)
                wait(lambda: ex('test', '-s', '/var/lib/backupctl/escaped', ok=False).returncode == 0, 'escaped-session barrier')
                pids = [ex('cat', f'/var/lib/backupctl/{p}').stdout.strip() for p in ('parent', 'escaped')]
                if termination == 'stop':
                    ex('dpkg', '-i', f'/work/upgrade/{upgrade}')
                    assert ctl('show', unit, '-p', 'MainPID', '--value').stdout.strip() == pids[0]
                    assert ex('test', '-d', f'/proc/{pids[1]}', ok=False).returncode == 0
                    ctl('stop', unit)
                elif termination == 'main-kill': ctl('kill', '--kill-whom=main', '--signal=KILL', unit)
                wait(lambda: ctl('show', unit, '-p', 'ActiveState', '--value').stdout.strip() in ('failed', 'inactive'), f'{termination} completion', 10)
                for pid in pids:
                    assert ex('test', '-d', f'/proc/{pid}', ok=False).returncode != 0, (termination, pid)
            ex('rm', dropin)
            ctl('daemon-reload')
            ctl('reset-failed', unit)
            timer_override = f'/etc/systemd/system/{timer}.d/acceptance.conf'
            put(timer_override, '[Timer]\nOnCalendar=\nOnActiveSec=1s\nAccuracySec=1us\nRandomizedDelaySec=0\nPersistent=false\n', mode=0o644)
            ctl('daemon-reload')
            ctl('enable', '--now', timer)
            wait(lambda: ex('test', '-f', '/var/lib/backupctl/store/inventory.db', ok=False).returncode == 0, 'timer starts CLI')

            def query(statement):
                return py(f'import sqlite3,json; c=sqlite3.connect("/var/lib/backupctl/store/inventory.db"); print(json.dumps(c.execute({statement!r}).fetchall()))')

            wait(lambda: json.loads(query("SELECT count(*) FROM job WHERE state='complete'"))[0][0] == 1, 'timer signed backup')
            ctl('stop', timer)
            assert ctl('show', unit, '-p', 'Result', '--value').stdout.strip() == 'success'
            assert len(json.loads(query('SELECT backup_id FROM artifact'))) == 1
            # Package installation never lifts production dispatch, even for a fixture-named source.
            put('/etc/backupctl/profiles/daily.toml', cfg.replace('mode = "fixture"', 'mode = "production"'), True)
            assert ctl('start', unit, ok=False).returncode != 0
            refused = [json.loads(line) for line in ex('journalctl', '-u', unit, '-o', 'cat', '--no-pager').stdout.splitlines() if line.startswith('{')][-1]
            assert refused['error']['code'] == 'PRODUCTION_NOT_ENABLED'
            assert json.loads(query('SELECT count(*) FROM job')) == [[1]]
            put('/etc/backupctl/profiles/daily.toml', cfg, True)
            ctl('reset-failed', unit)
            # Move an authentic inventory back to the v7 schema, then migrate under the shipped service.
            py('import sqlite3; c=sqlite3.connect("/var/lib/backupctl/store/inventory.db"); c.executescript("DROP TABLE completion_high_water; PRAGMA user_version=7;"); c.close()')
            ctl('start', unit)
            assert json.loads(query('PRAGMA user_version')) == [[8]]
            assert json.loads(query('SELECT count(*) FROM artifact')) == [[2]]
            # A real native dump waits on a table lock while timer/manual contenders meet it.
            locker = subprocess.Popen(['docker', 'exec', name, 'runuser', '-u', 'postgres', '--', 'psql', '-X', '-At', '-d', source,
                                       '-c', 'BEGIN; LOCK TABLE evidence IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(90);'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                wait(lambda: sql("SELECT count(*) FROM pg_stat_activity WHERE query LIKE 'BEGIN; LOCK TABLE evidence%' AND wait_event='PgSleep'") == '1', 'lock holder')
                before = json.loads(query('SELECT count(*) FROM job'))[0][0]
                ctl('start', '--no-block', unit)
                wait(lambda: sql(f"SELECT count(*) FROM pg_stat_activity WHERE datname='{source}' AND wait_event_type='Lock'") == '1', 'native dump lock wait')
                pid = ctl('show', unit, '-p', 'MainPID', '--value').stdout.strip()
                ctl('start', timer)
                time.sleep(2)
                assert ctl('show', unit, '-p', 'MainPID', '--value').stdout.strip() == pid
                assert json.loads(query('SELECT count(*) FROM job')) == [[before+1]]
                assert cli('backup', 'create', '--profile', 'daily', '--confirm-synthetic', ok=False)['status'] == 'error'
                ctl('stop', timer)
                ctl('stop', unit)
                cancelled = [json.loads(line) for line in ex('journalctl', '-u', unit, '-o', 'cat', '--no-pager').stdout.splitlines() if line.startswith('{')][-1]
                assert cancelled['error']['code'] == 'OPERATION_CANCELLED'
                assert cancelled['data']['effects'] == 'preparation_only'
                assert json.loads(query("SELECT count(*) FROM job WHERE state='failed'")) == [[1]]
                for d in ('staging', 'scratch'):
                    assert py(f'from pathlib import Path; print(len(list(Path("/var/lib/backupctl/store/{d}").iterdir())))') == '0'
            finally:
                sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE 'BEGIN; LOCK TABLE evidence%'")
                locker.wait(timeout=10)
            ctl('reset-failed', unit, ok=False)
            ctl('start', unit)
            reports = [json.loads(line) for line in ex('journalctl', '-u', unit, '-o', 'cat', '--no-pager').stdout.splitlines() if line.startswith('{')]
            artifact = reports[-1]['data']['public']['backup_id']
            assert reports[-1]['status'] == 'ok'
            reader = cfg.replace('access = "writer"', 'access = "reader"')
            reader = '\n'.join(line for line in reader.splitlines() if not line.startswith(('recipient_file', 'signing_key_file')))+'\n'
            put('/etc/backupctl/profiles/recovery.toml', reader, True)
            ex('mv', '/etc/backupctl/keys/recipient', '/root/recipient.saved')
            ex('mv', '/etc/backupctl/keys/signer', '/root/signer.saved')
            sql(f'DROP DATABASE {source}')
            base = '/usr/bin/backupctl --config /etc/backupctl/profiles/recovery.toml --output json-v1 restore '
            override(f'ExecStart=\nExecStart={base}plan {artifact} --target {target} --security portable\n')
            ctl('start', unit)
            reports = [json.loads(line) for line in ex('journalctl', '-u', unit, '-o', 'cat', '--no-pager').stdout.splitlines() if line.startswith('{')]
            plan = reports[-1]['data']['plan']['id']
            override(f'ExecStart=\nExecStart={base}run {plan} --confirm-target {target}\n')
            ctl('start', unit)
            assert sql('SELECT note FROM evidence', target) == 'package recovery'
            ex('rm', dropin)
            put(timer_override, '[Timer]\nOnCalendar=\nOnCalendar=2099-01-01 02:00:00 UTC\nRandomizedDelaySec=0\n', mode=0o644)
            ctl('daemon-reload')
            ctl('start', timer)

            def fingerprint():
                return py('import pathlib,hashlib,json; print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for root in ["/etc/backupctl","/var/lib/backupctl"] for p in pathlib.Path(root).rglob("*") if p.is_file()},sort_keys=True))')

            ctl('enable', 'backupctl-backup@unloaded.timer')
            ctl('enable', '--runtime', 'backupctl-backup@runtime.timer')
            baseline = fingerprint()
            identity = ex('id', '-u', 'backupctl').stdout.strip()
            ex('dpkg', '-i', f'/work/upgrade/{upgrade}')
            assert ctl('is-active', timer).stdout.strip() == 'active'
            assert ctl('is-enabled', timer).stdout.strip() == 'enabled'
            ex('dpkg', '-i', f'/work/upgrade/{upgrade}')
            assert fingerprint() == baseline
            ex('dpkg', '--remove', 'backupctl')
            assert ctl('is-active', timer, ok=False).returncode != 0
            assert ctl('is-enabled', timer, ok=False).returncode != 0
            ex('dpkg', '--purge', 'backupctl')
            assert fingerprint() == baseline
            assert ex('id', '-u', 'backupctl').stdout.strip() == identity
            ex('dpkg', '-i', f'/work/upgrade/{upgrade}')
            assert ctl('is-enabled', timer, ok=False).returncode != 0
            assert ctl('is-active', timer, ok=False).returncode != 0
            for instance in ('daily', 'unloaded', 'runtime'):
                assert ctl('is-enabled', f'backupctl-backup@{instance}.timer', ok=False).returncode != 0
            assert fingerprint() == baseline
            print(f'{tag} PG{major}: install/reconfigure/reinstall/upgrade/remove/purge, custody, real sandbox, timer/manual overlap, v7 migration, graceful cancellation, three escaped-session hard stops and reader-only lost-source restore passed', flush=True)
            run(['docker', 'rm', '-f', name])
            containers.remove(name)
        destination = ROOT/'target/packages'
        destination.mkdir(exist_ok=True)
        shutil.copy2(work/'packages'/package, destination/package)
        (destination/'SHA256SUMS').write_text(f'{digest}  {package}\n')
        print(f'Verified package retained: {destination/package}', flush=True)
        print('H03 package/systemd drill passed Debian 13 and Ubuntu 24.04', flush=True)
        completed = True
    finally:
        if not completed:
            for name in containers:
                print(run(['docker', 'exec', name, 'journalctl', '-u', 'backupctl-backup@daily.service', '--no-pager', '-n', '40'], ok=False).stdout, flush=True)
                print(run(['docker', 'exec', name, 'sh', '-c', 'tail -30 /var/log/postgresql/postgresql-*-main.log'], ok=False).stdout, flush=True)
        for name in containers:
            run(['docker', 'rm', '-f', name], ok=False)
        if completed or args.work is None:
            shutil.rmtree(work)
        else:
            print(f'Private build directory retained for this drill retry: {work}', flush=True)


if __name__ == '__main__':
    main()
