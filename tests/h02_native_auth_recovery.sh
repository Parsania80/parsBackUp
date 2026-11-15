#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl --locked --offline
# The host-built Rust binary needs its host libc. Its native children use the
# image's actual PostgreSQL clients/libpq and normal image loader/libraries.
python3 - "$repo_root/target/debug/backupctl" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys, time
binary = pathlib.Path(sys.argv[1]).resolve()
libdir = pathlib.Path('/lib/x86_64-linux-gnu').resolve()
assert (libdir / 'ld-linux-x86-64.so.2').is_file(), 'Linux amd64 host runtime required'
password = r'h02:synthetic\credential'
source = 'backupctl_fixture_h02'
target = 'backupctl_fixture_h02_restored'

def run(args, content=None, ok=True):
    p = subprocess.run(args, input=content, text=True, capture_output=True, timeout=90)
    if ok and p.returncode:
        raise AssertionError(f'command failed ({p.returncode}): {args[:5]}\n{p.stdout}\n{p.stderr}')
    return p

for major in (16, 17, 18):
    name = f'backupctl-h02-native-{major}-{os.getpid()}'
    try:
        run(['docker','run','-d','--name',name,'--network','none',
             '-e','POSTGRES_HOST_AUTH_METHOD=trust',
             '-v',f'{binary}:/backupctl:ro','-v',f'{libdir}:/host-lib:ro',
             f'docker.arvancloud.ir/library/postgres:{major}-bookworm','bash','-c',
             'install -d -m 755 /h02; install -d -m 700 -o postgres -g postgres /h02/socket; '
             'exec docker-entrypoint.sh postgres -c unix_socket_directories=/var/run/postgresql,/h02/socket'])
        def exec_(*args, content=None, user=None, ok=True):
            cmd = ['docker','exec','-i']
            if user: cmd += ['--user',user]
            return run(cmd + [name,*args], content, ok)
        def sql(statement, db='postgres'):
            return exec_('psql','-X','-U','postgres','-d',db,'-v','ON_ERROR_STOP=1','-At',content=statement,user='postgres').stdout.strip()
        for _ in range(100):
            # TCP proves final postmaster readiness, not the entrypoint's temporary server.
            if exec_('pg_isready','-h','127.0.0.1','-U','postgres',ok=False).returncode == 0: break
            time.sleep(.1)
        else: raise AssertionError('server not ready')
        exec_('chmod','755','/h02')
        def write(path, text, mode='600'):
            exec_('sh','-c',f'cat > {path} && chmod {mode} {path}',content=text)
        hba = sql('SHOW hba_file')
        def auth(method):
            write(hba, f'local all all trust\nhost all all 127.0.0.1/32 {method}\nhost all all ::1/128 {method}\n')
            sql('SELECT pg_reload_conf()')
            time.sleep(.15)
        quoted = password.replace("'", "''")
        sql(f"SET password_encryption='scram-sha-256'; ALTER ROLE postgres PASSWORD '{quoted}'; CREATE ROLE restore_h02 SUPERUSER LOGIN PASSWORD '{quoted}'; CREATE ROLE h02_restore_group; CREATE DATABASE {source};")
        sql("CREATE TABLE evidence(id integer PRIMARY KEY, note text); INSERT INTO evidence VALUES (1,'h02 recovered'); GRANT SELECT ON evidence TO h02_restore_group;", source)
        def config(role='writer', user='postgres', maintenance='postgres', peer=False):
            s = f'''config_version = 1
mode = "fixture"
access = "{role}"
read_only = false
timeout_seconds = 20
export_globals = {str(role == 'writer').lower()}
[storage]
root = "/h02/store"
[source]
host = "{'/h02/socket' if peer else '127.0.0.1'}"
port = 5432
user = "{user}"
database = "{source}"
maintenance_database = "{maintenance}"
auth = "{'peer' if peer else 'scram-passfile'}"
'''
            if not peer: s += 'password_file = "/h02/passfile"\n'
            s += f'[tools]\nclient_bin_dir = "/usr/lib/postgresql/{major}/bin"\n'
            s += '[encryption]\nidentity_file = "/h02/identity"\n'
            if role == 'writer': s += 'recipient_file = "/h02/recipient"\n'
            s += '[signing]\nverifying_key_file = "/h02/verifier"\n'
            if role == 'writer': s += 'signing_key_file = "/h02/signer"\n'
            s += f'[[profile]]\nname = "public_data"\ndatabase = "{source}"\nschemas = ["public"]\n'
            return s
        writer = config()
        reader = config('reader','restore_h02')
        write('/h02/writer.toml',writer)
        write('/h02/reader.toml',reader)
        def passfile(dbs=(source,'postgres',target), value=password):
            escaped = value.replace('\\','\\\\').replace(':','\\:')
            return ''.join(f'127.0.0.1:5432:{db}:{user}:{escaped}\n' for user in ('postgres','restore_h02') for db in dbs)
        write('/h02/passfile',passfile())
        def cli(path, *args, error=None, user=None, poisoned=True):
            cmd = ['docker','exec','-i']
            if user: cmd += ['--user',user]
            if poisoned:
                for value in ['PGPASSWORD=wrong','PGSERVICE=missing','PGHOST=bad.invalid',
                              'PGDATABASE=missing','PGSSLMODE=require','PGREQUIREAUTH=none',
                              'PGOPTIONS=-c definitely_invalid_setting=1','HOME=/no-home']:
                    cmd += ['-e',value]
            cmd += [name,'/host-lib/ld-linux-x86-64.so.2','--library-path','/host-lib',
                    '/backupctl','--config',path,'--output','json-v1',*args]
            p = run(cmd,ok=False)
            assert p.returncode == (1 if error else 0), (major,args,p.returncode,p.stdout,p.stderr)
            assert p.stderr == '', (args,p.stderr)
            envelope = json.loads(p.stdout)
            assert envelope['status'] == ('error' if error else 'ok'), envelope
            if error is not None: assert envelope['error']['code'] == error, envelope
            assert password not in p.stdout and quoted not in p.stdout
            return envelope['data']
        auth('scram-sha-256')
        assert cli('/h02/writer.toml','backup','create','--dry-run')['source_major'] == major
        assert cli('/h02/writer.toml','profile','validate','public_data')['source_major'] == major
        assert exec_('test','-e','/h02/store',ok=False).returncode != 0
        for method in ('trust','password','md5'):
            if method == 'md5': sql(f"SET password_encryption='md5'; ALTER ROLE postgres PASSWORD '{quoted}';")
            auth(method)
            cli('/h02/writer.toml','backup','create','--dry-run',error='NATIVE_OPERATION_FAILED')
            print(f'PG{major} refused actual {method} authentication fallback',flush=True)
        sql(f"SET password_encryption='scram-sha-256'; ALTER ROLE postgres PASSWORD '{quoted}';")
        auth('scram-sha-256')
        write('/h02/passfile',passfile(value='wrong'))
        cli('/h02/writer.toml','backup','create','--dry-run',error='NATIVE_OPERATION_FAILED')
        write('/h02/passfile',passfile().replace(':5432:',':*:',1))
        cli('/h02/writer.toml','backup','create','--dry-run',error='NATIVE_OPERATION_FAILED')
        write('/h02/passfile',passfile(),mode='644')
        cli('/h02/writer.toml','backup','create','--dry-run',error='NATIVE_OPERATION_FAILED')
        write('/h02/passfile',passfile())
        # Reject link/script/tool-directory drift before executing an untrusted tool.
        exec_('ln','-s',f'/usr/lib/postgresql/{major}/bin','/h02/linked-tools')
        write('/h02/unsafe.toml',writer.replace(f'/usr/lib/postgresql/{major}/bin','/h02/linked-tools'))
        cli('/h02/unsafe.toml','backup','create','--dry-run',error='NATIVE_OPERATION_FAILED')
        exec_('mkdir','-m','755','/h02/script-tools')
        for tool in ('pg_dump','pg_restore','pg_dumpall','psql','createdb'):
            write('/h02/script-tools/'+tool,'#!/bin/sh\nexit 0\n',mode='755')
        write('/h02/unsafe.toml',writer.replace(f'/usr/lib/postgresql/{major}/bin','/h02/script-tools'))
        cli('/h02/unsafe.toml','backup','create','--dry-run',error='NATIVE_OPERATION_FAILED')
        # Exercise actual peer HBA with the matching service OS identity and a private socket.
        exec_('chmod','755','/h02')
        write(hba,'local all all peer\nhost all all 127.0.0.1/32 scram-sha-256\n')
        sql('SELECT pg_reload_conf()'); time.sleep(.15)
        write('/h02/peer.toml',config(peer=True))
        exec_('chown','postgres:postgres','/h02/peer.toml')
        cli('/h02/peer.toml','profile','validate','public_data',user='postgres')
        exec_('chmod','777','/h02/socket')
        cli('/h02/peer.toml','profile','validate','public_data',user='postgres',error='NATIVE_OPERATION_FAILED')
        exec_('chmod','700','/h02/socket')
        write('/h02/peer-bad.toml',config(user='restore_h02',peer=True))
        exec_('chown','postgres:postgres','/h02/peer-bad.toml')
        cli('/h02/peer-bad.toml','profile','validate','public_data',user='postgres',error='NATIVE_OPERATION_FAILED')
        auth('scram-sha-256')
        print(f'PG{major} peer identity/socket and trusted executable checks passed',flush=True)
        # Existing legacy bootstrap remains explicit; new key-generation capability is gated.
        legacy = f'''[source]
host = "127.0.0.1"
port = 5432
user = "postgres"
database = "{source}"
client_bin_dir = "/usr/lib/postgresql/{major}/bin"
[storage]
root = "/h02/store"
[encryption]
identity_file = "/h02/identity"
recipient_file = "/h02/recipient"
[signing]
signing_key_file = "/h02/signer"
verifying_key_file = "/h02/verifier"
'''
        write('/h02/legacy.toml',legacy)
        cli('/h02/legacy.toml','key','generate')
        cli('/h02/writer.toml','backup','create',error='NATIVE_OPERATION_FAILED')
        created = cli('/h02/writer.toml','backup','create','--confirm-synthetic')
        backup_id = created['public']['backup_id']
        # Remove writer custody and original DB: all following recovery uses reader keys.
        exec_('rm','/h02/signer','/h02/recipient')
        sql(f'DROP DATABASE {source}; DROP ROLE h02_restore_group;')
        write('/h02/passfile',passfile(dbs=('postgres',)))
        cli('/h02/reader.toml','restore','plan',backup_id,'--target',target,'--security','portable',error='NATIVE_OPERATION_FAILED')
        assert sql(f"SELECT count(*) FROM pg_database WHERE datname='{target}'") == '0'
        write('/h02/passfile',passfile(dbs=('postgres',target)))
        result = cli('/h02/reader.toml','restore','plan',backup_id,'--target',target,'--security','portable')
        plan = result['plan']; plan_id = plan['id']
        assert plan['format'] == 'h02-restore-plan-v3' and plan['native_context']['user'] == 'restore_h02'
        assert plan['artifact_database'] == source and plan['rollback']
        plan_path = f'/h02/store/plans/{plan_id}.json'
        saved = exec_('cat',plan_path).stdout
        canonical = json.dumps(json.loads(saved),separators=(',',':'),ensure_ascii=False).encode()
        assert hashlib.sha256(canonical).hexdigest() == result['digest']
        # Context checks precede even a broken native tool path.
        jobs_before = cli('/h02/reader.toml','job','list')
        for old,new in [('host = "127.0.0.1"','host = "::1"'),
                        ('password_file = "/h02/passfile"','password_file = "/h02/missing-passfile"'),
                        ('user = "restore_h02"','user = "postgres"'),
                        ('maintenance_database = "postgres"','maintenance_database = "missing"'),
                        ('port = 5432','port = 5433'),
                        (f'/usr/lib/postgresql/{major}/bin','/missing-tools')]:
            write('/h02/drift.toml',reader.replace(old,new))
            cli('/h02/drift.toml','restore','run',plan_id,'--confirm-target',target,error='NATIVE_CONTEXT_MISMATCH')
        assert sql(f"SELECT count(*) FROM pg_database WHERE datname='{target}'") == '0'
        assert cli('/h02/reader.toml','job','list') == jobs_before
        # Plan downgrade and legacy/new cross-execution never silently select context.
        plan_path = f'/h02/store/plans/{plan_id}.json'
        saved = exec_('cat',plan_path).stdout
        downgraded = dict(plan); downgraded['format']='m5b-restore-plan-v2'; del downgraded['native_context']
        write(plan_path,json.dumps(downgraded))
        cli('/h02/reader.toml','restore','run',plan_id,'--confirm-target',target,error='NATIVE_CONTEXT_MISMATCH')
        write(plan_path,saved)
        cli('/h02/legacy.toml','restore','run',plan_id,'--confirm-target',target,error='NATIVE_OPERATION_FAILED')
        # Legacy config above still names absent writer files; create a legacy reader config
        # so the context refusal, rather than missing custody, is exercised directly.
        legacy_reader = legacy.replace('recipient_file = "/h02/recipient"','recipient_file = "/h02/unused"').replace('signing_key_file = "/h02/signer"\n','')
        write('/h02/legacy-reader.toml',legacy_reader)
        cli('/h02/legacy-reader.toml','restore','run',plan_id,'--confirm-target',target,error='NATIVE_CONTEXT_MISMATCH')
        assert cli('/h02/reader.toml','job','list') == jobs_before
        restored = cli('/h02/reader.toml','restore','run',plan_id,'--confirm-target',target)
        assert restored['target_database'] == target and not restored['recorded_in_artifact']
        assert sql('SELECT note FROM evidence WHERE id=1',target) == 'h02 recovered'
        assert sql(f"SELECT count(*) FROM pg_database WHERE datname='{source}'") == '0'
        dr_target = 'backupctl_fixture_h02_dr'
        write('/h02/passfile',passfile(dbs=('postgres',target,dr_target)))
        dr_plan = cli('/h02/reader.toml','restore','plan',backup_id,'--target',dr_target,'--security','dr')['plan']
        cli('/h02/reader.toml','restore','run',dr_plan['id'],'--confirm-target',dr_target)
        assert sql('SELECT note FROM evidence WHERE id=1',dr_target) == 'h02 recovered'
        assert sql("SELECT count(*) FROM pg_roles WHERE rolname='h02_restore_group'") == '1'
        assert sql("SELECT tableowner FROM pg_tables WHERE tablename='evidence'",dr_target) == 'postgres'
        assert sql("SELECT has_table_privilege('h02_restore_group','evidence','select')",dr_target) == 't'
        print(f'PG{major} signed portable/DR lost-source recovery passed; context/downgrade/custody checks passed',flush=True)
    finally:
        run(['docker','rm','-fv',name],ok=False)
print('H02 native SCRAM and maintenance recovery passed on PostgreSQL 16/17/18',flush=True)
PY
