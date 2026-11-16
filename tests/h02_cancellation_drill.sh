#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl --locked --offline
python3 - "$repo_root/target/debug/backupctl" <<'PY'
import json, os, pathlib, shlex, shutil, subprocess, sys, tempfile, time
binary = pathlib.Path(sys.argv[1]).resolve()
libdir = pathlib.Path('/lib/x86_64-linux-gnu').resolve()
uid, gid = os.getuid(), os.getgid()
assert uid != 0, 'read-only media acceptance must run as non-root'

def run(args, text=None, ok=True):
    p = subprocess.run(args, input=text, text=True, capture_output=True, timeout=90)
    if ok and p.returncode:
        raise AssertionError((args[:6], p.returncode, p.stdout, p.stderr))
    return p

for major in (16, 17, 18):
    writer = f'backupctl-h02-cancel-writer-{major}-{os.getpid()}'
    reader = f'backupctl-h02-cancel-reader-{major}-{os.getpid()}'
    scene = pathlib.Path(tempfile.mkdtemp(prefix='.backupctl-cancel-drill-', dir=pathlib.Path.home()))
    children=[]
    try:
        image = f'docker.arvancloud.ir/library/postgres:{major}-bookworm'
        run(['docker','run','-d','--name',writer,'--network','none',
             '-e','POSTGRES_PASSWORD=snapshot-synthetic',
             '-v',f'{binary}:/backupctl:ro','-v',f'{libdir}:/host-lib:ro', image,'bash','-c','docker-entrypoint.sh postgres & wait'])
        def execute(name, *args, text=None, ok=True):
            return run(['docker','exec','-i',name,*args], text, ok)
        for _ in range(100):
            if execute(writer,'pg_isready','-h','127.0.0.1','-U','postgres',ok=False).returncode == 0: break
            time.sleep(.1)
        else: raise AssertionError('writer not ready')
        execute(writer,'psql','-X','-U','postgres','-v','ON_ERROR_STOP=1','-c',
                'CREATE DATABASE backupctl_fixture_snapshot;')
        execute(writer,'psql','-X','-U','postgres','-d','backupctl_fixture_snapshot',
                '-v','ON_ERROR_STOP=1','-c',
                "CREATE TABLE evidence(id integer, note text); INSERT INTO evidence VALUES (1,'offline snapshot');")
        execute(writer,'mkdir','-m','755','/scene')
        execute(writer,'mkdir','-m','700','/scene/keys')
        def write(name, path, content):
            execute(name,'sh','-c',f'cat > {path} && chmod 600 {path}',text=content)
        write(writer,'/scene/passfile','127.0.0.1:5432:backupctl_fixture_snapshot:postgres:snapshot-synthetic\n127.0.0.1:5432:postgres:postgres:snapshot-synthetic\n')
        cfg = f'''config_version=1
mode="fixture"
access="writer"
read_only=false
export_globals=true
[storage]
root="/scene/store"
[source]
host="127.0.0.1"
port=5432
user="postgres"
database="backupctl_fixture_snapshot"
maintenance_database="postgres"
auth="scram-passfile"
password_file="/scene/passfile"
[tools]
client_bin_dir="/usr/lib/postgresql/{major}/bin"
[encryption]
identity_file="/scene/keys/identity"
recipient_file="/scene/keys/recipient"
[signing]
signing_key_file="/scene/keys/signer"
verifying_key_file="/scene/keys/verifier"
'''
        # Pin actual SCRAM HBA/password state; never rely on image initdb defaults.
        hba = execute(writer,'psql','-X','-U','postgres','-At','-c','SHOW hba_file').stdout.strip()
        write(writer,hba,'local all all trust\nhost all all 127.0.0.1/32 scram-sha-256\n')
        execute(writer,'psql','-X','-U','postgres','-v','ON_ERROR_STOP=1','-c',
                "SET password_encryption='scram-sha-256'; ALTER ROLE postgres PASSWORD 'snapshot-synthetic'; SELECT pg_reload_conf();")
        time.sleep(.15)
        write(writer,'/scene/writer.toml',cfg)
        runtime = ['/host-lib/ld-linux-x86-64.so.2','--library-path','/host-lib','/backupctl']
        def create(*args):
            p = execute(writer,*runtime,'--config','/scene/writer.toml','--output','json-v1',*args)
            e = json.loads(p.stdout)
            assert e['status']=='ok', e
            return e['data']
        create('key','generate')
        # Only the designated cancellation target stalls during COPY. The source
        # and subsequent recovery target validate this CHECK without sleeping.
        execute(writer,'psql','-X','-U','postgres','-d','backupctl_fixture_snapshot','-v','ON_ERROR_STOP=1','-c',
            "CREATE FUNCTION public.h02_cancel_barrier() RETURNS boolean LANGUAGE plpgsql AS $$BEGIN IF current_database()='backupctl_fixture_cancel_target' THEN PERFORM pg_sleep(30); END IF; RETURN true; END$$; ALTER TABLE evidence ADD CONSTRAINT h02_barrier CHECK (public.h02_cancel_barrier());")
        created = create('backup','create','--confirm-synthetic')
        artifact_id = created['public']['backup_id']
        target='backupctl_fixture_cancel_target'
        recovered='backupctl_fixture_cancel_recovered'
        write(writer,'/scene/passfile',''.join(f'127.0.0.1:5432:{db}:postgres:snapshot-synthetic\n'
              for db in ('backupctl_fixture_snapshot','postgres',target,recovered)))
        def sql(text,db='postgres'):
            return execute(writer,'psql','-X','-U','postgres','-d',db,'-At','-v','ON_ERROR_STOP=1','-c',text).stdout.strip()
        def wait_for(predicate,label):
            until=time.monotonic()+12
            while not predicate():
                assert time.monotonic()<until,label
                time.sleep(.03)
        def launch(*args):
            execute(writer,'rm','-f','/scene/running.pid')
            argv=[*runtime,'--config','/scene/writer.toml','--output','json-v1',*args]
            command='echo $$ > /scene/running.pid; exec '+shlex.join(argv)
            p=subprocess.Popen(['docker','exec',writer,'sh','-c',command],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(p)
            wait_for(lambda:execute(writer,'test','-f','/scene/running.pid',ok=False).returncode==0,'CLI pid barrier')
            return p,int(execute(writer,'cat','/scene/running.pid').stdout)
        def native_children(pid):
            return execute(writer,'cat',f'/proc/{pid}/task/{pid}/children').stdout.split()
        def cancel(p,pid,signal,effects):
            native=native_children(pid)
            assert native,'no active native child at cancellation barrier'
            started=time.monotonic()
            execute(writer,'sh','-c',f'kill -{signal} {pid}')
            out,err=p.communicate(timeout=8)
            assert time.monotonic()-started<5 and p.returncode==1,(out,err)
            assert not err,err
            report=json.loads(out)
            assert report['error']['code']=='OPERATION_CANCELLED',report
            assert report['status']==('partial' if effects=='database_may_be_modified' else 'error'),report
            if effects is None: assert report['data'] is None,report
            else:
                receipt=report['data']; assert receipt['effects']==effects,report
                assert set(receipt)=={'job_id','artifact_id','effects'}
                job=create('job','inspect',receipt['job_id'])
                assert job['job']['state']=='failed',job
            for child in native:
                assert execute(writer,'test','-d',f'/proc/{child}',ok=False).returncode!=0,child
            for directory in ('staging','scratch'):
                assert not execute(writer,'ls','-A',f'/scene/store/{directory}').stdout,directory
            return report
        # Stop the postmaster so a real captured preflight query waits for a backend.
        postmaster=int(execute(writer,'sh','-c','head -1 "$PGDATA/postmaster.pid"').stdout)
        assert postmaster!=1
        execute(writer,'sh','-c',f'kill -STOP {postmaster}')
        p,pid=launch('backup','create','--dry-run')
        def query_waiting():
            for child in native_children(pid):
                args=execute(writer,'cat',f'/proc/{child}/cmdline',ok=False).stdout
                if '--no-psqlrc' in args and '--version' not in args: return True
            return False
        wait_for(query_waiting,'captured psql preflight barrier')
        cancel(p,pid,'TERM',None)
        execute(writer,'sh','-c',f'kill -CONT {postmaster}')
        # Observe pg_dump's actual lock wait; avoid relying on a large/slow fixture.
        locker=subprocess.Popen(['docker','exec','-e','PGAPPNAME=h02_cancel_locker',writer,
            'psql','-X','-U','postgres','-d','backupctl_fixture_snapshot','-v','ON_ERROR_STOP=1','-c',
            'BEGIN; LOCK TABLE evidence IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(60);'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append(locker)
        wait_for(lambda:sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='h02_cancel_locker' AND wait_event='PgSleep'")=='1','table lock barrier')
        p,pid=launch('backup','create','--confirm-synthetic')
        wait_for(lambda:sql("SELECT count(*) FROM pg_stat_activity WHERE datname='backupctl_fixture_snapshot' AND wait_event_type='Lock'")=='1','streamed pg_dump barrier')
        cancel(p,pid,'INT','preparation_only')
        sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='h02_cancel_locker'")
        locker.communicate(timeout=8)
        # The signed fixture CHECK creates an observable post-create COPY barrier.
        plan=create('restore','plan',artifact_id,'--target',target,'--security','portable')['plan']['id']
        p,pid=launch('restore','run',plan,'--confirm-target',target)
        wait_for(lambda:sql(f"SELECT count(*) FROM pg_stat_activity WHERE datname='{target}' AND wait_event='PgSleep'")=='1','restore mutation barrier')
        cancel(p,pid,'TERM','database_may_be_modified')
        assert sql(f"SELECT count(*) FROM pg_database WHERE datname='{target}'")=='1','partial target was removed'
        sql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{target}'")
        # The same store/scope remains usable, including source-loss recovery.
        fresh=create('backup','create','--confirm-synthetic')
        artifact_id=fresh['public']['backup_id']
        sql('DROP DATABASE backupctl_fixture_snapshot')
        plan=create('restore','plan',artifact_id,'--target',recovered,'--security','portable')['plan']['id']
        create('restore','run',plan,'--confirm-target',recovered)
        assert sql('SELECT note FROM evidence',recovered)=='offline snapshot'
        print(f'PG{major} captured TERM, streamed INT, partial restore TERM, child reap, failed jobs, scratch/stage cleanup and source-loss recovery passed',flush=True)
    finally:
        for name in (reader,writer): run(['docker','rm','-f',name],ok=False)
        for p in children:
            try: p.communicate(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.communicate()
        shutil.rmtree(scene)
print('H02 cancellation drill passed PG16/17/18',flush=True)
PY
