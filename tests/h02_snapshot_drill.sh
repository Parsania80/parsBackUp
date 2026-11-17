#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl --locked --offline
python3 - "$repo_root/target/debug/backupctl" <<'PY'
import hashlib, json, os, pathlib, re, shutil, sqlite3, subprocess, sys, tempfile, time
binary = pathlib.Path(sys.argv[1]).resolve()
libdir = pathlib.Path('/lib/x86_64-linux-gnu').resolve()
strace = pathlib.Path(shutil.which('strace')).resolve()
uid, gid = os.getuid(), os.getgid()
assert uid != 0, 'read-only media acceptance must run as non-root'

def run(args, text=None, ok=True):
    p = subprocess.run(args, input=text, text=True, capture_output=True, timeout=90)
    if ok and p.returncode:
        raise AssertionError((args[:6], p.returncode, p.stdout, p.stderr))
    return p

def state(root):
    result = []
    for p in sorted([root, *root.rglob('*')]):
        m = p.lstat()
        result.append((str(p.relative_to(root)), m.st_mode, m.st_uid, m.st_gid,
                       m.st_size, m.st_mtime_ns, m.st_ctime_ns,
                       hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None))
    return result

for major in (16, 17, 18):
    writer = f'backupctl-h02-snapshot-writer-{major}-{os.getpid()}'
    reader = f'backupctl-h02-snapshot-reader-{major}-{os.getpid()}'
    scene = pathlib.Path(tempfile.mkdtemp(prefix='.backupctl-snapshot-drill-', dir=pathlib.Path.home()))
    try:
        image = f'docker.arvancloud.ir/library/postgres:{major}-bookworm'
        run(['docker','run','-d','--name',writer,'--network','none',
             '-e','POSTGRES_PASSWORD=snapshot-synthetic',
             '-v',f'{binary}:/backupctl:ro','-v',f'{libdir}:/host-lib:ro', image])
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
        created = create('backup','create','--confirm-synthetic')
        artifact_id = created['public']['backup_id']
        assert created['public']['format_version'] == 1
        execute(writer,'psql','-X','-U','postgres','-d','backupctl_fixture_snapshot',
                '-v','ON_ERROR_STOP=1','-c',
                "CREATE TABLE public.family(id integer) PARTITION BY RANGE(id); CREATE TABLE public.family_one PARTITION OF public.family FOR VALUES FROM (0) TO (10); INSERT INTO public.family VALUES(1);")
        write(writer,'/scene/writer.toml',cfg+'\n[[profile]]\nname="family"\ndatabase="backupctl_fixture_snapshot"\ntables=["public.family"]\n')
        family = create('backup','create','--profile','family','--confirm-synthetic')
        family_id = family['public']['backup_id']
        assert family['public']['format_version'] == 2
        for part in ('store','keys'):
            run(['docker','cp',f'{writer}:/scene/{part}',str(scene / part)])
        # Destroy the source server before launching the offline reader.
        run(['docker','rm','-f',writer])
        for p in [scene/'store', *(scene/'store').rglob('*')]:
            p.chmod(0o500 if p.is_dir() else 0o400)
        (scene/'keys').chmod(0o700)
        (scene/'config').mkdir(mode=0o700)
        (scene/'trace').mkdir(mode=0o700)
        base = f'''config_version=1
mode="fixture"
access="reader"
read_only=true
[storage]
root="/snap"
[source]
host="127.0.0.1"
port=1
user="unused"
database="backupctl_fixture_snapshot"
maintenance_database="postgres"
auth="scram-passfile"
password_file="/do-not-open/passfile"
[tools]
client_bin_dir="/usr/lib/postgresql/{major}/bin"
[encryption]
identity_file="/keys/identity"
[signing]
verifying_key_file="/keys/verifier"
[scratch]
root="/scratch"
[resources]
min_free_bytes=1048576
'''
        def config(text):
            p=scene/'config/read.toml'; p.write_text(text); p.chmod(0o600)
        config(base)
        run(['docker','run','-d','--name',reader,'--network','none','--read-only',
             '--user',f'{uid}:{gid}','--cap-add','SYS_PTRACE','--security-opt','seccomp=unconfined',
             '--tmpfs',f'/scratch:rw,size=64m,mode=700,uid={uid},gid={gid}',
             '-v',f'{scene / "store"}:/snap:ro','-v',f'{scene / "keys"}:/keys:ro',
             '-v',f'{scene / "config"}:/config:ro','-v',f'{scene / "trace"}:/trace:rw',
             '-v',f'{binary}:/backupctl:ro','-v',f'{strace}:/host-strace:ro',
             '-v',f'{libdir}:/host-lib:ro',image,'sleep','infinity'])
        # Positive kernel control: the same non-root service cannot create in the store.
        p=execute(reader,'touch','/snap/forbidden',ok=False)
        assert p.returncode and 'Read-only file system' in p.stderr, p.stderr
        execute(reader,'sh','-c','echo sibling > /scratch/untouched')
        baseline=state(scene/'store')
        trace_index=0
        def cli(*args, error=None):
            global trace_index
            trace_index+=1
            p=execute(reader,'/host-lib/ld-linux-x86-64.so.2','--library-path','/host-lib',
                '/host-strace','-f','-yy','-s','256','-o',f'/trace/{trace_index}',
                '-e','trace=%file,%network,flock,fcntl,write,pwrite64,fsync,fdatasync,ftruncate',
                *runtime,'--config','/config/read.toml','--output','json-v1',*args,ok=False)
            assert p.returncode==(1 if error else 0), (major,args,p.stdout,p.stderr)
            assert not p.stderr, p.stderr
            e=json.loads(p.stdout)
            assert e['status']==('error' if error else 'ok'), e
            if error: assert e['error']['code']==error,e
            trace=(scene/'trace'/str(trace_index)).read_text()
            assert '/do-not-open' not in trace, trace
            assert not re.search(r'\b(connect|socket)\(',trace), 'database/network access'
            for line in trace.splitlines():
                if '/snap' not in line: continue
                assert not re.search(r'\b(flock|mkdir|mkdirat|unlink|unlinkat|rename|renameat|chmod|fchmod|ftruncate|pwrite64|write|fsync|fdatasync)\(',line), line
                assert not ('open' in line and re.search(r'O_WRONLY|O_RDWR|O_CREAT|O_TRUNC',line)),line
                assert not ('fcntl(' in line and 'F_SETLK' in line),line
            assert state(scene/'store')==baseline,'snapshot bytes/metadata changed'
            leftovers=execute(reader,'ls','-A','/scratch').stdout.splitlines()
            assert leftovers==['untouched'],leftovers
            return e['data'],trace
        # Identity/scratch deliberately unusable: list needs neither; signature verifier only.
        config(base.replace('/keys/identity','/absent-key/identity').replace('root="/scratch"','root="/missing/scratch"'))
        _,trace=cli('backup','list')
        assert '/keys/' not in trace and '/absent-' not in trace
        _,trace=cli('backup','verify',artifact_id,'--level','signature')
        assert '/keys/identity' not in trace and '/absent-' not in trace
        public = f'config_version=1\nmode="fixture"\naccess="public"\nread_only=true\n[storage]\nroot="/snap"\n[signing]\nverifying_key_file="/keys/verifier"\n'
        config(public)
        cli('backup','list')
        cli('backup','verify',artifact_id,'--level','signature')
        cli('backup','inspect',artifact_id,error='ACCESS_DENIED')
        config(base)
        cli('backup','inspect',artifact_id)
        family_manifest,_=cli('backup','inspect',family_id)
        assert family_manifest['requested_selection']['tables'] == ['public.family']
        assert family_manifest['resolved_selection']['tables'] == ['public.family','public.family_one']
        for level in ('signature','checksum','archive'):
            data,_=cli('backup','verify',family_id,'--level',level)
            assert data['audit_recorded'] is False
        for level in ('signature','checksum','archive'):
            data,_=cli('backup','verify',artifact_id,'--level',level)
            assert data['audit_recorded'] is False
        for args in [('inventory','check'),('inventory','list'),('inventory','verification',artifact_id),('job','list')]:
            data,trace=cli(*args)
            assert data['audit_recorded'] is False
            assert '/keys/' not in trace and '/scratch/' not in trace
        jobs,_=cli('job','list')
        cli('job','inspect',jobs['jobs'][0]['job_id'])
        config(base.replace('[scratch]\nroot="/scratch"\n',''))
        cli('backup','inspect',artifact_id,error='SCRATCH_REQUIRED')
        config(base.replace('root="/scratch"','root="/snap"'))
        cli('backup','inspect',artifact_id,error='CONFIG_INVALID')
        config(base+'\nmax_scratch_bytes=1\n')
        cli('backup','inspect',artifact_id,error='RESOURCE_LIMIT')
        config(base.replace('min_free_bytes=1048576','min_free_bytes=67108864'))
        cli('backup','inspect',artifact_id,error='DISK_RESERVE_LOW')
        # Identity authentication failure, signature tamper and trusted tool refusal.
        identity=scene/'keys/identity'; saved_identity=identity.read_bytes()
        identity.write_bytes(b'invalid key\n')
        config(base)
        cli('backup','inspect',artifact_id,error='KEY_INVALID')
        identity.write_bytes(saved_identity)
        tools = base.replace(f'/usr/lib/postgresql/{major}/bin','/keys')
        (scene/'keys/pg_restore').write_text('#!/bin/sh\nexit 0\n')
        (scene/'keys/pg_restore').chmod(0o700)
        config(tools)
        cli('backup','verify',artifact_id,'--level','archive',error='NATIVE_OPERATION_FAILED')
        config(base)
        inventory = scene/'store/inventory.db'
        saved_inventory = inventory.read_bytes()
        inventory.chmod(0o600)
        # The copied tombstone must win over surviving complete artifact files.
        # Its rows are deliberately local history, never authenticated freshness proof.
        (scene/'store').chmod(0o700)
        with sqlite3.connect(inventory) as db:
            db.execute("UPDATE artifact SET state='deleted' WHERE backup_id=?",(artifact_id,))
        inventory.chmod(0o400)
        (scene/'store').chmod(0o500)
        baseline=state(scene/'store')
        cli('backup','verify',artifact_id,'--level','signature',error='DELETION_RECOVERY_REQUIRED')
        cli('backup','verify',artifact_id,'--level','checksum',error='DELETION_RECOVERY_REQUIRED')
        data,_=cli('backup','list')
        assert [h['backup_id'] for h in data['signed']] == [family_id]
        inventory.chmod(0o600); inventory.write_bytes(saved_inventory); inventory.chmod(0o400)
        payload=scene/'store/artifacts'/artifact_id/'payload.age'
        payload.chmod(0o600)
        saved=payload.read_bytes(); payload.write_bytes(saved[:-1]+bytes([saved[-1]^1])); payload.chmod(0o400)
        baseline=state(scene/'store')
        _,trace=cli('backup','verify',artifact_id,'--level','archive',error='NATIVE_OPERATION_FAILED')
        assert 'pg_restore' not in trace,'native tool ran before artifact authentication'
        print(f'PG{major} non-root read-only media: offline signature/checksum/archive, exact custody, immutable inventory, scratch cleanup/limits and syscall audit passed',flush=True)
    finally:
        for name in (reader,writer): run(['docker','rm','-f',name],ok=False)
        for p in [scene,*scene.rglob('*')]:
            if p.is_dir(): p.chmod(0o700)
        shutil.rmtree(scene)
print('H02 snapshot drill passed PG16/17/18',flush=True)
PY
