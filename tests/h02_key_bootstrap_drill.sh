#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl --locked --offline
python3 - "$repo_root/target/debug/backupctl" <<'PY'
import fcntl, hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile
binary = pathlib.Path(sys.argv[1]).resolve()
assert shutil.which('strace'), 'strace is required for real syscall fault/crash tests'
root = pathlib.Path(tempfile.mkdtemp(prefix='.backupctl-key-drill-',dir=pathlib.Path.home()))
roles = ['identity','signing','recipient','verifying']
try:
    def config(scene,role='writer',readonly=False,production=False):
        path=scene/f'{role}-{readonly}-{production}.toml'
        text=f'''config_version = 1
mode = "{'production' if production else 'fixture'}"
access = "{role}"
read_only = {str(readonly).lower()}
[storage]
root = "{scene}/absent-store"
'''
        if role in ('writer','reader'):
            text+=f'[encryption]\nidentity_file = "{scene}/identity"\n'
            if role=='writer': text+=f'recipient_file = "{scene}/recipient"\n'
        if role!='inventory':
            text+=f'[signing]\nverifying_key_file = "{scene}/verifying"\n'
            if role=='writer': text+=f'signing_key_file = "{scene}/signing"\n'
        path.write_text(text);path.chmod(0o600)
        return path
    def scene(name):
        path=root/name;path.mkdir(mode=0o700);return path
    def invoke(path,*args,code=None,inject=None,killed=False):
        cmd=[str(binary),'--config',str(path),'--output','json-v1',*args]
        trace=None
        if inject:
            trace=path.parent/'trace.txt'
            cmd=['strace','-f','-qq','-o',str(trace),'-e','trace=linkat,fsync','-e',f'inject={inject}',*cmd]
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
        if killed:
            assert p.returncode!=0 and p.stdout=='',(p.returncode,p.stdout,p.stderr)
            assert 'SIGKILL' in trace.read_text()
            return
        assert p.returncode==(1 if code else 0),(p.returncode,p.stdout,p.stderr)
        assert p.stderr=='',p.stderr
        envelope=json.loads(p.stdout)
        assert envelope['error']['code']==code if code else envelope['error'] is None,envelope
        assert envelope['status']==('partial' if code=='KEY_PARTIAL' else 'error' if code else 'ok'),envelope
        return envelope
    def hashes(path):
        return {r:hashlib.sha256((path/r).read_bytes()).hexdigest() for r in roles if (path/r).is_file()}
    def assert_no_store(path): assert not (path/'absent-store').exists()
    complete=scene('complete');writer=config(complete)
    created=invoke(writer,'key','generate')['data']
    assert created['created']==roles and created['pending']==[] and created['durability_confirmed']
    seeds=[(complete/r).read_text().splitlines()[1] for r in ('identity','signing')]
    for role,mode in [('writer',False),('reader',True),('public',True),('inventory',True)]:
        path=config(complete,role,mode)
        status=invoke(path,'key','status')
        assert len(status['data']['keys'])=={'writer':4,'reader':2,'public':1,'inventory':0}[role]
        for fact in status['data']['keys']:
            assert set(fact)=={'path','role','suite','mode','fingerprint'} and len(fact['fingerprint'])==16
        rendered=json.dumps(status)
        assert not any(seed in rendered for seed in seeds)
        if role!='writer':
            invoke(path,'key','generate',code='ACCESS_DENIED')
            invoke(path,'key','publish',code='ACCESS_DENIED')
    assert_no_store(complete)
    before=hashes(complete)
    invoke(writer,'key','generate',code='KEY_OCCUPIED')
    assert hashes(complete)==before
    for role,readonly in [('writer',False),('reader',True),('public',True),('inventory',True)]:
        path=config(complete,role,readonly,True)
        for action in ('generate','publish','status'):
            invoke(path,'key',action,code='PRODUCTION_NOT_ENABLED')
    assert hashes(complete)==before
    for r in ('recipient','verifying'): (complete/r).unlink()
    published=invoke(writer,'key','publish')['data'];assert published['created']==['recipient','verifying']
    assert hashes(complete)==before
    assert invoke(writer,'key','publish')['data']['created']==[]
    # Held real directory locks refuse competing commands without creating lock files.
    fd=os.open(complete,os.O_RDONLY|os.O_DIRECTORY)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        invoke(writer,'key','status',code='KEY_BUSY')
        invoke(writer,'key','publish',code='KEY_BUSY')
    finally: os.close(fd)
    assert hashes(complete)==before
    # Two actual CLI writers cannot publish mixed generations to one configuration.
    path=scene('competing');conf=config(path)
    command=[str(binary),'--config',str(conf),'--output','json-v1','key','generate']
    processes=[subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(2)]
    results=[]
    for process in processes:
        out,err=process.communicate(timeout=30)
        assert not err
        results.append((process.returncode,json.loads(out)))
    assert sorted(rc for rc,_ in results)==[0,1],results
    assert [r['error']['code'] for rc,r in results if rc] in [['KEY_BUSY'],['KEY_OCCUPIED']]
    invoke(conf,'key','status')
    assert set(hashes(path))==set(roles)
    assert_no_store(path)
    # Actual kernel no-replace failures expose the exact durable prefix, not success.
    for stop in range(4):
        path=scene(f'handled-{stop}');conf=config(path)
        result=invoke(conf,'key','generate',code='KEY_PARTIAL' if stop else 'KEY_OPERATION_FAILED',
                      inject=f'linkat:error=EACCES:when={stop+1}')['data']
        assert result=={'keys':[],'created':roles[:stop],'pending':roles[stop:],'durability_confirmed':True},result
        assert set(hashes(path))==set(roles[:stop])
        old=hashes(path)
        if stop: invoke(conf,'key','generate',code='KEY_OCCUPIED')
        if stop>=2:
            invoke(conf,'key','publish')
            assert all(hashes(path)[r]==v for r,v in old.items())
        elif stop==1:
            invoke(conf,'key','publish',code='KEY_INVALID')
            assert hashes(path)==old
        else: invoke(conf,'key','generate')
        assert_no_store(path)
    # A failed directory fsync is distinct from a failed link: name exists, durability unknown.
    path=scene('directory-sync');conf=config(path)
    outcome=invoke(conf,'key','generate',code='KEY_PARTIAL',inject='fsync:error=EIO:when=5')['data']
    assert outcome['created']==['identity'] and outcome['pending']==roles[1:] and outcome['durability_confirmed'] is False,outcome
    assert set(hashes(path))=={'identity'}
    # A staging failure has no final names. All four stage syncs precede the first link.
    path=scene('stage-sync');conf=config(path)
    invoke(conf,'key','generate',code='KEY_OPERATION_FAILED',inject='fsync:error=EIO:when=4')
    assert hashes(path)=={}
    # SIGKILL at each real link syscall leaves only its already completed prefix.
    for stop in range(4):
        path=scene(f'crash-{stop}');conf=config(path)
        invoke(conf,'key','generate',inject=f'linkat:signal=SIGKILL:when={stop+1}',killed=True)
        old=hashes(path)
        assert set(old)==set(roles[:stop]),(stop,old)
        assert not [p for p in path.iterdir() if p.name.startswith('.')]
        if stop: invoke(conf,'key','generate',code='KEY_OCCUPIED')
        if stop>=2:
            invoke(conf,'key','publish')
            invoke(conf,'key','status')
            assert all(hashes(path)[r]==v for r,v in old.items())
        elif stop==1:
            invoke(conf,'key','publish',code='KEY_INVALID')
            assert hashes(path)==old
        else: invoke(conf,'key','generate')
        assert_no_store(path)
        print(f'bootstrap SIGKILL boundary {stop+1}: exact {stop}-file prefix preserved and recovery checked',flush=True)
    # Reader/public status cannot reach absent secret/recipient material.
    for r in ('identity','recipient','signing'): (complete/r).unlink()
    invoke(config(complete,'public',True),'key','status')
    assert_no_store(complete)
    print('H02 key bootstrap: protected custody, 4 handled link failures, staging/durability faults and 4 SIGKILL boundaries passed',flush=True)
finally:
    shutil.rmtree(root)
PY
