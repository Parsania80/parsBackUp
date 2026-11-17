#!/usr/bin/env bash
# V01: actual versioned signed content/privilege acceptance on all supported majors.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
cargo build -p backupctl --locked --offline
python3 - "$repo_root" <<'PY'
import hashlib, json, os, pathlib, secrets, subprocess, sys, time
root = pathlib.Path(sys.argv[1]).resolve()
binary = root/'target/debug/backupctl'
old_binary = os.environ.get('BACKUPCTL_COMPAT_OLD_BINARY')
if old_binary:
    old_binary = pathlib.Path(old_binary).resolve(strict=True)
    print('Cross-build baseline CLI SHA256 '+hashlib.sha256(old_binary.read_bytes()).hexdigest(),flush=True)
libdir = pathlib.Path('/lib/x86_64-linux-gnu').resolve()
source = 'backupctl_fixture_m1'
roles = ('fixture_owner', 'fixture_reader', 'fixture_read_all', 'fixture_restore', 'postgres')
password = secrets.token_urlsafe(24)
sentinel = 'mapping-'+secrets.token_hex(12)


def run(args, content=None, ok=True):
    p = subprocess.run(args, input=content, text=True, capture_output=True, timeout=120)
    if ok and p.returncode:
        # Commands may carry generated credentials in stdin. Never print stdin or native output.
        raise AssertionError(f'fixture command failed, executable={args[0]}, exit={p.returncode}')
    return p


for major in (16, 17, 18):
    name = f'backupctl-v01-{major}-{os.getpid()}'
    try:
        tag = f'docker.arvancloud.ir/library/postgres:{major}-bookworm'
        reference = next(i['reference'] for i in json.loads((root/'ci/inputs.json').read_text())['images'] if i['tag'] == tag)
        assert run(['docker','image','inspect',tag,'--format','{{.Id}}']).stdout == run(['docker','image','inspect',reference,'--format','{{.Id}}']).stdout
        old_mount = ['-v', f'{old_binary}:/backupctl-old:ro'] if old_binary else []
        run(['docker', 'run', '-d', '--name', name, '--network', 'none', *old_mount,
             '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
             '-v', f'{binary}:/backupctl:ro', '-v', f'{libdir}:/host-lib:ro',
             f'docker.arvancloud.ir/library/postgres:{major}-bookworm'])

        def ex(*args, content=None, ok=True):
            return run(['docker', 'exec', '-i', name, *args], content, ok)

        def sql(statement, db='postgres'):
            return ex('psql', '-X', '-U', 'postgres', '-d', db, '-At', '-v', 'ON_ERROR_STOP=1', content=statement).stdout.strip()

        def write(path, text):
            ex('sh', '-c', f'cat > {path} && chmod 600 {path}', content=text)

        for _ in range(100):
            if ex('pg_isready', '-h', '127.0.0.1', '-U', 'postgres', ok=False).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise AssertionError('final server not ready')
        ex('mkdir', '-m', '700', '/v01')
        ex('mkdir', '-m', '700', '/v01/keys')
        sql("SET password_encryption='scram-sha-256';" + ''.join(
            f"CREATE ROLE {r} LOGIN PASSWORD '{password}' {'CREATEDB' if r == 'fixture_restore' else ''};"
            for r in roles if r != 'postgres') + f"ALTER ROLE postgres PASSWORD '{password}';")
        sql(f'CREATE DATABASE {source} OWNER fixture_owner TEMPLATE template0')
        core = (root/'tests/fixtures/postgres/core.sql').read_text()
        body, security = core.split('-- Synthetic security fixture.', 1)
        sql('SET ROLE fixture_owner;'+body, source)
        sql("SET ROLE fixture_owner; CREATE TYPE app.pair AS (label text,n int); CREATE TABLE app.pairs(v app.pair); INSERT INTO app.pairs VALUES(ROW('pair',7)); CREATE COLLATION app.c_copy FROM \"C\"; CREATE TABLE app.collated(value text COLLATE app.c_copy); INSERT INTO app.collated VALUES('stable'); CREATE TABLE app.rule_input(note text); CREATE RULE route_insert AS ON INSERT TO app.rule_input DO INSTEAD INSERT INTO app.audit_events(account_id,note) VALUES(999,NEW.note);", source)
        sql('-- Synthetic security fixture.'+security, source)
        sql('GRANT USAGE ON SCHEMA app,aux TO fixture_owner,fixture_reader; '
            'GRANT SELECT ON ALL TABLES IN SCHEMA app,aux TO fixture_owner,fixture_reader; '
            'GRANT SELECT ON ALL SEQUENCES IN SCHEMA app,aux TO fixture_reader; '
            "DO $$DECLARE r record; BEGIN FOR r IN SELECT oid FROM pg_largeobject_metadata LOOP "
            "EXECUTE format('GRANT SELECT ON LARGE OBJECT %s TO fixture_reader,fixture_read_all',r.oid); END LOOP; END$$;", source)
        sql('GRANT pg_read_all_data TO fixture_read_all')
        write(sql('SHOW hba_file'), 'local all all trust\nhost all all 127.0.0.1/32 scram-sha-256\n')
        sql('SELECT pg_reload_conf()'); time.sleep(.15)
        targets = [f'backupctl_fixture_v01_{n}' for n in range(1, 41)]
        write('/v01/passfile', ''.join(f'127.0.0.1:5432:{db}:{role}:{password}\n'
              for db in [source, 'postgres', 'template0', *targets] for role in roles))
        profiles = f'''[[profile]]
name="whole"
database="{source}"
large_objects=true
[[profile]]
name="both"
database="{source}"
schemas=["app","aux"]
[[profile]]
name="public"
database="{source}"
schemas=["public"]
[[profile]]
name="public_schema"
database="{source}"
schemas=["public"]
mode="schema-only"
[[profile]]
name="events"
database="{source}"
tables=["app.partitioned_events"]
[[profile]]
name="aux_only"
database="{source}"
schemas=["aux"]
[[profile]]
name="events_schema"
database="{source}"
tables=["app.partitioned_events"]
mode="schema-only"
[[profile]]
name="events_overlap"
database="{source}"
tables=["app.partitioned_events","app.partitioned_events_2025"]
[[profile]]
name="events_excluded"
database="{source}"
tables=["app.partitioned_events"]
exclude_tables=["app.partitioned_events_2025"]
[[profile]]
name="child_only"
database="{source}"
tables=["app.partitioned_events_2025"]
[[profile]]
name="nested"
database="{source}"
tables=["app.nested"]
[[profile]]
name="inherited"
database="{source}"
tables=["app.base_notes"]
[[profile]]
name="multiple_inheritance"
database="{source}"
tables=["app.inh_a","app.inh_b"]
[[profile]]
name="unsafe_family"
database="{source}"
tables=["app.unsafe_parent"]
[[profile]]
name="explicit_events"
database="{source}"
tables=["app.partitioned_events","app.partitioned_events_2025","app.partitioned_events_2026"]
'''

        def config(role='writer', user='fixture_owner'):
            text = f'''config_version=1
mode="fixture"
access="{role}"
read_only=false
timeout_seconds=30
[storage]
root="/v01/store"
[source]
host="127.0.0.1"
port=5432
user="{user}"
database="{source}"
maintenance_database="postgres"
auth="scram-passfile"
password_file="/v01/passfile"
[tools]
client_bin_dir="/usr/lib/postgresql/{major}/bin"
[encryption]
identity_file="/v01/keys/identity"
'''
            if role == 'writer': text += 'recipient_file="/v01/keys/recipient"\n'
            text += '[signing]\nverifying_key_file="/v01/keys/verifier"\n'
            if role == 'writer': text += 'signing_key_file="/v01/keys/signer"\n'
            return text+profiles

        for role in roles:
            write('/v01/'+role+'.toml', config(user=role))
        write('/v01/restore.toml', config('reader', 'fixture_restore'))
        ex('mkdir','-m','700','/external-v01-scratch')
        write('/v01/snapshot.toml',config('reader','fixture_restore').replace('read_only=false','read_only=true')+'\n[scratch]\nroot="/external-v01-scratch"\n')
        outputs = []

        def cli(config_name, *args, fail=False, old=False):
            # Offline reads use the implemented true snapshot contract. Writable
            # versioned offline dispatch remains a separate production gate.
            if args[:2] in (('backup','inspect'),('backup','verify'),('backup','list')):
                config_name = 'snapshot'
            executable = '/backupctl-old' if old else '/backupctl'
            p = ex('/host-lib/ld-linux-x86-64.so.2', '--library-path', '/host-lib', executable,
                   '--config', '/v01/'+config_name+'.toml', '--output', 'json-v1', *args, ok=False)
            result = json.loads(p.stdout)
            assert password not in p.stdout and sentinel not in p.stdout
            assert not p.stderr and p.returncode == (1 if fail else 0), (major, args, p.returncode, result.get('error'))
            assert result['status'] in (('error', 'partial') if fail else ('ok',)), (args, result['status'])
            outputs.append(p.stdout)
            return result

        def create(config_name='fixture_owner', profile='whole', old=False):
            return cli(config_name, 'backup', 'create', '--profile', profile, '--confirm-synthetic', old=old)['data']['public']['backup_id']

        target_index = 0
        def plan(artifact, target=None, fail=False, old=False):
            if target is None:
                target = targets[target_index]
            args = ['restore', 'plan', artifact, '--target', target, '--security', 'portable']
            if fail:
                return cli('restore', *args, fail=True, old=old)
            p = ex('/host-lib/ld-linux-x86-64.so.2', '--library-path', '/host-lib', '/backupctl-old' if old else '/backupctl',
                   '--config', '/v01/restore.toml', '--output', 'json-v1', *args, ok=False)
            result = json.loads(p.stdout)
            if p.returncode:
                assert result['error']['code'] == 'OLDER_SNAPSHOT_ACK_REQUIRED', result['error']['code']
                args += ['--acknowledge-older-snapshot']
            return cli('restore', *args, old=old)['data']['plan']

        def restore(artifact, fail=False, old=False):
            target = targets[target_index]
            p = plan(artifact, target, old=old)
            result = cli('restore', 'restore', 'run', p['id'], '--confirm-target', target, fail=fail, old=old)
            return target, result

        def count(db, statement, expected):
            assert sql(statement, db) == str(expected), (major, db, 'independent SQL assertion')

        def artifacts():
            return ex('find', '/v01/store/artifacts', '-name', 'complete').stdout.splitlines()

        cli('fixture_owner', 'key', 'generate')
        cli('snapshot','config','check')
        # Snapshot custody uses sibling key/store trees and external scratch.
        assert ex('stat','-c','%a','/v01/keys','/external-v01-scratch').stdout.splitlines() == ['700','700']
        if old_binary:
            old_full = create(old=True)
            before = ex('sh','-c',f'sha256sum /v01/store/artifacts/{old_full}/*').stdout
            old_detail = cli('fixture_owner','backup','inspect',old_full,old=True)['data']
            assert cli('fixture_owner','backup','inspect',old_full)['data'] == old_detail
            assert 'table_family_edges' not in old_detail['resolved_selection']
            cli('restore','backup','verify',old_full,'--level','archive')
            target, _ = restore(old_full); target_index += 1
            count(target, 'SELECT count(*) FROM app.accounts', 2)
            assert ex('sh','-c',f'sha256sum /v01/store/artifacts/{old_full}/*').stdout == before
        role_facts = sql("SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname IN ('fixture_owner','fixture_reader','fixture_read_all','fixture_restore') ORDER BY 1")
        assert 'fixture_restore|f|t|f|f' in role_facts
        assert all('|f|f|f|f' in line for line in role_facts.splitlines() if not line.startswith('fixture_restore|'))
        print(f'PG{major} server={sql("SHOW server_version")} client='+ex('pg_dump','--version').stdout.strip(), flush=True)
        print(role_facts, flush=True)
        full = create()
        target, result = restore(full); target_index += 1
        assert result['data']['recorded_in_artifact'] is False
        count(target, "SELECT nextval('app.accounts_id_seq')", 3)
        count(target, "SELECT nextval('app.external_counter')", 123)
        sql((root/'tests/fixtures/postgres/assertions.sql').read_text(), target)
        count(target, "SELECT nspowner::regrole FROM pg_namespace WHERE nspname='app'", 'fixture_restore')
        count(target, "SELECT relowner::regrole FROM pg_class WHERE oid='app.audit_events'::regclass", 'fixture_restore')
        count(target, "SELECT has_table_privilege('backupctl_fixture_bob','app.accounts','INSERT')", 'f')
        count(target, "SELECT count(*) FROM pg_default_acl WHERE defaclnamespace='app'::regnamespace", 0)
        count(target, "SELECT obj_description('app.accounts'::regclass)", 'Synthetic backup fixture')
        count(target, "SELECT doubled_units FROM app.accounts WHERE id=1", 4)
        count(target, "SELECT count(*) FROM pg_constraint WHERE conrelid='aux.orders'::regclass AND contype='f'", 1)
        count(target, "SELECT relrowsecurity FROM pg_class WHERE oid='app.tenant_rows'::regclass", 't')
        sql('CALL app.noop_procedure()', target)
        count(target, 'SELECT (v).label FROM app.pairs', 'pair')
        count(target, "SELECT value FROM app.collated", 'stable')
        count(target, "SELECT cfgname FROM pg_ts_config WHERE oid='app.simple_copy'::regconfig", 'simple_copy')
        sql("BEGIN; INSERT INTO app.rule_input VALUES('rule fired'); DO $$BEGIN IF NOT EXISTS(SELECT 1 FROM app.audit_events WHERE account_id=999 AND note='rule fired') THEN RAISE EXCEPTION 'rule missing'; END IF; END$$; ROLLBACK;", target)
        print(f'PG{major} full signed non-superuser owner -> CREATEDB-only different-role portable recovery passed', flush=True)
        if old_binary:
            before = ex('sh','-c',f'sha256sum /v01/store/artifacts/{full}/*').stdout
            cli('restore','backup','verify',full,'--level','archive',old=True)
            target, _ = restore(full, old=True); target_index += 1
            count(target, 'SELECT count(*) FROM app.accounts', 2)
            assert ex('sh','-c',f'sha256sum /v01/store/artifacts/{full}/*').stdout == before
            print(f'PG{major} old v1 -> new and new v1 -> old signed CLI recovery with identical manifest facts/immutable artifacts passed', flush=True)
        else:
            print(f'PG{major} cross-build checks NOT RUN: BACKUPCTL_COMPAT_OLD_BINARY unset', flush=True)
        # Actual native diagnostic is inspected privately to distinguish RLS from missing SELECT.
        for role in ('fixture_reader', 'fixture_read_all'):
            before = artifacts()
            cli(role, 'backup', 'create', '--profile', 'whole', '--confirm-synthetic', fail=True)
            assert artifacts() == before
            native = ex('env', 'PGPASSFILE=/v01/passfile', 'pg_dump', '-h', '127.0.0.1', '-U', role,
                        '-d', source, '-Fc', '--no-subscriptions', '--no-sync','--file=/dev/null', ok=False)
            assert native.returncode and 'row-level security' in native.stderr.lower()
        sql('ALTER TABLE app.tenant_rows DISABLE ROW LEVEL SECURITY', source)
        sql('REVOKE SELECT ON aux.orders FROM fixture_reader', source)
        before = artifacts()
        cli('fixture_reader', 'backup', 'create', '--profile', 'whole', '--confirm-synthetic', fail=True)
        assert artifacts() == before
        sql('GRANT SELECT ON aux.orders TO fixture_reader', source)
        reader_full = create('fixture_reader')
        target, _ = restore(reader_full); target_index += 1
        count(target, 'SELECT count(*) FROM app.tenant_rows', 2)
        sql('ALTER TABLE app.tenant_rows ENABLE ROW LEVEL SECURITY', source)
        print(f'PG{major} SELECT reader success, missing grant and pg_read_all_data/RLS no-publication controls passed', flush=True)
        # Filtered large objects remain an explicit unsupported scope.
        cli('fixture_owner', 'profile', 'validate', 'both', fail=True)
        sql('DELETE FROM app.documents; SELECT lo_unlink(oid) FROM pg_largeobject_metadata', source)
        cli('fixture_owner', 'profile', 'validate', 'aux_only', fail=True)
        both = create(profile='both')
        target, _ = restore(both); target_index += 1
        sql((root/'tests/fixtures/postgres/selective-assertions.sql').read_text(), target)
        dry = cli('fixture_owner','backup','create','--profile','events','--dry-run')['data']['selection']
        assert dry['resolved_tables'] == ['app.partitioned_events','app.partitioned_events_2025','app.partitioned_events_2026']
        assert len(dry['table_family_edges']) == 2
        family = create(profile='events')
        detail = cli('restore','backup','inspect',family)['data']
        assert detail['format_version'] == 2 and detail['requested_selection']['tables'] == ['app.partitioned_events']
        assert detail['profile_snapshot']['tables'] == detail['requested_selection']['tables']
        assert detail['resolved_selection']['tables'] == dry['resolved_tables']
        assert detail['resolved_selection']['table_family_edges'] == dry['table_family_edges']
        for level in ('signature','checksum','archive'):
            cli('restore','backup','verify',family,'--level',level)
        if old_binary:
            before = ex('sh','-c',f'sha256sum /v01/store/artifacts/{family}/*').stdout
            cli('restore','backup','verify',family,'--level','signature',old=True,fail=True)
            cli('restore','backup','inspect',family,old=True,fail=True)
            assert ex('sh','-c',f'sha256sum /v01/store/artifacts/{family}/*').stdout == before
        target, _ = restore(family); target_index += 1
        count(target,'SELECT count(*) FROM app.partitioned_events',2)
        count(target,"SELECT count(*) FROM pg_inherits WHERE inhparent='app.partitioned_events'::regclass",2)
        count(target,"SELECT to_regclass('app.accounts') IS NULL",'t')
        overlap = create(profile='events_overlap')
        assert cli('restore','backup','inspect',overlap)['data']['format_version'] == 2
        explicit = create(profile='explicit_events')
        assert cli('restore','backup','inspect',explicit)['data']['format_version'] == 1
        schema_family = create(profile='events_schema')
        target, _ = restore(schema_family); target_index += 1
        count(target,'SELECT count(*) FROM app.partitioned_events',0)
        count(target,"SELECT count(*) FROM pg_inherits WHERE inhparent='app.partitioned_events'::regclass",2)
        inherited = create(profile='inherited')
        target, _ = restore(inherited); target_index += 1
        count(target,'SELECT count(*) FROM ONLY app.child_notes',1)
        count(target,"SELECT count(*) FROM pg_inherits WHERE inhparent='app.base_notes'::regclass",1)
        # The security fixture transferred app to Alice; permit this non-superuser
        # fixture owner to construct the additional synthetic family tables.
        sql('GRANT CREATE ON SCHEMA app TO fixture_owner',source)
        sql('SET ROLE fixture_owner; CREATE TABLE app.nested(id int) PARTITION BY RANGE(id); CREATE TABLE aux.mid PARTITION OF app.nested FOR VALUES FROM(0) TO(100) PARTITION BY RANGE(id); CREATE TABLE aux.leaf PARTITION OF aux.mid FOR VALUES FROM(0) TO(100); INSERT INTO app.nested VALUES(7); CREATE TABLE app.unsafe_parent(id int); CREATE TABLE app."unsafe*child"() INHERITS(app.unsafe_parent); CREATE TABLE app.inh_a(a int); CREATE TABLE app.inh_b(b int); CREATE TABLE aux.inh_leaf() INHERITS(app.inh_a,app.inh_b); INSERT INTO aux.inh_leaf VALUES(11,12);',source)
        nested = create(profile='nested')
        nested_detail = cli('restore','backup','inspect',nested)['data']
        assert nested_detail['resolved_selection']['tables'] == ['app.nested','aux.leaf','aux.mid']
        assert nested_detail['resolved_selection']['table_family_edges'] == [{'parent':'app.nested','child':'aux.mid'},{'parent':'aux.mid','child':'aux.leaf'}]
        target, _ = restore(nested); target_index += 1
        count(target,'SELECT id FROM app.nested',7)
        count(target,"SELECT count(*) FROM pg_inherits",2)
        multiple = create(profile='multiple_inheritance')
        target, _ = restore(multiple); target_index += 1
        count(target,'SELECT a::text||\'|\'||b::text FROM ONLY aux.inh_leaf','11|12')
        count(target,"SELECT count(*) FROM pg_inherits WHERE inhrelid='aux.inh_leaf'::regclass",2)
        for bad in ('events_excluded','child_only','unsafe_family'):
            before = artifacts()
            cli('fixture_owner','backup','create','--profile',bad,'--confirm-synthetic',fail=True)
            assert artifacts() == before
        # Key-free discovery/reconcile understands the shared signed container shape.
        write('/v01/inventory.toml',f'config_version=1\nmode="fixture"\naccess="inventory"\nread_only=true\n[storage]\nroot="/v01/store"\n')
        cli('inventory','inventory','check')
        listing = cli('fixture_owner','inventory','reconcile')['data']
        assert all(e['status'] == 'registered' for e in listing['entries'])
        assert next(e for e in listing['entries'] if e['backup_id'] == family)['shape'] == 'v1-signed'
        compatibility = 'old-v2 refusal passed' if old_binary else 'old-v2 refusal NOT RUN'
        print(f'PG{major} signed v2 partition/inheritance/schema-only/overlapping roots/multilevel cross-schema restore, literal v1 and no-publication controls passed; {compatibility}',flush=True)
        sql('CREATE TABLE public.evidence(id int PRIMARY KEY,note text); INSERT INTO public.evidence VALUES(1,\'public recovered\')', source)
        sql('GRANT SELECT ON public.evidence TO fixture_owner', source)
        public = create(profile='public')
        target, _ = restore(public); target_index += 1
        count(target, 'SELECT note FROM public.evidence WHERE id=1', 'public recovered')
        schema = create(profile='public_schema')
        target, _ = restore(schema); target_index += 1
        count(target, 'SELECT count(*) FROM public.evidence', 0)
        p = plan(public, targets[target_index])
        conflict = targets[target_index]; target_index += 1
        sql(f'CREATE DATABASE {conflict} OWNER fixture_restore')
        sql('CREATE TABLE sentinel(id int); INSERT INTO sentinel VALUES(77)', conflict)
        cli('restore', 'restore', 'run', p['id'], '--confirm-target', conflict, fail=True)
        count(conflict, 'SELECT id FROM sentinel', 77)
        # A dirty template cannot turn namespace preparation into destructive cleanup.
        sql('ALTER DATABASE template0 ALLOW_CONNECTIONS true')
        sql('CREATE TABLE public.template_sentinel(id int); INSERT INTO public.template_sentinel VALUES(73)', 'template0')
        target, partial = restore(public, fail=True); target_index += 1
        assert partial['status'] == 'partial' and partial['data']['effects'] == 'database_may_be_modified'
        count(target, 'SELECT id FROM public.template_sentinel', 73)
        sql('DROP TABLE public.template_sentinel', 'template0')
        sql('ALTER DATABASE template0 ALLOW_CONNECTIONS false')
        print(f'PG{major} app/aux, public and schema-only restores; existing target and nonempty-public refusal passed', flush=True)
        # Supported extension on available target runtime; this proves hstore only.
        sql((root/'tests/fixtures/postgres/optional-extensions.sql').read_text(), source)
        sql('ALTER EXTENSION hstore ADD TABLE app.partitioned_events',source)
        before = artifacts()
        cli('fixture_owner','backup','create','--profile','events','--confirm-synthetic',fail=True)
        assert artifacts() == before
        sql('ALTER EXTENSION hstore DROP TABLE app.partitioned_events',source)
        print(f'PG{major} extension-owned family refused without publication',flush=True)
        sql('GRANT SELECT ON app.extension_values TO fixture_owner', source)
        extended = create()
        target, _ = restore(extended); target_index += 1
        count(target, "SELECT attributes->'color' FROM app.extension_values WHERE id=1", 'blue')
        # Privileged definitions stay separate from the normal scheduled owner/reader.
        sql((root/'tests/fixtures/postgres/optional-publication.sql').read_text(), source)
        sql("CREATE SUBSCRIPTION fixture_inert CONNECTION 'host=127.0.0.2 dbname=missing' PUBLICATION missing WITH (connect=false,slot_name=NONE)", source)
        sql((root/'tests/fixtures/postgres/optional-fdw.sql').read_text(), source)
        sql(f"CREATE USER MAPPING FOR PUBLIC SERVER fixture_remote OPTIONS(user 'fixture', password '{sentinel}')", source)
        admin_full = create('postgres')
        # postgres_fdw is untrusted: CREATEDB alone is insufficient, with honest partial receipt.
        target, partial = restore(admin_full, fail=True); target_index += 1
        assert partial['status'] == 'partial'
        # Same reader custody, explicitly privileged acting DB user, no signer/recipient.
        write('/v01/admin_restore.toml', config('reader', 'postgres'))
        target = targets[target_index]; target_index += 1
        p = cli('admin_restore', 'restore', 'plan', admin_full, '--target', target, '--security', 'portable')['data']['plan']
        cli('admin_restore', 'restore', 'run', p['id'], '--confirm-target', target)
        count(target, "SELECT count(*) FROM pg_publication WHERE pubname='fixture_accounts'", 1)
        count(target, "SELECT count(*) FROM pg_subscription WHERE subdbid=(SELECT oid FROM pg_database WHERE datname=current_database())", 0)
        count(target, "SELECT count(*) FROM pg_foreign_table", 1)
        count(target, "SELECT count(*) FROM pg_user_mapping WHERE array_to_string(umoptions,',') LIKE '%"+sentinel+"%'", 1)
        # A plain keyless store scan cannot reveal the DB-held credential sentinel.
        for secret in (sentinel, password):
            assert ex('grep', '-r', '-l', '-F', '--', secret, '/v01/store', ok=False).returncode == 1
        ex('rm', '/v01/keys/signer', '/v01/keys/recipient')
        sql('DROP SUBSCRIPTION fixture_inert', source)
        sql(f'DROP DATABASE {source}')
        target = targets[target_index]; target_index += 1
        p = cli('admin_restore', 'restore', 'plan', admin_full, '--target', target, '--security', 'portable')['data']['plan']
        cli('admin_restore', 'restore', 'run', p['id'], '--confirm-target', target)
        count(target, 'SELECT count(*) FROM app.accounts', 2)
        count(target, 'SELECT note FROM public.evidence', 'public recovered')
        target = targets[target_index]; target_index += 1
        p = cli('restore','restore','plan',nested,'--target',target,'--security','portable','--acknowledge-older-snapshot')['data']['plan']
        cli('restore','restore','run',p['id'],'--confirm-target',target)
        count(target,'SELECT id FROM app.nested',7)
        count(target,"SELECT count(*) FROM pg_inherits",2)
        assert ex('find', '/v01/store/scratch', '-mindepth', '1').stdout == ''
        assert ex('find', '/v01/store/staging', '-mindepth', '1').stdout == ''
        print(f'PG{major} hstore, publication/subscription omission, encrypted FDW sentinel, privilege refusal and reader-only lost-source recovery passed', flush=True)
        print(f'PG{major} explicit exclusions: security-label provider, arbitrary external extension/locale dependencies, DB settings/tablespaces/global parameter grants, host/WAL files; no support claim', flush=True)
    finally:
        run(['docker', 'rm', '-f', name], ok=False)
print('V01 content/privilege drill passed PG16/17/18; known production readiness blockers remain', flush=True)
PY
