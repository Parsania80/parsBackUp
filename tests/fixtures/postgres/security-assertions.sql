-- Run after a DR restore (roles + ownership + privileges) into a disposable
-- database. Requires superuser to inspect pg_authid.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'backupctl_fixture_alice' AND rolcanlogin) THEN
        RAISE EXCEPTION 'DR restore lost role backupctl_fixture_alice';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'backupctl_fixture_bob' AND rolcanlogin) THEN
        RAISE EXCEPTION 'DR restore lost role backupctl_fixture_bob';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'backupctl_fixture_reporting' AND NOT rolcanlogin) THEN
        RAISE EXCEPTION 'DR restore lost role backupctl_fixture_reporting';
    END IF;
    -- Role attributes survive the exported ALTER ROLE replay.
    IF EXISTS (SELECT 1 FROM pg_roles
               WHERE rolname IN ('backupctl_fixture_alice', 'backupctl_fixture_bob')
                 AND NOT (rolcanlogin AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb)) THEN
        RAISE EXCEPTION 'DR restore lost role attributes';
    END IF;
    -- The export used --no-role-passwords: no verifier may exist anywhere.
    IF (SELECT count(*) FROM pg_authid WHERE rolname LIKE 'backupctl_fixture_%' AND rolpassword IS NOT NULL) > 0 THEN
        RAISE EXCEPTION 'restored role carries a password verifier';
    END IF;
    IF NOT pg_has_role('backupctl_fixture_alice', 'backupctl_fixture_reporting', 'MEMBER') THEN
        RAISE EXCEPTION 'DR restore lost role membership reporting -> alice';
    END IF;
    IF (SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = 'app')
       <> 'backupctl_fixture_alice' THEN
        RAISE EXCEPTION 'DR restore lost schema ownership';
    END IF;
    IF NOT has_table_privilege('backupctl_fixture_bob', 'app.accounts', 'SELECT') THEN
        RAISE EXCEPTION 'DR restore lost table privileges';
    END IF;
    IF NOT has_table_privilege('backupctl_fixture_bob', 'app.accounts', 'INSERT') THEN
        RAISE EXCEPTION 'DR restore lost insert privilege';
    END IF;
    IF has_table_privilege('backupctl_fixture_bob', 'app.accounts', 'DELETE') THEN
        RAISE EXCEPTION 'DR restore granted a privilege that never existed';
    END IF;
    IF NOT has_table_privilege('backupctl_fixture_reporting', 'aux.orders', 'SELECT') THEN
        RAISE EXCEPTION 'DR restore lost reporting privileges';
    END IF;
    IF (SELECT relowner::regrole::text FROM pg_class
        WHERE oid = 'app.audit_events'::regclass) <> 'backupctl_fixture_alice' THEN
        RAISE EXCEPTION 'DR restore lost table ownership';
    END IF;
END
$$;
