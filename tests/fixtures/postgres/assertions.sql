-- Run after a full same-major restore into a disposable database.
DO $$
BEGIN
    IF (SELECT count(*) FROM app.accounts) <> 2 THEN
        RAISE EXCEPTION 'accounts row count mismatch';
    END IF;
    IF (SELECT count(*) FROM aux.orders) <> 2 THEN
        RAISE EXCEPTION 'orders row count mismatch';
    END IF;
    IF (SELECT count(*) FROM app.partitioned_events) <> 2 THEN
        RAISE EXCEPTION 'partition data mismatch';
    END IF;
    IF (SELECT count(*) FROM ONLY app.child_notes) <> 1 THEN
        RAISE EXCEPTION 'inheritance child row mismatch';
    END IF;
    IF (SELECT sum(n) FROM app.account_counts) <> 2 THEN
        RAISE EXCEPTION 'materialized view data mismatch';
    END IF;
    IF (SELECT lo_get(payload_oid) FROM app.documents WHERE id = 1)
       <> decode('666978747572652d6c6f', 'hex') THEN
        RAISE EXCEPTION 'large object bytes mismatch';
    END IF;
    IF app.account_label(1) <> 'one@example.invalid' THEN
        RAISE EXCEPTION 'function mismatch';
    END IF;
    IF (SELECT count(*) FROM pg_policies WHERE schemaname = 'app' AND tablename = 'tenant_rows') <> 1 THEN
        RAISE EXCEPTION 'RLS policy missing';
    END IF;
    IF (SELECT last_value FROM app.accounts_id_seq) < 2 THEN
        RAISE EXCEPTION 'identity sequence state mismatch';
    END IF;
END
$$;
BEGIN;
INSERT INTO app.accounts (email, units) VALUES ('three@example.invalid', 4);
DO $$
BEGIN
    IF (SELECT count(*) FROM app.audit_events WHERE note = 'three@example.invalid') <> 1 THEN
        RAISE EXCEPTION 'trigger mismatch';
    END IF;
END
$$;
ROLLBACK;
