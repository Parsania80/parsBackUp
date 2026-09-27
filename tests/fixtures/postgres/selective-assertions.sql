-- Run after a selective (profile-based) full restore into a disposable
-- database whose selection covered every dependency.
DO $$
BEGIN
    IF (SELECT count(*) FROM app.accounts) <> 2 THEN
        RAISE EXCEPTION 'accounts row count mismatch';
    END IF;
    IF (SELECT state FROM app.accounts WHERE id = 1) <> 'active' THEN
        RAISE EXCEPTION 'enum type mismatch';
    END IF;
    IF (SELECT units FROM app.accounts WHERE id = 1) <> 2 THEN
        RAISE EXCEPTION 'domain type mismatch';
    END IF;
    IF (SELECT doubled_units FROM app.accounts WHERE id = 1) <> 4 THEN
        RAISE EXCEPTION 'generated column mismatch';
    END IF;
    IF (SELECT count(*) FROM aux.orders) <> 2 THEN
        RAISE EXCEPTION 'orders row count mismatch';
    END IF;
    -- The cross-schema foreign key must exist, not merely its rows.
    IF (SELECT count(*) FROM pg_constraint
        WHERE contype = 'f'
          AND conrelid = 'aux.orders'::regclass
          AND confrelid = 'app.accounts'::regclass) <> 1 THEN
        RAISE EXCEPTION 'cross-schema foreign key missing';
    END IF;
    IF (SELECT count(*) FROM app.partitioned_events) <> 2 THEN
        RAISE EXCEPTION 'partition data mismatch';
    END IF;
    IF (SELECT count(*) FROM ONLY app.child_notes) <> 1 THEN
        RAISE EXCEPTION 'inheritance child row mismatch';
    END IF;
    IF (SELECT count(*) FROM app.account_emails) <> 2 THEN
        RAISE EXCEPTION 'view mismatch';
    END IF;
    IF (SELECT sum(n) FROM app.account_counts) <> 2 THEN
        RAISE EXCEPTION 'materialized view data mismatch';
    END IF;
    IF (SELECT counter_value FROM app.counters WHERE id = 1) <> 122 THEN
        RAISE EXCEPTION 'standalone sequence state mismatch';
    END IF;
    IF (SELECT app.account_label(1)) <> 'one@example.invalid' THEN
        RAISE EXCEPTION 'function mismatch';
    END IF;
    IF (SELECT count(*) FROM pg_policies
        WHERE schemaname = 'app' AND tablename = 'tenant_rows') <> 1 THEN
        RAISE EXCEPTION 'RLS policy missing';
    END IF;
    IF (SELECT count(*) FROM pg_trigger
        WHERE tgrelid = 'app.accounts'::regclass AND tgname = 'accounts_audit') <> 1 THEN
        RAISE EXCEPTION 'trigger missing';
    END IF;
    IF (SELECT last_value FROM app.accounts_id_seq) < 2 THEN
        RAISE EXCEPTION 'identity sequence state mismatch';
    END IF;
    IF (SELECT count(*) FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'app' AND c.relkind = 'S') < 1 THEN
        RAISE EXCEPTION 'sequence absent from the selective restore';
    END IF;
END
$$;
-- A trigger inside the selection must fire in the restored database.
BEGIN;
INSERT INTO app.accounts (email, units) VALUES ('three@example.invalid', 4);
DO $$
BEGIN
    IF (SELECT count(*) FROM app.audit_events WHERE note = 'three@example.invalid') <> 1 THEN
        RAISE EXCEPTION 'trigger did not fire after restore';
    END IF;
END
$$;
ROLLBACK;
