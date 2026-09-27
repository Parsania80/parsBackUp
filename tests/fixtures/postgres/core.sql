-- Synthetic PostgreSQL 16-18 source fixture. Run only in a disposable database.
CREATE SCHEMA app;
CREATE SCHEMA aux;

CREATE TYPE app.account_state AS ENUM ('active', 'disabled');
CREATE DOMAIN app.positive_int AS integer CHECK (VALUE > 0);
CREATE TABLE app.accounts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email text NOT NULL UNIQUE,
    state app.account_state NOT NULL DEFAULT 'active',
    units app.positive_int NOT NULL,
    doubled_units integer GENERATED ALWAYS AS (units * 2) STORED,
    CONSTRAINT email_shape CHECK (position('@' IN email) > 1)
);
CREATE INDEX accounts_email_lower_idx ON app.accounts ((lower(email)));
INSERT INTO app.accounts (email, units) VALUES ('one@example.invalid', 2), ('two@example.invalid', 3);
COMMENT ON TABLE app.accounts IS 'Synthetic backup fixture';

CREATE TABLE aux.orders (
    id integer PRIMARY KEY,
    account_id bigint NOT NULL REFERENCES app.accounts(id),
    amount integer NOT NULL CHECK (amount >= 0)
);
INSERT INTO aux.orders VALUES (10, 1, 25), (11, 2, 40);

CREATE SEQUENCE app.external_counter START 100;
SELECT setval('app.external_counter', 121, true);
CREATE TABLE app.counters (id integer PRIMARY KEY, counter_value bigint DEFAULT nextval('app.external_counter'));
INSERT INTO app.counters (id) VALUES (1);

CREATE FUNCTION app.account_label(p_id bigint) RETURNS text
LANGUAGE sql STABLE AS $$ SELECT email FROM app.accounts WHERE id = p_id $$;
CREATE PROCEDURE app.noop_procedure() LANGUAGE plpgsql AS $$ BEGIN PERFORM 1; END $$;
CREATE TABLE app.audit_events (account_id bigint, note text);
CREATE FUNCTION app.audit_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO app.audit_events VALUES (NEW.id, NEW.email);
    RETURN NEW;
END
$$;
CREATE TRIGGER accounts_audit AFTER INSERT ON app.accounts
FOR EACH ROW EXECUTE FUNCTION app.audit_account();
CREATE VIEW app.account_emails AS SELECT id, email FROM app.accounts;
CREATE MATERIALIZED VIEW app.account_counts AS SELECT state, count(*) AS n FROM app.accounts GROUP BY state;

CREATE TABLE app.partitioned_events (event_day date NOT NULL, payload text NOT NULL)
PARTITION BY RANGE (event_day);
CREATE TABLE app.partitioned_events_2025 PARTITION OF app.partitioned_events
FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
CREATE TABLE app.partitioned_events_2026 PARTITION OF app.partitioned_events
FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
INSERT INTO app.partitioned_events VALUES ('2025-02-01', 'older'), ('2026-02-01', 'newer');
CREATE TABLE app.base_notes (id integer, note text);
CREATE TABLE app.child_notes (tag text) INHERITS (app.base_notes);
INSERT INTO app.base_notes VALUES (1, 'base');
INSERT INTO app.child_notes (id, note, tag) VALUES (2, 'child', 'inherited');

CREATE TABLE app.tenant_rows (tenant_id integer, payload text);
INSERT INTO app.tenant_rows VALUES (1, 'a'), (2, 'b');
ALTER TABLE app.tenant_rows ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_filter ON app.tenant_rows
USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::integer);

CREATE TABLE app.documents (id integer PRIMARY KEY, payload_oid oid NOT NULL);
INSERT INTO app.documents
SELECT 1, lo_from_bytea(0, decode('666978747572652d6c6f', 'hex'));
CREATE TEXT SEARCH CONFIGURATION app.simple_copy (COPY = pg_catalog.simple);
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT ON TABLES TO PUBLIC;

-- Synthetic security fixture. All credentials are fake and live only in a
-- disposable container; password verifiers must never enter a backup.
CREATE ROLE backupctl_fixture_alice LOGIN;
CREATE ROLE backupctl_fixture_bob LOGIN;
CREATE ROLE backupctl_fixture_reporting NOLOGIN;
ALTER ROLE backupctl_fixture_alice PASSWORD 'fake-verifier-for-tests-only';
ALTER ROLE backupctl_fixture_bob PASSWORD 'fake-verifier-for-tests-only';
GRANT backupctl_fixture_reporting TO backupctl_fixture_alice;
GRANT CONNECT ON DATABASE backupctl_fixture_m1 TO backupctl_fixture_reporting;
ALTER SCHEMA app OWNER TO backupctl_fixture_alice;
ALTER TABLE app.audit_events OWNER TO backupctl_fixture_alice;
GRANT SELECT, INSERT, UPDATE ON app.accounts TO backupctl_fixture_bob;
GRANT SELECT ON aux.orders TO backupctl_fixture_reporting;
