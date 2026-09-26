-- Definition-only fixture; no user mapping password or external connection.
CREATE EXTENSION IF NOT EXISTS postgres_fdw;
CREATE SERVER fixture_remote FOREIGN DATA WRAPPER postgres_fdw
OPTIONS (host 'localhost', dbname 'fixture_unreachable');
CREATE FOREIGN TABLE app.remote_accounts (id bigint, email text)
SERVER fixture_remote OPTIONS (schema_name 'app', table_name 'accounts');
