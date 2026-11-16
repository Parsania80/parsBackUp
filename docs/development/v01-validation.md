# V01 production readiness validation

Recorded before implementation on 2026-11-16 after reviewed H05 checkpoint 046c22e.
This is an acceptance/evidence contract, not an operating flow. Production operations
remain disabled through V03. Validation uses synthetic isolated PostgreSQL 16/17/18
with matching clients; fixture success alone cannot authorize real sources.

## Content and privilege acceptance

Use actual versioned signed/encrypted CLI writes and reader-only recovery, protected
config/key/passfile paths and real SCRAM clients. Separate a non-superuser object owner,
an explicit SELECT reader, pg_read_all_data without BYPASSRLS, a CREATEDB-only restorer
and an ephemeral administrator used only to construct fixtures/observe privileged cases.
Record exact versions/role attributes, expected refusal categories and independent SQL
assertions. Missing SELECT and default RLS failure must publish no complete artifact;
never fall back to filtered rows or grant privileges in the application.

Full recovery covers rows, constraints/indexes, identity/standalone sequence next values,
generated values, enum/domain/composite types, views/materialized data, trigger/function/
procedure/rule behavior, comments/default ACL/RLS definitions, partition/inheritance,
large object bytes/OID references and text search/collation. Optional extension,
publication, subscription omission and FDW definition/credential-sentinel cases record
actual success or explicit unsupported dependencies; a skip is not a pass. Restore
portable mode as a CREATEDB-only different DB role and validate ownership/ACL omissions.
Privileged DR/role export, key loss/rotation, tamper, schema upgrades, races/crashes,
resource failure and target conflicts also retain dedicated existing native regressions;
record exactly which are rerun. Security label providers, tablespaces/global parameter
grants, database-level settings, physical/server/host files and arbitrary external
services must not inherit a full-support claim from a row-only test.

Selective cases cover schema selection including public, schema-only/pre-data,
partition/table selection and cross-scope refusal. Existing large-object filtered
scope refusal stays intact. Data-only into a fresh database remains unsupported.

## Public schema collision correction

Keep fresh-target planning/execution checks and template0 creation unchanged. Before
native restore, inspect the authenticated/decrypted archive TOC using the matching
client. Only a real SCHEMA entry naming public, with pre-data selected, permits static
`DROP SCHEMA IF EXISTS public RESTRICT` in the newly created fixture target. Do not
parse/execute dump SQL, use CASCADE, global --clean, change archive/plan bytes or
ignore native errors. Full/table archives without this entry keep template public.
The negative control puts a sentinel in template0's public schema: restore must fail
partially with the sentinel retained. Existing targets must still refuse before writes.

Primary references: PostgreSQL [pg_restore](https://www.postgresql.org/docs/18/app-pgrestore.html),
[DROP SCHEMA](https://www.postgresql.org/docs/18/sql-dropschema.html),
[predefined roles/RLS](https://www.postgresql.org/docs/18/predefined-roles.html).

## Security and release gate disposition

Review frozen hybrid encryption/signature transcript bindings, exact accepted suites,
both signature legs, consumption-time digest binding, independent verifier/identity
custody and secret lifetimes against code/tests. Run a current RustSec lockfile scan
with recorded tool/database revision and report findings without silently ignoring or
upgrading dependencies. This is an implementation/dependency review, not independent
cryptographic assurance or a constant-time proof. A clean advisory scan is time-bound.

V01 reports acceptance separately from blockers. Versioned writable offline reads and
retention dispatch still refuse CAPABILITY_NOT_ENABLED; production plan canonical
bytes/context must be defined before adding its writer. Those remain production
compatibility gates, not capabilities certified by these fixture tests. Resolve any
new content/security failures before V01 acceptance; do not mark the entire phase done
while required behavior remains unvalidated. V02 measurements, V03 license/security/
support/release decision, T03 off-host replay limitation and hosted CI execution remain
separate. No push, deployment, production mode bypass or controlled-flow change.

Inspection follow-up: native partition-family dump/resolution succeeds, but frozen artifact v1 refuses expanded children absent from the literal request. The matrix records this no-publication readiness blocker; full-database partition recovery is tested separately. No v1 validation relaxation or requested-selection falsification is authorized here.
