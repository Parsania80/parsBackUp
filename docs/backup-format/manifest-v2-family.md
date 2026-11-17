# Signed table-family scope contract

Recorded before implementation on 2026-11-17, authorized by the operator's request
to define and implement V01 signed partition-family compatibility. This is a format
contract, not an operating flow. The [frozen v1 contract](manifest-v1.md) is unchanged.

## Version and compatibility boundary

Keep writing format_version 1 for whole-database, schema and literal table selections
whose resolved tables are all explicitly requested. Write **format_version 2** in
both public.json and the encrypted manifest only when a table request expands to
additional partition or inheritance descendants. Preserve the original profile and
requested_selection exactly; never insert catalog-derived children into the request.

Version 2 has the same top-level manifest/header fields, file layout, limits, suites,
key encodings, encryption, signature bytes and publication/reader order as v1. Its
resolved_selection adds required nonempty **table_family_edges**, an array of closed
objects with exactly **parent** and **child**, each an exact schema.table name. This
field is absent in v1 output; a v1 record with any family metadata is refused.
An empty/absent graph cannot make version 2 valid. Unknown major versions, extra
fields, public/private version disagreement and invalid graphs are refused.

The existing signature domain `backupctl-artifact-v1\0` and HPKE info remain the
unchanged cryptographic container protocol. Version 2 changes scope semantics, not
that protocol: the manifest version and graph are authenticated through the signed
manifest ciphertext digest. Header version alone remains untrusted until compared
with the decrypted manifest. Old readers refuse public version 2 before decryption;
new readers retain strict v1 semantics and old artifact readability. No old artifact
is rewritten. Use the new tool for stores containing version 2 artifacts.

Inventory schema 8 and its historical `v1-signed` shape are retained: that shape
classifies the unchanged signed file layout/discovery fields, not the manifest's
scope version. It does not assert that an older binary can parse the artifact.
Reconcile/rebuild, verify, retention and read-only snapshots must consume v2 through
the same validated header/manifest path. Existing restore plan v2/v3 bytes need no
new field: their authenticated manifest digest already binds the version, graph and
scope. A plan must still refuse changed manifest bytes/context/source. No production
restore-plan definition, production writer or inventory migration is introduced here.

## Scope validity and native resolution

1. Version 2 is table-only, filtered, with no resolved schemas, no dangling references
   or extension-owned members. At least one resolved table was not literally requested.
2. Requested tables match the profile snapshot; resolved exclusions match the profile.
   Requested/resolved names are unique exact lower-case non-system identifiers. Every
   requested table is resolved. At most 512 resolved tables and 4096 direct edges.
3. Edges are unique, not self-links, have endpoints in the resolved table set and form
   an acyclic graph. Starting from the requested tables, following parent-to-child edges
   reaches every resolved table. Multiple roots, overlapping roots, cross-schema
   descendants, multiple inheritance and multiple partition levels are representable.
4. Excluding a resolved family table is refused, as are extension exclusions for this
   expanded scope. Do not publish an archive whose signed graph promises omitted tables.
   A selected child with an unselected parent remains a dangling-dependency refusal.
5. Read table names and direct pg_inherits edges in one catalog statement. Refuse
   pending partition detaches and descendants whose names cannot be safely expressed
   by the exact-name profile rules. Pass the bounded resolved table list explicitly
   to pg_dump with strict names, never delegate family expansion to patterns.
6. Re-resolve an expanded selection after dumping and listing the archive, before
   publication; an observed change in scope/edges/dependencies refuses publication.
   This detects observed DDL changes, not an atomic catalog/dump transaction or an
   ABA-proof DDL freeze. Avoid concurrent structural DDL during selective backups.

The signed graph is the trusted writer's catalog observation; an offline reader
validates its internal scope consistency, not the historical truth of a live catalog.
No SQL is taken from graph fields, and target schema preparation retains the existing
validated non-system name checks. Data-only fresh-target recovery remains unsupported.

Primary sources: [pg_inherits](https://www.postgresql.org/docs/18/catalog-pg-inherits.html)
defines direct inheritance edges and pending detaches; [pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html)
defines explicit table filtering and its dependency limits. Extension ownership and
automatic extension dependencies are identified by [pg_depend](https://www.postgresql.org/docs/18/catalog-pg-depend.html)
types e and x; both refuse expanded-family publication.

## Acceptance

Require domain negative controls for version/field/graph/scope/profile/exclusion
violations and unchanged v1 serialization/refusal. Actual signed CLI PostgreSQL
16/17/18 cases must verify, inspect, plan and restore expanded partition families,
multi-level cross-schema descendants and ordinary inheritance, independently checking
rows, parent links and unrelated-object absence. Test schema-only family recovery,
overlapping explicit roots, child-only/exclusion/unsafe-name refusals without complete
publication, keyless discovery/reconcile and read-only reader-key recovery after
source loss. Preserve the old CLI and prove old v1 -> new recovery, new v1 -> old
recovery, and old v2 refusal without rewriting artifacts. Unit-test observed post-dump
scope change refusal. Run locked/offline fast, M3 legacy, M4b signed, V01 content and
H02 snapshot all-major gates plus both-target package lifecycle/recovery. Freeze inputs
during final gates and retain the previous crypto package/evidence.

Production stays disabled. This closes only the signed-family gap; other V01 content,
security and production command/plan obligations, V02/V03 and T03 remain open. No
dependency update, controlled-flow edit, commit, push or host deployment is included.
