# Threat model

Status: M0 baseline, 2026-09-26. Review at M4 encryption, M7 API, and each release. Scope is the Rust backup service, PostgreSQL logical dumps, local artifact store, keys, catalog, CLI, and future API. A signed/encrypted backup can still contain malicious PostgreSQL SQL. This model does not assume the source server, backup host, and storage are equally trusted.

## Assets and trust boundaries

Assets: source database data and credentials; backup payload and private metadata; age decryption identity; Ed25519 signing key; PostgreSQL restore target; catalog/audit history; availability of at least one restorable copy. Boundaries: source PostgreSQL -> `pg_dump` process -> Rust runner -> staging directory -> artifact store -> `pg_restore` -> target. Local operator/CLI and future API actors enter at separate authorization boundaries. Public artifact headers and remote/local storage are untrusted inputs. The independently installed trusted signing public key is not read from an artifact.

## Threat register

| ID | Attacker; asset | Attack and impact | Required mitigation; residual risk | Test/gate |
| --- | --- | --- | --- | --- |
| T01 | Backup-file thief; data | Copies archive, including possible database-held credentials | Encrypt payload/private manifest with age; private identity outside store. A compromised running host can still expose plaintext. | E05/E06, M4 |
| T02 | Storage editor; integrity/origin | Replaces both age files with attacker-created ciphertext for public recipient | Detached Ed25519 signature over ID and both ciphertext hashes, trusted verifier outside artifact. Signing-key compromise still permits forgery. | E05, M4 |
| T03 | Storage editor; recoverability | Deletes or replays an older valid signed artifact | Independent inventory, alerting, protected/off-host copies and later immutable store. Local v1 alone cannot prevent host-loss/deletion/rollback. | E10, M5+ |
| T04 | Local user; filesystem | Path traversal, malicious filename, symlink race, unauthorized deletion | Opaque validated ID, directory ownership/mode, no-follow file operations, atomic stage/commit, least-privilege service account. | E09, M1/M4 |
| T05 | Malicious source admin; restore target | Puts executable SQL/functions in dump; target compromise | Treat archive as executable, trusted-source policy, inspect TOC/SQL if source untrusted, isolated target, restricted restore role. Signature authenticates signer, not SQL safety. | F04, M2 |
| T06 | Credential thief; source | Reads `.pgpass`/connection info; source data disclosure | Peer auth or dedicated 0600 password file, TLS verification remotely, least-privilege role, no argv/logged URL. | P01–P04, M1 |
| T07 | Malicious local/API actor; target | Requests destructive restore or deletion | RBAC, plan digest bound to target/actor/expiry, explicit confirmation, audit, rate/size limits, fresh-target default. | E04/E10, M2/M7 |
| T08 | Crafted identifier; runner | Shell injection or tool option injection | No shell; fixed absolute binary, argv array, explicit option separation, exact catalog resolution, restricted environment. | E09, M1 |
| T09 | Disk/process failure; artifact | Partial write appears complete | Stage, fsync, immutable publish, marker, signature, native exit check, quarantine and startup reconciliation. | E01/E02, M1/M4 |
| T10 | Key loss; recovery | Valid backups become unreadable | Separate offline identity recovery copy, key IDs, restoration drill, no destructive key rotation. | E06, M4 |
| T11 | Compromised backup host; source/keys | Exfiltrates live keys and data or signs fake backup | Dedicated user, filesystem sandbox, short key exposure, host hardening, independent monitoring. Host compromise remains severe. | Package security, M6 |
| T12 | Catalog loss; discoverability | Backup list disappears or stale state hides artifacts | Rebuild from signed artifacts with recovery identity; catalog backup and migration tests. | M5 |
| T13 | Metadata observer; privacy | Learns DB names/sizes/times | Minimal public header and encrypted private manifest. Ciphertext sizes and artifact count remain visible. | M4 |
| T14 | Malicious extension/FDW/subscription; target | Restore contacts external service, loads extension, or leaks credentials | Preflight packages/privileges, `--no-subscriptions`, no auto-activation, document FDW dependencies, treat archive as sensitive. | F05/F11/F12, M2/M3 |
| T15 | Backup overload; source availability | Too many dumps, long locks, disk/CPU pressure | Per-source job limit, bounded workers, lock wait timeout, resource budget and alerts. | M5 |
| T16 | Tool/version mismatch; recoverability | Older client refuses source or restore SQL incompatible | Matching source-major client, same-major restore matrix, extension/locale preflight, repeated restore drills. | E03, M1/M2 |

PostgreSQL explicitly warns that restoring a dump can execute code selected by a source superuser. [`pg_dump`](https://www.postgresql.org/docs/18/app-pgdump.html). User mappings and subscription connection strings can include passwords, so `--no-subscriptions` does not make an archive nonsensitive. [User mappings](https://www.postgresql.org/docs/18/sql-createusermapping.html), [subscription catalog](https://www.postgresql.org/docs/18/catalog-pg-subscription.html). The age recipient is public; sender provenance requires the separate trusted signature described in [artifact v1](../backup-format/manifest-v1.md).

## Security invariants

- No real-data artifact is published before M4 encryption **and** origin signing are implemented and verified.
- No service password or signing/decryption private key is stored in the repository, profile, public header, private manifest, logs, or backup store.
- Verification labels are distinct: ciphertext/signed-artifact integrity, archive readability, and actual isolated restore success.
- A verified signature does not authorize restore; the actor and target still need authorization and an explicit plan.
- Destructive restore and deletion are never inferred from a profile or retried automatically.
- No guarantee of survival of backup-host loss exists until copies reside on independent failure domains.

## Review triggers

Revisit attacker capabilities and mitigations whenever a new storage provider, recipient/key provider, API/UI, global-object export, physical/WAL backup mode, or multi-tenant model is added. Record owner, review date, changed trust boundary, tests, and accepted residual risk in the corresponding ADR/release note.
