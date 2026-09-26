# ADR 0001: Initial backup platform boundaries

Status: accepted for M0 design; artifact field layout is provisional until M4 tests. Date: 2026-09-26. Scope: first PostgreSQL logical-backup release. Supersede this ADR explicitly if experiments change a decision.

## Context

The platform needs trustworthy single-database backup and restore before adding remote storage, an HTTP API, or physical/WAL recovery. PostgreSQL already provides maintained logical dump/restore tooling. The first deployment is one Debian/Ubuntu service host. Security requires confidentiality and origin verification because database dumps may contain credentials and an age public recipient does not authenticate the sender.

## Options and decisions

| Decision | Options considered | Benefits / drawbacks | Chosen |
| --- | --- | --- | --- |
| Data movement | Native CLI; client-library catalog extraction; custom dump engine | CLI has mature format/TOC and version semantics but needs process supervision. Library extraction still lacks a complete backup implementation. Custom engine has unacceptable correctness burden. | Native `pg_dump`/`pg_restore` with fixed binary paths. |
| Archive | Custom, directory, tar, plain SQL | Custom is one file with TOC/parallel restore but no parallel dump. Directory supports parallel dump but complicates atomic artifact transport. Tar/plain lose useful flexibility. | Custom first; benchmark directory later. |
| Deployment shape | Modular monolith; microservices | Monolith shares business logic and simplifies local jobs; microservices add distributed failure modes without current need. | Modular Rust monolith. |
| Catalog | SQLite; PostgreSQL | SQLite avoids dependency on a database being protected but is single-host. PostgreSQL aids scale but creates bootstrap/dependency concerns. | SQLite at M5, rebuildable from artifacts. |
| Store | Local; S3/MinIO; SFTP | Local is simple and atomic on one filesystem but cannot survive host loss. Remote needs multipart/consistency behavior. | Local first, no host-loss claim. |
| Encryption | Standard age; bespoke chunked AEAD; no encryption | Age has a documented interoperable streaming format; bespoke framing increases crypto risk; no encryption is unacceptable for real data. | Age X25519 for published artifacts; synthetic-only pre-M4 output. |
| Origin | Age alone; keyed MAC; Ed25519 signature | Age authenticates ciphertext integrity but public recipients permit anyone to encrypt. MAC requires shared secret to verify. Signature allows verification with independently trusted public key but requires signing-key operations. | Detached Ed25519 signature over ID and ciphertext hashes. |
| Scheduling | systemd timer; cron; internal scheduler | systemd fits Debian service lifecycle; cron lacks integrated service state; internal scheduler adds restart/leader complexity. | systemd timer first. |
| Restore target | Existing in-place; fresh database | In-place is convenient but can destroy production; fresh target needs storage and an explicit cutover. | Fresh database by default. |

## Consequences

- The first supported server majors are 16–18; matching source-major client binaries and same-major restore are required until pairwise tests expand the matrix. [Version policy](https://www.postgresql.org/support/versioning/), [`pg_dump` compatibility](https://www.postgresql.org/docs/18/app-pgdump.html).
- `pg_dumpall` globals, subscriptions, WAL, physical backups, and OS/application files remain separate mechanisms or manual prerequisites. [`pg_dumpall`](https://www.postgresql.org/docs/18/app-pg-dumpall.html), [physical backup](https://www.postgresql.org/docs/18/app-pgbasebackup.html).
- Published artifacts contain an encrypted manifest/payload and signature; M1 plaintext output is limited to synthetic fixtures. [Artifact contract](../backup-format/manifest-v1.md).
- The signer public key must be trusted independently; a copied artifact's `signer_id` cannot establish trust by itself. Rotation and rollback protection need explicit operations.
- Evidence from [pgBackRest retention](https://pgbackrest.org/user-guide.html), [Barman recovery windows](https://docs.pgbarman.org/release/3.13.1/user_guide/retention_policies.html), and [WAL-G backup protection](https://github.com/wal-g/wal-g/blob/master/docs/PostgreSQL.md) informs retention expectations, but their physical/WAL semantics are not imported into this logical artifact.

## Validation before release

Run the [fixture matrix](../postgres/fixture-plan.md) on 16–18; test least-privilege roles, age interoperability, Ed25519 signature vectors, tampering, truncation, manifest/payload swap, crash recovery, same-major restore, and Debian/Ubuntu package installs. Publish measured throughput and restore times. Revisit this ADR if tests show that custom archive or local-only storage cannot meet an explicit deployment requirement.
