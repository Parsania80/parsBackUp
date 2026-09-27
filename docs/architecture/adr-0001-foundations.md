# ADR 0001: Initial backup platform boundaries

Status: accepted for M0 design; artifact field layout is provisional until the M4a/M4b tests, and the hybrid container question below is explicitly open. Date: 2026-09-26; post-quantum hybrid revision 2026-09-27. Scope: first PostgreSQL logical-backup release. Supersede this ADR explicitly if experiments change a decision.

## Context

The platform needs trustworthy single-database backup and restore before adding remote storage, an HTTP API, or physical/WAL recovery. PostgreSQL already provides maintained logical dump/restore tooling. The first deployment is one Debian/Ubuntu service host. Security requires confidentiality and origin verification because database dumps may contain credentials and an age public recipient does not authenticate the sender. Because backups are kept for years, an adversary who copies an artifact today can try to decrypt it later, so the confidentiality decision is made against a harvest-now-decrypt-later attacker rather than only against today's primitives.

## Options and decisions

| Decision | Options considered | Benefits / drawbacks | Chosen |
| --- | --- | --- | --- |
| Data movement | Native CLI; client-library catalog extraction; custom dump engine | CLI has mature format/TOC and version semantics but needs process supervision. Library extraction still lacks a complete backup implementation. Custom engine has unacceptable correctness burden. | Native `pg_dump`/`pg_restore` with fixed binary paths. |
| Archive | Custom, directory, tar, plain SQL | Custom is one file with TOC/parallel restore but no parallel dump. Directory supports parallel dump but complicates atomic artifact transport. Tar/plain lose useful flexibility. | Custom first; benchmark directory later. |
| Deployment shape | Modular monolith; microservices | Monolith shares business logic and simplifies local jobs; microservices add distributed failure modes without current need. | Modular Rust monolith. |
| Catalog | SQLite; PostgreSQL | SQLite avoids dependency on a database being protected but is single-host. PostgreSQL aids scale but creates bootstrap/dependency concerns. | SQLite at M5, rebuildable from artifacts. |
| Store | Local; S3/MinIO; SFTP | Local is simple and atomic on one filesystem but cannot survive host loss. Remote needs multipart/consistency behavior. | Local first, no host-loss claim. |
| Encryption | Age X25519 alone; age with a hybrid classical + post-quantum recipient; bespoke chunked AEAD; PQ-only (ML-KEM alone); no encryption | Age has a documented interoperable streaming format. X25519 alone falls to a future discrete-log break on a long-lived artifact. PQ alone trusts one young primitive. Bespoke framing increases crypto risk; no encryption is unacceptable for real data. | Hybrid recipient: X25519 **and** ML-KEM-768 combined per [RFC 10024](https://www.rfc-editor.org/info/rfc10024/), carried by age's streaming format. Synthetic-only output before M4a. |
| Origin | Age alone; keyed MAC; Ed25519 signature; Ed25519 + ML-DSA-65 | Age authenticates ciphertext integrity but public recipients permit anyone to encrypt. MAC requires a shared secret to verify. A signature allows verification with an independently trusted public key but needs signing-key operations. Ed25519 alone has the same long-lived-break problem as X25519 alone. | Detached hybrid Ed25519 + ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) signature over ID and both ciphertext hashes. |
| Scheduling | systemd timer; cron; internal scheduler | systemd fits Debian service lifecycle; cron lacks integrated service state; internal scheduler adds restart/leader complexity. | systemd timer first. |
| Restore target | Existing in-place; fresh database | In-place is convenient but can destroy production; fresh target needs storage and an explicit cutover. | Fresh database by default. |

## Consequences

- The first supported server majors are 16–18; matching source-major client binaries and same-major restore are required until pairwise tests expand the matrix. [Version policy](https://www.postgresql.org/support/versioning/), [`pg_dump` compatibility](https://www.postgresql.org/docs/18/app-pgdump.html).
- `pg_dumpall` globals, subscriptions, WAL, physical backups, and OS/application files remain separate mechanisms or manual prerequisites. [`pg_dumpall`](https://www.postgresql.org/docs/18/app-pg-dumpall.html), [physical backup](https://www.postgresql.org/docs/18/app-pgbasebackup.html).
- Published artifacts contain an encrypted manifest/payload and signature; M1 plaintext output is limited to synthetic fixtures. [Artifact contract](../backup-format/manifest-v1.md).
- The signer public key must be trusted independently; a copied artifact's `signer_id` cannot establish trust by itself. Rotation and rollback protection need explicit operations.
- Both halves of the hybrid recipient live in one identity file, so key size, file layout, and the recovery procedure are defined per suite rather than assumed from age's X25519-only identities. The signing key is a second, distinct hybrid key pair.
- Every artifact records its `recipient_suite` and `signature_suite`, and a reader refuses a suite outside its accepted list. Suite migration is rotation into a new artifact generation, never an in-place rewrite.
- Evidence from [pgBackRest retention](https://pgbackrest.org/user-guide.html), [Barman recovery windows](https://docs.pgbarman.org/release/3.13.1/user_guide/retention_policies.html), and [WAL-G backup protection](https://github.com/wal-g/wal-g/blob/master/docs/PostgreSQL.md) informs retention expectations, but their physical/WAL semantics are not imported into this logical artifact.

## Open: the age hybrid container (decided by the M4a spike, not by this ADR)

The upstream [`age` crate](https://docs.rs/age/latest/age/) exposes a hybrid post-quantum recipient type (`tagpq`, built on [`ml-kem`](https://docs.rs/ml-kem) plus `x25519-dalek`), but it is documented for hardware-backed keys, so whether it works with a plain software file identity is unproven. M4a must spike exactly that: encrypt with the crate, decrypt with the crate, then decrypt with the stock `rage`/`age` CLI, and record whether a plugin or hardware key is required.

| Outcome | Consequence |
| --- | --- |
| `tagpq` works with a software identity | Keep the standard `age-encryption.org/v1` container; prove CLI interoperability and make it a test. |
| It requires a plugin or hardware key | Wrap the per-artifact data key with the hybrid KEM (X25519 + ML-KEM-768, per RFC 10024) inside a thin envelope, then feed age's own authenticated stream; document explicitly that the artifact is no longer stock-age-decryptable. |

Neither outcome permits hand-rolled AEAD framing or a third-party unaudited PQ file-encryption container. Record the result and the chosen container here when the spike completes.

## Validation before release

Run the [fixture matrix](../postgres/fixture-plan.md) on 16–18; test least-privilege roles, age interoperability or the documented divergence from it, hybrid recipient round trip, Ed25519 and ML-DSA-65 signature vectors, suite-downgrade refusal, tampering, truncation, manifest/payload swap, crash recovery, same-major restore, and Debian/Ubuntu package installs. Publish measured throughput and restore times, and measure the size and time cost the post-quantum halves add. Revisit this ADR if tests show that custom archive or local-only storage cannot meet an explicit deployment requirement, or if a maintained implementation for any chosen primitive disappears.
