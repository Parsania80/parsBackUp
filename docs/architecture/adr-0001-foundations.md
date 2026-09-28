# ADR 0001: Initial backup platform boundaries

Status: accepted for M0 design; the hybrid container question is **closed** by the M4a spike recorded below. Artifact field layout stays provisional only until the M4b signature and failure tests. Date: 2026-09-26; post-quantum hybrid revision 2026-09-27; container decision 2026-09-27. Scope: first PostgreSQL logical-backup release. Supersede this ADR explicitly if experiments change a decision.

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
| Encryption | Age X25519 alone; age's native hybrid PQ recipient; PQ-only (ML-KEM alone); bespoke chunked AEAD; no encryption | Age has a documented interoperable streaming format. X25519 alone falls to a future discrete-log break on a long-lived artifact. PQ alone trusts one young primitive. Bespoke framing increases crypto risk; no encryption is unacceptable for real data. | Hybrid recipient carried by age's stream: our own `age::Recipient`/`age::Identity` type, stanza tag `mlkem768x25519`, combining **ML-KEM-768 first then X25519** per [RFC 10024](https://www.rfc-editor.org/info/rfc10024/)'s ordering rule. Decided by the M4a spike below; not stock-`rage`-decryptable. Synthetic-only output before M4a. |
| Hybrid construction | age's native `tagpq` (ML-KEM-768 + P-256); X-Wing via `x-wing` 0.1.0; our own RFC 10024-ordered X25519 + ML-KEM-768; RFC 10024 `SecP256r1MLKEM768` | `tagpq` is the only maintained PQ recipient in age but proved hardware-key-only. X-Wing has the best size and deployment story but is an unaudited individual draft. No IANA-registered HPKE X25519+ML-KEM id exists, so any X25519 choice means writing our own combiner. P-256 is a valid standard curve, rejected by the operator in favor of the curve age itself uses. | Our own X25519 + ML-KEM-768 combiner inside age's standard authenticated stream; no new third-party crypto dependency and no custom AEAD framing. See the spike evidence and the deviations that must be documented. |
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
- Interoperability with the `age`/`rage` ecosystem ends at the stream format: the container is a real age file, but the stanza tag and key encoding are ours, so only `backupctl` can decrypt a v1 artifact. Any future claim of age compatibility needs a registered recipient type and Bech32 keys, which is an explicit v2 decision rather than a refactor.
- The hybrid recipient reports no age `postquantum` label, so age itself will happily mix it with a classical-only recipient. The writer must reject that: one hybrid recipient stanza per artifact, no classical-only second recipient for the same file key. Age's mandatory `*-grease` stanza is not a recipient and is tolerated on both sides.
- Evidence from [pgBackRest retention](https://pgbackrest.org/user-guide.html), [Barman recovery windows](https://docs.pgbarman.org/release/3.13.1/user_guide/retention_policies.html), and [WAL-G backup protection](https://github.com/wal-g/wal-g/blob/master/docs/PostgreSQL.md) informs retention expectations, but their physical/WAL semantics are not imported into this logical artifact.

## Decided by the M4a spike: our own hybrid age recipient, not age's native `tagpq`

The spike ran on 2026-09-27 against `age` 0.12.1 and stock `rage` 0.12.1 in throwaway trees under `/tmp` (`/tmp/m4a-spike`, `/tmp/m4a-probe`, `/tmp/m4a-hybrid`). No repository code was modified. Two questions had to be answered before M4a could be planned: is age's native post-quantum recipient usable with a software key, and if not what carries the hybrid KEM.

**Question 1: age's native `tagpq` is encrypt-only. Unusable.**

| Probe | Result |
| --- | --- |
| `tagpq::Identity` exists | `error[E0433]: cannot find type Identity in module tagpq` |
| software key generation for `tagpq` | `no associated function or constant named generate found for struct age::tagpq::Recipient` |
| `Recipient` usable as an identity | `the trait bound age::tagpq::Recipient: age::Identity is not satisfied` |
| crate round trip, seeded from age's own public test recipient, decrypting with an `x25519::Identity` | `software decrypt failed: No matching keys found` |
| stock `rage -d` on a `tagpq` file that `rage -r` had just encrypted | `Error: No matching keys found`, exit 1 |
| mixing `tagpq` with X25519 in one file | `Cannot encrypt to a recipient with labels '⁨postquantum⁩' alongside a recipient with no labels` |

`tagpq` is therefore a hardware-key/plugin recipient (`AGE-PLUGIN-…` territory), and the roadmap option "age native PQ if it works" is closed. The control test that proves the harness is honest: a normal X25519 age file encrypted by the spike decrypted by stock `rage -d` to the exact expected SHA-256 (`fdee619e…fbf8`), so the `tagpq` failures above are the recipient type, not the test.

**Question 2: the container is our own `age::Recipient` / `age::Identity` implementation.** The `age` crate documents `Identity` as its extension joint and re-exports `age_core::primitives::{hpke_seal, hpke_open}` generic over any `hpke::Kem`. So a custom recipient can wrap the standard 16-byte age file key with a hybrid KEM and still be carried by age's real `age-encryption.org/v1` stream — age's own header MAC, chunked AEAD and truncation detection stay intact. No bespoke envelope, no custom AEAD framing.

A first pass at this design targeted age's `tagpq` shape (ML-KEM-768 + P-256, IANA HPKE id `0x0050`). The operator preferred the curve age itself uses, so X25519 became the classical half. That forced a check of the HPKE registry: no X25519 + ML-KEM KEM is registered (`0x0020` X25519, `0x0041` ML-KEM-768, `0x0050` MLKEM768-P256, `0x0051` MLKEM1024-P384, `0x647A` X-Wing), so with X25519 the construction is unavoidably ours. X-Wing via the RustCrypto `x-wing` 0.1.0 crate was considered and rejected: `draft-connolly-cfrg-xwing-kem-11` is an individual submission with no working-group adoption, was revised four days before the decision, has no third-party audit, and its README says "USE AT YOUR OWN RISK". RFC 10024 (standards-track, August 2026) defines the `X25519MLKEM768` ordering we follow instead.

| Measured (release build, 8 MiB synthetic payload) | Hybrid `mlkem768x25519` | X25519 baseline (debug build) |
| --- | --- | --- |
| Ciphertext size | 8,392,405 B | 8,390,913 B |
| Per-file overhead | 3,797 B | 2,305 B |
| Throughput | 585.0 MiB/s encrypt, 592.6 MiB/s decrypt | 4.2 / 3.9 MiB/s (debug build; not comparable) |
| Round trip | byte-exact | byte-exact |
| Recipient string | 2432 hex chars | 46 chars (`age1…`) |

Overhead scales as ≈1.7 KB fixed plus 16 B per 64 KiB age chunk (a 64 MiB file measured 18,112 B). The fixed part is dominated by the 1,120-byte encapsulated key in the header stanza, and the measured tagpq overhead of 3,862 B confirms the cost is the same shape for age's own PQ recipient. This is negligible for a database dump and needs no mitigation.

Fail-closed behavior, all observed verbatim: flipped byte in the stanza body → `Header MAC is invalid`; flipped byte in the payload → `decryption error`; truncated file → `decryption error`; wrong hybrid identity → `Header MAC is invalid`. Three unit tests cover deterministic seed expansion, exact 1216/1120-byte serialization with rejection of ±1-byte inputs, and HPKE seal/open failure under a foreign key.

Interoperability does not exist in either direction, and that is now a documented product boundary rather than a bug to fix. Stock `rage` cannot even load our key material — verbatim `Error: identity file contains non-identity data on line 1` for the identity file and `Error: Recipients file 'hybrid-recipient.txt' contains non-recipient data on line 1.` — and it has no handler for a stanza tag of `mlkem768x25519`, so a v1 artifact is readable by `backupctl` alone. `rage` stays useful as an independent oracle for the plain X25519 suite, which is why that suite remains in the reader's accepted list for development output.

**The one property the spike found that we must legislate against:** our recipient reports an *empty* age label set (deliberately, so we do not borrow age's `postquantum` promise), which means `Encryptor` accepts `[x25519, hybrid]` in one header — two stanzas, one file key, and either identity decrypts alone. Verified working. That is exactly a classical-only escape hatch: an operator who adds a recovery X25519 recipient silently re-exposes the artifact to a classical-only break. The availability temptation is real, so the rule is in [threat model](../security/threat-model.md) invariants and enforced by the writer: **one hybrid recipient stanza per artifact; a second, classical-only recipient for the same file key is rejected at write time.** Recovery of the hybrid identity, not a parallel classical recipient, is the answer to lost keys (T10).

**A second spike finding that narrowed that rule during implementation:** `HeaderV1::new` appends a random `*-grease` stanza to every age header it writes unless the header holds an scrypt recipient, which ours never does. Taking "exactly one stanza" literally therefore made the crate unable to read its own artifacts — the very first round-trip test failed with `Header is invalid`. The enforced rule is *exactly one recipient stanza*: the `mlkem768x25519` one, plus at most age's grease stanza, identified by a `-grease` tag suffix whose tag and arguments are all printable-ASCII arbitrary strings, with every other tag refused outright. The tolerance is provably safe: a stanza whose tag merely *looks* like a disguised classical recipient (`X25519-grease`) is still unreadable by age's own `x25519::Identity`, which is asserted rather than assumed.

## Spike review findings (corrections carried into the M4a implementation)

The stage-2 code is throwaway; these points are requirements for the real module, not defects to fix in `/tmp`.

- The combiner is **not** byte-identical to RFC 10024. It follows RFC 10024's ordering rule (ML-KEM shared secret first) but uses HKDF-SHA256-Extract with a versioned non-zero salt `backupctl-MLKEM768-X25519-v0` over `ss_pq ‖ ss_x ‖ ct_x ‖ pk_x`, binding both X25519 public keys into the transcript — age's own `tagpq` combiner does the equivalent with SHA3-256. RFC 9180's generic hybrid combiner is `Extract(salt = 0, ss_1 ‖ ss_2)`. Because no external tool can parse our stanza anyway, standards-byte-compatibility buys nothing here, but the deviation must be stated in the format document rather than described as "per RFC 10024" without qualification.
- `KEM_ID 0x00FF` is a local value only. RFC 9180 defines **no** private-use or experimental range for KEM IDs; `0x0000` is reserved and the rest are IANA-assigned. The `hpke` crate never transmits this identifier — it feeds only our labeled `SHAKE256` key-derivation domain separator. The spike comment calling it a "reserved/private range" is wrong and must not be copied forward.
- The spike comment claiming age rejects known low-order X25519 points at the stanza layer is wrong: `age` 0.12.1 contains no small-order check. Our KEM accepts any 32-byte ephemeral window, which is safe *here* only because a hostile `ct_x` cannot zero out the ML-KEM half of the combined secret and the AEAD tag gates the result. Keep the transcript binding; do not present it as curve validation.
- The 32-byte identity seed is not zeroized on drop, and the base-mode restrictions are `assert!` rather than typed impossibility. M4a must use a zeroizing wrapper for the seed and make authenticated-mode absence a compile-time property (newtype with no sender-key parameter), not a runtime assert.
- ML-KEM's implicit rejection is load-bearing and correct: a forged PQ ciphertext yields a pseudorandom `ss_pq`, which the HPKE ChaCha20-Poly1305 tag then rejects. There is no decryption oracle and no need to add a PQ-level validity check.

## Validation before release

Run the [fixture matrix](../postgres/fixture-plan.md) on 16–18; test least-privilege roles, hybrid recipient round trip and the stock-`rage` divergence recorded above as golden assertions, refusal of a classical-only second recipient stanza, Ed25519 and ML-DSA-65 signature vectors, suite-downgrade refusal, tampering, truncation, manifest/payload swap, crash recovery, same-major restore, and Debian/Ubuntu package installs. The spike already covers round trip, ±1-byte key-length rejection, stanza/payload tampering, truncation, wrong identity, and the mixed-recipient hazard; M4a must re-implement those as repository tests plus seed zeroization and authenticated-mode absence. Publish measured throughput and restore times, and re-measure the size and time cost the post-quantum halves add on real dumps. Revisit this ADR if tests show that custom archive or local-only storage cannot meet an explicit deployment requirement, or if a maintained implementation for any chosen primitive disappears.
