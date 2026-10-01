# M4b signed store guide

M4a answered "can somebody who steals my backup drive read it?" M4b answers the other
question: "is the artifact in front of me one that my own backup host published, and has
anything changed since it was written?" It adds two things to an encrypted store:

- the manifest moves **inside** the ciphertext (`manifest.age`), so the database name, the
  resolved scope and the timings are no longer sitting beside the archive in plaintext, and
- a **detached origin signature** (`signature.hybrid`, a hybrid Ed25519 + ML-DSA-65) is written
  over the backup id and the digests of the two ciphertext files, and every reader checks it
  *before* it decrypts or restores anything.

Like encryption, signing is a property of the **deployment**, not of a run: the store writes
what its configuration's blocks say, and there is no `--sign` flag to forget. This guide is the
operator path for that shape. The byte-level contract is
[artifact v1](../backup-format/manifest-v1.md), the decision behind it is
[ADR 0002](../architecture/adr-0002-artifact-v1-and-signing.md), and key custody, rotation and
loss recovery for both pairs is [key lifecycle](../security/key-lifecycle.md).

## Which shape a configuration writes

| Blocks present | Artifact on disk | Recorded format | Signed? |
|---|---|---|---|
| none | `payload.dump` + `globals.sql` + `manifest.json` | `m1-development-plaintext` | no |
| `[encryption]` | `payload.age` + `globals.age` + `manifest.json` | `m4a-development-age` | no |
| `[encryption]` + `[signing]` naming `signing_key_file` | `payload.age` + `globals.age` + `manifest.age` + `public.json` + `signature.hybrid` + `complete` | signed artifact v1 | yes |
| `[encryption]` + `[signing]` naming only `verifying_key_file` | writes nothing | signed artifact v1, read-only | verifies |

`config check` prints the shape rather than leaving you to re-read the TOML:

```text
configuration valid (synthetic-only mode)
active blocks: [encryption] + [signing]; this store writes: signed artifact v1
```

A read-only DR configuration reports the same two lines, because the reported shape comes from
the blocks the file carries. What makes it read-only is the refusal to seal or to sign — see
"The disaster-recovery host" below — not a separate shape name.

A `[signing]` block with no `[encryption]` block is refused at load, because the signature is
made over the ciphertext pair a plaintext store does not have:

```text
error: a [signing] block requires an [encryption] block: the origin signature covers the
ciphertext pair, which a plaintext store does not have
```

## Requirements

- Everything the [M4a guide](m4a-encryption.md) requires, unchanged: PostgreSQL 16–18 client
  tools, an isolated fixture database for synthetic runs, and both age key files.
- A signing pair: `signing_key_file` (mode `0600`, the secret seed) and `verifying_key_file`
  (mode `0644`, the trusted public half). Both absolute, both outside `[storage] root`, both
  refused if the path is already occupied.
- The verifying key is **installed independently of the store**. A verifying key copied out of
  the artifact directory it checks proves nothing; keep it where the writer cannot put a file.
- `[signing]` has a closed field set, so a typo (`signing_key` instead of `signing_key_file`) is
  refused rather than silently ignored: the CLI reports it as `invalid configuration; expected
  M3 TOML fields`, with no field name. Compare the block against
  [m4a.example.toml](../../config/m4a.example.toml), which carries both blocks and the read-only
  host shape.

## Writer commands

```text
backupctl --config /absolute/path/to/m4b.toml key generate
backupctl --config /absolute/path/to/m4b.toml key status
backupctl --config /absolute/path/to/m4b.toml config check
backupctl --config /absolute/path/to/m4b.toml backup create --confirm-synthetic
backupctl --config /absolute/path/to/m4b.toml backup list
backupctl --config /absolute/path/to/m4b.toml backup inspect BACKUP_UUID
backupctl --config /absolute/path/to/m4b.toml backup verify BACKUP_UUID --level signature
backupctl --config /absolute/path/to/m4b.toml backup verify BACKUP_UUID --level checksum
backupctl --config /absolute/path/to/m4b.toml backup verify BACKUP_UUID --level archive
```

`key generate` writes the age pair first and then the signing pair, so one command leaves the
four files a writer needs:

```text
suite: mlkem768x25519-v0
identity: /keys/gen1/identity.key (mode 0600)
recipient: /keys/gen1/recipient.key (mode 0644)
recipient key: fd55a1ed7a12973541e2da1d411477b4… (2432 hex characters, --output json for the full value)
signing: /keys/gen1/signing.key (mode 0600, suite ed25519+ml-dsa-65)
verifying: /keys/gen1/verifying.key (mode 0644, suite ed25519+ml-dsa-65)
signer key: 64f86d92fecfdc27
```

Neither seed is ever printed. `key status` is the command that proves a pair belongs together:
it loads both halves through the same path the store uses, so a signing key from one generation
beside a verifying key from another is reported as an error rather than as a mismatch you find
during a disaster:

```text
error: verifying key file /keys/gen1/verifying.key is not the public half of signing key file
/keys/gen2/signing.key
```

A backup writes the record it just signed, and names the two public fingerprints so the
ledger line can be written from the CLI output:

```text
created signed artifact v1 31bb661b-5b01-4dbc-93fa-ab71bbd51b11
source database: backupctl_fixture_m1
profile: whole-database
payload: 19095 bytes of ciphertext ead395e4…db7448f8, 17285 of archive
sealed: mlkem768x25519-v0 to recipient 90a5853755b55742
signed: ed25519+ml-dsa-65 by signer 64f86d92fecfdc27
security metadata: globals.age (roles and memberships, no password verifiers)
verification: none; the manifest is signed, so later checks are reported by backup verify
rather than written into the artifact
```

## What one artifact is

Six files when cluster metadata is exported, five when `export_globals = false` leaves
`globals.age` out — and the set is exact, because an extra file is a store that does not know
what it holds:

| File | Bytes in a real 17 KB run | What it is |
|---|---|---|
| `payload.age` | 19095 | the `pg_dump -Fc` stream, sealed to the hybrid recipient |
| `globals.age` | 2862 | `pg_dumpall --roles-only --no-role-passwords`, sealed; omitted, with `security metadata: none` in the create report, when `export_globals = false` |
| `manifest.age` | 3507 | the private manifest: scope, timings, client versions, every digest |
| `public.json` | 447 | the discovery record: id, both suite names, both key fingerprints, the two ciphertext sizes and digests. Capped at 4096 bytes |
| `signature.hybrid` | 3373 | the detached signature, always exactly this length (64 + 3309) |
| `complete` | 0 | the publication marker; no marker, no artifact |

All five or six files are written at mode `0600`, including `public.json`, which is public by
content, not by permission. `signature.hybrid` is 3373 bytes because that length is a property of
the signature *type*, not a claim in the header — a shorter file is refused as not-a-signature
rather than sized from what the header says it should be.

`backup inspect` reads the sealed manifest, so it needs the decryption identity. `backup list`
decrypts nothing and reads only each artifact's `public.json`, but it still needs the
configuration's key files to exist: the store loads its keys before it touches the storage root,
which is why a list through a configuration whose key directory is gone fails rather than falling
back to the discovery records.

```text
$ backupctl --config m4b.toml backup list
31bb661b-5b01-4dbc-93fa-ab71bbd51b11  19095 bytes  signed v1 (signer 64f86d92fecfdc27)

$ backupctl --config m4b.toml backup inspect 31bb661b-5b01-4dbc-93fa-ab71bbd51b11
format: signed artifact v1
engine: postgresql major 16
source fingerprint: 34bb996c938f38bf
scope: whole database
payload: 19095 bytes of ciphertext ead395e4…db7448f8, 17285 of archive
globals: 2862 bytes 401ddfac…b3ac5c38
sealed: mlkem768x25519-v0 to recipient 90a5853755b55742, signed: ed25519+ml-dsa-65 by signer 64f86d92fecfdc27
table of contents: 538e7a28…ba3c377e
verification: none
```

## What each verification level is allowed to touch

Levels are ascending: each one includes the checks of the one above it.

| Level | Reads | Runs a PostgreSQL tool | Needs |
|---|---|---|---|
| `signature` | `public.json`, both ciphertext files (hashed), `signature.hybrid` | no | the verifying key |
| `checksum` | the above, then decrypts `manifest.age` | no | verifying key + decryption identity |
| `archive` | the above, then decrypts `payload.age` into `scratch/` and parses its table of contents | yes (`pg_restore --list`) | the above plus the client tools |

```text
artifact 31bb661b-5b01-4dbc-93fa-ab71bbd51b11 verified at level signature
payload: 19095 bytes ead395e4…db7448f8
origin: ed25519+ml-dsa-65 signature by signer 64f86d92fecfdc27, sealed to recipient 90a5853755b55742
nothing was decrypted to produce this report
```

That last line is the level's meaning, not a caveat: at `signature` the globals digest is not in
the report because it lives inside `manifest.age`, and a reader that decrypts nothing cannot
state it. `checksum` adds the `globals:` line; `archive` adds no line of its own, because what it
proves is that the decrypted archive parses and its table of contents still matches the digest
the manifest recorded **at write time**. A signed manifest cannot learn a fact later, which is
why the archive level compares against that recorded digest and refuses an artifact that
recorded none.

Asking for `signature` on a store that never signed anything is refused instead of passing
vacuously:

```text
error: this store's artifacts carry no origin signature, so signature level has nothing to
verify; use --level checksum or --level archive, or configure [signing] before writing artifacts
```

## The disaster-recovery host

A DR box configures `[encryption]` and a `[signing]` block with **only** the verifying half:

```toml
[encryption]
identity_file = "/keys/gen1/identity.key"
recipient_file = "/keys/gen1/recipient.key"

[signing]
verifying_key_file = "/keys/gen1/verifying.key"
```

The result is a shape rather than a flag, and it is provable from the outside: the host has no
signing secret to be talked into using.

```text
backupctl --config /absolute/path/to/dr.toml backup create --confirm-synthetic
error: this store holds no recipient file, so it cannot seal a new dump

backupctl --config /absolute/path/to/dr.toml key generate
error: this [signing] block configures no signing_key_file, so this host may verify but not
produce a signing key; copy the verifying file here instead of generating
```

That second refusal happens **after** the age pair has been written, so a mis-run generate on a
DR host leaves an identity and a recipient behind and no signing secret — check both halves of
that outcome rather than assuming the command failed cleanly.

What the DR host can do is the whole restore path. Its `key status` reports one signing row, and
that single row is the claim:

```text
verifying: /keys/gen1/verifying.key (mode 0644, suite ed25519+ml-dsa-65)
signer key: 64f86d92fecfdc27
```

```text
backupctl --config /absolute/path/to/dr.toml backup verify BACKUP_UUID --level signature
backupctl --config /absolute/path/to/dr.toml restore plan BACKUP_UUID --target backupctl_fixture_dr --security portable
backupctl --config /absolute/path/to/dr.toml restore run PLAN_UUID --confirm-target backupctl_fixture_dr
```

The signature-level report is byte-for-byte what the writer printed, with no secret on this
host. `restore plan` performs the same authentication before it binds a target, so a forged
artifact stops at planning and no database is created behind it. The run then says:

```text
restored 31bb661b-5b01-4dbc-93fa-ab71bbd51b11 into backupctl_fixture_m4b_port
verification level: none
note: this run did not change what the artifact itself records about verification
```

That note is the design, not a gap. Raising the level the artifact records would mean re-signing
it, and a DR host that signed someone else's backup would be attributing it to itself. The
restore is proven by the run; the artifact cannot carry the fact.

A DR host needs the **identity** file for every command, including `--level signature`, because
the store loads it before it touches the storage root. It does not need the recipient file to
verify or restore: a verify-only store never opens it, and a run with that file moved away
verifies normally. `key status` is the one command that does read it.

`--security dr` still requires a cluster that does not already have those roles; against the
cluster the backup came from it refuses first:

```text
error: DR role restore refused: these roles already exist in the cluster:
backupctl_fixture_alice, backupctl_fixture_bob, backupctl_fixture_reporting, postgres; use the
portable policy or remove them first
```

## What tampering looks like from the CLI

Each of these was run against a real artifact in a real store on 2026-10-01. The refusal names
the check that caught it, which is the point: a parse error would tell you nothing about the
attack.

| What changed | What the CLI says | Caught by |
|---|---|---|
| `payload.age` replaced with another artifact's ciphertext, `public.json` rewritten to describe it exactly | `origin signature of artifact … does not verify` / `ed25519 signature check failed: this artifact was not written by the holder of the configured signing key, or its contents changed` | the signature. This is the swap M4a documented as undetectable |
| `public.json` lies about the payload digest while the file stays intact | `payload.age is not the ciphertext public.json describes: 19095 bytes digesting ead395e4…` | the digest recomputed from disk, one step before the signature |
| `signature.hybrid` truncated by one byte | `ed25519+ml-dsa-65 signature must be exactly 3373 bytes (64 + 3309), got 3372` | the fixed signature length |
| `complete` marker deleted | `No such file or directory (os error 2)` | the marker; see the message gap below |
| An artifact signed by a different key pair, copied into the store | `origin signature of artifact … does not verify` | the trusted verifying key |
| `public.json` naming a different backup id | `public.json records backup id …, found under directory …` | the directory name as the identity |
| An unknown field, an oversized `public.json`, or `format_version: 2` | `invalid public.json: unknown field surprise, expected one of …`, `public.json is 4097 bytes, over the 4096 byte cap`, `unknown public.json format version 2, this build writes 1` | the bounded parser, before any crypto |
| One byte flipped inside `manifest.age` | `manifest.age is not the ciphertext public.json describes: …` | the signature: the manifest digest is inside the signed tuple |

A reader that holds the signing secret is not stopped by any of this, and an attacker who holds
both the recipient and the identity can seal a fresh artifact of their own — what they cannot do
is make it carry *your* signer id. Origin rests on the custody of the signing key; see
[key lifecycle](../security/key-lifecycle.md) and the [threat model](../security/threat-model.md).

## Two limits this shape ships with

1. **The signature does not cover `public.json`'s own claims.** It is made over the backup id
   and the two ciphertext digests, so the suite names and key fingerprints in the discovery
   record are not authenticated by it. Downgrading the claim in a real artifact passes signature
   level and is caught one step later:

   ```text
   backupctl --config m4b.toml backup verify BACKUP_UUID --level signature
   artifact 31bb661b-… verified at level signature
   origin: ed25519 signature by signer 64f86d92fecfdc27, sealed to recipient 90a5853755b55742
   nothing was decrypted to produce this report

   backupctl --config m4b.toml backup verify BACKUP_UUID --level checksum
   error: public header and manifest disagree on signature_suite
   ```

   Read the other way round, the signed manifest is the record a reader trusts, and `public.json`
   is an index into it. Fixing the downgrade properly means moving those fields into the signed
   tuple, which is a **v2 format change**, not a patch. `restore plan` and every level from
   `checksum` up do read the signed manifest, so the lie never reaches a restore. The matrix
   asserts the signature-level *pass* on purpose (case 6.11 in
   [tests/m4b_docker_smoke.sh](../../tests/m4b_docker_smoke.sh)).
2. **Some refusals are bare OS errors.** A missing `complete` marker or a missing key file is
   refused before any crypto work, but reports `No such file or directory (os error 2)` with no
   mention of the marker. The refusal is correct; the sentence around it is not yet operator-useful.

## Known limitations

1. **A signed store can list what it cannot read.** An unsigned M4a artifact sitting in the same
   directory tree is named honestly by `backup list` and then refuses every read through the
   signed configuration:

   ```text
   6a9100a4-fe67-467b-b687-be4f35e841b0  unsigned development artifact; no record without keys
   ```

   `backup verify` and `backup inspect` on it both fail with `No such file or directory
   (os error 2)` — the signed reader is looking for the `public.json` that shape does not have.
   The other direction refuses with a sentence naming the mismatch: an `[encryption]`-only
   configuration reports `artifact … is a signed v1 artifact; the signed reader does, not the
   manifest.json reader`, for `backup list` as well as for `backup verify`. Read a mixed store
   through the configuration that matches each artifact. This asymmetry was observed by hand on
   2026-10-01 and is **not** in the matrix; automatic mixed-store reads are M5's catalog.
2. **Nothing protects you from an older valid artifact.** Replay and rollback detection need an
   inventory that knows which artifact was newest, which is M5. A local v1 store also has no
   second copy: host loss takes the backups with it. Threat model T03 stays open.
3. **`--confirm-synthetic` is still required on every write**, including a fully signed store.
   The guard is about this build's certification, not about the format: the signed shape is the
   one intended for real data, and no release-grade certification has run on it yet.
4. **No key-generation tracking.** A v1 artifact records `recipient_id` and `signer_id`, so the
   generation is visible in the bytes, but nothing in the CLI tells you which key directory
   holds the halves for a given artifact. That mapping is your ledger until M5.
5. **One pair per configuration, no re-encryption, no re-signing.** An artifact is written once
   and never rewritten; changing either pair means a new generation and a fresh backup.
6. **`source_fingerprint` binds engine, major, host, port and database.** A signed artifact can
   only be planned and restored by a configuration naming the address it was dumped from:

   ```text
   error: this artifact was dumped from a different source than the configured one: the signed
   manifest records fingerprint 34bb996c938f38bf while 8d86e527ec18caf0 describes the current
   configuration. Refusing to plan a restore whose archive does not belong to this server and
   database
   ```

   That check runs before the target database exists, so the refusal leaves nothing behind. When
   you move a database to a new host, the plan refuses by design: restore into the new address
   from a backup taken there.
7. **Verification level never rises inside a signed artifact.** It stays `none` in every v1
   manifest by design; `backup verify` and `restore run` report the truth at the moment they run.
8. **Hybrid age streams are not `rage`'s.** Stock `rage` refuses `payload.age`, and a
   stock-`rage`-encrypted file is refused here. The refusal is a tested contract, asserted at CLI
   level in the M4b run.

## Validation

[tests/m4b_docker_smoke.sh](../../tests/m4b_docker_smoke.sh) runs this guide against real
`pg_dump`, `pg_dumpall`, `pg_restore` and `psql` on PostgreSQL 16, 17 and 18: four key files and
the refusals that keep them apart, a v1 write whose six files and 3373-byte signature are
checked exactly, all three levels with their permitted reach asserted through wrapped client
tools (signature and checksum levels invoke no tool and leave `scratch/` empty), the
stock-`rage` refusal, twelve tampered variants, a foreign-key artifact, an operator-supplied
signing seed, and a DR restore from a host configured with a verifying key and no signing
secret. [tests/m4a_key_drill.sh](../../tests/m4a_key_drill.sh) runs the signing half of the key
lifecycle. Every command and every refusal quoted in this guide was also run by hand on
2026-10-01 against PostgreSQL 16 — the three levels, the DR host's refusal to write and its
restore, each tampering row, a five-file artifact written with `export_globals = false`, and
both directions of a mixed signed/unsigned store; the seed of every key file in that run
appeared in no command output and no stored byte.
