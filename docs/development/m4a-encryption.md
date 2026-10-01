# M4a encrypted store guide

M4a adds **encryption at rest inside the artifact store**. The rule the milestone is built
around is in its acceptance criteria: *plaintext never enters the published store*. A dump is
sealed while it streams, so no process ever writes a plaintext archive that later gets
encrypted, and a read decrypts only into a transient private view that the store removes.

Encryption is a property of the **deployment**, not of a run: a configuration with an
`[encryption]` block writes sealed artifacts, one without it writes the M1 plaintext
artifacts the earlier guides describe. There is deliberately no `--encrypt` or `--no-encrypt`
flag, because a flag is something a schedule forgets.

## Requirements

- Everything the [M1](m1-local-backup.md), [M2](m2-restore-verify.md) and
  [M3](m3-profiles-selective.md) guides require, unchanged.
- Two key files with absolute paths **outside** `[storage] root`, enforced at
  `config check`: the private identity and its public recipient half. See
  [key lifecycle](../security/key-lifecycle.md) for how they are made, published,
  backed up and rotated.
- The payload is sealed with `backupctl`'s own hybrid `mlkem768x25519` age recipient
  (ML-KEM-768 then X25519, per [RFC 10024](https://www.rfc-editor.org/info/rfc10024)) inside
  age's standard authenticated stream. It is therefore **not** decryptable by stock `rage`,
  and a stock-`rage` hybrid file is not decryptable here. The rationale and the measured
  cost are in [post-quantum hybrid](../security/post-quantum-hybrid.md).

## Commands

```text
backupctl --config /absolute/path/to/m4a.toml key generate
backupctl --config /absolute/path/to/m4a.toml key publish
backupctl --config /absolute/path/to/m4a.toml key status
backupctl --config /absolute/path/to/m4a.toml backup create --confirm-synthetic
backupctl --config /absolute/path/to/m4a.toml backup verify BACKUP_UUID --level archive
backupctl --config /absolute/path/to/m4a.toml restore plan BACKUP_UUID --target backupctl_fixture_dr --security dr
backupctl --config /absolute/path/to/m4a.toml restore run PLAN_UUID --confirm-target backupctl_fixture_dr
```

The commands and their output are identical to the earlier milestones apart from the key
block; a whole-database run, a profile run, a section-limited plan and the two security
policies all behave as documented there. `key generate`, `key publish` and `key status` act
only on the configured paths, so a key the store would refuse cannot be produced by typing a
different path at the prompt.

## What changes once `[encryption]` is configured

| | Without `[encryption]` | With `[encryption]` |
|---|---|---|
| Payload files | `payload.dump`, `globals.sql` | `payload.age`, `globals.age` |
| Recorded `format` | `m1-development-plaintext` | `m4a-development-age` |
| `pg_dump`/`pg_dumpall` | writes `--file` into staging | writes to standard output, piped into the age sink |
| Extra manifest fields | — | `recipient_suite = "mlkem768x25519-v0"`, `payload_plaintext_bytes` |
| Reading the payload | opened directly | decrypted into `<storage-root>/scratch/<id>/`, removed on drop and purged at startup |
| An artifact holding both `payload.dump` and `payload.age` | n/a | refused as a store that does not know what it contains |

The sink is the store's decision, so `backup-application` and `backup-postgres` hold no key
material and do no crypto: `backup-local` is the boundary. A stage whose stream was never
finished cannot be published, because a truncated age stream is not a backup.

`payload_plaintext_bytes` exists because the published size no longer tells anyone how much
plaintext to expect: decryption is bounded by it while streaming, so a payload that inflates
past its own manifest is refused rather than allowed to fill the disk.

## What is proven, and by what

| Claim | Evidence |
|---|---|
| No plaintext archive is ever created | `tests/m4a_docker_smoke.sh` wraps every client tool to log each absolute file argument it receives with that file's first five bytes; no dump tool is handed `--file`, and the only archive a restore tool opens in an encrypted store is a PGDMP file under `scratch/` |
| Those greps mean something | The same run repeats them against a keyless store in the same pass, where they *do* find the fixture role name in `globals.sql` |
| The private view cleans up | `a_refused_decryption_leaves_no_scratch_behind`, plus the drill asserting `staging/` and `scratch/` empty after a refused read |
| Tampering fails before restore | bit flip (dies at the digest), truncation (dies at the stream even with a rewritten manifest), payload from another key pair (passes `--level checksum`, dies at decryption) |
| A wrong key leaves nothing behind | The drill deletes a live identity and shows every command through that configuration fails before it reads the store, leaving no partial restore |
| A generation is actually separated | Each configuration refuses the other's artifact at `--level archive` while both sit in one store |
| No secret leaks into output | The 64-character seed of every identity in both runs is grepped out of the store tree, every JSON and every captured stderr |

## Known limitations

1. **Artifacts are not signed.** Integrity is proven, origin is not. Replacing a payload
   with a *different valid artifact sealed to the same recipient* is undetectable by M4a:
   age authenticates a stream, not which of your backups it came from. That is M4b's
   signature, and it is why **no real-data artifact should be published before M4b**.
2. **The manifest is still plaintext JSON.** `manifest.json` sits beside the ciphertext and
   `backup inspect` reads it without any key. It carries the database name, resolved scope,
   timings, client versions, digests and sizes — none of which age has sealed. Encrypting
   the manifest (`manifest.age`, plus a bounded `public.json` for discovery) is part of
   freezing artifact v1 at M4b. See [manifest v1](../backup-format/manifest-v1.md).
3. **Both key files must be present for every command**, including `backup create`. The
   configuration separates the two halves because a write-only host *should* need only the
   recipient, and today it does not get that: the store loads the pair before it touches the
   storage root. Keeping a secret the schedule never uses on the backup host is the cost of
   deferring that port split; it is listed as open work, not as a supported topology.
4. **One key pair per configuration, and no key ID in the manifest.** Which generation a
   backup belongs to is your ledger's job; automated generation tracking belongs to M5's
   catalog. See [key lifecycle](../security/key-lifecycle.md).
5. **No re-encryption.** There is no command that reads a plaintext archive out of one
   generation and seals it into another, because doing so puts plaintext in reach of the
   store that must never hold it. To keep a generation long-term, take a fresh backup under
   the new pair.
6. **Decryption still touches local disk.** The read path writes plaintext into a private
   mode-0700 directory inside the storage root rather than piping it to `pg_restore`,
   because the plan-time tooling needs a seekable archive. An attacker who has already read
   the store at the moment of a restore can read that file too; the milestone narrows the
   window and the cleanup, it does not eliminate plaintext on the restoring host.
7. **Stock-`rage` divergence is a contract, not yet a golden CLI assertion.** It is enforced
   by repository-level tests on the recipient; the CLI-level fixture is still open.
8. **Synthetic fixtures only.** The `backupctl_fixture_*` database-name requirement and
   `--confirm-synthetic` are unchanged; there is no scheduling, catalog, retention, or
   network transport in this CLI.

## Validation

`cargo test --workspace` covers the recipient, the key files, the sink, the refusal of
unfinished streams and the scratch cleanup. `tests/m4a_docker_smoke.sh` and
`tests/m4a_key_drill.sh` both run against PostgreSQL 16, 17 and 18; the drill executes the
key lifecycle document end to end, including an identity the operator supplied themselves.
The M1, M2 and M3 matrices were re-run after the encrypted write path landed.
