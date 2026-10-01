# Key lifecycle for encrypted artifacts

Scope: the `mlkem768x25519-v0` hybrid age identity that opens an `m4a-development-age`
artifact. Encryption is a property of a store: it is on when the configuration carries an
`[encryption]` block and off when it does not, with no per-run flag to forget. See the
[example config](../../config/m4a.example.toml) for the shape and
[the threat model](threat-model.md) for why both hybrid halves must be retained.

## The unit is a generation

A **generation** is one key pair and one configuration, plus every artifact written under
that pair. Nothing in `backupctl` rotates a key in place, and that is deliberate:

- `key generate` writes into the two configured paths and **refuses an occupied path before
  writing either half**, so a rotation cannot quietly overwrite the identity that today's
  backups need. A new generation means a new key directory.
- The store loads exactly one pair, and it loads it before touching the storage root. So a
  generation is also the thing a configuration selects: with a new pair in place, older
  artifacts are not "still readable by accident", they are readable only through the older
  configuration.
- The recipient is recorded per artifact only as a suite name. There is no key ID in the
  manifest yet, so **which generation a backup belongs to is your ledger's job**, and
  recovering a backup starts with knowing which configuration opens it.

Consequence to accept before rotating: an artifact's readability lasts exactly as long as
somebody keeps that generation's identity file. Retire nothing you have not re-dumped.

## Where the files live

Both paths must be absolute and outside `[storage] root` — an encrypted archive in a
directory that also holds the identity that opens it is a plaintext archive with extra
steps. `config check` and `key generate` both refuse otherwise. The identity is written at
mode `0600`, its public recipient half at `0644`, and each must be a regular non-symlink
file owned by the service account, in a directory no other local user can write.

The two halves are configured separately because a host that may only write backups needs
only `recipient_file` to seal an artifact to. That split is not yet enforced: the store loads
the pair before it touches the storage root, so today `backup create` fails on a host holding
only the recipient. Keep both files on any host that runs the CLI until that port split
lands; the separation is what it will be built on.

## The ledger

One line per generation, kept somewhere the storage host's compromise does not reach it:

| Field | Where it comes from |
|---|---|
| generation name and date | yours |
| configuration file path | the file whose `[encryption]` block names this pair |
| identity file path, and the offline copy's location | `backupctl --config gen.toml key status --output json` → `identity.path` |
| recipient fingerprint | `key status` prints 32 characters; `--output json` carries the full 2432 |
| suite | `key status` reports `mlkem768x25519-v0`; a manifest must agree |
| artifact IDs written under it | `backup list`, or the `id` each `backup create` returns |

The recipient and its fingerprint are public. The identity file and its offline copy are the
only secret material in this table's reach, and they are never printed by any command: the
64-character seed appears in no CLI output, in no log line, and in no stored byte. Confirm
that for yourself with `key status --output json | grep -f <(sed -n 2p identity.key)` — no
match is the expected result.

## Procedure: take the offline copy first

Do this before the first backup of a generation, not before the first restore attempt.

```text
install -d -m 700 /secure/offline/gen1
cp -p /var/lib/backupctl-keys/gen1/identity.key /secure/offline/gen1/
cp -p /var/lib/backupctl-keys/gen1/recipient.key /secure/offline/gen1/
```

`-p` matters: a copy that arrives world-readable is refused on the way back in, so the mode
is part of the recovery rather than a detail of it. Keep at least two offline copies of
every generation's identity, on media that stay out of the hands of whoever can read the
artifact store. Treat this copy as the recovery path, because it is the only one: age gives
no backdoor, and adding a classical-only second recipient as a safety net would cancel the
post-quantum property the hybrid exists to provide.

## Procedure: rotate to a new generation

1. Confirm the offline copy from the section above exists and is readable only by the
   service account.
2. Copy the configuration and change only the two `[encryption]` paths to a fresh
   directory, e.g. `keys/gen2`. `key generate` and `key status` act on those paths and
   nothing else, so the new file is what makes the new generation.
3. Generate and confirm:

   ```text
   backupctl --config gen2.toml key generate
   backupctl --config gen2.toml --output json key status
   ```

   `key generate` creates a missing parent directory at mode `0700`. Compare the reported
   recipient with the previous generation's in the ledger: two generations with the same
   recipient means one of the two configurations was edited wrong.
4. Take a backup and verify it at `--level archive`. The manifest must record
   `format = "m4a-development-age"` and `recipient_suite = "mlkem768x25519-v0"`.
5. Prove the generations are actually separated, which costs one command each way:

   ```text
   backupctl --config gen2.toml backup verify OLD_ARTIFACT --level archive   # must refuse
   backupctl --config gen1.toml backup verify NEW_ARTIFACT --level archive   # must refuse
   ```

   Both artifacts sit in the same store and both are well-formed age streams; the refusal
   is decryption failing to find a matching identity, not a damaged file.
6. Point the schedule at `gen2.toml`, and mark `gen1.toml` in the ledger as read-only: it
   exists from now on to restore, never to write.

Old artifacts are **not** re-encrypted into the new generation. There is no command that
reads a plaintext archive out of one generation and seals it into another, because doing so
would put plaintext in reach of the store that is supposed to never hold it. If a generation
is one you want to keep long-term, take a fresh backup under the new pair instead.

## Procedure: restore a backup taken under an older generation

Use that generation's configuration:

```text
backupctl --config gen1.toml restore plan ARTIFACT --target backupctl_dr --security dr
backupctl --config gen1.toml restore run PLAN --confirm-target backupctl_dr
```

If the live key directory is gone, do not "fix" the configuration by deleting history. Make
a recovery configuration that is a copy of the old one with `identity_file` and
`recipient_file` pointed at the offline copy, restore the artifact, then remove the
recovery file. A restore reads the archive into the store's transient `scratch/` view and
nothing else, so the decrypted plaintext never lands beside the artifacts.

Two rejections you will see if the copy was handled carelessly, both by design:

- `identity key file … must be mode 0600 or stricter, not 0644` — `chmod 600` it.
- `identity key file … must be a regular non-symlink file` — a symlinked recovery mount is
  refused; copy the file instead.

## Procedure: a key file is lost

**One copy lost, the other present.** Every command through the affected configuration
fails before it reads the store, because the pair is loaded first, including `backup list`
and `backup inspect`:

```text
inspect identity key file /var/lib/backupctl-keys/gen1/identity.key: No such file or directory
```

That failure writes nothing and leaves nothing behind: no `scratch/` content, no partial
restore, no plaintext. Recover by copying the offline identity back with mode `0600`,
running `key status` to confirm the pair agrees again, and re-running the verification that
was interrupted.

**Every copy lost.** The artifacts are not corrupted and not lost — they are inert. The
ciphertext still hashes to what its manifest recorded, and nothing can read it. There is no
recovery procedure to write for this case, and the honest answer is a decision: declare the
generation lost, record that in the ledger, and keep or delete the bytes accordingly. If a
rotation ever appears to have made a backup unreadable, that is almost always the
configuration, not the key — check which generation the artifact belongs to before deleting
anything.

## Using an identity you did not generate

The store does not care where the key came from: an identity file you wrote yourself is
loaded under the same rules as one `key generate` wrote, and a seed derived from your own
secret, a passphrase, or an HSM is a valid identity as far as decryption is concerned.

Publishing the matching recipient file is `key publish`:

```text
install -m 700 -d /var/lib/backupctl-keys/gen1
# write the identity by hand at /var/lib/backupctl-keys/gen1/identity.key, mode 0600
backupctl --config gen1.toml key publish
backupctl --config gen1.toml --output json key status
```

The command loads the identity with the store's own rules first, so a seed that is world-
readable, symlinked, or missing the suite marker is refused before anything is written — a
file the CLI will not open to restore should not get a public half published beside it. It
then writes only the recipient: **the identity is read and never modified**, because
rewriting a seed is the one action that makes every artifact sealed under it permanently
unreadable. Like `key generate`, it refuses an occupied recipient path, so a publish can
never replace the recipient a running schedule is writing to. It creates a missing parent
directory at mode `0700`.

The check that the pair agrees is `key status`, and it performs that check rather than
leaving it to you: it loads the pair through the same path the store uses, so two halves
that do not match are reported as an error instead of 2432 characters of hex to compare by
eye. A `key status` that succeeds after a publish means the configuration is ready. Until
you run `key publish`, though, a hand-written identity is unusable in exactly the way a
missing one is: the configuration refuses every command, including `backup list`, because
the pair is loaded before the store is touched.

Two notes on the seed itself. Its format is the 64 hex characters on line 2 of the file,
under the `!backupctl-mlkem768x25519-v0` marker on line 1; nothing about it is a PostgreSQL
or age-ecosystem standard, so keep the tooling that produced it with the offline copy. And
a seed you derived from a passphrase is only as strong as that passphrase: the hybrid
schemes are intact, but the human input is now part of the threat model.

## What M4a does not provide

- Re-encryption of existing artifacts under a new pair.
- More than one `[encryption]` pair per configuration. Tracking generations automatically,
  and reading a store whose artifacts span several generations in one command, is M5's
  catalog, not a key-file convention.
- Scheduling or automatic rotation; there is no timer in this CLI yet.
- Origin authentication. Artifacts are still unsigned, so a replaced artifact of the *same*
  recipient is not detectable by M4a at all — that is M4b's signature. See
  [artifact v1](../backup-format/manifest-v1.md).

## How this file is tested

`tests/m4a_key_drill.sh` runs the procedure above against real `pg_dump`, `pg_restore` and
`psql` on PostgreSQL 16, 17 and 18: generation 1 writes and verifies; the offline copy is
taken; `key generate` refuses to overwrite generation 1; generation 2 writes; each
generation refuses the other's artifact at `--level archive`; the live generation 1 identity
disappears and every command through its configuration is refused; the copy comes back
world-readable and is refused until its mode is fixed; the old artifact restores into a new
cluster configured only by the offline copy; then the offline copy goes too, and the drill
reads the manifest directly to show the ciphertext is intact, uncorrupted, and unreadable,
while the current generation still verifies and restores. The drill finishes on a third
generation whose identity it writes by hand from a fixed seed, shows `key status` refusing
the pair while the recipient is missing, publishes the recipient, confirms the identity
file is byte-identical afterwards and that a republish is refused, and then takes, verifies
and portably restores a backup under that operator-supplied pair. The seed of each identity
appears in no stored byte and no command output at any point.
