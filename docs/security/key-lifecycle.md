# Key lifecycle for encrypted and signed artifacts

Scope: the two pairs a published v1 artifact depends on — the `mlkem768x25519-v0` hybrid age
identity that opens it, and the `ed25519+ml-dsa-65` hybrid signing pair that proves who wrote
it. Both are properties of a store and of its configuration, not per-run flags: encryption is
on when the configuration carries an `[encryption]` block, signing when it also carries a
`[signing]` block. See the
[example config](../../config/m4a.example.toml) for the shape of both blocks,
[the threat model](threat-model.md) for why both hybrid halves of each pair must be retained,
and the [M4b signed store guide](../development/m4b-signing.md) for the commands these
procedures assume.

## The unit is a generation

A **generation** is one set of key files and one configuration, plus every artifact written
under them. Nothing in `backupctl` rotates a key in place, and that is deliberate:

- `key generate` writes into the configured paths — the two `[encryption]` ones and, if the
  configuration has a `[signing]` block with a `signing_key_file`, the two `[signing]` ones —
  and **refuses an occupied path before writing either half**, so a rotation cannot quietly
  overwrite the identity that today's backups need. A new generation means a new key
  directory.
- The store loads exactly one set, and it loads it before touching the storage root. So a
  generation is also the thing a configuration selects: with a new pair in place, older
  artifacts are not "still readable by accident", they are readable only through the older
  configuration.
- A published v1 artifact records `recipient_id` and `signer_id`, each 16 hex characters
  derived from its key, in both the encrypted manifest and `public.json`, and the two must
  agree with each other. `key status` prints both fingerprints for the files it is
  configured with. The reader's authority is the signature rather than the recorded id: an
  artifact signed by another key fails against the configured verifying file with "origin
  signature of artifact … does not verify", and an artifact sealed to another recipient fails
  at decryption. **What the artifact still cannot tell you is where the matching key files
  are** — that mapping stays your ledger's job, and recovering a backup starts with knowing
  which configuration opens it.

Consequence to accept before rotating: an artifact's readability lasts exactly as long as
somebody keeps that generation's identity file. Retire nothing you have not re-dumped.

## Where the files live

All four paths must be absolute and outside `[storage] root` — an encrypted archive in a
directory that also holds the identity that opens it is a plaintext archive with extra
steps. `config check` and `key generate` both refuse otherwise, and no two of the four may
name the same file. Each secret (`identity.key`, `signing.key`) is written at mode `0600` and
each public half (`recipient.key`, `verifying.key`) at `0644`, and each must be a regular
non-symlink file owned by the service account, in a directory no other local user can write.

| File | Block | Mode | Who needs it |
|---|---|---|---|
| `identity_file` | `[encryption]` | 0600 | the host that writes, and any host that decrypts to restore |
| `recipient_file` | `[encryption]` | 0644 | the host that writes |
| `signing_key_file` | `[signing]` | 0600 | **only** the host that creates backups |
| `verifying_key_file` | `[signing]` | 0644 | every host that verifies, plans or restores |

The halves are configured separately because they have genuinely different custody from M4b
onward. A verify-only or DR host omits `signing_key_file` from its `[signing]` block
altogether, and that omission is what makes "this host cannot forge a backup" a property of
its configuration rather than of your trust in its operator:

```toml
[encryption]
identity_file = "/var/lib/backupctl-keys/gen1/identity.key"
recipient_file = "/var/lib/backupctl-keys/gen1/recipient.key"

[signing]
verifying_key_file = "/var/lib/backupctl-keys/gen1/verifying.key"
```

Such a store can `backup list`, `backup verify`, `backup inspect`, `restore plan` and
`restore run`, and refuses `backup create` with "this [signing] block configures no
signing_key_file, so this host may verify but not produce a signing key". Note that the
refusal comes *after* `key generate` has already written the `[encryption]` pair, because the
age pair is generated first: run `key generate` only on the host that writes backups.

The age pair's own split is not yet enforced: the store loads the pair before it touches the
storage root, so today `backup create` fails on a host holding only the recipient. Keep both
age files on any host that runs the CLI until that port split lands.

## The ledger

One line per generation, kept somewhere the storage host's compromise does not reach it:

| Field | Where it comes from |
|---|---|
| generation name and date | yours |
| configuration file path | the file whose `[encryption]` and `[signing]` blocks name this set |
| identity file path, and the offline copy's location | `backupctl --config gen.toml key status --output json` → `identity.path` |
| recipient fingerprint | `key status` prints 32 characters; `--output json` carries the full 2432 |
| signing file path, and the offline copy's location | `key status --output json` → the `signing` row whose role is `signing` (absent on a verify-only host) |
| verifying file path | the same rows, role `verifying` |
| signer fingerprint | `key status` prints `signer key:` as 16 hex; this is the `signer_id` an artifact records |
| recipient id | not printed by `key status`; read it from an artifact's `public.json` (`backup inspect` shows it) and confirm it is the one this generation writes |
| suites | `key status` reports `mlkem768x25519-v0` and `ed25519+ml-dsa-65`; a manifest must agree |
| artifact IDs written under it | `backup list`, or the `id` each `backup create` returns |

The recipient, the verifying key and both fingerprints are public. The `identity.key` and
`signing.key` files and their offline copies are the only secret material in this table's
reach, and neither is ever printed by any command: the 64-character age seed and the
128-character signing seed appear in no CLI output, in no log line, and in no stored byte.
Confirm that for yourself with
`backupctl --config gen.toml key status --output json | grep -f <(sed -n 2p identity.key) -f <(sed -n 2p signing.key)` —
no match is the expected result.

## Procedure: take the offline copy first

Do this before the first backup of a generation, not before the first restore attempt.

```text
install -d -m 700 /secure/offline/gen1
cp -p /var/lib/backupctl-keys/gen1/identity.key /secure/offline/gen1/
cp -p /var/lib/backupctl-keys/gen1/recipient.key /secure/offline/gen1/
cp -p /var/lib/backupctl-keys/gen1/signing.key /secure/offline/gen1/
cp -p /var/lib/backupctl-keys/gen1/verifying.key /secure/offline/gen1/
```

`-p` matters: a copy that arrives world-readable is refused on the way back in, so the mode
is part of the recovery rather than a detail of it. Keep at least two offline copies of
every generation's secrets, on media that stay out of the hands of whoever can read the
artifact store. Treat this copy as the recovery path, because it is the only one: age gives
no backdoor, and adding a classical-only second recipient as a safety net would cancel the
post-quantum property the hybrid exists to provide.

The two secrets cost different things when they are gone, which is why both belong in the
copy but neither belongs on the DR host. Losing `identity.key` makes the generation's
artifacts unreadable — the data is inert. Losing `signing.key` costs only the ability to
*publish*: existing artifacts stay restorable, and once the offline copy is back (or a new
pair has been generated and installed as the trusted verifying key), everything else still
works. Losing `verifying.key` costs no data at all, because it is public: re-install it from
the offline copy or derive it again from the signing key with `key publish`.

## Procedure: rotate to a new generation

1. Confirm the offline copy from the section above exists and is readable only by the
   service account.
2. Copy the configuration and change the `[encryption]` and `[signing]` paths to a fresh
   directory, e.g. `keys/gen2`. `key generate` and `key status` act on those paths and
   nothing else, so the new files are what make the new generation. Rotate both blocks
   together: a generation that reuses an old recipient with a new signing key is two
   generations in your ledger, not one.
3. Generate and confirm:

   ```text
   backupctl --config gen2.toml key generate
   backupctl --config gen2.toml --output json key status
   ```

   `key generate` creates a missing parent directory at mode `0700`. Compare the reported
   recipient and the reported `signer key` with the previous generation's in the ledger: two
   generations with the same value for either means one of the two configurations was edited
   wrong.
4. Take a backup and verify it at `--level archive`. The manifest must record
   `format_version = 1`, `recipient_suite = "mlkem768x25519-v0"` and
   `signature_suite = "ed25519+ml-dsa-65"`, and `backup list` must show it as
   `signed v1 (signer …)`.
5. Prove the generations are actually separated, which costs one command each way:

   ```text
   backupctl --config gen2.toml backup verify OLD_ARTIFACT --level archive   # must refuse
   backupctl --config gen1.toml backup verify NEW_ARTIFACT --level archive   # must refuse
   ```

   Both artifacts sit in the same store. The first refusal is decryption failing to find a
   matching identity; the second arrives earlier, as "origin signature of artifact … does not
   verify", because generation 1's verifying key was not the signer. Neither is a damaged
   file.
6. Point the schedule at `gen2.toml`, and mark `gen1.toml` in the ledger as read-only: it
   exists from now on to restore, never to write. If you want the read-only host to be
   provably unable to publish, also drop `signing_key_file` from its copy of the block, as
   shown in "Where the files live".

Old artifacts are **not** re-encrypted or re-signed into the new generation. There is no
command that reads a plaintext archive out of one generation and seals it into another,
because doing so would put plaintext in reach of the store that is supposed to never hold it,
and no command that re-signs an artifact in place, because the signature covers the exact
bytes beside it. If a generation is one you want to keep long-term, take a fresh backup under
the new pair instead.

## Procedure: restore a backup taken under an older generation

Use that generation's configuration:

```text
backupctl --config gen1.toml restore plan ARTIFACT --target backupctl_dr --security dr
backupctl --config gen1.toml restore run PLAN --confirm-target backupctl_dr
```

If the live key directory is gone, do not "fix" the configuration by deleting history. Make
a recovery configuration that is a copy of the old one with `identity_file`,
`recipient_file`, `signing_key_file` and `verifying_key_file` pointed at the offline copies —
or, better, drop `signing_key_file` from that copy entirely: a restore needs the decryption
identity and the trusted verifying key and nothing else, so the recovery host never holds a
signing secret it has no use for. Restore the artifact, then remove the recovery file. A
restore reads the archive into the store's transient `scratch/` view and nothing else, so the
decrypted plaintext never lands beside the artifacts.

Two rejections you will see if the copy was handled carelessly, both by design:

- `identity key file … must be mode 0600 or stricter, not 0644` (and the same sentence with
  `signing` in place of `identity`) — `chmod 600` it.
- `identity key file … must be a regular non-symlink file` — a symlinked recovery mount is
  refused; copy the file instead.

## Procedure: a key file is lost

**One copy lost, the other present.** Every command through the affected configuration
fails before it reads the store, because the key files are loaded first, including
`backup list` and `backup inspect`:

```text
inspect identity key file /var/lib/backupctl-keys/gen1/identity.key: No such file or directory
```

That failure writes nothing and leaves nothing behind: no `scratch/` content, no partial
restore, no plaintext. Recover by copying the offline file back with mode `0600`, running
`key status` to confirm the pair agrees again, and re-running the verification that was
interrupted. The same sentence, with `signing` or `verifying` in place of `identity`, is what
a missing signing half looks like — and note which one is the cheaper loss:

- **`signing.key` gone** stops `backup create`, because a v1 store is a writer that must
  sign. Verifying, listing and restoring still work: they need the verifying key, not the
  secret. Restore the copy from the vault, or rotate to a new pair and install its
  verifying half on the readers — either way no artifact becomes unreadable.
- **`verifying.key` gone** stops every command on that host, because no signature can be
  trusted without it ("no verifying key is configured, so no signature can be trusted"). It
  is public, so recovering it is a copy or a `key publish` from the signing half, never a
  re-dump. Do not "recover" it by copying one out of an artifact or from a peer's store: the
  whole value of the check is that this file was installed independently of what it verifies.

**Every copy of the identity lost.** The artifacts are not corrupted and not lost — they are
inert. The ciphertext still hashes to what its manifest recorded, and nothing can read it.
There is no recovery procedure to write for this case, and the honest answer is a decision:
declare the generation lost, record that in the ledger, and keep or delete the bytes
accordingly. If a rotation ever appears to have made a backup unreadable, that is almost
always the configuration, not the key — check which generation the artifact belongs to before
deleting anything.

**Every copy of the signing key lost, identity intact.** Nothing is lost except the ability
to publish under that generation. Existing artifacts verify and restore against the
generation's verifying key forever; a new generation restores signing, and its verifying key
goes on every reader host beside the old one. What you must *not* do is re-point a reader at
a fresh verifying key and expect the old artifacts to still pass: they will not, and that
refusal is the origin check working.

## Using a key you did not generate

The store does not care where a key came from: an identity file you wrote yourself is
loaded under the same rules as one `key generate` wrote, and a seed derived from your own
secret, a passphrase, or an HSM is a valid identity as far as decryption is concerned. The
same holds for a signing seed.

Publishing the matching public half is `key publish`, which acts on whichever blocks the
configuration names — the recipient from the identity, the verifying key from the signing
key:

```text
install -m 700 -d /var/lib/backupctl-keys/gen1
# write the identity by hand at /var/lib/backupctl-keys/gen1/identity.key, mode 0600
# write the signing seed by hand at .../signing.key, mode 0600, if this host signs
backupctl --config gen1.toml key publish
backupctl --config gen1.toml --output json key status
```

The command loads the secret with the store's own rules first, so a seed that is world-
readable, symlinked, or missing the suite marker is refused before anything is written — a
file the CLI will not open to restore should not get a public half published beside it. It
then writes only the public file: **the secret is read and never modified**, because
rewriting a seed is the one action that makes every artifact sealed under it permanently
unreadable. Like `key generate`, it refuses an occupied public path, so a publish can never
replace the recipient or the verifying key a running configuration is using. It creates a
missing parent directory at mode `0700`.

The check that a pair agrees is `key status`, and it performs that check rather than leaving
it to you: it loads each pair through the same path the store uses, so two halves that do not
match are reported as an error instead of thousands of characters of hex to compare by eye —
for the signing pair, "verifying key file … is not the public half of signing key file …". A
`key status` that succeeds after a publish means the configuration is ready. Until you run
`key publish`, though, a hand-written secret is unusable in exactly the way a missing one is:
the configuration refuses every command, including `backup list`, because the key files are
loaded before the store is touched.

Two notes on the seeds themselves. The identity's is the 64 hex characters on line 2 of the
file, under the `!backupctl-mlkem768x25519-v0` marker on line 1; the signing file's is **128**
hex characters under `!backupctl-ed25519mldsa65-v0`, because it is two independent 32-byte
seeds concatenated (Ed25519 first, then ML-DSA-65) rather than one seed and a derivation.
Nothing about either format is a PostgreSQL or age-ecosystem standard, so keep the tooling
that produced them with the offline copy. And a seed you derived from a passphrase is only as
strong as that passphrase: the hybrid schemes are intact, but the human input is now part of
the threat model.

## What this lifecycle does not provide

- Re-encryption or re-signing of existing artifacts under a new pair.
- More than one `[encryption]`/`[signing]` set per configuration. Tracking generations
  automatically, and reading a store whose artifacts span several generations in one command,
  is M5's catalog, not a key-file convention.
- Scheduling or automatic rotation; there is no timer in this CLI yet.
- Revocation. A verifying key is trusted because it is installed; there is no list of
  compromised generations to check against, so retiring a generation is a ledger action and a
  file deletion on the readers, not a command.
- An external or HSM signer. `signing_key_file` names a file this binary reads; a seed you
  derived inside an HSM is fine, but the file itself must exist on the backup host in mode
  `0600`, and a host that can create backups can therefore read the signing seed while it
  runs.
- Independent copies. Everything above protects against a lost or damaged key file and
  against a storage host editing artifacts. It does not protect against the backup host being
  compromised: that host holds both secrets by design (see T10 and T11 in
  [the threat model](threat-model.md)).

## How this file is tested

`tests/m4a_key_drill.sh` runs the procedure above against real `pg_dump`, `pg_restore` and
`psql` on PostgreSQL 16, 17 and 18. Steps 1–7 are the age half: generation 1 writes and
verifies; the offline copy is taken; `key generate` refuses to overwrite generation 1;
generation 2 writes; each generation refuses the other's artifact at `--level archive`; the
live generation 1 identity disappears and every command through its configuration is refused;
the copy comes back world-readable and is refused until its mode is fixed; the old artifact
restores into a new cluster configured only by the offline copy; then the offline copy goes
too, and the drill reads the manifest directly to show the ciphertext is intact, uncorrupted,
and unreadable, while the current generation still verifies and restores. Step 8 is the
identity the operator supplies by hand from a fixed seed: `key status` refuses the pair while
its recipient is missing, `key publish` writes the recipient and leaves the identity file
byte-identical, a republish is refused, and a backup taken under that pair verifies and
restores.

Steps 9–11 are the signing half. Step 9: a pair generates with the same refusal of an
occupied path and the same `0600`/`0644` modes, its seed is 128 hex characters, the store now
writes `public.json` and `manifest.age` rather than a plaintext `manifest.json`, and two
generations report two different `signer` fingerprints; each generation refuses the other's
signed artifact at `--level signature`, and the refusal is the origin signature rather than a
decryption error. Step 10: the vault copy of `signing.key` and `verifying.key` is taken with
`cp -p`, the live secret is removed, and every command through the writer configuration —
including `backup inspect` — fails on `load signing key file`; a configuration holding only
`verifying_key_file` then verifies the same artifact at signature level, reporting the same
`signer_id`, plans it and restores it, which is the proof that the read path needs no signing
secret; the secret comes back from the vault and that generation publishes again. Step 11:
the *verifying* file goes, both the verify and the plan are refused on `load verifying key
file`, a `pg_database` check confirms the refused plan created no target database behind it,
and re-installing the copy makes verification pass again — after which the drill hashes
`payload.age` against `public.json` and checks `signature.hybrid` is still 3373 bytes, so
what was missing was trust, not data. Step 12 sweeps the store and the captured output for
every secret in the drill.
