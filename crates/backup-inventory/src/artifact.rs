//! One artifact as the inventory knows it: its identity, the shape its files are in, and what
//! this host has done with it since.
//!
//! Every field is either something a file in `artifacts/<id>/` states in plaintext — a UUID, two
//! key fingerprints, two digests, two ciphertext sizes, from `public.json` — or something this
//! host observed: whether it ever read the sealed manifest, whether the files are still there.
//! Nothing else. That is the whole vocabulary, and it is why two groups of columns are nullable:
//!
//! - `signer_id`, `recipient_id`, both suites, both digests, both sizes: `public.json` exists
//!   only for a v1-signed artifact, so for the two older shapes these are absent rather than
//!   empty. [`ArtifactRow::validate`] refuses a row that claims them for a shape that has no
//!   file to have read them from, because such a value was invented.
//! - `profile_fingerprint` and `completed_at_utc`: both live only inside `manifest.age`, which is
//!   encrypted in every shape and *signed-then-sealed* in the current one. The signature covers
//!   `backup_id` and two ciphertext digests, so a host holding no key can list a v1-signed
//!   artifact perfectly and still not know what it is a backup *of* or when it finished. A
//!   rebuild on a DR host therefore writes NULLs here, and the row is honest about being partial.
//!   That is also a limit worth stating where it matters: [`keep_last`] counts per profile, so a
//!   row whose profile this host never read cannot satisfy a retention rule and must never be a
//!   pruning candidate.
//!
//! [`keep_last`]: ../../docs/architecture/adr-0003-backup-inventory-jobs-retention.md

use crate::{Estate, is_hex, is_hex_id};
use anyhow::{Result, bail, ensure};
use backup_domain::{
    DIGEST_HEX_LEN, ID_HEX_LEN, READABLE_RECIPIENT_SUITES, READABLE_SIGNATURE_SUITES,
    is_utc_timestamp,
};
use rusqlite::{Connection, Row, params};
use uuid::Uuid;

/// The columns of `artifact`, in one place so a `SELECT` and the `INSERT` cannot drift from each
/// other or from the schema. Checked against both by a test rather than by care.
pub(super) const ARTIFACT_COLUMNS: &str = "backup_id, source_fingerprint, profile_fingerprint, \
    shape, signer_id, recipient_id, payload_sha256, manifest_sha256, recipient_suite, \
    signature_suite, payload_bytes, manifest_bytes, completed_at_utc, state";

/// Registers a row, replacing whatever this id's row said.
///
/// `INSERT OR REPLACE` rather than an upsert with a per-column list: every column is rewritten
/// from the same row, there is no foreign key pointing here for a delete-then-insert to break,
/// and the two callers that land on the same id — a backup that just published, and a reconcile
/// pass that found the same directory again — are expected to disagree about *completeness*
/// rather than about truth. A keyless rebuild writes a row of NULLs; the first run that holds the
/// keys fills it in, and that replacement is the point.
pub(super) const UPSERT_ARTIFACT: &str = "INSERT OR REPLACE INTO artifact \
    (backup_id, source_fingerprint, profile_fingerprint, shape, signer_id, recipient_id, \
    payload_sha256, manifest_sha256, recipient_suite, signature_suite, payload_bytes, \
    manifest_bytes, completed_at_utc, state) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";

/// Writes one row. Split out so [`crate::Inventory::register`] is the only place that decides
/// what an inventory error becomes.
pub(super) fn write(conn: &Connection, row: &ArtifactRow) -> Result<()> {
    let payload_bytes = sql_size("payload_bytes", row.payload_bytes)?;
    let manifest_bytes = sql_size("manifest_bytes", row.manifest_bytes)?;
    conn.execute(
        UPSERT_ARTIFACT,
        params![
            row.backup_id.to_string(),
            row.source_fingerprint,
            row.profile_fingerprint,
            row.shape.as_str(),
            row.signer_id,
            row.recipient_id,
            row.payload_sha256,
            row.manifest_sha256,
            row.recipient_suite,
            row.signature_suite,
            payload_bytes,
            manifest_bytes,
            row.completed_at_utc,
            row.state.as_str()
        ],
    )?;
    Ok(())
}

/// SQLite's INTEGER holds signed 64-bit values, so a byte count is stored as one and refused here
/// rather than wrapped: a `u64` above that bound cannot be a file size, and a row that quietly
/// became negative would read back as one an operator could not explain.
fn sql_size(field: &str, bytes: Option<u64>) -> Result<Option<i64>> {
    let Some(bytes) = bytes else { return Ok(None) };
    let size = i64::try_from(bytes)
        .map_err(|_| anyhow::anyhow!("{field} = {bytes} is above what a SQLite INTEGER holds"))?;
    Ok(Some(size))
}

fn row_size(row: &Row<'_>, column: &str) -> Result<Option<u64>> {
    let stored: Option<i64> = row.get(column)?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let bytes = u64::try_from(stored).map_err(|_| {
        anyhow::anyhow!("inventory holds {column} = {stored}, which is not a byte count")
    })?;
    Ok(Some(bytes))
}

/// How many files an artifact directory holds, and therefore what may be claimed about it without
/// decrypting anything.
///
/// These are the three shapes a store can contain at once — ADR 0003's gate 3 is that `backup
/// list` names the shape of every entry instead of refusing a mixed store — and the rule that
/// `validate` enforces follows from it: a v1-signed artifact has a `public.json`, so its discovery
/// fields must be present; the other two have no such file, so their discovery fields must not be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Artifact v1: signed, `public.json` present, payload and manifest sealed.
    V1Signed,
    /// M4a: age-sealed payload and manifest, no signature and no discovery record.
    AgeUnsigned,
    /// M1–M3: a plaintext custom-format dump plus its JSON manifest.
    PlaintextDev,
}

impl Shape {
    /// The exact string the schema's `CHECK (shape IN (...))` admits.
    pub fn as_str(self) -> &'static str {
        match self {
            Shape::V1Signed => "v1-signed",
            Shape::AgeUnsigned => "age-unsigned",
            Shape::PlaintextDev => "plaintext-dev",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        let shape = match text {
            "v1-signed" => Shape::V1Signed,
            "age-unsigned" => Shape::AgeUnsigned,
            "plaintext-dev" => Shape::PlaintextDev,
            other => bail!(
                "inventory holds shape {other:?}, which is not one of '{}', '{}' or '{}'",
                Shape::V1Signed.as_str(),
                Shape::AgeUnsigned.as_str(),
                Shape::PlaintextDev.as_str()
            ),
        };
        Ok(shape)
    }

    /// Whether a row of this shape may carry `public.json`'s fields.
    fn has_discovery_record(self) -> bool {
        matches!(self, Shape::V1Signed)
    }
}

/// What this index has done with an artifact.
///
/// Deliberately *not* a table constraint: ADR 0003's choice 5 adds `deleted` in M5b and choice 3
/// adds `missing` when the reconcile pass exists, and a lifecycle vocabulary frozen in a
/// `CHECK` would force a schema version bump and a rewrite of every row to add a word. Rust
/// validates it instead, and the only cost is that a hand-edited database can hold a state no
/// build writes — which is choice 2's residual anyway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// This host saw the artifact's files. The one state anything writes today.
    Registered,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Registered => "registered",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "registered" => Ok(State::Registered),
            other => bail!("inventory holds state {other:?}, which this build cannot write"),
        }
    }
}

/// A row of the `artifact` table.
///
/// All fields are public because a row is a record of what files said, not an object with
/// invariants to maintain: the invariants are checked once, in [`ArtifactRow::validate`], at the
/// only place that writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRow {
    pub backup_id: Uuid,
    /// Which estate this row belongs to. Kept per row as well as in `meta` so a rebuild that
    /// walks a store directory by directory cannot quietly write a foreign artifact's row into a
    /// file that has already refused a foreign open.
    pub source_fingerprint: String,
    /// [`backup_domain::profile_fingerprint`] of the profile that made this dump, or NULL when
    /// this host has not decrypted the manifest and so does not know.
    pub profile_fingerprint: Option<String>,
    pub shape: Shape,
    pub signer_id: Option<String>,
    pub recipient_id: Option<String>,
    pub payload_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub recipient_suite: Option<String>,
    pub signature_suite: Option<String>,
    pub payload_bytes: Option<u64>,
    pub manifest_bytes: Option<u64>,
    /// The manifest's own claim about when the dump finished, second precision UTC. NULL on a
    /// keyless rebuild; ordering and the replay ledger treat NULL as unknown, never as oldest.
    pub completed_at_utc: Option<String>,
    pub state: State,
}

impl ArtifactRow {
    /// Refuses a row this inventory must not hold, before any statement sees it.
    pub(crate) fn validate(&self, estate: &Estate) -> Result<()> {
        ensure!(
            self.source_fingerprint == estate.source_fingerprint,
            "refusing to register backup {}: it belongs to source {}, and this inventory indexes \
             {}",
            self.backup_id,
            self.source_fingerprint,
            estate.source_fingerprint
        );
        if let Some(profile) = &self.profile_fingerprint {
            ensure!(
                is_hex_id(profile),
                "profile fingerprint for backup {} must be {ID_HEX_LEN} lowercase hex characters, \
                 not {profile:?}",
                self.backup_id
            );
        }
        if let Some(completed) = &self.completed_at_utc {
            ensure!(
                is_utc_timestamp(completed),
                "completed_at_utc for backup {} must be the artifact timestamp form, not \
                 {completed:?}",
                self.backup_id
            );
        }

        let discovery = [
            ("signer_id", self.signer_id.as_deref()),
            ("recipient_id", self.recipient_id.as_deref()),
            ("payload_sha256", self.payload_sha256.as_deref()),
            ("manifest_sha256", self.manifest_sha256.as_deref()),
            ("recipient_suite", self.recipient_suite.as_deref()),
            ("signature_suite", self.signature_suite.as_deref()),
        ];
        if self.shape.has_discovery_record() {
            for (field, value) in &discovery {
                let Some(value) = value else {
                    bail!(
                        "a v1-signed row for backup {} must record {field}: public.json states it, \
                         so an absent value means the file was not read",
                        self.backup_id
                    );
                };
                match *field {
                    "signer_id" | "recipient_id" => ensure!(
                        is_hex(value, ID_HEX_LEN),
                        "{field} for backup {} must be {ID_HEX_LEN} lowercase hex characters, not \
                         {value:?}",
                        self.backup_id
                    ),
                    "payload_sha256" | "manifest_sha256" => ensure!(
                        is_hex(value, DIGEST_HEX_LEN),
                        "{field} for backup {} must be {DIGEST_HEX_LEN} lowercase hex characters, \
                         not {value:?}",
                        self.backup_id
                    ),
                    "recipient_suite" => ensure!(
                        READABLE_RECIPIENT_SUITES.contains(value),
                        "backup {} records recipient suite {value:?}, which this build cannot even \
                         read",
                        self.backup_id
                    ),
                    _ => ensure!(
                        READABLE_SIGNATURE_SUITES.contains(value),
                        "backup {} records signature suite {value:?}, which this build cannot even \
                         read",
                        self.backup_id
                    ),
                }
            }
            for (field, size) in [
                ("payload_bytes", self.payload_bytes),
                ("manifest_bytes", self.manifest_bytes),
            ] {
                ensure!(
                    matches!(size, Some(bytes) if bytes > 0),
                    "{field} for backup {} must be a non-zero ciphertext size",
                    self.backup_id
                );
            }
        } else {
            for (field, value) in &discovery {
                ensure!(
                    value.is_none(),
                    "{field} on a {} row for backup {} is invented: that shape has no public.json \
                     to have read it from",
                    self.shape.as_str(),
                    self.backup_id
                );
            }
            ensure!(
                self.payload_bytes.is_none() && self.manifest_bytes.is_none(),
                "a {} row for backup {} carries ciphertext sizes, which nothing in that shape \
                 states",
                self.shape.as_str(),
                self.backup_id
            );
        }
        Ok(())
    }

    /// Reads one row. Columns are fetched by name, so this stays correct if the column list is
    /// ever reordered.
    pub(super) fn from_row(row: &Row<'_>) -> Result<Self> {
        let backup_id: String = row.get("backup_id")?;
        let backup_id = Uuid::parse_str(&backup_id).map_err(|_| {
            anyhow::anyhow!("inventory holds backup_id {backup_id:?}, which is not a UUID")
        })?;
        Ok(ArtifactRow {
            backup_id,
            source_fingerprint: row.get("source_fingerprint")?,
            profile_fingerprint: row.get("profile_fingerprint")?,
            shape: Shape::parse(&row.get::<_, String>("shape")?)?,
            signer_id: row.get("signer_id")?,
            recipient_id: row.get("recipient_id")?,
            payload_sha256: row.get("payload_sha256")?,
            manifest_sha256: row.get("manifest_sha256")?,
            recipient_suite: row.get("recipient_suite")?,
            signature_suite: row.get("signature_suite")?,
            payload_bytes: row_size(row, "payload_bytes")?,
            manifest_bytes: row_size(row, "manifest_bytes")?,
            completed_at_utc: row.get("completed_at_utc")?,
            state: State::parse(&row.get::<_, String>("state")?)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "c1cb425f097b6522";

    fn estate() -> Estate {
        Estate::new(SOURCE.to_string()).unwrap()
    }

    /// A complete v1-signed row, the shape the writer host produces.
    fn signed() -> ArtifactRow {
        ArtifactRow {
            backup_id: Uuid::parse_str("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a").unwrap(),
            source_fingerprint: SOURCE.to_string(),
            profile_fingerprint: Some("651dd7a74505b176".to_string()),
            shape: Shape::V1Signed,
            signer_id: Some("a".repeat(ID_HEX_LEN)),
            recipient_id: Some("b".repeat(ID_HEX_LEN)),
            payload_sha256: Some("c".repeat(DIGEST_HEX_LEN)),
            manifest_sha256: Some("d".repeat(DIGEST_HEX_LEN)),
            recipient_suite: Some("mlkem768x25519-v0".to_string()),
            signature_suite: Some("ed25519+ml-dsa-65".to_string()),
            payload_bytes: Some(4096),
            manifest_bytes: Some(1024),
            completed_at_utc: Some("2026-09-28T06:15:00Z".to_string()),
            state: State::Registered,
        }
    }

    fn unsigned(shape: Shape) -> ArtifactRow {
        ArtifactRow {
            backup_id: Uuid::parse_str("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a").unwrap(),
            source_fingerprint: SOURCE.to_string(),
            profile_fingerprint: None,
            shape,
            signer_id: None,
            recipient_id: None,
            payload_sha256: None,
            manifest_sha256: None,
            recipient_suite: None,
            signature_suite: None,
            payload_bytes: None,
            manifest_bytes: None,
            completed_at_utc: None,
            state: State::Registered,
        }
    }

    #[test]
    fn the_column_list_and_the_write_agree_with_the_schema() {
        let listed = ARTIFACT_COLUMNS
            .split(',')
            .map(str::trim)
            .collect::<Vec<_>>();
        assert_eq!(listed.len(), 14, "{listed:?}");

        // The `INSERT`'s column list, read back out of the statement text.
        let start = UPSERT_ARTIFACT.find("INTO artifact (").unwrap() + "INTO artifact (".len();
        let end = UPSERT_ARTIFACT.find(") VALUES").unwrap();
        let inserted = UPSERT_ARTIFACT[start..end]
            .split(',')
            .map(str::trim)
            .collect::<Vec<_>>();
        assert_eq!(
            inserted, listed,
            "a SELECT and an INSERT must name one row shape"
        );

        // Placeholders are numbered, not positional, so the two lists must match in count.
        for (index, _) in listed.iter().enumerate() {
            assert!(
                UPSERT_ARTIFACT.contains(&format!("?{}", index + 1)),
                "missing ?{} for {}",
                index + 1,
                listed[index]
            );
        }
        assert!(UPSERT_ARTIFACT.contains("?14"));
        assert!(!UPSERT_ARTIFACT.contains("?15"));
    }

    #[test]
    fn a_fully_described_signed_row_is_accepted() {
        signed().validate(&estate()).unwrap();
    }

    #[test]
    fn a_signed_row_must_state_what_public_json_states() {
        for field in [
            "signer_id",
            "recipient_id",
            "payload_sha256",
            "manifest_sha256",
            "recipient_suite",
            "signature_suite",
            "payload_bytes",
            "manifest_bytes",
        ] {
            let mut row = signed();
            match field {
                "payload_bytes" | "manifest_bytes" => {
                    if field == "payload_bytes" {
                        row.payload_bytes = None;
                    } else {
                        row.manifest_bytes = None;
                    }
                }
                "signer_id" => row.signer_id = None,
                "recipient_id" => row.recipient_id = None,
                "payload_sha256" => row.payload_sha256 = None,
                "manifest_sha256" => row.manifest_sha256 = None,
                "recipient_suite" => row.recipient_suite = None,
                _ => row.signature_suite = None,
            }
            let error = row
                .validate(&estate())
                .expect_err(&format!("a signed row without {field} was a read file"));
            assert!(error.to_string().contains(field), "{error}");
        }
    }

    #[test]
    fn identifiers_and_digests_are_validated_by_shape_not_by_origin() {
        // A digest of the wrong length is a different kind of mistake from a missing one, and the
        // row cannot tell them apart, so the shapes have to be checked here.
        let mut short = signed();
        short.signer_id = Some("a".repeat(ID_HEX_LEN + 1));
        assert!(
            short
                .validate(&estate())
                .expect_err("an id is 16 hex characters")
                .to_string()
                .contains("signer_id")
        );

        let mut hashed = signed();
        hashed.payload_sha256 = Some("c".repeat(DIGEST_HEX_LEN - 1));
        assert!(
            hashed
                .validate(&estate())
                .expect_err("a digest is 64 hex characters")
                .to_string()
                .contains("payload_sha256")
        );

        // Readable-but-not-writable is the reader's rule, not this one: an inventory may index a
        // classical-only artifact long enough to report it as the downgrade it is.
        let mut downgraded = signed();
        downgraded.signature_suite = Some("ed25519".to_string());
        downgraded.validate(&estate()).unwrap();

        let mut invented = signed();
        invented.recipient_suite = Some("mlkem768-only".to_string());
        assert!(
            invented
                .validate(&estate())
                .expect_err("no reader knows that suite")
                .to_string()
                .contains("cannot even read")
        );
    }

    #[test]
    fn an_unsigned_shape_has_no_discovery_fields_to_hold() {
        for shape in [Shape::AgeUnsigned, Shape::PlaintextDev] {
            unsigned(shape).validate(&estate()).unwrap();

            let mut claimed = unsigned(shape);
            claimed.signer_id = Some("a".repeat(ID_HEX_LEN));
            let error = claimed
                .validate(&estate())
                .expect_err("public.json does not exist in this shape")
                .to_string();
            assert!(error.contains("invented"), "{error}");
            assert!(error.contains(shape.as_str()), "{error}");

            let mut sized = unsigned(shape);
            sized.manifest_bytes = Some(1);
            assert!(
                sized
                    .validate(&estate())
                    .expect_err("nothing in that shape states a size")
                    .to_string()
                    .contains("ciphertext sizes")
            );
        }
    }

    #[test]
    fn a_row_belongs_to_the_estate_its_inventory_indexes() {
        let mut foreign = signed();
        foreign.source_fingerprint = "0".repeat(ID_HEX_LEN);
        let error = foreign
            .validate(&estate())
            .expect_err("two estates in one index answer both wrongly")
            .to_string();
        assert!(error.contains("refusing to register"), "{error}");
        assert!(error.contains(&foreign.backup_id.to_string()), "{error}");
    }

    #[test]
    fn unknown_profile_and_timestamp_are_unknown_rather_than_oldest() {
        // A keyless rebuild: a signed artifact listed from public.json alone.
        let mut keyless = signed();
        keyless.profile_fingerprint = None;
        keyless.completed_at_utc = None;
        keyless.validate(&estate()).unwrap();

        let mut sloppy = signed();
        sloppy.profile_fingerprint = Some("Nightly".to_string());
        assert!(
            sloppy
                .validate(&estate())
                .expect_err("a name is not a fingerprint")
                .to_string()
                .contains("profile fingerprint")
        );

        let mut drifted = signed();
        drifted.completed_at_utc = Some("2026-09-28 06:15:00".to_string());
        assert!(
            drifted
                .validate(&estate())
                .expect_err("an offset-less local time cannot be compared")
                .to_string()
                .contains("completed_at_utc")
        );
    }

    #[test]
    fn shape_and_state_words_are_the_schema_vocabulary() {
        for shape in [Shape::V1Signed, Shape::AgeUnsigned, Shape::PlaintextDev] {
            assert_eq!(Shape::parse(shape.as_str()).unwrap(), shape);
        }
        assert_eq!(
            State::parse(State::Registered.as_str()).unwrap(),
            State::Registered
        );
        for word in ["", "V1-SIGNED", "v1", "signed", "deleted", "missing"] {
            assert!(Shape::parse(word).is_err(), "{word} is not a shape");
        }
        // `deleted` and `missing` are states a future build will write, and this one must say so
        // rather than read them as a row it does not understand.
        for word in ["", "registered ", "deleted", "v1-signed"] {
            assert!(
                State::parse(word).is_err(),
                "{word} is not a state this build writes"
            );
        }
    }
}
