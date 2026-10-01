//! The two records a published v1 artifact carries.
//!
//! [`ArtifactManifest`] is the private manifest whose plaintext is what `manifest.age`
//! decrypts to; [`PublicHeader`] is `public.json`, the discovery record `backup list`
//! reads with no keys at all. They are deliberately asymmetric: everything the manifest
//! knows is secret at rest and inside the signature, while the header states only enough
//! to find and check an artifact and is therefore untrusted until that signature verifies.
//! A reader compares the two after decrypting, and the fields they share are exactly the
//! ones that comparison covers.

use crate::config::Source;
use crate::profile::{Profile, is_valid_schema_name, is_valid_table_name};
use crate::protocol::{
    ARCHIVE_COMPRESSION, ARCHIVE_FORMAT, ARTIFACT_FORMAT_VERSION, DIGEST_HEX_LEN,
    ENGINE_POSTGRESQL, GLOBALS_POLICY_EXPORTED, GLOBALS_POLICY_SKIPPED, ID_HEX_LEN,
    MAX_COMPATIBILITY_NOTES, MAX_PUBLIC_JSON_BYTES, MAX_TEXT_FIELD_CHARS,
    READABLE_RECIPIENT_SUITES, READABLE_SIGNATURE_SUITES, RECIPIENT_SUITES, SIGNATURE_SUITES,
    SOURCE_FINGERPRINT_DOMAIN, SUBSCRIPTION_POLICY_DROPPED, SUPPORTED_MAJOR_RANGE,
    SUPPORTED_MAJORS, VERIFICATION_NONE,
};
use crate::selection::ResolvedSelection;
use crate::utc::is_utc_timestamp;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use uuid::Uuid;

/// The names the operator asked for, before the live catalog was read. It is recorded
/// next to the resolved selection so a reader can see whether an artifact dumped what it
/// was told to: an object in the resolved list that nobody requested is a lie about scope,
/// and one that was requested but vanished is a lie about completeness.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedSelection {
    pub schemas: Vec<String>,
    pub tables: Vec<String>,
    pub exclude_schemas: Vec<String>,
    pub exclude_tables: Vec<String>,
    pub exclude_extensions: Vec<String>,
}

impl RequestedSelection {
    pub fn from_profile(profile: &Profile) -> Self {
        Self {
            schemas: profile.schemas.clone(),
            tables: profile.tables.clone(),
            exclude_schemas: profile.exclude_schemas.clone(),
            exclude_tables: profile.exclude_tables.clone(),
            exclude_extensions: profile.exclude_extensions.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        if !self.schemas.is_empty() && !self.tables.is_empty() {
            bail!("manifest requested selection cannot name both schemas and tables");
        }
        for schema in self.schemas.iter().chain(&self.exclude_schemas) {
            if !is_valid_schema_name(schema) {
                bail!("manifest requested schema {schema:?} is not an exact lower-case name");
            }
        }
        for table in self.tables.iter().chain(&self.exclude_tables) {
            if !is_valid_table_name(table) {
                bail!("manifest requested table {table:?} is not an exact schema.table name");
            }
        }
        for extension in &self.exclude_extensions {
            if !is_valid_schema_name(extension) {
                bail!("manifest excluded extension {extension:?} is not an exact name");
            }
        }
        Ok(())
    }

    fn is_whole_database(&self) -> bool {
        self.schemas.is_empty() && self.tables.is_empty()
    }
}

/// The private manifest of a v1 artifact, as it exists once `manifest.age` is
/// authenticated. Fields are required, not optional, wherever the writer always knows the
/// answer: an absent field here would be a format gap rather than a fact about a dump.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub format_version: u32,
    pub backup_id: Uuid,
    pub engine: String,
    pub source_server_major: u32,
    /// `server_version_num`, as reported by the source.
    pub source_server_version: String,
    pub dump_client_version: String,
    pub application_version: String,
    /// Fingerprint of the recipient public key the payload was sealed to.
    pub recipient_id: String,
    /// Fingerprint of the verifying key that authenticates the origin signature.
    pub signer_id: String,
    pub recipient_suite: String,
    pub signature_suite: String,
    pub started_at_utc: String,
    pub completed_at_utc: String,
    /// Non-secret, and a digest rather than a `host:port/database` string so that binding
    /// two artifacts to the same source never leaks where the source is.
    pub source_fingerprint: String,
    pub profile_snapshot: Profile,
    pub requested_selection: RequestedSelection,
    pub resolved_selection: ResolvedSelection,
    pub archive_format: String,
    pub compression: String,
    pub subscription_policy: String,
    pub globals_policy: String,
    pub globals_sha256: Option<String>,
    pub globals_ciphertext_bytes: Option<u64>,
    pub payload_ciphertext_sha256: String,
    pub payload_ciphertext_bytes: u64,
    /// Bytes the payload decrypts to, which is the bound a restore writes under before it
    /// has authenticated anything.
    pub archive_plaintext_bytes: u64,
    /// Recorded when the artifact is written, from the table of contents listed off the
    /// staged archive before anything was sealed. A signed manifest cannot gain a fact
    /// later, so archive-level verification compares against this digest instead of
    /// filling it in, and refuses an artifact that recorded none.
    pub archive_toc_sha256: Option<String>,
    pub verification_level: String,
    pub compatibility_notes: Vec<String>,
}

impl ArtifactManifest {
    /// Checks a manifest a reader has just decrypted. Suites are checked against the
    /// readable lists rather than the writable ones, so that a classical-only or
    /// downgraded artifact is refused by name as a policy violation instead of failing to
    /// parse and looking like corruption.
    pub fn validate(&self) -> Result<()> {
        if self.format_version != ARTIFACT_FORMAT_VERSION {
            bail!(
                "unknown artifact manifest format version {}, this build writes {ARTIFACT_FORMAT_VERSION}",
                self.format_version
            );
        }
        validate_backup_id(self.backup_id)?;
        if self.engine != ENGINE_POSTGRESQL {
            bail!(
                "artifact manifest engine must be {ENGINE_POSTGRESQL}, not {:?}",
                self.engine
            );
        }
        if !SUPPORTED_MAJORS.contains(&self.source_server_major) {
            bail!(
                "artifact manifest source major {} is outside PostgreSQL {SUPPORTED_MAJOR_RANGE}",
                self.source_server_major
            );
        }
        validate_server_version(&self.source_server_version, self.source_server_major)?;
        for (field, value) in [
            ("dump_client_version", &self.dump_client_version),
            ("application_version", &self.application_version),
        ] {
            if !is_bounded_text(value) {
                bail!("manifest {field} must be short printable text");
            }
        }
        for (field, value) in [
            ("recipient_id", &self.recipient_id),
            ("signer_id", &self.signer_id),
            ("source_fingerprint", &self.source_fingerprint),
        ] {
            if !is_hex_id(value) {
                bail!("manifest {field} must be {ID_HEX_LEN} lowercase hex characters");
            }
        }
        if !READABLE_RECIPIENT_SUITES.contains(&self.recipient_suite.as_str()) {
            bail!(
                "manifest records unsupported recipient suite {}",
                self.recipient_suite
            );
        }
        if !READABLE_SIGNATURE_SUITES.contains(&self.signature_suite.as_str()) {
            bail!(
                "manifest records unsupported signature suite {}",
                self.signature_suite
            );
        }
        for (field, value) in [
            ("started_at_utc", &self.started_at_utc),
            ("completed_at_utc", &self.completed_at_utc),
        ] {
            if !is_utc_timestamp(value) {
                bail!("manifest {field} must be a UTC timestamp like 2026-01-02T03:04:05Z");
            }
        }
        // Both are the fixed-width form, so ordering them as text is ordering them as time.
        if self.completed_at_utc < self.started_at_utc {
            bail!("manifest completed before it started");
        }
        self.profile_snapshot.validate()?;
        self.requested_selection.validate()?;
        self.resolved_selection_validate()?;
        if self.archive_format != ARCHIVE_FORMAT {
            bail!(
                "artifact manifest archive format must be {ARCHIVE_FORMAT}, not {:?}",
                self.archive_format
            );
        }
        if self.compression != ARCHIVE_COMPRESSION {
            bail!(
                "artifact manifest compression must be {ARCHIVE_COMPRESSION}, not {:?}",
                self.compression
            );
        }
        if self.subscription_policy != SUBSCRIPTION_POLICY_DROPPED {
            bail!(
                "manifest subscription policy {:?} is not {SUBSCRIPTION_POLICY_DROPPED}: a restored \
                 subscription would start replicating from the database it was dumped from",
                self.subscription_policy
            );
        }
        let exported = match self.globals_policy.as_str() {
            GLOBALS_POLICY_EXPORTED => true,
            GLOBALS_POLICY_SKIPPED => false,
            other => bail!("manifest globals policy {other:?} is neither of the two known values"),
        };
        let globals_present =
            self.globals_sha256.is_some() || self.globals_ciphertext_bytes.is_some();
        if exported != globals_present {
            bail!(
                "manifest globals fields must be present exactly when globals_policy is exported"
            );
        }
        if !is_digest(&self.payload_ciphertext_sha256) {
            bail!(
                "manifest payload_ciphertext_sha256 must be {DIGEST_HEX_LEN} lowercase hex characters"
            );
        }
        for (field, value) in [
            ("globals_sha256", &self.globals_sha256),
            ("archive_toc_sha256", &self.archive_toc_sha256),
        ] {
            if let Some(digest) = value
                && !is_digest(digest)
            {
                bail!("manifest {field} must be {DIGEST_HEX_LEN} lowercase hex characters");
            }
        }
        if self.payload_ciphertext_bytes == 0 || self.archive_plaintext_bytes == 0 {
            bail!("manifest payload sizes must be non-zero");
        }
        if self.globals_ciphertext_bytes == Some(0) {
            bail!("manifest globals size must be non-zero");
        }
        if self.verification_level != VERIFICATION_NONE {
            bail!(
                "a published manifest records verification level {VERIFICATION_NONE}; {:?} cannot \
                 be true in signed bytes, because verifying an artifact after signing it would \
                 change what the signature covers",
                self.verification_level
            );
        }
        if self.compatibility_notes.len() > MAX_COMPATIBILITY_NOTES {
            bail!(
                "manifest carries {} compatibility notes, over the {MAX_COMPATIBILITY_NOTES} limit",
                self.compatibility_notes.len()
            );
        }
        for note in &self.compatibility_notes {
            if !is_bounded_text(note) {
                bail!("manifest compatibility notes must be short printable text");
            }
        }
        Ok(())
    }

    /// Checks a manifest this build is about to write. Stricter than [`Self::validate`] by
    /// exactly one thing: the suites must be the ones this build writes, so a code path
    /// that reaches for a classical suite fails at the writer instead of in the field.
    pub fn validate_writable(&self) -> Result<()> {
        self.validate()?;
        if !RECIPIENT_SUITES.contains(&self.recipient_suite.as_str()) {
            bail!(
                "this build never writes recipient suite {}",
                self.recipient_suite
            );
        }
        if !SIGNATURE_SUITES.contains(&self.signature_suite.as_str()) {
            bail!(
                "this build never writes signature suite {}",
                self.signature_suite
            );
        }
        Ok(())
    }

    /// Checks the manifest against the public header the reader trusted before decrypting.
    /// Every shared field must agree: a header and a manifest that disagree describe two
    /// different artifacts that happen to share a directory.
    pub fn matches_header(&self, header: &PublicHeader) -> Result<()> {
        if header.format_version != self.format_version {
            bail!("public header and manifest disagree on format_version");
        }
        if header.backup_id != self.backup_id {
            bail!("public header and manifest disagree on backup_id");
        }
        if header.recipient_id != self.recipient_id {
            bail!("public header and manifest disagree on recipient_id");
        }
        if header.signer_id != self.signer_id {
            bail!("public header and manifest disagree on signer_id");
        }
        if header.recipient_suite != self.recipient_suite {
            bail!("public header and manifest disagree on recipient_suite");
        }
        if header.signature_suite != self.signature_suite {
            bail!("public header and manifest disagree on signature_suite");
        }
        if header.payload_sha256 != self.payload_ciphertext_sha256 {
            bail!("public header and manifest disagree on the payload checksum");
        }
        if header.payload_ciphertext_bytes != self.payload_ciphertext_bytes {
            bail!("public header and manifest disagree on the payload size");
        }
        Ok(())
    }

    fn resolved_selection_validate(&self) -> Result<()> {
        let resolved = &self.resolved_selection;
        let whole = resolved.whole_database;
        if whole && (!resolved.schemas.is_empty() || !resolved.tables.is_empty()) {
            bail!("a whole-database resolved selection must not list objects");
        }
        if !whole && resolved.schemas.is_empty() && resolved.tables.is_empty() {
            bail!("a filtered resolved selection must list the objects it resolved to");
        }
        if whole != self.requested_selection.is_whole_database() {
            bail!("manifest selection changed scope between request and resolution");
        }
        if !whole {
            for object in resolved.schemas.iter().chain(&resolved.tables) {
                let requested = if object.contains('.') {
                    &self.requested_selection.tables
                } else {
                    &self.requested_selection.schemas
                };
                if !requested.iter().any(|name| name == object) {
                    bail!("manifest resolved {object} without it being requested");
                }
            }
        }
        Ok(())
    }
}

/// `public.json`: what `backup list` can say about an artifact while holding no keys.
///
/// It carries no database name, host, timestamp, SQL or secret, and the field set is
/// closed — an extra key is refused rather than ignored, so nothing can be smuggled in
/// beside the fields this type knows about. Paths are impossible by construction: the only
/// identifiers here are a UUID and two hex fingerprints, and the artifact directory is
/// chosen from the requested ID, never from this file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicHeader {
    pub format_version: u32,
    pub backup_id: Uuid,
    pub recipient_id: String,
    pub signer_id: String,
    pub recipient_suite: String,
    pub signature_suite: String,
    pub manifest_ciphertext_bytes: u64,
    pub payload_ciphertext_bytes: u64,
    pub manifest_sha256: String,
    pub payload_sha256: String,
}

impl PublicHeader {
    /// Parses the bounded discovery record. The size cap is checked against the text
    /// before `serde_json` is called, so an oversized file never reaches the parser.
    pub fn from_json(text: &str) -> Result<Self> {
        if text.len() > MAX_PUBLIC_JSON_BYTES {
            bail!(
                "public.json is {} bytes, over the {MAX_PUBLIC_JSON_BYTES} byte cap",
                text.len()
            );
        }
        let header: Self =
            serde_json::from_str(text).map_err(|e| anyhow::anyhow!("invalid public.json: {e}"))?;
        header.validate()?;
        Ok(header)
    }

    /// Serializes it, refusing to produce a record a reader would have to reject for its
    /// size rather than reporting the mistake where it was made.
    pub fn to_json(&self) -> Result<String> {
        self.validate()?;
        let text = serde_json::to_string(self)?;
        if text.len() > MAX_PUBLIC_JSON_BYTES {
            bail!(
                "public.json would be {} bytes, over the {MAX_PUBLIC_JSON_BYTES} byte cap",
                text.len()
            );
        }
        Ok(text)
    }

    /// Builds the discovery record for a manifest that has just been sealed to disk.
    ///
    /// A manifest cannot carry its own ciphertext digest — that number only exists once the
    /// encrypted bytes are written — so the header takes it as an argument. The two are then
    /// checked against each other here, which is what keeps a writer from publishing a header
    /// describing a different artifact than the one it signed.
    pub fn seal(
        manifest: &ArtifactManifest,
        manifest_sha256: &str,
        manifest_ciphertext_bytes: u64,
    ) -> Result<Self> {
        if !is_digest(manifest_sha256) {
            bail!(
                "sealed manifest digest must be {DIGEST_HEX_LEN} lowercase hex characters, not {manifest_sha256:?}"
            );
        }
        let header = Self {
            format_version: manifest.format_version,
            backup_id: manifest.backup_id,
            recipient_id: manifest.recipient_id.clone(),
            signer_id: manifest.signer_id.clone(),
            recipient_suite: manifest.recipient_suite.clone(),
            signature_suite: manifest.signature_suite.clone(),
            manifest_ciphertext_bytes,
            payload_ciphertext_bytes: manifest.payload_ciphertext_bytes,
            manifest_sha256: manifest_sha256.to_string(),
            payload_sha256: manifest.payload_ciphertext_sha256.clone(),
        };
        manifest.matches_header(&header)?;
        header.validate_writable_suites()?;
        Ok(header)
    }

    pub fn validate(&self) -> Result<()> {
        if self.format_version != ARTIFACT_FORMAT_VERSION {
            bail!(
                "unknown public.json format version {}, this build writes {ARTIFACT_FORMAT_VERSION}",
                self.format_version
            );
        }
        validate_backup_id(self.backup_id)?;
        for (field, value) in [
            ("recipient_id", &self.recipient_id),
            ("signer_id", &self.signer_id),
        ] {
            if !is_hex_id(value) {
                bail!("public.json {field} must be {ID_HEX_LEN} lowercase hex characters");
            }
        }
        if !READABLE_RECIPIENT_SUITES.contains(&self.recipient_suite.as_str()) {
            bail!(
                "public.json records unsupported recipient suite {}",
                self.recipient_suite
            );
        }
        if !READABLE_SIGNATURE_SUITES.contains(&self.signature_suite.as_str()) {
            bail!(
                "public.json records unsupported signature suite {}",
                self.signature_suite
            );
        }
        if self.manifest_ciphertext_bytes == 0 || self.payload_ciphertext_bytes == 0 {
            bail!("public.json ciphertext sizes must be non-zero");
        }
        for (field, value) in [
            ("manifest_sha256", &self.manifest_sha256),
            ("payload_sha256", &self.payload_sha256),
        ] {
            if !is_digest(value) {
                bail!("public.json {field} must be {DIGEST_HEX_LEN} lowercase hex characters");
            }
        }
        Ok(())
    }

    /// Refuses a header whose suites are readable but not writable, so a store cannot be
    /// talked into publishing a classical-only generation.
    pub fn validate_writable_suites(&self) -> Result<()> {
        self.validate()?;
        if !RECIPIENT_SUITES.contains(&self.recipient_suite.as_str()) {
            bail!(
                "this build never writes recipient suite {}",
                self.recipient_suite
            );
        }
        if !SIGNATURE_SUITES.contains(&self.signature_suite.as_str()) {
            bail!(
                "this build never writes signature suite {}",
                self.signature_suite
            );
        }
        Ok(())
    }
}

/// The manifest's `source_fingerprint`: a digest of where the dump came from, never the
/// address itself.
///
/// Two artifacts carry the same value exactly when they came from the same database on the
/// same major, which is what lets a reader refuse to restore an artifact written against a
/// different source than the one it is configured for. A plaintext `host:port/database` in a
/// manifest would answer a question no artifact file needs to answer, and the major is part
/// of the input because a 16 dump and an 18 dump of one database are not the same generation.
pub fn source_fingerprint(source: &Source, server_major: u32) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(SOURCE_FINGERPRINT_DOMAIN);
    for field in [
        ENGINE_POSTGRESQL,
        &server_major.to_string(),
        &source.host,
        &source.port.to_string(),
        &source.database,
    ] {
        hasher.update(field);
        // A length-separating byte: two configurations whose field boundaries differ by one
        // character must not hash to the same digest.
        hasher.update([0_u8]);
    }
    let digest = hasher.finalize();
    let mut text = String::with_capacity(ID_HEX_LEN);
    for byte in &digest[..ID_HEX_LEN / 2] {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

fn validate_backup_id(id: Uuid) -> Result<()> {
    // The writer allocates a random v4 and nothing else, so a nil or non-v4 id is not an
    // artifact this tool made. Rejecting it also rejects the empty and placeholder ids a
    // hand-edited directory tends to carry.
    if id.is_nil() {
        bail!("artifact backup id must not be the nil UUID");
    }
    if id.get_version_num() != 4 {
        bail!("artifact backup id must be a random (version 4) UUID");
    }
    Ok(())
}

fn validate_server_version(version: &str, major: u32) -> Result<()> {
    let Ok(number) = version.parse::<u32>() else {
        bail!("manifest source server version {version:?} is not a server_version_num");
    };
    // From PostgreSQL 10 on, `server_version_num` is `major * 10000 + minor`, so the
    // recorded major has to be derivable rather than merely plausible.
    if number / 10_000 != major {
        bail!("manifest server version {version} does not have major version {major}");
    }
    Ok(())
}

fn is_hex_id(value: &str) -> bool {
    is_lowercase_hex(value, ID_HEX_LEN)
}

fn is_digest(value: &str) -> bool {
    is_lowercase_hex(value, DIGEST_HEX_LEN)
}

fn is_lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Short, single-line, printable text. Version strings and compatibility notes are the
/// only free-text fields a manifest carries, and bounding them keeps a hostile or corrupted
/// file from turning a metadata field into a document.
fn is_bounded_text(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_TEXT_FIELD_CHARS
        && value.chars().all(|c| !c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use backup_crypto::protocol::{SUITE_HYBRID, SUITE_SIGNATURE_HYBRID};

    /// A field a manifest refuses, and the edit that makes it so.
    type BrokenField = (&'static str, fn(&mut ArtifactManifest));

    #[test]
    fn a_published_manifest_validates_and_is_writable() {
        let manifest = fixture::manifest_v1_fixture();
        assert!(manifest.validate().is_ok());
        assert!(manifest.validate_writable().is_ok());
    }

    /// The two records have closed field sets. An unknown key is refused rather than
    /// ignored, because a field a reader does not know about is a field it cannot check —
    /// and because this is the only place a path or a database name could be smuggled in.
    #[test]
    fn unknown_fields_are_refused_because_the_field_set_is_closed() {
        let manifest = fixture::manifest_v1_fixture();
        let mut value = serde_json::to_value(&manifest).unwrap();
        value.as_object_mut().unwrap().insert(
            "restore_command".to_string(),
            serde_json::json!("rm -rf /".to_string()),
        );
        let error = serde_json::from_value::<ArtifactManifest>(value)
            .expect_err("an unknown manifest field must not load");
        assert!(error.to_string().contains("restore_command"), "{error}");

        let header = public_header_fixture(&manifest);
        let mut value = serde_json::to_value(&header).unwrap();
        value.as_object_mut().unwrap().insert(
            "payload_path".to_string(),
            serde_json::json!("../payload.age".to_string()),
        );
        let text = serde_json::to_string(&value).unwrap();
        let error = PublicHeader::from_json(&text).expect_err("a path must not be accepted");
        assert!(error.to_string().contains("payload_path"), "{error}");
    }

    /// The contract's downgrade rule, in the type that holds it: a classical-only suite
    /// parses so a reader can name it, and no writer can choose it.
    #[test]
    fn classical_suites_are_readable_but_never_writable() {
        let mut manifest = fixture::manifest_v1_fixture();
        manifest.signature_suite = "ed25519".to_string();
        assert!(manifest.validate().is_ok());
        let error = manifest.validate_writable().unwrap_err().to_string();
        assert!(
            error.contains("never writes signature suite ed25519"),
            "{error}"
        );

        manifest.signature_suite = SIGNATURE_SUITES[0].to_string();
        manifest.recipient_suite = "x25519".to_string();
        assert!(manifest.validate().is_ok());
        let error = manifest.validate_writable().unwrap_err().to_string();
        assert!(
            error.contains("never writes recipient suite x25519"),
            "{error}"
        );

        let mut unknown = fixture::manifest_v1_fixture();
        unknown.recipient_suite = "mlkem768x25519-v1".to_string();
        let error = unknown.validate().unwrap_err().to_string();
        assert!(error.contains("mlkem768x25519-v1"), "{error}");
    }

    /// A suite name this crate allows and the name `backup-crypto` reports must not drift
    /// apart, or every artifact written is refused by its own manifest.
    #[test]
    fn writable_suites_are_the_names_the_crypto_adapter_writes() {
        assert_eq!(RECIPIENT_SUITES, &[SUITE_HYBRID]);
        assert_eq!(SIGNATURE_SUITES, &[SUITE_SIGNATURE_HYBRID]);
        assert!(READABLE_RECIPIENT_SUITES.contains(&SUITE_HYBRID));
        assert!(READABLE_SIGNATURE_SUITES.contains(&SUITE_SIGNATURE_HYBRID));
    }

    /// The fingerprint is the only way a v1 artifact binds itself to a source, so its input
    /// is fixed here by a golden value: changing the domain string or the field order would
    /// silently make every existing artifact look like it came from somewhere else.
    #[test]
    fn the_source_fingerprint_is_a_stable_digest_of_the_configured_source() {
        let source = fixture::config("backupctl_fixture_m1").source;
        let digest = source_fingerprint(&source, 16);
        assert_eq!(digest, "c1cb425f097b6522");
        assert!(is_hex_id(&digest));
        assert_eq!(source_fingerprint(&source, 16), digest);

        // Every field is load-bearing. A 16 dump and an 18 dump of one database are not the
        // same generation, and neither is the same database on another port or host.
        let mut on_other_port = source.clone();
        on_other_port.port = 5433;
        let mut on_other_host = source.clone();
        on_other_host.host = "localhost".to_string();
        let mut other_database = source.clone();
        other_database.database = "backupctl_fixture_other".to_string();
        for (label, other) in [
            ("major", (&source, 18_u32)),
            ("port", (&on_other_port, 16_u32)),
            ("host", (&on_other_host, 16_u32)),
            ("database", (&other_database, 16_u32)),
        ] {
            assert_ne!(
                source_fingerprint(other.0, other.1),
                digest,
                "a changed {label} must change the fingerprint"
            );
        }

        // Field boundaries are separated: moving one character from the host to the database
        // keeps the concatenation identical, so it must still change the digest.
        let mut shifted = source.clone();
        shifted.host = "127.0.0.12".to_string();
        shifted.database = "backupctl_fixture_3".to_string();
        assert_ne!(source_fingerprint(&shifted, 16), digest);
    }

    #[test]
    fn header_and_manifest_must_describe_one_artifact() {
        let manifest = fixture::manifest_v1_fixture();
        let header = public_header_fixture(&manifest);
        assert!(header.validate().is_ok());
        assert!(manifest.matches_header(&header).is_ok());

        let mut swapped_id = fixture::manifest_v1_fixture();
        swapped_id.backup_id = Uuid::new_v4();
        let error = swapped_id
            .matches_header(&header)
            .expect_err("two ids are two artifacts")
            .to_string();
        assert!(error.contains("backup_id"), "{error}");

        let mut changed_digest = public_header_fixture(&manifest);
        changed_digest.payload_sha256 = "f".repeat(DIGEST_HEX_LEN);
        let error = manifest
            .matches_header(&changed_digest)
            .expect_err("a payload digest that moved is a replaced payload")
            .to_string();
        assert!(error.contains("payload checksum"), "{error}");

        let mut downgraded_header = public_header_fixture(&manifest);
        downgraded_header.signature_suite = "ed25519".to_string();
        let error = manifest
            .matches_header(&downgraded_header)
            .expect_err("suite disagreement is a refusal, not a warning")
            .to_string();
        assert!(error.contains("signature_suite"), "{error}");

        let mut changed_size = public_header_fixture(&manifest);
        changed_size.payload_ciphertext_bytes += 1;
        assert!(manifest.matches_header(&changed_size).is_err());

        let mut changed_signer = public_header_fixture(&manifest);
        changed_signer.signer_id = "9".repeat(ID_HEX_LEN);
        assert!(manifest.matches_header(&changed_signer).is_err());
    }

    /// `public.json` is the only artifact file a keyless reader parses, so its bounds are
    /// enforced before and after parsing, and what it does not contain matters as much as
    /// what it does: no host, no database name, no timestamp, no SQL, no path.
    #[test]
    fn public_json_is_bounded_and_holds_nothing_locatable() {
        let manifest = fixture::manifest_v1_fixture();
        let header = public_header_fixture(&manifest);
        let text = header.to_json().unwrap();
        assert!(text.len() <= MAX_PUBLIC_JSON_BYTES);

        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "backup_id",
                "format_version",
                "manifest_ciphertext_bytes",
                "manifest_sha256",
                "payload_ciphertext_bytes",
                "payload_sha256",
                "recipient_id",
                "recipient_suite",
                "signature_suite",
                "signer_id"
            ]
        );
        assert!(!text.contains("backupctl_fixture"), "{text}");

        let oversized = format!("{}{}", " ".repeat(MAX_PUBLIC_JSON_BYTES + 1), text);
        let error = PublicHeader::from_json(&oversized)
            .expect_err("an oversized header must be refused before parsing")
            .to_string();
        assert!(error.contains("over the 4096 byte cap"), "{error}");

        let mut uppercase = header.clone();
        uppercase.payload_sha256 = uppercase.payload_sha256.to_uppercase();
        assert!(uppercase.validate().is_err());

        let mut path_shaped = header.clone();
        path_shaped.recipient_id = "../keys/recipient".to_string();
        assert!(path_shaped.validate().is_err());

        let mut empty = header.clone();
        empty.payload_ciphertext_bytes = 0;
        assert!(empty.validate().is_err());

        let mut unknown_version = header.clone();
        unknown_version.format_version = 2;
        let error = unknown_version.validate().unwrap_err().to_string();
        assert!(
            error.contains("unknown public.json format version 2"),
            "{error}"
        );

        let mut nil = header.clone();
        nil.backup_id = Uuid::nil();
        assert!(nil.validate().is_err());
        let mut first_made = header.clone();
        first_made.backup_id =
            Uuid::parse_str("2e1a7f2c-7b23-11ef-8c7a-4f2c9a1b3d7e").expect("a version 1 UUID");
        assert!(first_made.validate().is_err());
    }

    /// Each refusal names the field, because an operator reading this output is being told
    /// that bytes they were handed are not what this tool writes.
    #[test]
    fn manifest_shape_rules_are_refused_by_name() {
        let cases: Vec<BrokenField> = vec![
            ("engine", |m| m.engine = "mysql".to_string()),
            ("archive format", |m| m.archive_format = "plain".to_string()),
            ("compression", |m| m.compression = "zstd".to_string()),
            ("subscription", |m| {
                m.subscription_policy = "kept".to_string()
            }),
            ("verification level", |m| {
                m.verification_level = "restore-tested".to_string()
            }),
            ("server version", |m| {
                m.source_server_version = "170002".to_string()
            }),
            ("source server version", |m| {
                m.source_server_version = "not-a-number".to_string()
            }),
            ("source major", |m| m.source_server_major = 15),
            ("format version", |m| m.format_version = 7),
            ("signer_id", |m| m.signer_id = "B".repeat(ID_HEX_LEN)),
            ("dump_client_version", |m| {
                m.dump_client_version = "x".repeat(MAX_TEXT_FIELD_CHARS + 1)
            }),
            ("started_at_utc", |m| {
                m.started_at_utc = "2025-09-27 20:26:40".to_string()
            }),
            ("completed before", |m| {
                m.completed_at_utc = fixture::timestamp(1_759_000_000_000 - 1);
            }),
            ("payload_ciphertext_sha256", |m| {
                m.payload_ciphertext_sha256 = "d".repeat(DIGEST_HEX_LEN - 1);
            }),
            ("payload sizes", |m| m.payload_ciphertext_bytes = 0),
            ("compatibility notes", |m| {
                m.compatibility_notes = vec!["n".repeat(MAX_TEXT_FIELD_CHARS + 1)];
            }),
        ];
        for (expected, break_it) in cases {
            let mut manifest = fixture::manifest_v1_fixture();
            break_it(&mut manifest);
            let error = match manifest.validate() {
                Ok(()) => panic!("{expected} must be refused"),
                Err(error) => error.to_string(),
            };
            assert!(
                !error.is_empty() && error.contains(expected),
                "{expected}: {error}"
            );
        }

        let mut too_many_notes = fixture::manifest_v1_fixture();
        too_many_notes.compatibility_notes = (0..=MAX_COMPATIBILITY_NOTES)
            .map(|i| format!("note {i}"))
            .collect();
        assert!(
            too_many_notes
                .validate()
                .unwrap_err()
                .to_string()
                .contains("compatibility notes")
        );
    }

    #[test]
    fn globals_fields_follow_the_policy() {
        let mut exported = fixture::manifest_v1_fixture();
        exported.globals_policy = GLOBALS_POLICY_EXPORTED.to_string();
        let error = exported.validate().unwrap_err().to_string();
        assert!(
            error.contains("exactly when globals_policy is exported"),
            "{error}"
        );

        exported.globals_sha256 = Some("9".repeat(DIGEST_HEX_LEN));
        exported.globals_ciphertext_bytes = Some(1024);
        assert!(exported.validate().is_ok());

        exported.globals_ciphertext_bytes = Some(0);
        assert!(
            exported
                .validate()
                .unwrap_err()
                .to_string()
                .contains("non-zero")
        );
        exported.globals_ciphertext_bytes = Some(1024);

        exported.globals_sha256 = Some("not-hex".to_string());
        assert!(
            exported
                .validate()
                .unwrap_err()
                .to_string()
                .contains("globals_sha256")
        );

        let mut skipped = fixture::manifest_v1_fixture();
        skipped.globals_sha256 = Some("9".repeat(DIGEST_HEX_LEN));
        assert!(
            skipped
                .validate()
                .unwrap_err()
                .to_string()
                .contains("exactly")
        );

        let mut unknown = fixture::manifest_v1_fixture();
        unknown.globals_policy = "as-configured".to_string();
        assert!(
            unknown
                .validate()
                .unwrap_err()
                .to_string()
                .contains("globals policy")
        );
    }

    /// The recorded scope is the answer to "what did this dump contain", so a manifest
    /// cannot claim an object nobody asked for, nor flip between whole-database and
    /// filtered between the request and the resolution.
    #[test]
    fn selection_cannot_widen_between_request_and_resolution() {
        let mut widened = fixture::manifest_v1_fixture();
        widened
            .resolved_selection
            .schemas
            .push("reporting".to_string());
        let error = widened.validate().unwrap_err().to_string();
        assert!(error.contains("without it being requested"), "{error}");

        let mut flipped = fixture::manifest_v1_fixture();
        flipped.resolved_selection = ResolvedSelection {
            whole_database: true,
            schemas: Vec::new(),
            tables: Vec::new(),
            ..flipped.resolved_selection
        };
        let error = flipped.validate().unwrap_err().to_string();
        assert!(
            error.contains("changed scope between request and resolution"),
            "{error}"
        );

        // A whole-database selection that still lists objects is corrupt before it is a
        // scope change, and the two rules report differently.
        let mut listed_whole = fixture::manifest_v1_fixture();
        listed_whole.resolved_selection.whole_database = true;
        assert!(
            listed_whole
                .validate()
                .unwrap_err()
                .to_string()
                .contains("must not list objects")
        );

        let mut empty_filtered = fixture::manifest_v1_fixture();
        empty_filtered.resolved_selection.schemas = Vec::new();
        assert!(
            empty_filtered
                .validate()
                .unwrap_err()
                .to_string()
                .contains("must list the objects")
        );

        let mut wildcard = fixture::manifest_v1_fixture();
        wildcard.requested_selection.schemas = vec!["app*".to_string()];
        assert!(
            wildcard
                .validate()
                .unwrap_err()
                .to_string()
                .contains("requested schema")
        );
    }

    fn public_header_fixture(manifest: &ArtifactManifest) -> PublicHeader {
        fixture::public_header_fixture(manifest)
    }
}
