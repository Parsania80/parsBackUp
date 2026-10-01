use crate::profile::{Profile, SelectionMode};
use crate::protocol::{
    AGE_FORMAT, ARCHIVE_COMPRESSION, ARCHIVE_FORMAT, BACKUP_STATUS, DEV_FORMAT, DIGEST_HEX_LEN,
    FIXTURE_PREFIX, RECIPIENT_SUITES, SUPPORTED_MAJORS, VERIFY_ARCHIVE, VERIFY_RESTORE_TESTED,
};
use crate::selection::ResolvedSelection;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The exact scope an artifact was built from, as recorded in its manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactScope {
    pub profile: String,
    pub mode: SelectionMode,
    pub requested_schemas: Vec<String>,
    pub requested_tables: Vec<String>,
    pub exclude_schemas: Vec<String>,
    pub exclude_tables: Vec<String>,
    pub exclude_extensions: Vec<String>,
    pub resolved_schemas: Vec<String>,
    pub resolved_tables: Vec<String>,
    pub large_objects: bool,
    pub whole_database: bool,
    pub extension_members: Vec<String>,
}

impl ArtifactScope {
    pub fn from_profile(profile: &Profile, resolved: &ResolvedSelection) -> Self {
        Self {
            profile: profile.name.clone(),
            mode: profile.mode,
            requested_schemas: profile.schemas.clone(),
            requested_tables: profile.tables.clone(),
            exclude_schemas: profile.exclude_schemas.clone(),
            exclude_tables: profile.exclude_tables.clone(),
            exclude_extensions: profile.exclude_extensions.clone(),
            resolved_schemas: resolved.schemas.clone(),
            resolved_tables: resolved.tables.clone(),
            large_objects: profile.large_objects,
            whole_database: resolved.whole_database,
            extension_members: resolved.extension_members.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.profile.is_empty() {
            bail!("manifest scope requires a profile name");
        }
        if self.whole_database
            && (!self.resolved_schemas.is_empty() || !self.resolved_tables.is_empty())
        {
            bail!("a whole-database scope must not list resolved objects");
        }
        if !self.whole_database
            && self.resolved_schemas.is_empty()
            && self.resolved_tables.is_empty()
        {
            bail!("a filtered scope must list the objects it resolved to");
        }
        if !self.requested_schemas.is_empty() && !self.requested_tables.is_empty() {
            bail!("manifest scope cannot request both schemas and tables");
        }
        Ok(())
    }

    /// The namespaces a restore target must hold even though the archive does
    /// not create them. A signed v1 manifest has no scope record — its resolved
    /// selection is the same fact — so both shapes reach this through one rule.
    pub fn restore_required_schemas(&self) -> Vec<String> {
        ResolvedSelection {
            whole_database: self.whole_database,
            schemas: self.resolved_schemas.clone(),
            tables: self.resolved_tables.clone(),
            ..Default::default()
        }
        .restore_required_schemas()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentManifest {
    pub format: String,
    pub id: Uuid,
    pub synthetic_only: bool,
    pub database: String,
    pub source_major: u32,
    pub source_version: String,
    pub dump_client_version: String,
    pub application_version: String,
    pub archive_format: String,
    pub compression: String,
    pub created_unix_ms: u128,
    pub size_bytes: u64,
    pub sha256: String,
    pub status: String,
    pub security_globals: bool,
    pub globals_sha256: Option<String>,
    pub globals_size_bytes: Option<u64>,
    pub verification_level: Option<String>,
    pub verified_unix_ms: Option<u128>,
    /// Absent means an unfiltered whole-database dump, which is what every
    /// pre-M3 artifact is.
    pub scope: Option<ArtifactScope>,
    pub toc_sha256: Option<String>,
    /// The suite the payload key was agreed under, or absent for an artifact whose
    /// payload is plaintext. A reader must take this from the manifest rather than
    /// guess from file sizes or stanza counts.
    pub recipient_suite: Option<String>,
    /// Plaintext archive bytes, recorded so a restore can bound how much it is
    /// willing to write before it has decrypted anything. Present exactly when
    /// `recipient_suite` is.
    pub payload_plaintext_bytes: Option<u64>,
}

impl DevelopmentManifest {
    pub fn validate_shape(&self) -> Result<()> {
        if (self.format != DEV_FORMAT && self.format != AGE_FORMAT)
            || !self.synthetic_only
            || !self.database.starts_with(FIXTURE_PREFIX)
            || !SUPPORTED_MAJORS.contains(&self.source_major)
            || self.archive_format != ARCHIVE_FORMAT
            || self.compression != ARCHIVE_COMPRESSION
            || self.status != BACKUP_STATUS
            || self.size_bytes == 0
            || self.sha256.len() != DIGEST_HEX_LEN
            || !self.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("invalid development manifest");
        }
        // The format tag and the recorded suite are two views of one fact, so a
        // manifest that disagrees with itself is corrupt rather than ambiguous.
        let encrypted = self.format == AGE_FORMAT;
        if encrypted != self.recipient_suite.is_some() {
            bail!("an artifact records a recipient suite exactly when its payload is encrypted");
        }
        if encrypted != self.payload_plaintext_bytes.is_some() {
            bail!("an encrypted artifact must record the plaintext size it decrypts to");
        }
        if let Some(suite) = &self.recipient_suite
            && !RECIPIENT_SUITES.contains(&suite.as_str())
        {
            bail!("manifest records unsupported recipient suite {suite}");
        }
        if self.payload_plaintext_bytes == Some(0) {
            bail!("manifest plaintext payload size must not be zero");
        }
        let globals_present = self.globals_sha256.is_some() || self.globals_size_bytes.is_some();
        if self.security_globals != globals_present {
            bail!("manifest globals fields must be present exactly when security_globals is set");
        }
        if let Some(sha) = &self.globals_sha256
            && (sha.len() != DIGEST_HEX_LEN || !sha.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            bail!("invalid manifest globals checksum");
        }
        if let Some(size) = self.globals_size_bytes
            && size == 0
        {
            bail!("manifest globals file must not be empty");
        }
        if let Some(level) = &self.verification_level
            && !matches!(level.as_str(), VERIFY_ARCHIVE | VERIFY_RESTORE_TESTED)
        {
            bail!("invalid manifest verification level");
        }
        if self.verified_unix_ms.is_some() != self.verification_level.is_some() {
            bail!("manifest verification fields must appear together");
        }
        if let Some(scope) = &self.scope {
            scope.validate()?;
        }
        if let Some(digest) = &self.toc_sha256
            && (digest.len() != DIGEST_HEX_LEN || !digest.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            bail!("invalid manifest table-of-contents checksum");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use crate::is_safe_created_schema_name;
    use backup_crypto::protocol::SUITE_HYBRID;

    /// A manifest states its encryption instead of leaving it to be inferred: the
    /// format tag, the suite, and the recorded plaintext size are one fact written in
    /// three places, so a manifest that disagrees with itself must not load.
    #[test]
    fn encrypted_manifests_record_the_suite_they_were_written_with() {
        let mut manifest = fixture::manifest_fixture();
        assert!(manifest.validate_shape().is_ok());

        manifest.format = AGE_FORMAT.to_string();
        let error = manifest.validate_shape().unwrap_err().to_string();
        assert!(error.contains("recipient suite"), "{error}");

        manifest.recipient_suite = Some(SUITE_HYBRID.to_string());
        let error = manifest.validate_shape().unwrap_err().to_string();
        assert!(error.contains("plaintext size"), "{error}");

        manifest.payload_plaintext_bytes = Some(4096);
        assert!(manifest.validate_shape().is_ok());

        manifest.payload_plaintext_bytes = Some(0);
        assert!(manifest.validate_shape().is_err());
        manifest.payload_plaintext_bytes = Some(4096);

        // A suite outside the accepted list is refused by name rather than worked
        // around by guessing from key sizes. `x25519` is age's classical suite: legal
        // in the contract's vocabulary, never written by this build.
        manifest.recipient_suite = Some("x25519".to_string());
        let error = manifest.validate_shape().unwrap_err().to_string();
        assert!(error.contains("x25519"), "{error}");

        // The plaintext format cannot carry a suite either.
        let mut marked = fixture::manifest_fixture();
        marked.recipient_suite = Some(SUITE_HYBRID.to_string());
        assert!(marked.validate_shape().is_err());
    }

    /// The suite names a manifest may record and the names the crypto adapter writes
    /// must not drift apart: an unlisted suite makes every new artifact unreadable.
    #[test]
    fn recorded_suites_are_the_suites_the_crypto_adapter_writes() {
        assert_eq!(RECIPIENT_SUITES.len(), 1);
        assert_eq!(RECIPIENT_SUITES[0], SUITE_HYBRID);
    }

    #[test]
    fn manifest_globals_and_verification_fields_are_consistent() {
        let mut manifest = fixture::manifest_fixture();
        assert!(manifest.validate_shape().is_ok());
        manifest.security_globals = true;
        assert!(manifest.validate_shape().is_err());
        manifest.globals_sha256 = Some("b".repeat(64));
        manifest.globals_size_bytes = Some(5);
        assert!(manifest.validate_shape().is_ok());
        manifest.verification_level = Some(VERIFY_RESTORE_TESTED.to_string());
        assert!(manifest.validate_shape().is_err());
        manifest.verified_unix_ms = Some(2);
        assert!(manifest.validate_shape().is_ok());
    }

    #[test]
    fn manifest_scope_records_requested_and_resolved_names() {
        let profile = fixture::profile("app-only");
        let resolved = ResolvedSelection {
            whole_database: false,
            schemas: vec!["app".to_string()],
            exclude_schemas: Vec::new(),
            tables: Vec::new(),
            exclude_tables: Vec::new(),
            dangling: Vec::new(),
            extension_members: vec!["hstore".to_string()],
        };
        let scope = ArtifactScope::from_profile(&profile, &resolved);
        assert_eq!(scope.requested_schemas, vec!["app".to_string()]);
        assert_eq!(scope.resolved_schemas, vec!["app".to_string()]);
        assert_eq!(scope.extension_members, vec!["hstore".to_string()]);
        assert!(scope.validate().is_ok());
        // A schema-based scope carries its own CREATE SCHEMA in the archive.
        assert!(scope.restore_required_schemas().is_empty());

        // A table-based scope names namespaces the restore must prepare.
        let table_scope = ArtifactScope {
            requested_tables: vec!["app.partitioned_events".to_string()],
            requested_schemas: Vec::new(),
            resolved_schemas: Vec::new(),
            resolved_tables: vec![
                "app.partitioned_events".to_string(),
                "app.partitioned_events_2025".to_string(),
                "aux.other".to_string(),
            ],
            ..scope.clone()
        };
        assert_eq!(
            table_scope.restore_required_schemas(),
            vec!["app".to_string(), "aux".to_string()]
        );
        assert!(is_safe_created_schema_name("app"));
        assert!(!is_safe_created_schema_name("pg_catalog"));
        assert!(!is_safe_created_schema_name("App"));
        assert!(!is_safe_created_schema_name("a*"));

        let empty = ArtifactScope {
            profile: "nothing".to_string(),
            mode: SelectionMode::SchemaAndData,
            requested_schemas: vec!["app".to_string()],
            requested_tables: Vec::new(),
            exclude_schemas: Vec::new(),
            exclude_tables: Vec::new(),
            exclude_extensions: Vec::new(),
            resolved_schemas: Vec::new(),
            resolved_tables: Vec::new(),
            large_objects: false,
            whole_database: false,
            extension_members: Vec::new(),
        };
        assert!(empty.validate().is_err());

        let both = ArtifactScope {
            whole_database: true,
            resolved_schemas: vec!["app".to_string()],
            ..empty.clone()
        };
        assert!(both.validate().is_err());

        let mut manifest = DevelopmentManifest {
            scope: Some(scope.clone()),
            toc_sha256: Some("c".repeat(64)),
            ..fixture::manifest_fixture()
        };
        assert!(manifest.validate_shape().is_ok());
        manifest.toc_sha256 = Some("not-hex".to_string());
        assert!(manifest.validate_shape().is_err());
    }
}
