//! Shared test builders. Their values stay literal on purpose: they are the
//! independent check that the protocol consts and the validators agree.
use crate::artifact::DevelopmentManifest;
use crate::artifact_v1::{ArtifactManifest, PublicHeader, RequestedSelection};
use crate::config::{Config, Source, Storage};
use crate::profile::{Profile, SelectionMode};
use crate::protocol::{
    ARCHIVE_COMPRESSION, ARCHIVE_FORMAT, ARTIFACT_FORMAT_VERSION, DEV_FORMAT, ENGINE_POSTGRESQL,
    GLOBALS_POLICY_SKIPPED, ID_HEX_LEN, PLAN_FORMAT, RECIPIENT_SUITES, SIGNATURE_SUITES,
    SUBSCRIPTION_POLICY_DROPPED, VERIFICATION_NONE,
};
use crate::restore::{RestorePlan, RestoreSections, RestoreSecurityPolicy};
use crate::selection::ResolvedSelection;
use crate::utc::format_utc;
use std::path::PathBuf;
use uuid::Uuid;

/// The timestamp form, from a fixed epoch: 2025-09-27T19:06:40Z.
pub(crate) fn timestamp(unix_ms: i128) -> String {
    format_utc(unix_ms).expect("fixture epoch is after 1970")
}

pub(crate) fn config(database: &str) -> Config {
    Config {
        source: Source {
            host: "127.0.0.1".to_string(),
            port: 5432,
            user: "fixture".to_string(),
            database: database.to_string(),
            client_bin_dir: PathBuf::from("/usr/lib/postgresql/16/bin"),
            password_file: None,
        },
        storage: Storage {
            root: PathBuf::from("/tmp/backupctl-fixture-test"),
        },
        export_globals: false,
        encryption: None,
        signing: None,
        timeout_seconds: 30,
        profiles: Vec::new(),
    }
}

pub(crate) fn profile(name: &str) -> Profile {
    Profile {
        name: name.to_string(),
        database: "backupctl_fixture_m1".to_string(),
        mode: SelectionMode::SchemaAndData,
        schemas: vec!["app".to_string()],
        exclude_schemas: Vec::new(),
        tables: Vec::new(),
        exclude_tables: Vec::new(),
        exclude_extensions: Vec::new(),
        large_objects: false,
    }
}

pub(crate) fn plan(target: &str, policy: RestoreSecurityPolicy) -> RestorePlan {
    RestorePlan {
        format: PLAN_FORMAT.to_string(),
        id: Uuid::new_v4(),
        artifact_id: Uuid::new_v4(),
        artifact_database: "backupctl_fixture_m1".to_string(),
        source_major: 16,
        client_version: "pg_restore (PostgreSQL) 16.4".to_string(),
        target_database: target.to_string(),
        security: policy,
        sections: RestoreSections::full(),
        artifact_scope: None,
        created_unix_ms: 1_000,
        expires_unix_ms: 2_000,
    }
}

pub(crate) fn manifest_fixture() -> DevelopmentManifest {
    DevelopmentManifest {
        format: DEV_FORMAT.to_string(),
        id: Uuid::new_v4(),
        synthetic_only: true,
        database: "backupctl_fixture_m1".to_string(),
        source_major: 16,
        source_version: "160004".to_string(),
        dump_client_version: "pg_dump (PostgreSQL) 16.4".to_string(),
        application_version: "0.1.0".to_string(),
        archive_format: "custom".to_string(),
        compression: "gzip".to_string(),
        created_unix_ms: 1,
        size_bytes: 10,
        sha256: "a".repeat(64),
        status: "complete".to_string(),
        security_globals: false,
        globals_sha256: None,
        globals_size_bytes: None,
        verification_level: None,
        verified_unix_ms: None,
        scope: None,
        toc_sha256: None,
        recipient_suite: None,
        payload_plaintext_bytes: None,
    }
}

/// A v1 manifest for a filtered, globals-free dump of the fixture database, holding the
/// same literal values a writer emits: suites from the writable lists, digests as repeated
/// hex characters, and one minute between start and completion.
pub(crate) fn manifest_v1_fixture() -> ArtifactManifest {
    let profile = profile("app-only");
    ArtifactManifest {
        format_version: ARTIFACT_FORMAT_VERSION,
        backup_id: Uuid::new_v4(),
        engine: ENGINE_POSTGRESQL.to_string(),
        source_server_major: 16,
        source_server_version: "160004".to_string(),
        dump_client_version: "pg_dump (PostgreSQL) 16.4".to_string(),
        application_version: "0.1.0".to_string(),
        recipient_id: "a".repeat(ID_HEX_LEN),
        signer_id: "b".repeat(ID_HEX_LEN),
        recipient_suite: RECIPIENT_SUITES[0].to_string(),
        signature_suite: SIGNATURE_SUITES[0].to_string(),
        started_at_utc: timestamp(1_759_000_000_000),
        completed_at_utc: timestamp(1_759_000_060_000),
        source_fingerprint: "c".repeat(ID_HEX_LEN),
        profile_snapshot: profile.clone(),
        requested_selection: RequestedSelection::from_profile(&profile),
        resolved_selection: ResolvedSelection {
            whole_database: false,
            schemas: vec!["app".to_string()],
            exclude_schemas: Vec::new(),
            tables: Vec::new(),
            exclude_tables: Vec::new(),
            dangling: Vec::new(),
            extension_members: vec!["hstore".to_string()],
        },
        archive_format: ARCHIVE_FORMAT.to_string(),
        compression: ARCHIVE_COMPRESSION.to_string(),
        subscription_policy: SUBSCRIPTION_POLICY_DROPPED.to_string(),
        globals_policy: GLOBALS_POLICY_SKIPPED.to_string(),
        globals_sha256: None,
        globals_ciphertext_bytes: None,
        payload_ciphertext_sha256: "d".repeat(64),
        payload_ciphertext_bytes: 4096,
        archive_plaintext_bytes: 8192,
        archive_toc_sha256: None,
        verification_level: VERIFICATION_NONE.to_string(),
        compatibility_notes: Vec::new(),
    }
}

/// The discovery record that matches `manifest`, sharing every field the two carry so a
/// test that breaks one of them is breaking a binding rather than a typo.
pub(crate) fn public_header_fixture(manifest: &ArtifactManifest) -> PublicHeader {
    PublicHeader {
        format_version: ARTIFACT_FORMAT_VERSION,
        backup_id: manifest.backup_id,
        recipient_id: manifest.recipient_id.clone(),
        signer_id: manifest.signer_id.clone(),
        recipient_suite: manifest.recipient_suite.clone(),
        signature_suite: manifest.signature_suite.clone(),
        manifest_ciphertext_bytes: 2048,
        payload_ciphertext_bytes: manifest.payload_ciphertext_bytes,
        manifest_sha256: "e".repeat(64),
        payload_sha256: manifest.payload_ciphertext_sha256.clone(),
    }
}
