//! Shared test builders. Their values stay literal on purpose: they are the
//! independent check that the protocol consts and the validators agree.
use crate::artifact::DevelopmentManifest;
use crate::config::{Config, Source, Storage};
use crate::profile::{Profile, SelectionMode};
use crate::protocol::{DEV_FORMAT, PLAN_FORMAT};
use crate::restore::{RestorePlan, RestoreSections, RestoreSecurityPolicy};
use std::path::PathBuf;
use uuid::Uuid;

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
