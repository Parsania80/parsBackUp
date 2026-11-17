//! Writable versioned offline commands use protected handles and source-free policies.
use crate::cli::{BackupCommand, VerifyLevel};
use crate::output::{Refusal, Reporter};
use anyhow::Result;
use backup_application::{ArtifactStore, SignedArtifactHandle};
use backup_domain::{Config, ConfigV1, Source};
use backup_local::{KeyUse, ProtectedRoot, open_protected_store};
use backup_postgres::PostgresAdapter;

pub(crate) fn run(config: ConfigV1, command: BackupCommand, report: &mut Reporter) -> Result<()> {
    let store = match &command {
        BackupCommand::List => ProtectedRoot::open(&config, false)?.keyless_store()?,
        BackupCommand::Verify {
            level: VerifyLevel::Signature,
            ..
        } => open_protected_store(&config, KeyUse::Signature)?,
        _ => open_protected_store(&config, KeyUse::Reader)?,
    };
    let engine = if let BackupCommand::Verify {
        id,
        level: VerifyLevel::Archive,
        ..
    } = &command
    {
        let major = store.open_signed(*id)?.manifest().source_server_major;
        let tools = config.tools.as_ref().ok_or(Refusal("CONFIG_INVALID"))?;
        PostgresAdapter::offline_for_major(
            &tools.client_bin_dir,
            major,
            std::time::Duration::from_secs(config.timeout_seconds),
        )?
    } else {
        PostgresAdapter
    };
    // No source credential or key path is projected into the legacy command/report
    // adapter. The supplied store owns custody, root pinning and resource limits.
    let fixture = Config {
        source: Source {
            host: "/unused".into(),
            port: 1,
            user: "unused".into(),
            database: "unused".into(),
            client_bin_dir: config
                .tools
                .as_ref()
                .map_or_else(|| "/unused".into(), |t| t.client_bin_dir.clone()),
            password_file: None,
        },
        storage: config.storage,
        encryption: None,
        signing: None,
        export_globals: false,
        profiles: config.profiles,
        timeout_seconds: config.timeout_seconds,
    };
    crate::backup::run_with_store(fixture, command, engine, Some(store), report)
}
