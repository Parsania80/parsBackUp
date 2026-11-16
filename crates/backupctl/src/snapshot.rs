//! Versioned snapshot reads never pass through writable legacy constructors.
use crate::cli::{
    BackupCommand, InventoryCommand, TopCommand, VerifyLevel, json_inventory, json_record,
};
use crate::output::{Refusal, Reporter, refuse};
use anyhow::Result;
use backup_domain::{Config, ConfigV1, Source, VERIFY_ARCHIVE, VERIFY_CHECKSUM, VERIFY_SIGNATURE};
use backup_local::{SnapshotReader, SnapshotUse};
use backup_postgres::PostgresAdapter;

pub(crate) fn run(config: ConfigV1, command: TopCommand, report: &mut Reporter) -> Result<()> {
    let usage = match &command {
        TopCommand::Backup {
            command:
                BackupCommand::Inspect { .. }
                | BackupCommand::Verify {
                    level: VerifyLevel::Checksum | VerifyLevel::Archive,
                    ..
                },
        } => SnapshotUse::Authenticated,
        TopCommand::Backup {
            command: BackupCommand::Verify { .. },
        } => SnapshotUse::Signature,
        _ => SnapshotUse::Discovery,
    };
    let reader = SnapshotReader::open(&config, usage)?;
    match command {
        TopCommand::Backup {
            command: BackupCommand::List,
        } => {
            let inventory = backup_application::Inventory::Public(reader.list()?);
            if report.is_json() {
                report.data(json_inventory(&inventory)?)?;
            } else {
                crate::report::print_inventory(&inventory);
            }
        }
        TopCommand::Backup {
            command: BackupCommand::Inspect { id },
        } => {
            let record = backup_application::Record::Signed(Box::new(reader.inspect(id)?));
            if report.is_json() {
                report.data(json_record(&record)?)?;
            } else {
                crate::report::print_inspect(&record);
            }
        }
        TopCommand::Backup {
            command: BackupCommand::Verify { id, level, .. },
        } => {
            // Deliberately do not project config.source or any credential/key path.
            let tool_dir = config
                .tools
                .as_ref()
                .map(|t| t.client_bin_dir.clone())
                .unwrap_or_else(|| "/unused".into());
            let engine = if matches!(level, VerifyLevel::Archive) {
                let major = reader.inspect(id)?.source_server_major;
                let tools = config.tools.as_ref().ok_or(Refusal("CONFIG_INVALID"))?;
                PostgresAdapter::offline_for_major(
                    &tools.client_bin_dir,
                    major,
                    std::time::Duration::from_secs(config.timeout_seconds),
                )?
            } else {
                PostgresAdapter
            };
            let fixture = Config {
                source: Source {
                    host: "/unused".into(),
                    port: 1,
                    user: "unused".into(),
                    database: "unused".into(),
                    client_bin_dir: tool_dir,
                    password_file: None,
                },
                storage: config.storage,
                encryption: None,
                signing: None,
                profiles: Vec::new(),
                export_globals: false,
                timeout_seconds: config.timeout_seconds,
            };
            let level = match level {
                VerifyLevel::Signature => VERIFY_SIGNATURE,
                VerifyLevel::Checksum => VERIFY_CHECKSUM,
                VerifyLevel::Archive => VERIFY_ARCHIVE,
            };
            let verification = reader.verify(engine, &fixture, id, level)?;
            crate::backup::report_verification(&verification, report)?;
        }
        TopCommand::Inventory {
            command: InventoryCommand::List,
        } => {
            crate::inventory::report_discovery(reader.discover_inventory()?, report)?;
        }
        TopCommand::Inventory { command } => {
            crate::inventory::inventory_snapshot(reader.root(), command, report)?
        }
        TopCommand::Job { command } => {
            crate::inventory::job_snapshot(reader.root(), command, report)?
        }
        _ => return refuse("CAPABILITY_NOT_ENABLED"),
    }
    Ok(())
}
