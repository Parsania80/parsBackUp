//! Exhaustive command classification keeps authorization separate from availability.
//! Versioned writable offline backup reads and retention dispatch remain unavailable.
//! Authorized native, custody and snapshot commands dispatch to their explicit owners.
use crate::cli::*;
use crate::output::{Reporter, refuse};
use anyhow::Result;
use backup_domain::{Access, ConfigMode, ConfigV1};
use serde_json::json;

impl TopCommand {
    pub(crate) fn operation(&self) -> &'static str {
        match self {
            Self::Config {
                command: ConfigCommand::Check,
            } => "config.check",
            Self::Key { command } => match command {
                KeyCommand::Generate => "key.generate",
                KeyCommand::Publish => "key.publish",
                KeyCommand::Status => "key.status",
            },
            Self::Profile { command } => match command {
                ProfileCommand::List => "profile.list",
                ProfileCommand::Validate { .. } => "profile.validate",
            },
            Self::Job { command } => match command {
                JobCommand::List => "job.list",
                JobCommand::Inspect { .. } => "job.inspect",
            },
            Self::Inventory { command } => match command {
                InventoryCommand::Check => "inventory.check",
                InventoryCommand::List => "inventory.list",
                InventoryCommand::Verification { .. } => "inventory.verification",
                InventoryCommand::Reconcile => "inventory.reconcile",
                InventoryCommand::Recover => "inventory.recover",
                InventoryCommand::Adopt { .. } => "inventory.adopt",
                InventoryCommand::Rebuild { .. } => "inventory.rebuild",
            },
            Self::Restore { command } => match command {
                RestoreCommand::Plan { .. } => "restore.plan",
                RestoreCommand::Run { .. } => "restore.run",
            },
            Self::Backup { command } => match command {
                BackupCommand::Create { .. } => "backup.create",
                BackupCommand::List => "backup.list",
                BackupCommand::Inspect { .. } => "backup.inspect",
                BackupCommand::Verify { .. } => "backup.verify",
                BackupCommand::Protect { .. } => "backup.protect",
                BackupCommand::Unprotect { .. } => "backup.unprotect",
                BackupCommand::Prune { command: None, .. } => "backup.prune",
                BackupCommand::Prune {
                    command: Some(_), ..
                } => "backup.prune.run",
                BackupCommand::Delete { command: None, .. } => "backup.delete",
                BackupCommand::Delete {
                    command: Some(_), ..
                } => "backup.delete.run",
            },
        }
    }
    fn permitted(&self, access: Access) -> bool {
        let private = matches!(access, Access::Writer | Access::Reader);
        let maintenance = access != Access::Public;
        match self {
            Self::Config { .. }
            | Self::Key {
                command: KeyCommand::Status,
            }
            | Self::Job { .. } => true,
            Self::Key { .. } => access == Access::Writer,
            Self::Profile { .. } | Self::Restore { .. } => private,
            Self::Inventory { command } => match command {
                InventoryCommand::Check
                | InventoryCommand::List
                | InventoryCommand::Verification { .. } => true,
                InventoryCommand::Reconcile
                | InventoryCommand::Recover
                | InventoryCommand::Adopt { .. }
                | InventoryCommand::Rebuild { .. } => maintenance,
            },
            Self::Backup { command } => match command {
                BackupCommand::Create { .. } => access == Access::Writer,
                BackupCommand::Protect { .. } | BackupCommand::Unprotect { .. } => maintenance,
                BackupCommand::List => access != Access::Inventory,
                BackupCommand::Verify {
                    level: VerifyLevel::Signature,
                    ..
                } => access != Access::Inventory,
                BackupCommand::Inspect { .. }
                | BackupCommand::Verify { .. }
                | BackupCommand::Prune { .. }
                | BackupCommand::Delete { .. } => private,
            },
        }
    }
    fn snapshot_safe(&self) -> bool {
        matches!(
            self,
            Self::Config { .. }
                | Self::Key {
                    command: KeyCommand::Status
                }
                | Self::Profile {
                    command: ProfileCommand::List
                }
                | Self::Job { .. }
                | Self::Inventory {
                    command: InventoryCommand::Check
                        | InventoryCommand::List
                        | InventoryCommand::Verification { .. }
                }
                | Self::Backup {
                    command: BackupCommand::List
                        | BackupCommand::Inspect { .. }
                        | BackupCommand::Verify { .. }
                }
        )
    }
}

pub(crate) fn run(
    config: ConfigV1,
    command: TopCommand,
    output: Output,
    report: &mut Reporter,
) -> Result<()> {
    if config.mode == ConfigMode::Production && matches!(output, Output::Json) {
        return refuse("OUTPUT_FORMAT_UNSUPPORTED");
    }
    if matches!(command, TopCommand::Config { .. }) {
        let value = json!({"valid": true, "config_version": 1, "mode": config.mode.as_str(),
            "access": config.access.as_str(), "read_only": config.read_only, "production_enabled": false});
        if report.is_json() {
            report.data(value)?;
        } else {
            println!(
                "configuration valid ({} mode; production disabled)",
                config.mode.as_str()
            );
        }
        return Ok(());
    }
    if config.mode == ConfigMode::Production {
        return refuse("PRODUCTION_NOT_ENABLED");
    }
    if !command.permitted(config.access) {
        return refuse("ACCESS_DENIED");
    }
    if config.read_only && !command.snapshot_safe() {
        return refuse("READ_ONLY");
    }
    if matches!(
        command,
        TopCommand::Profile {
            command: ProfileCommand::List
        }
    ) {
        if report.is_json() {
            report.data(serde_json::to_value(&config.profiles)?)?;
        } else if config.profiles.is_empty() {
            println!("no profiles configured");
        } else {
            for profile in &config.profiles {
                crate::report::print_profile_scope(profile);
            }
        }
        return Ok(());
    }
    if let TopCommand::Key { command } = command {
        return crate::keys::run(&config, command, report);
    }
    // Snapshot readers must never enter the legacy lock/scratch path, even for inventory.
    if config.read_only {
        return crate::snapshot::run(config, command, report);
    }
    if matches!(
        command,
        TopCommand::Profile {
            command: ProfileCommand::Validate { .. }
        } | TopCommand::Backup {
            command: BackupCommand::Create { .. }
        } | TopCommand::Restore { .. }
    ) {
        if matches!(command, TopCommand::Restore { .. }) {
            existing_reader_root(&config)?;
        }
        return crate::native::run(config, command, report);
    }
    let store_command = matches!(
        command,
        TopCommand::Job { .. }
            | TopCommand::Inventory { .. }
            | TopCommand::Backup {
                command: BackupCommand::Protect { .. } | BackupCommand::Unprotect { .. }
            }
    );
    let guard = if store_command {
        Some(backup_local::ProtectedRoot::open(&config, false)?)
    } else {
        None
    };
    let root = guard
        .as_ref()
        .map_or(config.storage.root.as_path(), |g| g.path());
    match command {
        TopCommand::Job { command } => {
            existing_reader_root(&config)?;
            crate::inventory::job(root, command, report)
        }
        TopCommand::Inventory { command } => {
            existing_reader_root(&config)?;
            let store = if matches!(command, InventoryCommand::Recover) {
                Some(guard.as_ref().unwrap().keyless_store()?)
            } else {
                None
            };
            crate::inventory::inventory_with_store(
                root,
                command,
                store,
                Some(&config.storage.root),
                report,
            )
        }
        TopCommand::Backup {
            command: BackupCommand::Protect { id },
        } => {
            existing_reader_root(&config)?;
            crate::backup::protection(root, id, true, report)
        }
        TopCommand::Backup {
            command: BackupCommand::Unprotect { id },
        } => {
            existing_reader_root(&config)?;
            crate::backup::protection(root, id, false, report)
        }
        _ => refuse("CAPABILITY_NOT_ENABLED"),
    }
}
fn existing_reader_root(config: &ConfigV1) -> Result<()> {
    if config.access == Access::Reader && !config.storage.root.is_dir() {
        return refuse("CONFIG_INVALID");
    }
    Ok(())
}
