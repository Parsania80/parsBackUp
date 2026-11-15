//! The `backupctl` entry point: parse the configuration, dispatch one command,
//! and print either the human report (see `report`) or the JSON of the same
//! result. Argument types live in `cli`; nothing here computes domain rules.

mod access;
mod backup;
mod cli;
mod configuration;
mod inventory;
mod keys;
mod native;
mod output;
mod report;

use crate::cli::{
    Cli, ConfigCommand, KeyCommand, ProfileCommand, RestoreCommand, SecurityPreset, TopCommand,
    key_json, sections_from, selection_json, signing_json,
};
use crate::output::{Refusal, Reporter};
use crate::report::{
    print_keys, print_plan, print_profile_scope, print_restore, print_selection, print_signing_keys,
};
use anyhow::{Result, anyhow};
use backup_application::{BackupService, RestoreService};
use backup_domain::{AGE_FORMAT, Config, DEV_FORMAT, RestoreSecurityPolicy};
use backup_local::{
    LocalStore, generate_key_pair, generate_signing_pair, key_status, publish_recipient,
    publish_verifying, signing_key_status,
};
use backup_postgres::PostgresAdapter;
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut report = Reporter::new(cli.output, cli.command.operation());
    let result = run(cli, &mut report);
    report.finish(result)
}

fn run(cli: Cli, report: &mut Reporter) -> Result<()> {
    let path = cli.config.as_ref().ok_or(Refusal("CONFIG_INVALID"))?;
    match configuration::load(path)? {
        configuration::Configuration::Legacy(config) => run_legacy(config, cli.command, report),
        configuration::Configuration::V1(config) => {
            access::run(config, cli.command, cli.output, report)
        }
    }
}

/// Opens the configured store.
///
/// Encryption and signing are properties of the configuration rather than of a command: a
/// config without `[encryption]` writes the plaintext artifacts every earlier milestone
/// expects, one with only that seals them, and adding `[signing]` makes every artifact a
/// signed v1. A `[signing]` block that names no `signing_key_file` opens the disaster-recovery
/// shape instead, which verifies and restores and can write nothing.
fn open_store(config: &Config) -> Result<LocalStore> {
    let root = config.storage.root.clone();
    let Some(encryption) = &config.encryption else {
        // Config validation refuses a [signing] block with no [encryption] to seal under.
        return LocalStore::new(root);
    };
    let Some(signing) = &config.signing else {
        return LocalStore::with_keys(root, &encryption.identity_file, &encryption.recipient_file);
    };
    match &signing.signing_key_file {
        Some(path) => LocalStore::with_signing_keys(
            root,
            &encryption.identity_file,
            &encryption.recipient_file,
            path,
            &signing.verifying_key_file,
        ),
        None => {
            LocalStore::for_reading(root, &encryption.identity_file, &signing.verifying_key_file)
        }
    }
}

fn run_legacy(config: Config, command: TopCommand, report: &mut Reporter) -> Result<()> {
    let json = report.is_json();
    match command {
        TopCommand::Config {
            command: ConfigCommand::Check,
        } => {
            let (encrypted, signed) = (config.encryption.is_some(), config.signing.is_some());
            // Which optional blocks are present is the only thing that decides what this
            // store writes, so `config check` reports the resulting shape instead of
            // leaving the operator to re-read the TOML after a backup has run.
            let blocks = match (encrypted, signed) {
                (true, true) => "[encryption] + [signing]",
                (true, false) => "[encryption]",
                (false, _) => "no key blocks",
            };
            let shape = if signed {
                "signed artifact v1"
            } else if encrypted {
                AGE_FORMAT
            } else {
                DEV_FORMAT
            };
            if json {
                report.data(serde_json::json!({"valid":true,"mode":"synthetic-only",
                    "encryption":encrypted,"signing":signed,"shape":shape}))?;
            } else {
                println!("configuration valid (synthetic-only mode)");
                println!("active blocks: {blocks}; this store writes: {shape}");
            }
        }
        TopCommand::Key { command } => {
            let encryption = config.encryption.as_ref().ok_or_else(|| {
                anyhow!(
                    "the configuration has no [encryption] block; key commands act on its \
                     identity_file and recipient_file paths"
                )
            })?;
            let (identity, recipient) = match command {
                KeyCommand::Generate => {
                    generate_key_pair(&encryption.identity_file, &encryption.recipient_file)?
                }
                KeyCommand::Publish => {
                    publish_recipient(&encryption.identity_file, &encryption.recipient_file)?
                }
                KeyCommand::Status => {
                    key_status(&encryption.identity_file, &encryption.recipient_file)?
                }
            };
            // The signing files are reported and acted on by the same command, because a
            // backup host needs both pairs correct before a single artifact is trustworthy.
            let signing = match (&config.signing, &command) {
                (None, _) => None,
                (Some(signing), KeyCommand::Status) => Some(signing_key_status(
                    signing.signing_key_file.as_deref(),
                    &signing.verifying_key_file,
                )?),
                (Some(signing), _) => {
                    let signing_key_file = signing.signing_key_file.as_ref().ok_or_else(|| {
                        anyhow!(
                            "this [signing] block configures no signing_key_file, so this host may verify \
                             but not produce a signing key; copy the verifying file here instead of generating"
                        )
                    })?;
                    let statuses = match command {
                        KeyCommand::Generate => {
                            generate_signing_pair(signing_key_file, &signing.verifying_key_file)?
                        }
                        _ => publish_verifying(signing_key_file, &signing.verifying_key_file)?,
                    };
                    Some(statuses)
                }
            };
            if json {
                let mut value = serde_json::json!({
                    "identity": key_json("identity", &identity),
                    "recipient": key_json("recipient", &recipient),
                });
                if let Some(statuses) = &signing {
                    value["signing"] =
                        serde_json::Value::Array(statuses.iter().map(signing_json).collect());
                }
                report.data(value)?;
            } else {
                print_keys(&identity, &recipient);
                if let Some(statuses) = &signing {
                    print_signing_keys(statuses);
                }
            }
        }
        TopCommand::Profile { command } => match command {
            ProfileCommand::List => {
                if json {
                    report.data(serde_json::to_value(&config.profiles)?)?;
                } else if config.profiles.is_empty() {
                    println!("no profiles configured");
                } else {
                    for profile in &config.profiles {
                        print_profile_scope(profile);
                    }
                }
            }
            ProfileCommand::Validate { name } => {
                let profile = config.profile(&name)?;
                // The live probe needs the same wiring as a backup, so a
                // profile is only truly valid against its configured database.
                let store = open_store(&config)?;
                let service = BackupService::new(PostgresAdapter, store);
                let (info, selection) = service.resolve(&config, Some(&name))?;
                if json {
                    report.data(serde_json::json!({
                        "profile": profile,
                        "source_major": info.source_major,
                        "selection": selection_json(&selection),
                    }))?;
                } else {
                    print_profile_scope(profile);
                    println!("resolves against source major {}", info.source_major);
                    print_selection(&selection);
                }
            }
        },
        TopCommand::Backup { command } => backup::run(config, command, report)?,
        TopCommand::Job { command } => inventory::job(&config.storage.root, command, report)?,
        TopCommand::Inventory { command } => {
            inventory::inventory(&config.storage.root, command, report)?
        }
        TopCommand::Restore { command } => {
            let store = open_store(&config)?;
            restore(&config, command, PostgresAdapter, store, report)?;
        }
    }
    Ok(())
}

pub(crate) fn restore(
    config: &Config,
    command: RestoreCommand,
    engine: PostgresAdapter,
    store: LocalStore,
    report: &mut Reporter,
) -> Result<()> {
    let json = report.is_json();
    let service = RestoreService::new(engine, store);
    match command {
        RestoreCommand::Plan {
            id,
            target,
            security,
            sections,
            acknowledge_older_snapshot,
        } => {
            let policy = match security {
                SecurityPreset::Dr => RestoreSecurityPolicy::dr_full(),
                SecurityPreset::Portable => RestoreSecurityPolicy::portable(),
            };
            let plan = service.plan_with_acknowledgement(
                config,
                id,
                &target,
                policy,
                sections_from(&sections),
                acknowledge_older_snapshot,
            )?;
            if json {
                report.data(serde_json::json!({
                    "plan": plan,
                    "digest": plan.digest(),
                }))?;
            } else {
                print_plan(&plan);
            }
        }
        RestoreCommand::Run {
            plan,
            confirm_target,
        } => {
            let executed = service.run(config, plan, &confirm_target)?;
            if json {
                report.data(serde_json::json!({
                    "plan_id": executed.plan.id,
                    "digest": executed.plan.digest(),
                    "artifact_id": executed.plan.artifact_id,
                    "target_database": executed.plan.target_database,
                    "sections": executed.plan.sections,
                    "security": executed.plan.security,
                    "verification_level": executed.verification_level,
                    "recorded_in_artifact": executed.recorded_in_artifact,
                }))?;
            } else {
                print_restore(&executed);
            }
        }
    }
    Ok(())
}
