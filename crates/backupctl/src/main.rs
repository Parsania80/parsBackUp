//! The `backupctl` entry point: parse the configuration, dispatch one command,
//! and print either the human report (see `report`) or the JSON of the same
//! result. Argument types live in `cli`; nothing here computes domain rules.

mod cli;
mod report;

use crate::cli::{
    BackupCommand, Cli, ConfigCommand, KeyCommand, Output, ProfileCommand, RestoreCommand,
    SecurityPreset, TopCommand, VerifyLevel, key_json, sections_from, selection_json,
};
use crate::report::{
    print_backup_created, print_inspect, print_keys, print_plan, print_profile_scope,
    print_restore, print_selection, print_verify,
};
use anyhow::{Context, Result, anyhow, bail};
use backup_application::{BackupService, RestoreService, VerifyService};
use backup_domain::{Config, RestoreSecurityPolicy, VERIFY_ARCHIVE, VERIFY_CHECKSUM};
use backup_local::{LocalStore, generate_key_pair, key_status, publish_recipient};
use backup_postgres::PostgresAdapter;
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Full cause chain; engine output is deliberately withheld by the
            // adapter so this can never carry credentials or SQL data.
            eprintln!("error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

/// Opens the configured store.
///
/// Encryption is a property of the configuration rather than of a command: a config
/// without an `[encryption]` block writes the plaintext artifacts every earlier
/// milestone expects, and one with it seals every artifact to the configured recipient.
fn open_store(config: &Config) -> Result<LocalStore> {
    match &config.encryption {
        None => LocalStore::new(config.storage.root.clone()),
        Some(encryption) => LocalStore::with_keys(
            config.storage.root.clone(),
            &encryption.identity_file,
            &encryption.recipient_file,
        ),
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let json = matches!(cli.output, Output::Json);
    let config_path = cli.config.as_ref().context("--config is required")?;
    let content = std::fs::read_to_string(config_path).context("read configuration file")?;
    // Never render the TOML error: its source snippet repeats field values,
    // which must not reach CLI output or logs.
    let config: Config = toml::from_str(&content)
        .map_err(|_| anyhow!("invalid configuration; expected M3 TOML fields"))?;
    config.validate()?;
    match cli.command {
        TopCommand::Config {
            command: ConfigCommand::Check,
        } => {
            if json {
                println!("{{\"valid\":true,\"mode\":\"synthetic-only\"}}");
            } else {
                println!("configuration valid (synthetic-only mode)");
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
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "identity": key_json("identity", &identity),
                        "recipient": key_json("recipient", &recipient),
                    }))?
                );
            } else {
                print_keys(&identity, &recipient);
            }
        }
        TopCommand::Profile { command } => match command {
            ProfileCommand::List => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&config.profiles)?);
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
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "profile": profile,
                            "source_major": info.source_major,
                            "selection": selection_json(&selection),
                        }))?
                    );
                } else {
                    print_profile_scope(profile);
                    println!("resolves against source major {}", info.source_major);
                    print_selection(&selection);
                }
            }
        },
        TopCommand::Backup { command } => {
            let store = open_store(&config)?;
            let service = BackupService::new(PostgresAdapter, store);
            match command {
                BackupCommand::Create {
                    confirm_synthetic,
                    profile,
                    dry_run,
                } => {
                    if dry_run {
                        let (info, selection) = service.resolve(&config, profile.as_deref())?;
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "profile": profile,
                                    "source_major": info.source_major,
                                    "client_version": info.dump_client_version,
                                    "selection": selection_json(&selection),
                                }))?
                            );
                        } else {
                            println!(
                                "resolved scope for source major {} (nothing written)",
                                info.source_major
                            );
                            print_selection(&selection);
                        }
                        return Ok(());
                    }
                    if !confirm_synthetic {
                        bail!(
                            "backup create requires --confirm-synthetic; never use this plaintext format for real data"
                        );
                    }
                    if config.export_globals && config.encryption.is_none() && !json {
                        eprintln!(
                            "warning: globals.sql holds cluster role definitions (never password verifiers) in plaintext; configure [encryption] to seal it"
                        );
                    }
                    let manifest = service.create(&config, profile.as_deref())?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&manifest)?);
                    } else {
                        print_backup_created(&manifest);
                    }
                }
                BackupCommand::List => {
                    let manifests = service.list()?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&manifests)?);
                    } else {
                        for item in manifests {
                            println!("{}  {}  {} bytes", item.id, item.database, item.size_bytes);
                        }
                    }
                }
                BackupCommand::Inspect { id } => {
                    let manifest = service.inspect(id)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&manifest)?);
                    } else {
                        print_inspect(manifest);
                    }
                }
                BackupCommand::Verify { id, level } => {
                    let store = open_store(&config)?;
                    let service = VerifyService::new(PostgresAdapter, store);
                    let level_name = match level {
                        VerifyLevel::Checksum => VERIFY_CHECKSUM,
                        VerifyLevel::Archive => VERIFY_ARCHIVE,
                    };
                    let report = service.verify(&config, id, level_name)?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "artifact_id": report.artifact_id,
                                "level": report.level,
                                "payload_size_bytes": report.payload_size_bytes,
                                "payload_sha256": report.payload_sha256,
                                "globals_size_bytes": report.globals_size_bytes,
                                "globals_sha256": report.globals_sha256,
                            }))?
                        );
                    } else {
                        print_verify(&report);
                    }
                }
            }
        }
        TopCommand::Restore { command } => {
            let store = open_store(&config)?;
            let service = RestoreService::new(PostgresAdapter, store);
            match command {
                RestoreCommand::Plan {
                    id,
                    target,
                    security,
                    sections,
                } => {
                    let policy = match security {
                        SecurityPreset::Dr => RestoreSecurityPolicy::dr_full(),
                        SecurityPreset::Portable => RestoreSecurityPolicy::portable(),
                    };
                    let plan =
                        service.plan(&config, id, &target, policy, sections_from(&sections))?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "plan": plan,
                                "digest": plan.digest(),
                            }))?
                        );
                    } else {
                        print_plan(&plan);
                    }
                }
                RestoreCommand::Run {
                    plan,
                    confirm_target,
                } => {
                    let executed = service.run(&config, plan, &confirm_target)?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "plan_id": executed.plan.id,
                                "digest": executed.plan.digest(),
                                "artifact_id": executed.plan.artifact_id,
                                "target_database": executed.plan.target_database,
                                "sections": executed.plan.sections,
                                "security": executed.plan.security,
                                "verification_level": executed.verification_level,
                            }))?
                        );
                    } else {
                        print_restore(&executed);
                    }
                }
            }
        }
    }
    Ok(())
}
