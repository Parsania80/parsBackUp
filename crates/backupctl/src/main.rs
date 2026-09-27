//! The `backupctl` entry point: parse the configuration, dispatch one command,
//! and print either the human report (see `report`) or the JSON of the same
//! result. Argument types live in `cli`; nothing here computes domain rules.

mod cli;
mod report;

use crate::cli::{
    BackupCommand, Cli, ConfigCommand, Output, ProfileCommand, RestoreCommand, SecurityPreset,
    TopCommand, VerifyLevel, sections_from, selection_json,
};
use crate::report::{
    print_backup_created, print_inspect, print_plan, print_profile_scope, print_restore,
    print_selection, print_verify,
};
use anyhow::{Context, Result, anyhow, bail};
use backup_application::{BackupService, RestoreService, VerifyService};
use backup_domain::{Config, RestoreSecurityPolicy, VERIFY_ARCHIVE, VERIFY_CHECKSUM};
use backup_local::LocalStore;
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
                let store = LocalStore::new(config.storage.root.clone())?;
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
            let store = LocalStore::new(config.storage.root.clone())?;
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
                    if config.export_globals && !json {
                        eprintln!(
                            "warning: globals.sql contains cluster role definitions (without password verifiers) and is plaintext until M4"
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
                    let store = LocalStore::new(config.storage.root.clone())?;
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
            let store = LocalStore::new(config.storage.root.clone())?;
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
