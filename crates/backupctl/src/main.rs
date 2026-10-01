//! The `backupctl` entry point: parse the configuration, dispatch one command,
//! and print either the human report (see `report`) or the JSON of the same
//! result. Argument types live in `cli`; nothing here computes domain rules.

mod cli;
mod report;

use crate::cli::{
    BackupCommand, Cli, ConfigCommand, KeyCommand, Output, ProfileCommand, RestoreCommand,
    SecurityPreset, TopCommand, VerifyLevel, json_created, json_inventory, json_record, key_json,
    sections_from, selection_json, signing_json,
};
use crate::report::{
    print_backup_created, print_inspect, print_inventory, print_keys, print_plan,
    print_profile_scope, print_restore, print_selection, print_signing_keys, print_verify,
};
use anyhow::{Context, Result, anyhow, bail};
use backup_application::{BackupService, RestoreService, VerifyService};
use backup_domain::{
    AGE_FORMAT, Config, DEV_FORMAT, RestoreSecurityPolicy, VERIFY_ARCHIVE, VERIFY_CHECKSUM,
    VERIFY_SIGNATURE,
};
use backup_local::{
    LocalStore, generate_key_pair, generate_signing_pair, key_status, publish_recipient,
    publish_verifying, signing_key_status,
};
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
                println!(
                    "{{\"valid\":true,\"mode\":\"synthetic-only\",\"encryption\":{encrypted},\"signing\":{signed},\"shape\":\"{shape}\"}}"
                );
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
                let mut report = serde_json::json!({
                    "identity": key_json("identity", &identity),
                    "recipient": key_json("recipient", &recipient),
                });
                if let Some(statuses) = &signing {
                    report["signing"] =
                        serde_json::Value::Array(statuses.iter().map(signing_json).collect());
                }
                println!("{}", serde_json::to_string_pretty(&report)?);
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
                            "backup create requires --confirm-synthetic; no format this build writes is \
                             trusted for real data until [signing] is configured, and the unsigned \
                             development formats stay refused for it"
                        );
                    }
                    if config.export_globals && config.encryption.is_none() && !json {
                        eprintln!(
                            "warning: globals.sql holds cluster role definitions (never password verifiers) in plaintext; configure [encryption] to seal it"
                        );
                    }
                    let created = service.create(&config, profile.as_deref())?;
                    if json {
                        let report = json_created(&created)?;
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        print_backup_created(&created);
                    }
                }
                BackupCommand::List => {
                    let inventory = service.list()?;
                    if json {
                        let report = json_inventory(&inventory)?;
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        print_inventory(&inventory);
                    }
                }
                BackupCommand::Inspect { id } => {
                    let record = service.inspect(id)?;
                    if json {
                        let report = json_record(&record)?;
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        print_inspect(&record);
                    }
                }
                BackupCommand::Verify { id, level } => {
                    let store = open_store(&config)?;
                    let service = VerifyService::new(PostgresAdapter, store);
                    let level_name = match level {
                        VerifyLevel::Signature => VERIFY_SIGNATURE,
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
                                "origin": report.origin.as_ref().map(|origin| serde_json::json!({
                                    "signer_id": origin.signer_id,
                                    "recipient_id": origin.recipient_id,
                                    "signature_suite": origin.signature_suite,
                                })),
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
                                "recorded_in_artifact": executed.recorded_in_artifact,
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
