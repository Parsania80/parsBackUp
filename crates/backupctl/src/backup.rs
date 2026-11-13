use crate::cli::{
    BackupCommand, DeletionCommand, VerifyLevel, json_created, json_inventory, json_record,
    selection_json,
};
use crate::open_store;
use crate::report::{
    print_backup_created, print_inspect, print_inventory, print_recovery, print_selection,
    print_verify,
};
use anyhow::{Result, bail};
use backup_application::{BackupService, VerifyService};
use backup_domain::{Config, VERIFY_ARCHIVE, VERIFY_CHECKSUM, VERIFY_SIGNATURE};
use backup_postgres::PostgresAdapter;

pub(crate) fn run(config: Config, command: BackupCommand, json: bool) -> Result<()> {
    match command {
        BackupCommand::Prune {
            command: Some(command),
            ..
        } => deletion(
            config,
            command,
            backup_domain::RetentionOperation::Prune,
            json,
        )?,
        BackupCommand::Delete {
            command: Some(command),
            ..
        } => deletion(
            config,
            command,
            backup_domain::RetentionOperation::Delete,
            json,
        )?,
        BackupCommand::Prune {
            keep_last,
            profile,
            command: None,
        } => {
            let name = match profile.as_deref() {
                Some(name) => &config.profile(name)?.name,
                None => backup_domain::WHOLE_DATABASE_PROFILE,
            };
            let request = backup_domain::RetentionRequest::Prune {
                keep_last: keep_last.expect("clap requires quota for preview"),
                profile_fingerprint: backup_domain::profile_fingerprint(name),
            };
            retention(config, request, json)?;
        }
        BackupCommand::Delete { id, command: None } => retention(
            config,
            backup_domain::RetentionRequest::Delete {
                backup_id: id.expect("clap requires ID for preview"),
            },
            json,
        )?,
        BackupCommand::Protect { id } | BackupCommand::Unprotect { id } => {
            let protected = matches!(command, BackupCommand::Protect { .. });
            let report = backup_application::InventoryService::new(backup_local::LocalProtection(
                config.storage.root.clone(),
            ))
            .set_protection(id, protected)?;
            let state = if report.protected {
                "protected"
            } else {
                "unprotected"
            };
            if json {
                if report.previous.is_none() && !report.protected {
                    eprintln!(
                        "prior protection was unknown; explicit unprotect establishes unprotected and cannot recover lost protection history"
                    );
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "backup_id": report.backup_id,
                        "protection": state,
                        "changed": report.changed,
                        "audit_recorded": report.changed,
                    }))?
                );
            } else {
                println!(
                    "{}: {} -> {} (changed={}, audit_recorded={})",
                    report.backup_id,
                    match report.previous {
                        None => "unknown",
                        Some(true) => "protected",
                        Some(false) => "unprotected",
                    },
                    state,
                    report.changed,
                    report.changed
                );
            }
        }
        BackupCommand::Create {
            confirm_synthetic,
            profile,
            dry_run,
        } => {
            let store = open_store(&config)?;
            // Recovery precedes the new scope claim and only runs for a real create.
            if !dry_run {
                let recovery = store.recover()?;
                if !json {
                    print_recovery(&recovery);
                }
            }
            let service = BackupService::new(PostgresAdapter, store);
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
            let inventory = BackupService::new(PostgresAdapter, open_store(&config)?).list()?;
            if json {
                let report = json_inventory(&inventory)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_inventory(&inventory);
            }
        }
        BackupCommand::Inspect { id } => {
            let record = BackupService::new(PostgresAdapter, open_store(&config)?).inspect(id)?;
            if json {
                let report = json_record(&record)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_inspect(&record);
            }
        }
        BackupCommand::Verify {
            id,
            level,
            read_only,
        } => {
            let store = open_store(&config)?;
            let service = VerifyService::new(PostgresAdapter, store);
            let level_name = match level {
                VerifyLevel::Signature => VERIFY_SIGNATURE,
                VerifyLevel::Checksum => VERIFY_CHECKSUM,
                VerifyLevel::Archive => VERIFY_ARCHIVE,
            };
            let report = if read_only {
                service.verify_read_only(&config, id, level_name)?
            } else {
                service.verify(&config, id, level_name)?
            };
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
                        "audit_recorded": report.audit_recorded,
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
    Ok(())
}

fn retention(config: Config, request: backup_domain::RetentionRequest, json: bool) -> Result<()> {
    let r = backup_application::preview_retention(&backup_local::LocalRetention(config), &request)?;
    let value = serde_json::json!({
        "operation": r.operation, "source_fingerprint": r.source_fingerprint,
        "profile_fingerprint": r.profile_fingerprint, "keep_last": r.keep_last,
        "candidates": r.candidates, "retained": r.retained, "excluded": r.excluded,
        "plan_id": r.plan_id, "digest": r.digest, "expires_unix_ms": r.expires_unix_ms,
        "audit_recorded": r.audit_recorded,
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Retention preview (no deletion):");
        println!("{}", serde_json::to_string_pretty(&value)?);
        println!(
            "Local history only: rebuild loses protection/deletion history; this digest is not rollback protection. No execution is enabled."
        );
    }
    Ok(())
}

fn deletion(
    config: Config,
    command: DeletionCommand,
    operation: backup_domain::RetentionOperation,
    json: bool,
) -> Result<()> {
    let DeletionCommand::Run {
        plan_id,
        confirm_digest,
    } = command;
    let outcome = backup_application::execute_deletion(
        &backup_local::LocalRetention(config),
        plan_id,
        operation,
        &confirm_digest,
    )?;
    let r = outcome.result;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "operation": r.operation, "plan_id": r.plan_id, "digest": r.digest, "job_id": r.job_id,
                "outcome": r.outcome, "completed": r.completed, "deleting": r.deleting, "pending": r.pending,
                "audit_recorded": r.audit_recorded,
            }))?
        );
    } else {
        println!(
            "{:?} plan={} digest={} job={} outcome={} completed={:?} deleting={:?} pending={:?} audit_recorded={}",
            operation,
            r.plan_id,
            r.digest,
            r.job_id,
            r.outcome,
            r.completed,
            r.deleting,
            r.pending,
            r.audit_recorded
        );
    }
    if let Some(code) = outcome.error {
        bail!("{code}: run inventory recover for started IDs; pending IDs require a new preview");
    }
    Ok(())
}
