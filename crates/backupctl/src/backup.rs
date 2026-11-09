use crate::cli::{
    BackupCommand, VerifyLevel, json_created, json_inventory, json_record, selection_json,
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
    let store = open_store(&config)?;
    // ADR 0004: this is the command that clears abandoned working directories, and it does
    // so before any scope is claimed — afterwards the dead job's row and the new one are
    // indistinguishable to the lock probe. A dry run writes nothing, so it removes nothing
    // either.
    if matches!(command, BackupCommand::Create { dry_run: false, .. }) {
        let recovery = store.recover()?;
        if !json {
            print_recovery(&recovery);
        }
    }
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
