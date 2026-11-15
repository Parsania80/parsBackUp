use crate::cli::{InventoryCommand, JobCommand};
use crate::output::Reporter;
use anyhow::{Result, bail};
use backup_application::{InventoryService, JobInfo};
use backup_local::LocalInventory;
use serde_json::{Value, json};
use std::path::Path;

fn job_json(job: &JobInfo) -> Value {
    let mut value = json!({
        "job_id": job.job_id,
        "backup_id": job.backup_id,
        "source_fingerprint": job.source_fingerprint,
        "profile_fingerprint": job.profile_fingerprint,
        "state": job.state,
        "started_at_utc": job.started_at_utc,
        "updated_at_utc": job.updated_at_utc,
        "operation": job.operation,
        "target_fingerprint": job.target_fingerprint,
    });
    if let Some(ids) = &job.artifact_ids {
        value["artifact_ids"] = json!(ids);
    }
    value
}

fn print_job(job: &JobInfo) {
    if let Some(ids) = &job.artifact_ids {
        println!("artifacts={ids:?}");
    }
    println!(
        "{}  {}  {}  backup={}  source={}  profile={}  updated={}  operation={}  target={}",
        job.job_id,
        job.started_at_utc,
        job.state,
        job.backup_id
            .map_or_else(|| "unknown".to_owned(), |id| id.to_string()),
        job.source_fingerprint,
        job.profile_fingerprint.as_deref().unwrap_or("unknown"),
        job.updated_at_utc,
        job.operation.as_deref().unwrap_or("unknown"),
        job.target_fingerprint.as_deref().unwrap_or("unknown"),
    );
}

pub(crate) fn job(root: &Path, command: JobCommand, report: &mut Reporter) -> Result<()> {
    let json_output = report.is_json();
    let service = InventoryService::new(LocalInventory::open(root)?);
    match command {
        JobCommand::List => {
            let jobs = service.jobs()?;
            if json_output {
                report.data(json!({"jobs": jobs.iter().map(job_json).collect::<Vec<_>>(), "audit_recorded": false}))?;
            } else if jobs.is_empty() {
                println!("no jobs recorded");
            } else {
                for job in &jobs {
                    print_job(job);
                }
            }
        }
        JobCommand::Inspect { id } => {
            let job = service.job(id)?;
            if json_output {
                report.data(json!({"job": job_json(&job), "audit_recorded": false}))?;
            } else {
                print_job(&job);
            }
        }
    }
    if !json_output {
        println!("audit not recorded (read-only)");
    }
    Ok(())
}

pub(crate) fn inventory(
    root: &Path,
    command: InventoryCommand,
    report: &mut Reporter,
) -> Result<()> {
    let json_output = report.is_json();
    match command {
        InventoryCommand::Recover => {
            let recovery = backup_local::LocalStore::new(root.to_path_buf())?.recover()?;
            if json_output {
                report.data(json!({"claimed":recovery.claimed,
                    "interrupted":recovery.interrupted,"deleted":recovery.deleted,
                    "removed":recovery.removed,"refused":recovery.refused}))?;
            } else {
                crate::report::print_recovery(&recovery);
            }
            if !recovery.claimed {
                bail!("RETENTION_BUSY: store has active work");
            }
        }
        InventoryCommand::Verification { id } => {
            let service = InventoryService::new(LocalInventory::open(root)?);
            let events = service.verification_events(id)?;
            if json_output {
                let events: Vec<_> = events.iter().map(|e| json!({"backup_id":e.backup_id, "at_utc":e.at_utc, "level":e.level, "outcome":e.outcome, "payload_sha256":e.payload_sha256, "manifest_sha256":e.manifest_sha256, "current":e.current})).collect();
                report.data(json!({"events": events, "audit_recorded": false}))?;
            } else {
                for e in events {
                    println!(
                        "{}  {}  {}  current={}  payload={}  manifest={}",
                        e.at_utc,
                        e.level,
                        e.outcome,
                        e.current,
                        e.payload_sha256.as_deref().unwrap_or("unknown"),
                        e.manifest_sha256.as_deref().unwrap_or("unknown")
                    );
                }
                println!("audit not recorded (read-only)");
            }
        }
        InventoryCommand::Check => {
            let service = InventoryService::new(LocalInventory::open(root)?);
            let check = service.check()?;
            let valid = check.problems.is_empty();
            if json_output {
                report.data(json!({
                    "valid": valid,
                    "schema_version": check.schema_version,
                    "source_fingerprint": check.source_fingerprint,
                    "problems": check.problems,
                    "audit_recorded": false,
                }))?;
            } else {
                println!(
                    "inventory {} (schema {}, source {}; audit not recorded)",
                    if valid {
                        "structurally valid"
                    } else {
                        "structurally damaged"
                    },
                    check.schema_version,
                    check.source_fingerprint
                );
                for problem in &check.problems {
                    println!("{problem}");
                }
            }
            if !valid {
                bail!("INVENTORY_CORRUPT: structural integrity check failed");
            }
        }
        command @ (InventoryCommand::List | InventoryCommand::Reconcile) => {
            let reader = backup_local::LocalReconciler(root.to_path_buf());
            let discovery = match command {
                InventoryCommand::List => backup_application::discover(&reader)?,
                InventoryCommand::Reconcile => backup_application::reconcile(&reader)?,
                InventoryCommand::Check | InventoryCommand::Recover => unreachable!(),
                InventoryCommand::Verification { .. } => unreachable!(),
                InventoryCommand::Rebuild { .. } => unreachable!(),
                InventoryCommand::Adopt { .. } => unreachable!(),
            };
            if json_output {
                let entries: Vec<_> = discovery
                    .entries
                    .iter()
                    .map(|entry| {
                        json!({
                            "backup_id": entry.backup_id,
                            "shape": entry.shape,
                            "status": entry.status,
                            "reason": entry.reason,
                            "provenance": entry.provenance,
                        })
                    })
                    .collect();
                report.data(
                    json!({"entries": entries, "audit_recorded": discovery.audit_recorded}),
                )?;
            } else {
                for entry in discovery.entries {
                    println!(
                        "{}  {}  {}  {}  provenance={}",
                        entry
                            .backup_id
                            .map_or_else(|| "unknown".to_owned(), |id| id.to_string()),
                        entry.shape.unwrap_or("unknown"),
                        entry.status,
                        entry.reason.unwrap_or("-"),
                        entry.provenance.unwrap_or("unknown")
                    );
                }
            }
        }
        InventoryCommand::Adopt {
            id,
            source_fingerprint,
        } => {
            backup_local::LocalReconciler(root.to_path_buf()).adopt(id, &source_fingerprint)?;
            if json_output {
                report.data(json!({"backup_id": id, "source_fingerprint": source_fingerprint, "estate_provenance": "unconfirmed", "audit_recorded": true}))?;
            } else {
                println!("adopted {id}; source {source_fingerprint} is unconfirmed");
            }
        }
        InventoryCommand::Rebuild {
            source_fingerprint,
            dry_run: _,
            prepare_rebuild,
            confirm_rebuild,
            plan_id,
        } => {
            let scanner = backup_local::LocalReconciler(root.to_path_buf());
            let (discovery, previous_inventory, prepared_plan) = if confirm_rebuild {
                let (discovery, previous) =
                    scanner.rebuild(&source_fingerprint, plan_id.expect("clap requires a plan"))?;
                (discovery, previous, None)
            } else if prepare_rebuild {
                let (id, discovery) = scanner.prepare_rebuild(&source_fingerprint)?;
                (discovery, None, Some(id))
            } else {
                (scanner.preview_rebuild(&source_fingerprint)?, None, None)
            };
            if json_output {
                let entries: Vec<_> = discovery
                    .entries
                    .iter()
                    .map(|entry| {
                        json!({
                            "backup_id": entry.backup_id,
                            "shape": entry.shape,
                            "status": entry.status,
                            "reason": entry.reason,
                        "provenance": entry.provenance,
                        })
                    })
                    .collect();
                report.data(json!({
                        "source_fingerprint": source_fingerprint,
                        "entries": entries,
                        "estate_provenance": "unconfirmed",
                        "unknown_facts": ["source_provenance", "profile_fingerprint", "completed_at_utc", "verification"],
                        "lost_history": ["jobs", "audit", "protection", "verification", "rollback"],
                        "audit_recorded": discovery.audit_recorded,
                        "previous_inventory": previous_inventory,
                        "rebuilt": confirm_rebuild,
                        "plan_id": prepared_plan,
                    }))?;
            } else {
                println!(
                    "source {source_fingerprint} is unconfirmed; rebuild loses job, audit, protection, verification, and local rollback history"
                );
                for entry in discovery.entries {
                    println!(
                        "{}  {}  {}  {}",
                        entry
                            .backup_id
                            .map_or_else(|| "unknown".to_owned(), |id| id.to_string()),
                        entry.shape.unwrap_or("unknown"),
                        entry.status,
                        entry.reason.unwrap_or("-")
                    );
                }
                if confirm_rebuild {
                    println!(
                        "inventory rebuilt; previous inventory: {}",
                        previous_inventory
                            .as_ref()
                            .map_or_else(|| "none".to_owned(), |path| path.display().to_string())
                    );
                }
                if let Some(id) = prepared_plan {
                    println!("rebuild plan: {id}");
                }
            }
        }
    }
    Ok(())
}
