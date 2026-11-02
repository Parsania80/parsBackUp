use crate::cli::{InventoryCommand, JobCommand};
use anyhow::{Result, bail};
use backup_application::{InventoryService, JobInfo};
use backup_domain::Config;
use backup_local::LocalInventory;
use serde_json::{Value, json};

fn job_json(job: &JobInfo) -> Value {
    json!({
        "job_id": job.job_id,
        "backup_id": job.backup_id,
        "source_fingerprint": job.source_fingerprint,
        "profile_fingerprint": job.profile_fingerprint,
        "state": job.state,
        "started_at_utc": job.started_at_utc,
        "updated_at_utc": job.updated_at_utc,
        "operation": null,
    })
}

fn print_job(job: &JobInfo) {
    println!(
        "{}  {}  {}  backup={}  source={}  profile={}  updated={}  operation=unknown",
        job.job_id,
        job.started_at_utc,
        job.state,
        job.backup_id
            .map_or_else(|| "unknown".to_owned(), |id| id.to_string()),
        job.source_fingerprint,
        job.profile_fingerprint,
        job.updated_at_utc,
    );
}

pub(crate) fn job(config: &Config, command: JobCommand, json_output: bool) -> Result<()> {
    let service = InventoryService::new(LocalInventory::open(&config.storage.root)?);
    match command {
        JobCommand::List => {
            let jobs = service.jobs()?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"jobs": jobs.iter().map(job_json).collect::<Vec<_>>(), "audit_recorded": false})
                    )?
                );
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
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"job": job_json(&job), "audit_recorded": false})
                    )?
                );
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
    config: &Config,
    command: InventoryCommand,
    json_output: bool,
) -> Result<()> {
    match command {
        InventoryCommand::Check => {
            let service = InventoryService::new(LocalInventory::open(&config.storage.root)?);
            let check = service.check()?;
            let valid = check.problems.is_empty();
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "valid": valid,
                        "schema_version": check.schema_version,
                        "source_fingerprint": check.source_fingerprint,
                        "problems": check.problems,
                        "audit_recorded": false,
                    }))?
                );
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
    }
    Ok(())
}
