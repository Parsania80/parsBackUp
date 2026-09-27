use anyhow::{Context, Result, anyhow, bail};
use backup_application::{BackupService, RestoreService, VerifyService};
use backup_domain::{Config, RestoreSecurityPolicy, VERIFY_ARCHIVE, VERIFY_CHECKSUM};
use backup_local::LocalStore;
use backup_postgres::PostgresAdapter;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "backupctl",
    version,
    about = "Synthetic-data PostgreSQL backup development CLI"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true, value_enum, default_value_t = Output::Human)]
    output: Output,
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Human,
    Json,
}

#[derive(Subcommand)]
enum TopCommand {
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    Restore {
        #[command(subcommand)]
        command: RestoreCommand,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    Check,
}

#[derive(Clone, Copy, ValueEnum)]
enum VerifyLevel {
    Checksum,
    Archive,
}

#[derive(Clone, Copy, ValueEnum)]
enum SecurityPreset {
    /// Restore roles, ownership, and privileges from the security metadata.
    Dr,
    /// Contents only: skip roles, ownership, and privileges.
    Portable,
}

#[derive(Subcommand)]
enum BackupCommand {
    Create {
        #[arg(long)]
        confirm_synthetic: bool,
    },
    List,
    Inspect {
        id: Uuid,
    },
    Verify {
        id: Uuid,
        #[arg(long, value_enum, default_value_t = VerifyLevel::Archive)]
        level: VerifyLevel,
    },
}

#[derive(Subcommand)]
enum RestoreCommand {
    Plan {
        id: Uuid,
        #[arg(long)]
        target: String,
        #[arg(long, value_enum, default_value_t = SecurityPreset::Dr)]
        security: SecurityPreset,
    },
    Run {
        plan: Uuid,
        #[arg(long)]
        confirm_target: String,
    },
}

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
    let config: Config = toml::from_str(&content)
        .map_err(|_| anyhow!("invalid configuration; expected M2 TOML fields"))?;
    config.validate()?;
    match cli.command {
        TopCommand::Config {
            command: ConfigCommand::Check,
        } => {
            if json {
                println!("{{\"valid\":true,\"mode\":\"synthetic-only\"}}");
            } else {
                println!("configuration valid (synthetic-only M2 mode)");
            }
        }
        TopCommand::Backup { command } => {
            let store = LocalStore::new(config.storage.root.clone())?;
            let service = BackupService::new(PostgresAdapter, store);
            match command {
                BackupCommand::Create { confirm_synthetic } => {
                    if !confirm_synthetic {
                        bail!(
                            "M2 requires --confirm-synthetic; never use this plaintext format for real data"
                        );
                    }
                    if config.export_globals && !json {
                        eprintln!(
                            "warning: globals.sql contains cluster role definitions (without password verifiers) and is plaintext until M4"
                        );
                    }
                    let manifest = service.create(&config)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&manifest)?);
                    } else {
                        println!("created synthetic development backup {}", manifest.id);
                        println!("database: {}", manifest.database);
                        println!("bytes: {}", manifest.size_bytes);
                        println!(
                            "security metadata: {}",
                            if manifest.security_globals {
                                "globals.sql (roles and memberships, no password verifiers)"
                            } else {
                                "none"
                            }
                        );
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
                        println!("id: {}", manifest.id);
                        println!("format: {}", manifest.format);
                        println!("database: {}", manifest.database);
                        println!("source major: {}", manifest.source_major);
                        println!("client: {}", manifest.dump_client_version);
                        println!("bytes: {}", manifest.size_bytes);
                        println!("sha256: {}", manifest.sha256);
                        println!("security globals: {}", manifest.security_globals);
                        println!(
                            "verification: {}",
                            manifest
                                .verification_level
                                .unwrap_or_else(|| "none".to_string())
                        );
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
                        println!(
                            "artifact {} verified at level {}",
                            report.artifact_id, report.level
                        );
                        println!(
                            "payload: {} bytes {}",
                            report.payload_size_bytes, report.payload_sha256
                        );
                        if let (Some(size), Some(sha)) =
                            (report.globals_size_bytes, &report.globals_sha256)
                        {
                            println!("globals: {size} bytes {sha}");
                        }
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
                } => {
                    let policy = match security {
                        SecurityPreset::Dr => RestoreSecurityPolicy::dr_full(),
                        SecurityPreset::Portable => RestoreSecurityPolicy::portable(),
                    };
                    let plan = service.plan(&config, id, &target, policy)?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "plan": plan,
                                "digest": plan.digest(),
                            }))?
                        );
                    } else {
                        println!("restore plan {} (digest {})", plan.id, plan.digest());
                        println!(
                            "artifact: {} ({})",
                            plan.artifact_id, plan.artifact_database
                        );
                        println!("target: {} (new database)", plan.target_database);
                        println!(
                            "security: roles={} ownership={} privileges={}",
                            plan.security.roles, plan.security.ownership, plan.security.privileges
                        );
                        println!(
                            "expires in 15 minutes; run with --confirm-target {}",
                            plan.target_database
                        );
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
                                "plan_id": executed.id,
                                "digest": executed.digest(),
                                "artifact_id": executed.artifact_id,
                                "target_database": executed.target_database,
                                "security": executed.security,
                                "verification_level": backup_domain::VERIFY_RESTORE_TESTED,
                            }))?
                        );
                    } else {
                        println!(
                            "restored {} into {}",
                            executed.artifact_id, executed.target_database
                        );
                        println!("verification level: restore-tested");
                    }
                }
            }
        }
    }
    Ok(())
}
