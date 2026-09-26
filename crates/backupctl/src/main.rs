use anyhow::{Context, Result, anyhow, bail};
use backup_application::BackupService;
use backup_domain::Config;
use backup_local::LocalStore;
use backup_postgres::PostgresAdapter;
use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;
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
}

#[derive(Subcommand)]
enum ConfigCommand {
    Check,
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
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.as_ref().context("--config is required")?;
    let content = fs::read_to_string(config_path).context("read configuration file")?;
    let config: Config = toml::from_str(&content)
        .map_err(|_| anyhow!("invalid configuration; expected M1 TOML fields"))?;
    config.validate()?;
    match cli.command {
        TopCommand::Config {
            command: ConfigCommand::Check,
        } => {
            if matches!(cli.output, Output::Json) {
                println!("{{\"valid\":true,\"mode\":\"synthetic-only\"}}");
            } else {
                println!("configuration valid (synthetic-only M1 mode)");
            }
        }
        TopCommand::Backup { command } => {
            let store = LocalStore::new(config.storage.root.clone())?;
            let service = BackupService::new(PostgresAdapter, store);
            match command {
                BackupCommand::Create { confirm_synthetic } => {
                    if !confirm_synthetic {
                        bail!(
                            "M1 requires --confirm-synthetic; never use this plaintext format for real data"
                        );
                    }
                    let manifest = service.create(&config)?;
                    if matches!(cli.output, Output::Json) {
                        println!("{}", serde_json::to_string_pretty(&manifest)?);
                    } else {
                        println!("created synthetic development backup {}", manifest.id);
                        println!("database: {}", manifest.database);
                        println!("bytes: {}", manifest.size_bytes);
                    }
                }
                BackupCommand::List => {
                    let manifests = service.list()?;
                    if matches!(cli.output, Output::Json) {
                        println!("{}", serde_json::to_string_pretty(&manifests)?);
                    } else {
                        for item in manifests {
                            println!("{}  {}  {} bytes", item.id, item.database, item.size_bytes);
                        }
                    }
                }
                BackupCommand::Inspect { id } => {
                    let manifest = service.inspect(id)?;
                    if matches!(cli.output, Output::Json) {
                        println!("{}", serde_json::to_string_pretty(&manifest)?);
                    } else {
                        println!("id: {}", manifest.id);
                        println!("format: {}", manifest.format);
                        println!("database: {}", manifest.database);
                        println!("source major: {}", manifest.source_major);
                        println!("client: {}", manifest.dump_client_version);
                        println!("bytes: {}", manifest.size_bytes);
                        println!("sha256: {}", manifest.sha256);
                    }
                }
            }
        }
    }
    Ok(())
}
