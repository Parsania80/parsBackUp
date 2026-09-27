use anyhow::{Context, Result, anyhow, bail};
use backup_application::{BackupService, RestoreService, VerifyService};
use backup_domain::{
    Config, Profile, ResolvedSelection, RestoreSections, RestoreSecurityPolicy, VERIFY_ARCHIVE,
    VERIFY_CHECKSUM,
};
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
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
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

#[derive(Subcommand)]
enum ProfileCommand {
    /// Check a profile against the configured database and report the exact
    /// object set it resolves to without writing an artifact.
    Validate { name: String },
    /// List the configured profiles.
    List,
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

#[derive(Clone, Copy, ValueEnum)]
enum Section {
    PreData,
    Data,
    PostData,
}

#[derive(Subcommand)]
enum BackupCommand {
    Create {
        #[arg(long)]
        confirm_synthetic: bool,
        /// Select a configured profile; omitting it dumps the whole database.
        #[arg(long)]
        profile: Option<String>,
        /// Resolve and report the scope, then stop without writing anything.
        #[arg(long)]
        dry_run: bool,
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
        /// Restrict the restore to archive sections; repeatable.
        #[arg(long = "section", value_enum)]
        sections: Vec<Section>,
    },
    Run {
        plan: Uuid,
        #[arg(long)]
        confirm_target: String,
    },
}

fn sections_from(selected: &[Section]) -> RestoreSections {
    if selected.is_empty() {
        return RestoreSections::full();
    }
    let mut sections = RestoreSections {
        pre_data: false,
        data: false,
        post_data: false,
    };
    for section in selected {
        match section {
            Section::PreData => sections.pre_data = true,
            Section::Data => sections.data = true,
            Section::PostData => sections.post_data = true,
        }
    }
    sections
}

fn selection_json(selection: &ResolvedSelection) -> serde_json::Value {
    serde_json::json!({
        "whole_database": selection.whole_database,
        "resolved_schemas": selection.schemas,
        "resolved_tables": selection.tables,
        "excluded_schemas": selection.exclude_schemas,
        "excluded_tables": selection.exclude_tables,
        "extension_members": selection.extension_members,
    })
}

fn print_list(label: &str, values: &[String]) {
    if !values.is_empty() {
        println!("{label}: {}", values.join(", "));
    }
}

fn print_selection(selection: &ResolvedSelection) {
    if selection.whole_database {
        println!("scope: whole database");
        return;
    }
    print_list("schemas", &selection.schemas);
    print_list("relations", &selection.tables);
    print_list("excluded schemas", &selection.exclude_schemas);
    print_list("excluded relations", &selection.exclude_tables);
    print_list("extension members", &selection.extension_members);
}

fn print_profile_scope(profile: &Profile) {
    println!("profile: {}", profile.name);
    println!("database: {}", profile.database);
    let mode = serde_json::to_value(profile.mode).unwrap_or_default();
    println!("mode: {}", mode.as_str().unwrap_or_default());
    print_list("requested schemas", &profile.schemas);
    print_list("requested tables", &profile.tables);
    print_list("excluded schemas", &profile.exclude_schemas);
    print_list("excluded tables", &profile.exclude_tables);
    print_list("excluded extensions", &profile.exclude_extensions);
    println!("large objects: {}", profile.large_objects);
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
                        println!("created synthetic development backup {}", manifest.id);
                        println!("database: {}", manifest.database);
                        println!("bytes: {}", manifest.size_bytes);
                        if let Some(scope) = &manifest.scope {
                            println!("profile: {}", scope.profile);
                            println!("resolved schemas: {}", scope.resolved_schemas.join(", "));
                            println!("resolved relations: {}", scope.resolved_tables.join(", "));
                            if scope.large_objects {
                                println!("large objects: every one in the database");
                            }
                        }
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
                        if let Some(scope) = &manifest.scope {
                            println!("profile: {}", scope.profile);
                            println!("whole database: {}", scope.whole_database);
                            println!("resolved schemas: {}", scope.resolved_schemas.join(", "));
                            println!("resolved relations: {}", scope.resolved_tables.join(", "));
                            println!("extension members: {}", scope.extension_members.join(", "));
                        }
                        println!(
                            "table of contents: {}",
                            manifest.toc_sha256.unwrap_or_else(|| "none".to_string())
                        );
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
                        println!("restore plan {} (digest {})", plan.id, plan.digest());
                        println!(
                            "artifact: {} ({})",
                            plan.artifact_id, plan.artifact_database
                        );
                        if let Some(profile) = &plan.artifact_scope {
                            println!("backup profile scope: {profile}");
                        }
                        println!("target: {} (new database)", plan.target_database);
                        println!(
                            "security: roles={} ownership={} privileges={}",
                            plan.security.roles, plan.security.ownership, plan.security.privileges
                        );
                        println!(
                            "sections: pre-data={} data={} post-data={}",
                            plan.sections.pre_data, plan.sections.data, plan.sections.post_data
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
                        println!(
                            "restored {} into {}",
                            executed.plan.artifact_id, executed.plan.target_database
                        );
                        println!("verification level: {}", executed.verification_level);
                        if !executed.plan.sections.is_full() {
                            println!(
                                "warning: only part of the archive was replayed, so this run does not prove the artifact restores completely"
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
