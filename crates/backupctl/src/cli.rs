//! The command-line surface: argument types plus the two pure helpers that
//! translate them. No I/O here, so the mapping from flags to domain values is
//! readable on its own.

use backup_domain::{ResolvedSelection, RestoreSections};
use backup_local::KeyStatus;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "backupctl",
    version,
    about = "Synthetic-data PostgreSQL backup development CLI"
)]
pub(crate) struct Cli {
    #[arg(long, global = true)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long, global = true, value_enum, default_value_t = Output::Human)]
    pub(crate) output: Output,
    #[command(subcommand)]
    pub(crate) command: TopCommand,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Output {
    Human,
    Json,
}

#[derive(Subcommand)]
pub(crate) enum TopCommand {
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommand,
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
pub(crate) enum ConfigCommand {
    Check,
}

/// Every key command acts on the `[encryption]` paths in the configuration, never on
/// paths typed at the prompt: a key the store will not load is worse than no key at all.
#[derive(Subcommand)]
pub(crate) enum KeyCommand {
    /// Generate the configured identity and publish its recipient half.
    Generate,
    /// Publish the recipient half of an identity that already exists, leaving the
    /// identity itself untouched.
    Publish,
    /// Report the configured key files without decrypting or printing secret material.
    Status,
}

#[derive(Subcommand)]
pub(crate) enum ProfileCommand {
    /// Check a profile against the configured database and report the exact
    /// object set it resolves to without writing an artifact.
    Validate { name: String },
    /// List the configured profiles.
    List,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum VerifyLevel {
    Checksum,
    Archive,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum SecurityPreset {
    /// Restore roles, ownership, and privileges from the security metadata.
    Dr,
    /// Contents only: skip roles, ownership, and privileges.
    Portable,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Section {
    PreData,
    Data,
    PostData,
}

#[derive(Subcommand)]
pub(crate) enum BackupCommand {
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
pub(crate) enum RestoreCommand {
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

pub(crate) fn sections_from(selected: &[Section]) -> RestoreSections {
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

pub(crate) fn selection_json(selection: &ResolvedSelection) -> serde_json::Value {
    serde_json::json!({
        "whole_database": selection.whole_database,
        "resolved_schemas": selection.schemas,
        "resolved_tables": selection.tables,
        "excluded_schemas": selection.exclude_schemas,
        "excluded_tables": selection.exclude_tables,
        "extension_members": selection.extension_members,
    })
}

/// A key file as an operator sees it in `--output json`: public facts only. The
/// recipient is the public half, so publishing it is the point of the report; no field
/// here can carry the identity seed.
pub(crate) fn key_json(label: &'static str, status: &KeyStatus) -> serde_json::Value {
    serde_json::json!({
        "path": status.path.display().to_string(),
        "role": label,
        "suite": status.suite,
        "mode": format!("{:04o}", status.mode),
        "recipient": status.recipient_hex,
    })
}
