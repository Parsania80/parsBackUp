//! The command-line surface: argument types plus the two pure helpers that
//! translate them. No I/O here, so the mapping from flags to domain values is
//! readable on its own.

use anyhow::Result;
use backup_application::{Created, Inventory, Record};
use backup_domain::{ResolvedSelection, RestoreSections};
use backup_local::{KeyStatus, SigningKeyStatus, SigningRole};
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

/// Every key command acts on the paths in the configuration, never on paths typed at the
/// prompt: a key the store will not load is worse than no key at all. With a `[signing]`
/// block present the same command acts on its two files as well, so one call reports the
/// whole set this deployment depends on.
#[derive(Subcommand)]
pub(crate) enum KeyCommand {
    /// Generate the configured identity and publish its recipient half, plus the signing
    /// key and its verifying half when `[signing]` names a signing key file.
    Generate,
    /// Publish the public halves of key files that already exist, leaving the secrets
    /// untouched.
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

/// Ascending trust: each level includes the one above it. `signature` is only available for
/// an artifact written as signed v1, and is the level a host that holds nothing but a
/// verifying key can run.
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum VerifyLevel {
    Signature,
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

/// A signing or verifying key file, in the same shape as [`key_json`]: path, role, suite,
/// permission bits, and the public fingerprint both halves derive. The signing seed is not
/// in this report, which is why printing it is safe on a host that may only write backups.
pub(crate) fn signing_json(status: &SigningKeyStatus) -> serde_json::Value {
    let role = match status.role {
        SigningRole::Signing => "signing",
        SigningRole::Verifying => "verifying",
    };
    serde_json::json!({
        "path": status.path.display().to_string(),
        "role": role,
        "suite": status.suite,
        "mode": format!("{:04o}", status.mode),
        "signer": status.signer_id,
    })
}

/// What a write published, as JSON.
///
/// A signed artifact reports two records rather than one, because the two are trusted by
/// different readers: `public` is what `backup list` and `verify --level signature` check
/// with no key material at all, while `manifest` is the authenticated detail only a holder of
/// the decryption identity can read.
pub(crate) fn json_created(created: &Created) -> Result<serde_json::Value> {
    Ok(match created {
        Created::Development(manifest) => serde_json::to_value(manifest)?,
        Created::Signed { header, manifest } => serde_json::json!({
            "public": header,
            "manifest": manifest,
        }),
    })
}

/// The store's contents, as JSON, in the shape the store itself can support: a signed store
/// reports what `public.json` says plus the ids it cannot describe.
pub(crate) fn json_inventory(inventory: &Inventory) -> Result<serde_json::Value> {
    Ok(match inventory {
        Inventory::Development(manifests) => serde_json::to_value(manifests)?,
        Inventory::Public(listing) => serde_json::json!({
            "signed": listing.signed,
            "unsigned": listing.unsigned,
        }),
    })
}

pub(crate) fn json_record(record: &Record) -> Result<serde_json::Value> {
    Ok(match record {
        Record::Development(manifest) => serde_json::to_value(manifest)?,
        Record::Signed(manifest) => serde_json::to_value(&**manifest)?,
    })
}
