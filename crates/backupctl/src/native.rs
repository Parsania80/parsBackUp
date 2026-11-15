//! Explicit native dispatch for writable versioned fixtures. No production bypass.
use crate::cli::{BackupCommand, ProfileCommand, TopCommand, selection_json};
use crate::output::{Refusal, Reporter, refuse};
use anyhow::Result;
use backup_application::resolve_backup;
use backup_domain::{Access, Config, ConfigV1, Encryption, Signing, Source};
use backup_postgres::PostgresAdapter;

pub(crate) fn run(config: ConfigV1, command: TopCommand, report: &mut Reporter) -> Result<()> {
    let source = config.source.as_ref().ok_or(Refusal("CONFIG_INVALID"))?;
    let tools = config.tools.as_ref().ok_or(Refusal("CONFIG_INVALID"))?;
    let engine = if matches!(command, TopCommand::Restore { .. }) {
        PostgresAdapter::configured_for_restore(&config)?
    } else {
        PostgresAdapter::configured(&config)?
    };
    // Only service-level fixture fields are projected. Connection policy remains in
    // the adapter; reader keys are opened explicitly and never represented as writer custody.
    let mut fixture = Config {
        source: Source {
            host: source.host.clone(),
            port: source.port,
            user: source.user.clone(),
            database: source.database.clone(),
            client_bin_dir: tools.client_bin_dir.clone(),
            password_file: source.password_file.clone(),
        },
        storage: config.storage.clone(),
        export_globals: config.export_globals,
        encryption: None,
        signing: None,
        profiles: config.profiles.clone(),
        timeout_seconds: config.timeout_seconds,
    };
    match command {
        TopCommand::Profile {
            command: ProfileCommand::Validate { name },
        } => {
            let (info, selection) = resolve_backup(&engine, &fixture, Some(&name))?;
            if report.is_json() {
                report.data(serde_json::json!({"profile": fixture.profile(&name)?,
                    "source_major": info.source_major, "selection": selection_json(&selection)}))?;
            } else {
                crate::report::print_profile_scope(fixture.profile(&name)?);
                println!("resolves against source major {}", info.source_major);
                crate::report::print_selection(&selection);
            }
            Ok(())
        }
        TopCommand::Backup {
            command:
                BackupCommand::Create {
                    dry_run: true,
                    profile,
                    ..
                },
        } => {
            let (info, selection) = resolve_backup(&engine, &fixture, profile.as_deref())?;
            if report.is_json() {
                report.data(serde_json::json!({"profile": profile, "source_major": info.source_major,
                    "client_version": info.dump_client_version, "selection": selection_json(&selection)}))?;
            } else {
                println!(
                    "resolved scope for source major {} (nothing written)",
                    info.source_major
                );
                crate::report::print_selection(&selection);
            }
            Ok(())
        }
        TopCommand::Backup {
            command: command @ BackupCommand::Create { .. },
        } => {
            if config.access != Access::Writer {
                return refuse("ACCESS_DENIED");
            }
            let encryption = config
                .encryption
                .as_ref()
                .ok_or(Refusal("CONFIG_INVALID"))?;
            let signing = config.signing.as_ref().ok_or(Refusal("CONFIG_INVALID"))?;
            fixture.encryption = Some(Encryption {
                identity_file: encryption
                    .identity_file
                    .clone()
                    .ok_or(Refusal("CONFIG_INVALID"))?,
                recipient_file: encryption
                    .recipient_file
                    .clone()
                    .ok_or(Refusal("CONFIG_INVALID"))?,
            });
            fixture.signing = Some(Signing {
                signing_key_file: signing.signing_key_file.clone(),
                verifying_key_file: signing
                    .verifying_key_file
                    .clone()
                    .ok_or(Refusal("CONFIG_INVALID"))?,
            });
            let store = backup_local::open_protected_store(&config, backup_local::KeyUse::Writer)?;
            crate::backup::run_with_store(fixture, command, engine, Some(store), report)
        }
        TopCommand::Restore { command } => {
            let store = backup_local::open_protected_store(&config, backup_local::KeyUse::Reader)?;
            crate::restore(&fixture, command, engine, store, report)
        }
        _ => refuse("CAPABILITY_NOT_ENABLED"),
    }
}
