//! Versioned key reports contain public facts and exact publication receipts only.
use crate::cli::KeyCommand;
use crate::output::{Reporter, refuse};
use anyhow::Result;
use backup_domain::ConfigV1;
use backup_local::{KeyMutation, mutate_protected_keys, protected_key_status};

pub(crate) fn run(config: &ConfigV1, command: KeyCommand, report: &mut Reporter) -> Result<()> {
    let data = match command {
        KeyCommand::Status => protected_key_status(config)?,
        KeyCommand::Generate | KeyCommand::Publish => {
            let action = match command {
                KeyCommand::Generate => KeyMutation::Generate,
                _ => KeyMutation::Publish,
            };
            let outcome = mutate_protected_keys(config, action)?;
            if let Some(code) = outcome.error {
                if outcome.partial {
                    report.partial();
                }
                if report.is_json() {
                    report.data(outcome.data)?;
                } else {
                    println!("{}", serde_json::to_string_pretty(&outcome.data)?);
                }
                return refuse(code);
            }
            outcome.data
        }
    };
    if report.is_json() {
        report.data(data)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&data)?);
    }
    Ok(())
}
