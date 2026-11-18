use anyhow::{Result, ensure};
use backup_api::{Config, serve_http};
use std::{path::PathBuf, process::ExitCode};

fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(arguments.len() == 2, "USAGE");
    let path = PathBuf::from(&arguments[1]);
    if arguments[0] == "--worker" {
        return backup_api::worker(&path);
    }
    let supervised = arguments[0] == "--supervise";
    ensure!(supervised || arguments[0] == "--read-only", "USAGE");
    let config = Config::load(&path)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve_http(config, supervised))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(code) = error.downcast_ref::<backup_api::ErrorCode>() {
                eprintln!("{code}");
            } else {
                eprintln!("BACKUP_API_START_OR_WORKER_FAILED");
            }
            ExitCode::FAILURE
        }
    }
}
