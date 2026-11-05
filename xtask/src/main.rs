//! Development-only release preparation and verification.

mod release;

use std::{path::Path, process::ExitCode};

use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Prepare or verify a release of githits-scan.
    Release {
        #[command(subcommand)]
        command: release::Command,
    },
}

fn main() -> ExitCode {
    let Cli { command } = Cli::parse();
    let Command::Release { command } = command;
    let Some(root) = Path::new(env!("CARGO_MANIFEST_DIR")).parent() else {
        eprintln!("xtask has no workspace parent");
        return ExitCode::FAILURE;
    };
    match release::run(root, command) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
