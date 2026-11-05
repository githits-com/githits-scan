//! Process entry point for `githits-scan`.
//!
//! This file owns only argument parsing and the process exit code. Behavior lives in
//! the `githits_scan` library so it can be tested without spawning a process.

use std::process::ExitCode;

use clap::Parser;

use githits_scan::cli::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();
    cli.run()
}
