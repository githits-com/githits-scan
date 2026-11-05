//! Command-line contract for `githits-scan`.
//!
//! The argument surface is a compatibility boundary: automation depends on flag
//! names, exit codes, and output streams. Changes here need a changelog fragment
//! and a compatibility test in `tests/cli.rs`.

use std::error::Error as _;
use std::io::{self, IsTerminal, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::api::OutputFormat;
use crate::api::http::HttpSbomApi;
use crate::commands::{self, ErrorKind, Outcome, audit, detect, license, sbom};
use crate::env;
use crate::style::Palette;

/// Exit code for a successful run; for checks, no findings.
pub const EXIT_SUCCESS: u8 = 0;
/// Exit code for findings: empty/drift, policy violations, audit findings or unassessed evidence.
///
/// A pipeline blocks on this code; it means the repository, not the tool, needs
/// attention.
pub const EXIT_FINDINGS: u8 = 1;
/// Exit code for a usage or configuration error. `clap` uses the same code for
/// invalid arguments.
pub const EXIT_USAGE: u8 = 2;
/// Exit code for an execution error: I/O, network, service or protocol failure.
///
/// A pipeline may retry on this code.
pub const EXIT_EXECUTION: u8 = 3;

/// Shared `--exclude` help; the glob language is the configuration's.
const EXCLUDE_GLOB_HELP: &str = "Omit matching package files, including owning and workspace manifests (repeatable; same glob rules as lockfiles.exclude). Directory patterns ending in /** prune matching subtrees before reading them.";

/// Top-level command line.
#[derive(Debug, Parser)]
#[command(
    name = "githits-scan",
    version,
    about = "Generate SBOMs, report licenses and audit dependencies with the GitHits public API",
    long_about = None,
    arg_required_else_help = true,
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Preview package uploads and excluded candidates locally (no network, no token)
    Detect(DetectArgs),
    /// Audit dependency vulnerabilities, maintenance findings and native input disagreements
    #[command(
        long_about = "Audit selected repository evidence through one asynchronous job (GITHITS_API_TOKEN required), or re-display --from-analysis offline.\n\nExit 1 for any vulnerability, deprecated release, outdated version, duplicate group, manifest/lock disagreement or incomplete/unsupported/excluded evidence. Exit 0 only for fully checked selected evidence. Versions are source evidence, not constraint-compatible upgrade guarantees."
    )]
    Audit(AuditArgs),
    /// Software bill of materials commands
    Sbom(SbomArgs),
    /// License reports and policy checks
    License(LicenseArgs),
}

/// Arguments of the combined audit command.
#[derive(Debug, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent command-line switches"
)]
struct AuditArgs {
    /// Directory to scan
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,
    /// Existing configuration file (default: githits-scan.toml in PATH)
    #[arg(long, value_name = "FILE", display_order = 10)]
    config: Option<PathBuf>,
    /// Audit configured selections despite inventory drift
    #[arg(long, display_order = 20)]
    no_check: bool,
    /// Skip manifest-only dependency resolution
    #[arg(long, display_order = 30)]
    lockfiles_only: bool,
    #[arg(long, value_name = "GLOB", help = EXCLUDE_GLOB_HELP, display_order = 40)]
    exclude: Vec<String>,
    /// Write compact findings and incomplete checks as JSON
    #[arg(long, display_order = 60)]
    json: bool,
    /// Include deprecated, outdated and duplicate lists in human audit output
    #[arg(long, display_order = 65)]
    details: bool,
    /// Write the selected report representation to FILE ('-' means stdout)
    #[arg(short, long, value_name = "FILE", display_order = 80)]
    output: Option<PathBuf>,
    /// Save consumed analysis facts to a new file for later offline inspection
    #[arg(long, value_name = "FILE", value_parser = analysis_path, conflicts_with_all = ["from_analysis", "output"], display_order = 70)]
    save_analysis: Option<PathBuf>,
    /// Re-display a saved analysis offline (no token or network)
    #[arg(long, value_name = "FILE", value_parser = analysis_path, conflicts_with_all = ["path", "config", "exclude", "lockfiles_only", "no_check", "save_analysis"], display_order = 5)]
    from_analysis: Option<PathBuf>,
    /// Explain an exact vulnerable registry:name@version in the saved analysis
    #[arg(
        long,
        value_name = "PACKAGE",
        requires = "from_analysis",
        display_order = 55
    )]
    explain: Option<String>,
    /// Disable colored output (also honors `NO_COLOR`)
    #[arg(long, display_order = 100)]
    no_color: bool,
    /// Suppress progress and success messages; keep reports, warnings and errors
    #[arg(short = 'q', long, display_order = 90)]
    quiet: bool,
}

/// Arguments of `githits-scan license`.
#[derive(Debug, Args)]
struct LicenseArgs {
    #[command(subcommand)]
    command: LicenseCommand,
}

#[derive(Debug, Subcommand)]
enum LicenseCommand {
    /// List packages and their reported licenses without applying a policy
    #[command(
        long_about = "List supplied package occurrences and their reported licenses, including labelled project/local subjects. This report is informational; no [licenses] policy is required. Use --details for source links, observations and coverage gaps.\n\nOnline runs require GITHITS_API_TOKEN. --from-report replays saved license report JSON offline without a token. Exit 0 means the report was produced, even when evidence is incomplete; use license check to enforce policy.",
        after_help = "Examples:\n  githits-scan license report\n  githits-scan license report --details\n  githits-scan license report --json -o licenses.json\n  githits-scan license report --from-report licenses.json"
    )]
    Report(ReportArgs),
    /// Check inventory component licenses against your explicit policy
    #[command(
        long_about = "Check the component inventory and nested assemblies against [licenses] in githits-scan.toml. Project-root and local-source markers exclude those nodes, not their children. Every other component type, including files, needs license evidence.\n\nGenerate a CycloneDX JSON document (GITHITS_API_TOKEN required), or read one with --sbom offline without a token. Exit 1 means violations or unresolved projects; --no-check bypasses inventory drift only. Use explicit SPDX identifiers and AND/OR/WITH operators; names and slash-separated text are not guessed.",
        after_help = "Setup:\n  githits-scan detect --save\n  # Enable [licenses] in githits-scan.toml, then:\n  githits-scan license check\n  githits-scan license check --sbom bom.cdx.json --json"
    )]
    Check(CheckArgs),
}

/// Arguments of the informational license report.
#[derive(Debug, Args)]
#[expect(clippy::struct_excessive_bools, reason = "independent CLI switches")]
struct ReportArgs {
    /// Directory to scan
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,
    /// Replay JSON saved by license report --json (no token or network)
    #[arg(long, value_name = "FILE", value_parser = report_path, conflicts_with_all = ["path", "config", "no_check", "lockfiles_only", "exclude"], display_order = 5)]
    from_report: Option<PathBuf>,
    /// Existing inventory config (default: githits-scan.toml in PATH); no license policy required
    #[arg(long, value_name = "FILE", display_order = 10)]
    config: Option<PathBuf>,
    /// Bypass inventory drift only; does not widen selection
    #[arg(long, display_order = 20)]
    no_check: bool,
    /// Skip manifest-only dependency resolution
    #[arg(long, display_order = 30)]
    lockfiles_only: bool,
    #[arg(long, value_name = "GLOB", help = EXCLUDE_GLOB_HELP, display_order = 40)]
    exclude: Vec<String>,
    /// Write the full experimental license report JSON, including all evidence
    #[arg(long, display_order = 60)]
    json: bool,
    /// Include source attribution, observations and coverage in human output
    #[arg(long, display_order = 65)]
    details: bool,
    /// Write the selected representation to FILE ('-' means stdout)
    #[arg(short, long, value_name = "FILE", display_order = 80)]
    output: Option<PathBuf>,
    /// Suppress progress and success messages; keep reports, warnings and errors
    #[arg(short = 'q', long, display_order = 90)]
    quiet: bool,
    /// Disable colored output (also honors `NO_COLOR`)
    #[arg(long, display_order = 100)]
    no_color: bool,
}

/// Arguments of `githits-scan license check`.
#[derive(Debug, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent switch on the command line"
)]
struct CheckArgs {
    /// Directory to scan; the configuration is read from here
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,

    /// Evaluate existing CycloneDX JSON offline instead of generating it
    #[arg(long, value_name = "FILE", display_order = 5)]
    sbom: Option<PathBuf>,

    /// Existing configuration file (default: githits-scan.toml in PATH); paths inside
    /// it are relative to PATH
    #[arg(long, value_name = "FILE", display_order = 10)]
    config: Option<PathBuf>,

    /// Bypass inventory drift only; license policy is still enforced
    #[arg(long, conflicts_with = "sbom", display_order = 20)]
    no_check: bool,

    /// Skip projects that have a manifest but no lockfile when generating
    #[arg(long, conflicts_with = "sbom", display_order = 30)]
    lockfiles_only: bool,

    #[arg(long, value_name = "GLOB", conflicts_with = "sbom", help = EXCLUDE_GLOB_HELP, display_order = 40)]
    exclude: Vec<String>,

    /// Print a machine-readable JSON report instead of the human-readable one
    #[arg(long, display_order = 60)]
    json: bool,

    /// Disable colored output (the `NO_COLOR` environment variable does the same)
    #[arg(long, display_order = 100)]
    no_color: bool,
    /// Write the report to FILE instead of stdout ('-' means stdout)
    #[arg(short, long, value_name = "FILE", display_order = 80)]
    output: Option<PathBuf>,
    /// Suppress progress and success messages; keep reports, warnings and errors
    #[arg(short = 'q', long, display_order = 90)]
    quiet: bool,
    /// Include violation component references and package URLs
    #[arg(long, display_order = 65)]
    details: bool,
}

/// Arguments of `githits-scan sbom`.
#[derive(Debug, Args)]
struct SbomArgs {
    #[command(subcommand)]
    command: SbomCommand,
}

#[derive(Debug, Subcommand)]
enum SbomCommand {
    /// Upload the repository's lockfiles and manifests and write the generated SBOM
    #[command(
        long_about = "Upload the repository's lockfiles and manifests and write the generated SBOM.\n\n\
                      Reads the API token from GITHITS_API_TOKEN. Submits one job and reports progress on stderr; \
                      the document is written only after the service returned it completely."
    )]
    Generate(GenerateArgs),
}

/// Document formats the service produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// CycloneDX 1.7 JSON
    Cyclonedx,
    /// SPDX 2.3 tag-value
    Spdx,
    /// Human-readable inventory report
    Text,
}

impl From<Format> for OutputFormat {
    fn from(format: Format) -> Self {
        match format {
            Format::Cyclonedx => Self::CycloneDx,
            Format::Spdx => Self::Spdx,
            Format::Text => Self::Text,
        }
    }
}

/// Arguments of `githits-scan sbom generate`.
#[derive(Debug, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent command-line switches"
)]
struct GenerateArgs {
    /// Directory to scan; uploaded paths are relative to it
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,

    /// Existing configuration file (default: githits-scan.toml in PATH); paths inside
    /// it are relative to PATH
    #[arg(long, value_name = "FILE", display_order = 10)]
    config: Option<PathBuf>,

    /// Upload despite inventory drift against the configuration
    #[arg(long, display_order = 20)]
    no_check: bool,

    /// Document format to request
    #[arg(long, value_enum, default_value_t = Format::Cyclonedx, display_order = 50)]
    format: Format,

    /// Write the document to this file instead of stdout ("-" means stdout)
    #[arg(short, long, value_name = "FILE", display_order = 80)]
    output: Option<PathBuf>,

    /// Upload only lockfiles with their owning manifests. By default, projects
    /// that have a manifest but no lockfile are uploaded too and the service
    /// resolves their dependencies from the declared constraints; the summary
    /// names every such project
    #[arg(long, display_order = 30)]
    lockfiles_only: bool,

    #[arg(long, value_name = "GLOB", help = EXCLUDE_GLOB_HELP, display_order = 40)]
    exclude: Vec<String>,

    /// Disable colored output (the `NO_COLOR` environment variable does the same)
    #[arg(long, display_order = 100)]
    no_color: bool,
    /// Suppress progress and success messages; keep reports, warnings and errors
    #[arg(short = 'q', long, display_order = 90)]
    quiet: bool,
}

/// Arguments of `githits-scan detect`.
#[derive(Debug, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent switch on the command line"
)]
struct DetectArgs {
    /// Directory to scan; reported paths are relative to it
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,

    /// Configuration file (default: githits-scan.toml in PATH); paths inside
    /// it are relative to PATH
    #[arg(long, value_name = "FILE", display_order = 10)]
    config: Option<PathBuf>,

    /// Report inventory drift against the configuration without failing on it
    #[arg(long, display_order = 20)]
    no_check: bool,

    /// Write the inventory, creating the selected config from a commented template
    /// if needed. Keeps existing excludes, policy, and comments
    #[arg(long, conflicts_with = "no_check", display_order = 45)]
    save: bool,

    /// Leave projects that have a manifest but no lockfile out of the
    /// inventory. By default they are part of it, and their dependencies are
    /// resolved from the declared constraints
    #[arg(long, display_order = 30)]
    lockfiles_only: bool,

    #[arg(long, value_name = "GLOB", help = EXCLUDE_GLOB_HELP, display_order = 40)]
    exclude: Vec<String>,

    /// Print a machine-readable JSON report instead of the human-readable one
    #[arg(long, display_order = 60)]
    json: bool,

    /// Disable colored output (the `NO_COLOR` environment variable does the same)
    #[arg(long, display_order = 100)]
    no_color: bool,
    /// Write the report to FILE instead of stdout ('-' means stdout)
    #[arg(short, long, value_name = "FILE", display_order = 80)]
    output: Option<PathBuf>,
    /// Suppress progress and success messages; keep reports, warnings and errors
    #[arg(short = 'q', long, display_order = 90)]
    quiet: bool,
}

impl Cli {
    /// Run the parsed command and return the process exit code.
    #[must_use]
    pub fn run(self) -> ExitCode {
        let result = match self.command {
            Command::Detect(args) => run_detect(&args),
            Command::Audit(args) => run_audit(&args),
            Command::Sbom(SbomArgs {
                command: SbomCommand::Generate(args),
            }) => run_generate(&args),
            Command::License(LicenseArgs {
                command: LicenseCommand::Check(args),
            }) => run_check(&args),
            Command::License(LicenseArgs {
                command: LicenseCommand::Report(args),
            }) => run_report(&args),
        };
        match result {
            Ok(Outcome::Success) => ExitCode::from(EXIT_SUCCESS),
            Ok(Outcome::Findings) => ExitCode::from(EXIT_FINDINGS),
            Err(error) => {
                report_error(&error);
                match error.kind() {
                    ErrorKind::Usage => ExitCode::from(EXIT_USAGE),
                    ErrorKind::Execution => ExitCode::from(EXIT_EXECUTION),
                }
            }
        }
    }
}

fn output_destination(path: Option<&Path>) -> sbom::Output {
    match path {
        Some(path) if path.as_os_str() != "-" => sbom::Output::File(path.to_path_buf()),
        _ => sbom::Output::Stdout,
    }
}

fn run_detect(args: &DetectArgs) -> Result<Outcome, commands::Error> {
    let stdout = io::stdout();
    let palette = palette(args.no_color, &stdout);
    let drift = if args.save {
        detect::DriftPolicy::Accept
    } else if args.no_check {
        detect::DriftPolicy::Report
    } else {
        detect::DriftPolicy::Fail
    };
    let request = detect::Request {
        root: &args.path,
        config: args.config.as_deref(),
        include_manifests: !args.lockfiles_only,
        exclude: &args.exclude,
        json: args.json,
        drift,
        quiet: args.quiet,
        output: output_destination(args.output.as_deref()),
    };
    let mut out = io::BufWriter::new(stdout.lock());
    let outcome = detect::run(&request, &mut out, palette)?;
    out.flush().map_err(commands::Error::Output)?;
    commands::saved_report(&request.output, args.quiet, &mut io::stderr().lock())?;
    Ok(outcome)
}

fn run_generate(args: &GenerateArgs) -> Result<Outcome, commands::Error> {
    let environment = env::from_source(|name| std::env::var_os(name))?;
    let api = HttpSbomApi::new(environment)?;
    let stderr = io::stderr();
    let palette = palette(args.no_color, &stderr);
    let output = output_destination(args.output.as_deref());
    let request = sbom::Request {
        root: &args.path,
        config: args.config.as_deref(),
        no_check: args.no_check,
        format: args.format.into(),
        output,
        include_manifests: !args.lockfiles_only,
        exclude: &args.exclude,
        quiet: args.quiet,
    };
    let mut out = io::BufWriter::new(io::stdout().lock());
    let outcome = sbom::run(&request, &api, &mut out, &mut stderr.lock(), palette)?;
    out.flush().map_err(commands::Error::Output)?;
    Ok(outcome)
}

fn analysis_path(value: &str) -> Result<PathBuf, String> {
    if value == "-" {
        return Err("analysis requires a file path; '-' is not supported".into());
    }
    Ok(PathBuf::from(value))
}

fn run_audit(args: &AuditArgs) -> Result<Outcome, commands::Error> {
    let stdout = io::stdout();
    let stderr = io::stderr();
    if let Some(file) = &args.from_analysis {
        let request = audit::ReplayRequest {
            file,
            json: args.json,
            details: args.details,
            explain: args.explain.as_deref(),
            output: output_destination(args.output.as_deref()),
        };
        let mut out = io::BufWriter::new(stdout.lock());
        let outcome = audit::replay(&request, &mut out, palette(args.no_color, &stdout))?;
        out.flush().map_err(commands::Error::Output)?;
        commands::saved_report(&request.output, args.quiet, &mut io::stderr().lock())?;
        return Ok(outcome);
    }
    let api = HttpSbomApi::new(env::from_source(|name| std::env::var_os(name))?)?;
    let output = output_destination(args.output.as_deref());
    let request = audit::Request {
        root: &args.path,
        config: args.config.as_deref(),
        no_check: args.no_check,
        include_manifests: !args.lockfiles_only,
        exclude: &args.exclude,
        json: args.json,
        details: args.details,
        output,
        quiet: args.quiet,
        save_analysis: args.save_analysis.as_deref(),
    };
    let mut out = io::BufWriter::new(stdout.lock());
    let outcome = audit::run(
        &request,
        &api,
        &mut out,
        &mut stderr.lock(),
        palette(args.no_color, &stdout),
        palette(args.no_color, &stderr),
    )?;
    out.flush().map_err(commands::Error::Output)?;
    Ok(outcome)
}

fn report_path(value: &str) -> Result<PathBuf, String> {
    if value == "-" {
        return Err("report requires a file path; '-' is not supported".into());
    }
    Ok(PathBuf::from(value))
}

fn run_report(args: &ReportArgs) -> Result<Outcome, commands::Error> {
    use license::report::{self, Source};
    let stdout = io::stdout();
    let stderr = io::stderr();
    let api;
    let source = if let Some(file) = &args.from_report {
        Source::File(file)
    } else {
        api = HttpSbomApi::new(env::from_source(|name| std::env::var_os(name))?)?;
        Source::Generate(&api)
    };
    let output = output_destination(args.output.as_deref());
    let request = report::Request {
        root: &args.path,
        config: args.config.as_deref(),
        no_check: args.no_check,
        include_manifests: !args.lockfiles_only,
        exclude: &args.exclude,
        json: args.json,
        details: args.details,
        quiet: args.quiet,
        output,
        source,
    };
    let mut out = io::BufWriter::new(stdout.lock());
    let outcome = report::run(
        &request,
        &mut out,
        &mut stderr.lock(),
        palette(args.no_color, &stdout),
        palette(args.no_color, &stderr),
    )?;
    out.flush().map_err(commands::Error::Output)?;
    Ok(outcome)
}

fn run_check(args: &CheckArgs) -> Result<Outcome, commands::Error> {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let stdout_palette = palette(args.no_color, &stdout);
    let stderr_palette = palette(args.no_color, &stderr);
    // The client is built only when a document must be generated, so
    // `--sbom` never needs a token.
    let api;
    let source = if let Some(file) = &args.sbom {
        license::Source::File(file)
    } else {
        api = HttpSbomApi::new(env::from_source(|name| std::env::var_os(name))?)?;
        license::Source::Generate(&api)
    };
    let request = license::Request {
        root: &args.path,
        config: args.config.as_deref(),
        no_check: args.no_check,
        include_manifests: !args.lockfiles_only,
        exclude: &args.exclude,
        json: args.json,
        quiet: args.quiet,
        details: args.details,
        output: output_destination(args.output.as_deref()),
        source,
    };
    let mut out = io::BufWriter::new(stdout.lock());
    let outcome = license::run(
        &request,
        &mut out,
        &mut stderr.lock(),
        stdout_palette,
        stderr_palette,
    )?;
    out.flush().map_err(commands::Error::Output)?;
    Ok(outcome)
}

/// Styling is on only when the caller did not opt out, `NO_COLOR` is unset or
/// empty (per the `no-color.org` convention), and the report goes to a terminal.
fn palette(no_color: bool, stream: &impl IsTerminal) -> Palette {
    let env_opt_out = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    if no_color || env_opt_out || !stream.is_terminal() {
        Palette::PLAIN
    } else {
        Palette::ENABLED
    }
}

/// Print an error and its causes to stderr, one per line.
fn report_error(error: &commands::Error) {
    eprintln!("error: {}", commands::diagnostic(&error.to_string()));
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("  caused by: {}", commands::diagnostic(&cause.to_string()));
        source = cause.source();
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    fn detect_args(cli: Cli) -> Option<DetectArgs> {
        match cli.command {
            Command::Detect(args) => Some(args),
            Command::Sbom(_) | Command::License(_) | Command::Audit(_) => None,
        }
    }

    fn generate_args(cli: Cli) -> Option<GenerateArgs> {
        match cli.command {
            Command::Sbom(SbomArgs {
                command: SbomCommand::Generate(args),
            }) => Some(args),
            Command::Detect(_) | Command::License(_) | Command::Audit(_) => None,
        }
    }

    fn check_args(cli: Cli) -> Option<CheckArgs> {
        match cli.command {
            Command::License(LicenseArgs {
                command: LicenseCommand::Check(args),
            }) => Some(args),
            Command::Detect(_)
            | Command::Sbom(_)
            | Command::Audit(_)
            | Command::License(LicenseArgs {
                command: LicenseCommand::Report(_),
            }) => None,
        }
    }

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn version_flag_reports_the_crate_version() {
        let error = Cli::try_parse_from(["githits-scan", "--version"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(error.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn detect_defaults_to_the_current_directory_without_options() {
        let cli = Cli::try_parse_from(["githits-scan", "detect"]).expect("parse");
        let args = detect_args(cli).expect("detect");
        assert_eq!(args.path, PathBuf::from("."));
        assert_eq!(args.config, None);
        assert!(!args.lockfiles_only && !args.json && !args.no_color);
        assert!(!args.no_check && !args.save);
        assert!(args.exclude.is_empty(), "{:?}", args.exclude);
    }

    #[test]
    fn sbom_generate_accepts_every_documented_option() {
        let cli = Cli::try_parse_from([
            "githits-scan",
            "sbom",
            "generate",
            "--format",
            "spdx",
            "-o",
            "bom.spdx",
            "--lockfiles-only",
            "--no-color",
            "--config",
            "ci/scan.toml",
            "--no-check",
            "some/dir",
        ])
        .expect("parse");
        let args = generate_args(cli).expect("sbom generate");
        assert_eq!(args.path, PathBuf::from("some/dir"));
        assert_eq!(args.config, Some(PathBuf::from("ci/scan.toml")));
        assert!(args.no_check);
        assert_eq!(args.format, Format::Spdx);
        assert_eq!(args.output, Some(PathBuf::from("bom.spdx")));
        assert!(args.lockfiles_only && args.no_color);
        assert!(args.exclude.is_empty(), "{:?}", args.exclude);
    }

    #[test]
    fn detect_accepts_repeated_exclude_globs() {
        let cli = Cli::try_parse_from([
            "githits-scan",
            "detect",
            "--exclude",
            "test/**",
            "--exclude",
            "graphql-docs/**",
        ])
        .expect("parse");
        let args = detect_args(cli).expect("detect");
        assert_eq!(args.exclude, ["test/**", "graphql-docs/**"]);
    }

    #[test]
    fn license_check_rejects_exclude_together_with_sbom() {
        let error = Cli::try_parse_from([
            "githits-scan",
            "license",
            "check",
            "--sbom",
            "bom.cdx.json",
            "--exclude",
            "test/**",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn sbom_generate_defaults_to_cyclonedx_on_stdout() {
        let cli = Cli::try_parse_from(["githits-scan", "sbom", "generate"]).expect("parse");
        let args = generate_args(cli).expect("sbom generate");
        assert_eq!(args.format, Format::Cyclonedx);
        assert_eq!(args.output, None);
        assert!(!args.lockfiles_only);
    }

    #[test]
    fn license_check_accepts_every_documented_option() {
        let cli = Cli::try_parse_from([
            "githits-scan",
            "license",
            "check",
            "--sbom",
            "bom.cdx.json",
            "--config",
            "ci/scan.toml",
            "--json",
            "--no-color",
            "some/dir",
        ])
        .expect("parse");
        let args = check_args(cli).expect("license check");
        assert_eq!(args.path, PathBuf::from("some/dir"));
        assert_eq!(args.sbom, Some(PathBuf::from("bom.cdx.json")));
        assert_eq!(args.config, Some(PathBuf::from("ci/scan.toml")));
        assert!(args.json && args.no_color && !args.no_check && !args.lockfiles_only);
    }

    #[test]
    fn sbom_file_conflicts_with_generation_flags() {
        for flag in ["--no-check", "--lockfiles-only"] {
            let error =
                Cli::try_parse_from(["githits-scan", "license", "check", "--sbom", "x", flag])
                    .expect_err(flag);
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{flag}"
            );
        }
    }

    #[test]
    fn detect_accepts_every_documented_option() {
        let cli = Cli::try_parse_from([
            "githits-scan",
            "detect",
            "--lockfiles-only",
            "--json",
            "--no-color",
            "--config",
            "ci/scan.toml",
            "--save",
            "some/dir",
        ])
        .expect("parse");
        let args = detect_args(cli).expect("detect");
        assert_eq!(args.path, PathBuf::from("some/dir"));
        assert_eq!(args.config, Some(PathBuf::from("ci/scan.toml")));
        assert!(args.lockfiles_only && args.json && args.no_color && args.save);
    }

    #[test]
    fn save_and_no_check_are_mutually_exclusive() {
        let error = Cli::try_parse_from(["githits-scan", "detect", "--save", "--no-check"])
            .expect_err("conflict");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
