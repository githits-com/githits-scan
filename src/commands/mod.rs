//! Command handlers.
//!
//! Each submodule orchestrates one command: it calls the library modules that
//! compute, renders the result to the writer it is given, and reports an
//! [`Outcome`] or an [`enum@Error`]. Handlers never print to the process's standard
//! streams directly, so tests capture output without spawning a process, and
//! they never decide exit codes: [`crate::cli`] maps outcomes and error kinds to
//! the documented exit-code scheme.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::api::{ApiError, UploadError};
use crate::config::{self, ConfigError, Evaluation, Status};
use crate::discover::{DiscoverError, Inventory};
use crate::env::EnvError;
use crate::license::DocumentError;

pub mod audit;
pub mod detect;
pub mod diff;
mod evidence;
pub mod license;
mod progress;
pub mod sbom;
mod upload;

/// How a command finished when it did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The command did its job and found nothing to act on.
    Success,
    /// The repository needs attention: nothing to scan, inventory drift, or
    /// policy violations, audit findings or unassessed evidence. Pipelines block on this.
    Findings,
}

/// Which exit-code class an [`enum@Error`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The caller's arguments or configuration are wrong; retrying the same
    /// invocation cannot succeed.
    Usage,
    /// The environment failed: I/O, network, or the service. A retry may succeed.
    Execution,
}

/// Why a command failed.
#[derive(Debug, Error)]
pub enum Error {
    /// Git snapshot input could not be read.
    #[error(transparent)]
    Repository(#[from] crate::repository::Error),
    /// The producer inventory cannot be interpreted safely.
    #[error("invalid diff evidence: {0}")]
    Diff(&'static str),
    /// Diff selection exceeded the shared upload count limit.
    #[error(
        "{count} files exceed the {}-file upload limit; narrow both diff inputs with --exclude GLOB or --lockfiles-only",
        crate::api::MAX_FILES
    )]
    DiffFileLimit {
        /// Selected file count.
        count: usize,
    },
    /// The scan could not complete.
    #[error(transparent)]
    Discover(#[from] DiscoverError),
    /// The configuration file exists but cannot be used.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The token or origin could not be resolved from the environment.
    #[error(transparent)]
    Environment(#[from] EnvError),
    /// The selected files exceed the service's upload limits.
    #[error(transparent)]
    Upload(#[from] UploadError),
    /// Automatically selected workspace members exceeded the upload's file-count limit.
    #[error(
        "{files} files exceed the {}-file upload limit; automatic workspace member manifests: {automatic_manifests}\nuse --exclude to omit enough additional member manifests; for example {exclusions}; required evidence may remain incomplete",
        crate::api::MAX_FILES
    )]
    WorkspaceMemberLimit {
        /// Total selected files, as counted by API validation.
        files: usize,
        /// Member manifests added automatically beyond the initial selection.
        automatic_manifests: usize,
        /// Example exclusion switches naming automatically added member paths.
        exclusions: String,
    },
    /// The service did not return a document.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The report or document could not be written to its output stream.
    #[error("cannot write to the output stream")]
    Output(#[source] io::Error),
    /// `license check` requires a configuration file containing its policy.
    #[error(
        "configuration file {} not found; run `githits-scan detect --save` with the same PATH, then enable [licenses], or select an existing file with --config",
        path.display()
    )]
    MissingLicenseConfig {
        /// The configuration file that was looked for.
        path: PathBuf,
    },
    /// `license check` has no policy to apply.
    #[error(
        "{} has no [licenses] table; add one with `allow = [...]` (see the README) to enable license check",
        path.display()
    )]
    NoLicensePolicy {
        /// The configuration file that was looked for.
        path: PathBuf,
    },
    /// The selected license policy contains unsupported or misleading entries.
    #[error("invalid license policy in {}", path.display())]
    LicensePolicy {
        /// Configuration path.
        path: PathBuf,
        /// Invalid entry and its required form.
        #[source]
        source: crate::license::PolicyError,
    },
    /// An explicitly selected document or analysis file could not be read.
    #[error("cannot read {}", path.display())]
    ReadDocument {
        /// The file.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// An explicitly selected document is larger than the tool accepts.
    #[error("{} is larger than the {limit}-byte limit for a document", path.display())]
    DocumentTooLarge {
        /// The file.
        path: PathBuf,
        /// The limit in bytes.
        limit: usize,
    },
    /// The document to check is not a CycloneDX document.
    #[error(transparent)]
    Document(#[from] DocumentError),
    /// A saved dependency-license report is invalid or unsupported.
    #[error("invalid license report {}", path.display())]
    InvalidLicenseReport {
        /// Selected report file.
        path: PathBuf,
        /// Safe structural diagnostic without input excerpts.
        source: crate::api::licenses::ReportError,
    },
    /// The saved analysis format or contained report is invalid.
    #[error("invalid analysis {}: {reason}", path.display())]
    InvalidAnalysis {
        /// Selected analysis path.
        path: PathBuf,
        /// Safe format diagnostic; never contains input excerpts.
        reason: String,
    },
    /// An explicit analysis save could not represent the returned facts.
    #[error("cannot save analysis {}: {reason}", path.display())]
    SaveAnalysis {
        /// Requested destination.
        path: PathBuf,
        /// Safe encoding diagnostic.
        reason: String,
    },
    /// Saving must not overwrite an existing path.
    #[error("analysis destination {} already exists; choose a new file", path.display())]
    AnalysisExists {
        /// Existing destination.
        path: PathBuf,
    },
    /// The selector does not identify a vulnerable component in this analysis.
    #[error(
        "no vulnerable component matched; use an exact registry:name@version from this saved report{candidates}"
    )]
    NoAuditPackage {
        /// Safe, bounded suggestion text derived only from saved coordinates.
        candidates: String,
    },
    /// The document could not be written to the requested file.
    #[error("cannot write {}", path.display())]
    OutputFile {
        /// The requested file.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
}

impl Error {
    /// Classify the error for exit-code mapping.
    ///
    /// Upload limits are usage errors: the invocation cannot succeed as given
    /// and the caller must narrow the scan, so a retry is pointless.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Config(ConfigError::Write { .. }) => ErrorKind::Execution,
            Self::Repository(
                crate::repository::Error::Input(_)
                | crate::repository::Error::Upload(_)
                | crate::repository::Error::Discover(
                    DiscoverError::NotADirectory { .. }
                    | DiscoverError::FileTooLarge { .. }
                    | DiscoverError::NotUtf8 { .. }
                    | DiscoverError::InvalidPath { .. },
                ),
            )
            | Self::DiffFileLimit { .. }
            | Self::Discover(
                DiscoverError::NotADirectory { .. }
                | DiscoverError::FileTooLarge { .. }
                | DiscoverError::NotUtf8 { .. }
                | DiscoverError::InvalidPath { .. },
            )
            | Self::Config(_)
            | Self::Environment(_)
            | Self::Upload(_)
            | Self::WorkspaceMemberLimit { .. }
            | Self::MissingLicenseConfig { .. }
            | Self::NoLicensePolicy { .. }
            | Self::LicensePolicy { .. }
            | Self::Document(_)
            | Self::DocumentTooLarge { .. }
            | Self::InvalidAnalysis { .. }
            | Self::InvalidLicenseReport { .. }
            | Self::AnalysisExists { .. }
            | Self::NoAuditPackage { .. } => ErrorKind::Usage,
            Self::Api(error) if error.is_caller_error() => ErrorKind::Usage,
            Self::ReadDocument { source, .. } if source.kind() == io::ErrorKind::NotFound => {
                ErrorKind::Usage
            }
            Self::Repository(_)
            | Self::Diff(_)
            | Self::Api(_)
            | Self::Discover(_)
            | Self::Output(_)
            | Self::ReadDocument { .. }
            | Self::OutputFile { .. }
            | Self::SaveAnalysis { .. } => ErrorKind::Execution,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Output(io::Error::from(error))
    }
}

/// Route a validated report to its destination; files never contain terminal colors.
pub(crate) fn write_report(
    output: &sbom::Output,
    stdout: &mut dyn io::Write,
    palette: crate::style::Palette,
    write: impl FnOnce(&mut dyn io::Write, crate::style::Palette) -> Result<(), Error>,
) -> Result<(), Error> {
    match output {
        sbom::Output::Stdout => write(stdout, palette),
        sbom::Output::File(path) => {
            let file = std::fs::File::create(path).map_err(|source| Error::OutputFile {
                path: path.clone(),
                source,
            })?;
            let mut out = io::BufWriter::new(file);
            write(&mut out, crate::style::Palette::PLAIN).map_err(|error| match error {
                Error::Output(source) => Error::OutputFile {
                    path: path.clone(),
                    source,
                },
                other => other,
            })?;
            io::Write::flush(&mut out).map_err(|source| Error::OutputFile {
                path: path.clone(),
                source,
            })
        }
    }
}

/// Report a completed file write without treating skipped generation as a saved report.
pub(crate) fn saved_report(
    output: &sbom::Output,
    quiet: bool,
    stderr: &mut dyn io::Write,
) -> Result<(), Error> {
    if let sbom::Output::File(path) = output
        && !quiet
    {
        writeln!(stderr, "saved {}", safe_path(path)).map_err(Error::Output)?;
    }
    Ok(())
}

/// Unsupported-format notices respect the same explicit exclusions as scan evidence.
fn unsupported_files<'a>(
    inventory: &'a Inventory,
    config: Option<&config::Config>,
    extra: &[String],
) -> Result<Vec<&'a crate::discover::UnsupportedFile>, Error> {
    let invocation = config::exclude_set(extra, Path::new(config::CLI_EXCLUDE))?;
    Ok(inventory
        .unsupported
        .iter()
        .filter(|file| {
            !invocation.is_match(&file.path)
                && !config.is_some_and(|c| c.is_excluded(&file.path))
                && !config::is_default_excluded(&file.path)
        })
        .collect())
}

/// The configuration file a command reads: the override when given, otherwise
/// `githits-scan.toml` in the scanned directory. Paths inside the file are
/// relative to the scanned directory either way.
#[must_use]
pub fn config_path(root: &Path, override_path: Option<&Path>) -> PathBuf {
    override_path.map_or_else(|| root.join(config::FILE_NAME), Path::to_path_buf)
}

/// Load the default configuration optionally, or require an explicit selection.
fn load_config(
    root: &Path,
    override_path: Option<&Path>,
) -> Result<Option<config::Config>, ConfigError> {
    override_path.map_or_else(
        || config::load(&config_path(root, None)),
        |path| config::load_required(path).map(Some),
    )
}

/// Lines describing inventory drift, for both commands' reports.
#[must_use]
pub fn drift_lines(evaluation: &Evaluation, config: &Path) -> Vec<String> {
    let mut lines = vec![format!(
        "inventory drift against {} (run `githits-scan detect --save` to accept the detected inventory, or pass --no-check)",
        safe_path(config)
    )];
    if !evaluation.unlisted.is_empty() {
        lines.push(format!("  unlisted: {}", safe_names(&evaluation.unlisted)));
    }
    if !evaluation.missing.is_empty() {
        lines.push(format!("  missing: {}", safe_names(&evaluation.missing)));
    }
    lines
}

/// Warnings for ambiguous lockfiles that no exclude acknowledges, for both
/// commands' reports.
#[must_use]
pub fn ambiguous_warnings(inventory: &Inventory, evaluation: Option<&Evaluation>) -> Vec<String> {
    inventory
        .ambiguous
        .iter()
        .filter(|lock| {
            evaluation.and_then(|e| e.status(&lock.path)) != Some(Status::Excluded)
        })
        .map(|lock| {
            format!(
                "warning: {} is not uploaded: {} could each own it, so they are manifest-only projects; exclude the lockfile to accept this",
                safe(&lock.path),
                safe_names(&lock.manifests)
            )
        })
        .collect()
}

/// What happens to a manifest-only project; one rule for what `sbom generate`
/// uploads and what `detect` reports it would upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Uploaded for resolution from its declared constraints.
    Upload,
    /// Left out and reported, with the run's reason.
    Skip,
    /// Excluded: left out silently, a recorded decision.
    Ignore,
}

/// Decide whether a manifest-only project is uploaded.
///
/// An included project is uploaded and an excluded one silently left out. An
/// unlisted one, under a configuration or `--lockfiles-only`, is reported as
/// skipped. Without any evaluation the run's scope decides.
#[must_use]
pub const fn manifest_selection(status: Option<Status>, include_manifests: bool) -> Selection {
    match status {
        Some(Status::Included) => Selection::Upload,
        None if include_manifests => Selection::Upload,
        Some(Status::Excluded) => Selection::Ignore,
        Some(Status::Unlisted) | None => Selection::Skip,
    }
}

/// Read an explicitly selected document or analysis file, at most one byte
/// past [`MAX_RESPONSE_BYTES`](crate::api::MAX_RESPONSE_BYTES), the largest
/// document the service returns. A longer result means the file is over the
/// limit; callers reject it before parsing.
fn read_selected(path: &Path) -> Result<Vec<u8>, Error> {
    use std::io::Read as _;
    let read = || {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(crate::api::MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        Ok::<_, io::Error>(bytes)
    };
    read().map_err(|source| Error::ReadDocument {
        path: path.to_path_buf(),
        source,
    })
}

/// Formats a count with its noun, e.g. `1 lockfile` or `3 entries`.
pub(crate) fn plural(count: usize, noun: &str) -> String {
    match (count, noun) {
        (1, _) => format!("1 {noun}"),
        (_, "entry") => format!("{count} entries"),
        _ => format!("{count} {noun}s"),
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Escape {
    Text,
    Path,
}

pub(crate) fn push_safe(text: &mut String, ch: char, mode: Escape) {
    if matches!(ch, '\'' | '"') || (matches!(mode, Escape::Path) && ch == '\\') {
        text.push(ch);
    } else {
        text.extend(ch.escape_debug());
    }
}

pub(crate) fn safe(value: &str) -> String {
    escaped(value, Escape::Text, false)
}

pub(crate) fn safe_path(value: &Path) -> String {
    escaped(&value.to_string_lossy(), Escape::Path, false)
}

pub(crate) fn diagnostic(value: &str) -> String {
    escaped(value, Escape::Path, true)
}

fn escaped(value: &str, mode: Escape, multiline: bool) -> String {
    let mut text = String::with_capacity(value.len());
    for ch in value.chars() {
        if multiline && ch == '\n' {
            text.push(ch);
        } else {
            push_safe(&mut text, ch, mode);
        }
    }
    text
}

pub(crate) fn safe_names(values: &[String]) -> String {
    values
        .iter()
        .map(|value| safe(value))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::{diagnostic, plural, safe_path};

    #[test]
    fn non_utf8_upload_paths_require_caller_action() {
        let error = super::Error::Discover(crate::discover::DiscoverError::InvalidPath {
            path: std::path::PathBuf::from("invalid"),
        });
        assert_eq!(error.kind(), super::ErrorKind::Usage);
    }

    #[test]
    fn diagnostic_layout_and_windows_backslashes_survive_control_escaping() {
        let raw = "C:\\Users\\someone\\config.toml\n  cause: \u{1b}[31mbad\ttext";
        assert_eq!(
            diagnostic(raw),
            "C:\\Users\\someone\\config.toml\n  cause: \\u{1b}[31mbad\\ttext"
        );
        assert_eq!(
            safe_path(std::path::Path::new("C:\\Users\\someone")),
            "C:\\Users\\someone"
        );
    }

    #[test]
    fn plural_counts_nouns() {
        assert_eq!(plural(1, "lockfile"), "1 lockfile");
        assert_eq!(plural(0, "lockfile"), "0 lockfiles");
        assert_eq!(
            plural(2, "manifest-only project"),
            "2 manifest-only projects"
        );
        assert_eq!(plural(1, "entry"), "1 entry");
        assert_eq!(plural(3, "entry"), "3 entries");
    }
}
