//! Experimental repository comparison; the service owns dependency interpretation.
use super::{Error, Outcome, sbom, upload};
use crate::api::diff::{DiffApi, Input as PairedInput, UnlockedManifests};
use crate::api::{self, UploadSet};
use crate::{config, discover, repository::Snapshot, style::Palette};
use clap::ValueEnum;
use std::io::Write;
use std::path::Path;

mod output;
mod render;

/// Experimental report representation.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    /// Compact dependency comparison.
    Human,
    /// Exact backend JSON for automation.
    Json,
    /// Complete escaped Markdown report.
    Markdown,
}

/// Representations selected for one paired analysis.
pub enum Output {
    /// One document, including the original `--format` / `--output` contract.
    Single {
        /// Selected representation.
        format: Format,
        /// Selected destination.
        destination: sbom::Output,
    },
    /// Exact JSON followed by Markdown rendered from the same report.
    JsonAndMarkdown {
        /// Exact producer JSON destination.
        json: sbom::Output,
        /// Scan-rendered Markdown destination, distinct from JSON.
        markdown: sbom::Output,
    },
}

/// A two-point comparison; omitted head selects actual working-tree bytes.
pub struct Request<'a> {
    /// Git repository root.
    pub root: &'a Path,
    /// Base revision expression.
    pub base: &'a str,
    /// Head revision, or the working tree when absent.
    pub head: Option<&'a str>,
    /// Explicit exclusions shared by both sides.
    pub exclude: &'a [String],
    /// Include and resolve manifest-only projects.
    pub include_manifests: bool,
    /// Suppress progress.
    pub quiet: bool,
    /// Selected report representations and destinations.
    pub output: Output,
}

struct Input {
    label: String,
    upload: Option<UploadSet>,
    notices: Vec<String>,
}

fn prepare(request: &Request<'_>, revision: Option<&str>) -> Result<Input, Error> {
    let excluded = config::exclude_set(request.exclude, Path::new(config::CLI_EXCLUDE))?;
    let snapshot = Snapshot::open(request.root, revision, &excluded)?;
    let inventory = discover::from_files(&snapshot.files)?;
    let upload = upload::from_inventory(
        &inventory,
        request.include_manifests,
        request.exclude,
        |path| snapshot.read(path).map_err(Error::from),
    )
    .map_err(|error| match error {
        Error::Upload(api::UploadError::TooManyFiles { count }) => Error::DiffFileLimit { count },
        error => error,
    })?;
    let selected: std::collections::BTreeSet<_> = upload
        .as_ref()
        .into_iter()
        .flat_map(UploadSet::files)
        .map(|f| f.path.as_str())
        .collect();
    let mut notices: Vec<_> = snapshot
        .files
        .keys()
        .filter(|p| !selected.contains(p.as_str()))
        .map(|p| {
            format!(
                "{}: package evidence not selected/supported: {p}",
                snapshot.label
            )
        })
        .collect();
    if snapshot.has_config {
        notices.push(format!(
            "{}: diff ignores {}; use --exclude and --lockfiles-only",
            snapshot.label,
            config::FILE_NAME
        ));
    }
    Ok(Input {
        label: snapshot.label,
        upload,
        notices,
    })
}

/// Validate both snapshots and their combined upload before acquiring credentials.
///
/// # Errors
/// Returns typed input, admission, transport, report or output errors.
pub fn run<A: DiffApi>(
    request: &Request<'_>,
    create_api: impl FnOnce() -> Result<A, Error>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<Outcome, Error> {
    output::validate(&request.output)?;
    let base = prepare(request, Some(request.base))?;
    let head = prepare(request, request.head)?;
    let mode = if request.include_manifests {
        UnlockedManifests::Resolve
    } else {
        UnlockedManifests::RecordedOnly
    };
    let paired = PairedInput::try_new(base.upload, head.upload, mode).map_err(|e| match e {
        api::UploadError::TooManyFiles { count } => Error::DiffFileLimit { count },
        error => Error::Upload(error),
    })?;
    for notice in base.notices.iter().chain(&head.notices) {
        writeln!(stderr, "Note: {}", super::safe(notice)).map_err(Error::Output)?;
    }
    let report = create_api()?.diff(paired, &mut |event| {
        if request.quiet {
            return Ok(());
        }
        super::progress::write_diff(event, stderr)
    })?;
    for (format, destination) in output::reports(&request.output) {
        super::write_report(destination, stdout, Palette::PLAIN, |out, _| {
            render::write(&report, format, (&base.label, &head.label), out).map_err(Error::Output)
        })?;
        if matches!(destination, sbom::Output::Stdout) {
            stdout.flush().map_err(Error::Output)?;
        }
        super::saved_report(destination, request.quiet, stderr)?;
        if matches!(format, Format::Json) {
            // Creating JSON makes previously absent case aliases resolvable.
            output::validate(&request.output)?;
        }
    }
    Ok(Outcome::Success)
}

#[cfg(test)]
mod tests;
