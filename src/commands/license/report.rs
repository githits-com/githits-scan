//! Informational dependency-license reporting, independent of policy evaluation.

use std::fs::File;
use std::io::{Read as _, Write};
use std::path::Path;

use crate::api::licenses::Report;
use crate::api::{LicensesApi, MAX_RESPONSE_BYTES, ProgressEvent};
use crate::commands::{Error, Outcome, progress, sbom, upload};
use crate::style::Palette;

mod render;

/// Where a dependency-license report comes from.
pub enum Source<'a> {
    /// Generate one analysis using the selected repository evidence.
    Generate(&'a dyn LicensesApi),
    /// Replay a saved public licenses report without authentication or discovery.
    File(&'a Path),
}

/// Selection and presentation options for an informational report.
#[expect(clippy::struct_excessive_bools, reason = "independent CLI switches")]
pub struct Request<'a> {
    /// Repository root, used only for generation.
    pub root: &'a Path,
    /// Optional inventory configuration.
    pub config: Option<&'a Path>,
    /// Continue despite inventory drift.
    pub no_check: bool,
    /// Include manifest-only evidence.
    pub include_manifests: bool,
    /// Invocation exclusions.
    pub exclude: &'a [String],
    /// Write the exact public JSON report instead of human text.
    pub json: bool,
    /// Include attribution, observations and coverage in human output.
    pub details: bool,
    /// Suppress routine diagnostics, retaining warnings and errors.
    pub quiet: bool,
    /// Report destination, including offline replay.
    pub output: sbom::Output,
    /// Online generation or a saved report.
    pub source: Source<'a>,
}

/// Render the full inventory without applying a license policy.
///
/// Valid partial reports are successful; only the existing pre-upload drift and
/// empty-selection gates return findings. Failures before output leave an existing
/// destination untouched; output I/O errors can leave partial writes.
///
/// # Errors
/// Returns typed discovery, configuration, API, saved-report or output failures.
pub fn run(
    request: &Request<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    palette: Palette,
    stderr_palette: Palette,
) -> Result<Outcome, Error> {
    let (report, summary) = match request.source {
        Source::File(path) => (read(path)?, None),
        Source::Generate(api) => {
            let options = upload::Options {
                root: request.root,
                config: request.config,
                no_check: request.no_check,
                include_manifests: request.include_manifests,
                exclude: request.exclude,
                progress: !request.json && !request.quiet,
            };
            let Some(prepared) = upload::prepare(&options, stderr, stderr_palette)? else {
                return Ok(Outcome::Findings);
            };
            let report = api.report(prepared.upload, &mut |event| {
                write_progress(event, stderr, !request.json && !request.quiet)
            })?;
            (report, Some(prepared.summary))
        }
    };
    let view = report.view();
    let incomplete =
        super::display::warn_incomplete(view.completeness(), stderr).map_err(Error::Output)?;
    write_result(&report, view, request, stdout, palette)?;
    if !request.quiet {
        if !request.json && !request.details {
            writeln!(
                stderr,
                "Use --details for evidence and coverage; --json for the complete report."
            )
            .map_err(Error::Output)?;
        }
        if let Some(summary) = summary {
            writeln!(stderr, "{summary}").map_err(Error::Output)?;
        }
        if !incomplete {
            writeln!(
                stderr,
                "inventory: {}",
                super::display::completeness(view.completeness().unwrap_or("not reported"))
            )
            .map_err(Error::Output)?;
        }
    }
    crate::commands::saved_report(&request.output, request.quiet, stderr)?;
    Ok(Outcome::Success)
}

fn write_progress(
    event: &ProgressEvent,
    stderr: &mut dyn Write,
    enabled: bool,
) -> std::io::Result<()> {
    if !progress::visible(event, enabled) {
        return Ok(());
    }
    progress::write_licenses(event, stderr)
}

fn read(path: &Path) -> Result<Report, Error> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take(MAX_RESPONSE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|source| Error::ReadDocument {
            path: path.to_path_buf(),
            source,
        })?;
    Report::from_bytes(bytes).map_err(|source| Error::InvalidLicenseReport {
        path: path.to_path_buf(),
        source,
    })
}

fn write_result(
    report: &Report,
    view: &crate::api::licenses::View,
    request: &Request<'_>,
    stdout: &mut dyn Write,
    palette: Palette,
) -> Result<(), Error> {
    let write = |out: &mut dyn Write, colors| {
        if request.json {
            out.write_all(report.bytes())?;
        } else {
            render::write(view, report.bytes(), request.details, out, colors)?;
        }
        out.flush()
    };
    crate::commands::write_report(&request.output, stdout, palette, |out, palette| {
        write(out, palette).map_err(Error::Output)
    })
}
