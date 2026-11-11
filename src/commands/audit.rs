//! One combined audit submission, truthful outcomes and injected-stream rendering.

use std::io::Write;
use std::path::Path;

use super::{Error, Outcome, sbom, upload};
use crate::api::AuditApi;
use crate::style::Palette;

mod explain;
mod render;
mod saved;
mod view;

/// Inputs for an audit of the selected repository evidence.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent command-line switches"
)]
pub struct Request<'a> {
    /// Repository root.
    pub root: &'a Path,
    /// Optional inventory configuration override.
    pub config: Option<&'a Path>,
    /// Continue with configured selections despite drift.
    pub no_check: bool,
    /// Include manifest-only resolution.
    pub include_manifests: bool,
    /// Invocation exclusion globs.
    pub exclude: &'a [String],
    /// Write the compact command result as JSON instead of human text.
    pub json: bool,
    /// Expand maintenance lists in human output; structured facts stay complete.
    pub details: bool,
    /// Suppress routine progress and success messages; retain actionable diagnostics.
    pub quiet: bool,
    /// Destination, written only after a structurally valid complete result.
    pub output: sbom::Output,
    /// Explicit new analysis file; report output stays separate.
    pub save_analysis: Option<&'a Path>,
}

/// Inputs for offline re-display or investigation of a saved analysis.
#[derive(Debug)]
pub struct ReplayRequest<'a> {
    /// Saved analysis file; never interpreted as a repository path.
    pub file: &'a Path,
    /// Emit a structured report instead of human text.
    pub json: bool,
    /// Expand maintenance lists in human output; structured facts stay complete.
    pub details: bool,
    /// Exact vulnerable coordinate to inspect; absent re-displays the compact report.
    pub explain: Option<&'a str>,
    /// Destination of the replayed report or explanation.
    pub output: sbom::Output,
}

/// Re-display or explain saved evidence without credentials, discovery or network.
///
/// # Errors
/// Returns typed input, selection, file I/O or output errors.
pub fn replay(
    request: &ReplayRequest<'_>,
    out: &mut dyn Write,
    palette: Palette,
) -> Result<Outcome, Error> {
    saved::replay(request, out, palette)
}

/// Submit once and render all finding categories and evidence gaps.
///
/// # Errors
///
/// Returns discovery/configuration/admission/transport/decoding or output errors.
/// Output I/O errors may leave partial writes; preceding failures leave it untouched.
pub fn run(
    request: &Request<'_>,
    api: &dyn AuditApi,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    palette: Palette,
    stderr_palette: Palette,
) -> Result<Outcome, Error> {
    if let Some(path) = request.save_analysis {
        saved::preflight(path)?;
    }
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
    let report = api.audit(prepared.upload, &mut |event| {
        if super::progress::visible(event, !request.json && !request.quiet) {
            super::progress::write_audit(event, stderr)
        } else {
            Ok(())
        }
    })?;
    if let Some(path) = request.save_analysis {
        saved::save(path, &report, &prepared.manifests, &prepared.audit_policy)?;
    }
    let (view, outcome) = project(&report, prepared.manifests, &prepared.audit_policy);
    write_result(
        &view,
        request.json,
        request.details,
        &request.output,
        stdout,
        palette,
    )?;
    if let Some(path) = request.save_analysis
        && !request.quiet
    {
        writeln!(stderr, "saved {}", super::safe_path(path)).map_err(Error::Output)?;
    }
    super::saved_report(&request.output, request.quiet, stderr)?;
    Ok(outcome)
}

fn project(
    report: &crate::api::audit::Report,
    manifests: Vec<String>,
    policy: &crate::config::Audit,
) -> (view::View, Outcome) {
    let assessment = crate::audit::assess(report, policy);
    let attention = assessment.attention;
    (
        view::View::new(report, &assessment, manifests, policy),
        if attention {
            Outcome::Findings
        } else {
            Outcome::Success
        },
    )
}

fn write_result(
    view: &view::View,
    json: bool,
    details: bool,
    output: &sbom::Output,
    stdout: &mut dyn Write,
    palette: Palette,
) -> Result<(), Error> {
    let write = |out: &mut dyn Write, palette| -> std::io::Result<()> {
        if json {
            serde_json::to_writer_pretty(&mut *out, view).map_err(std::io::Error::other)?;
            writeln!(out)?;
        } else {
            render::write(view, details, out, palette)?;
        }
        out.flush()
    };
    super::write_report(output, stdout, palette, |out, palette| {
        write(out, palette).map_err(Error::Output)
    })
}

#[cfg(test)]
mod tests;
