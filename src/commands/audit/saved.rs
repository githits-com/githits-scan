//! Explicit analysis files; replay never reaches discovery or credential setup.
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use super::{Error, Outcome, ReplayRequest, view};
use crate::api::audit::Report;
use crate::audit::{explain, saved};
use crate::style::Palette;

pub(super) fn preflight(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::AnalysisExists {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::OutputFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(super) fn save(
    path: &Path,
    report: &Report,
    manifests: &[String],
    policy: &crate::config::Audit,
) -> Result<(), Error> {
    let bytes =
        saved::encode(report, &manifests.iter().cloned().collect(), policy).map_err(|error| {
            Error::SaveAnalysis {
                path: path.to_path_buf(),
                reason: error.to_string(),
            }
        })?;
    let write = || {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(&bytes)?;
        file.flush()
    };
    write().map_err(|source| Error::OutputFile {
        path: path.to_path_buf(),
        source,
    })
}

fn load(path: &Path) -> Result<saved::Analysis, Error> {
    let bytes = super::super::read_selected(path)?;
    saved::decode(&bytes).map_err(|error| Error::InvalidAnalysis {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

pub(super) fn replay(
    request: &ReplayRequest<'_>,
    out: &mut dyn std::io::Write,
    palette: Palette,
) -> Result<Outcome, Error> {
    let analysis = load(request.file)?;
    let (mut result, outcome) = super::project(
        &analysis.report,
        analysis.selected_manifests.into_iter().collect(),
        &analysis.audit_policy,
    );
    if let Some(package) = request.explain {
        let mut selected =
            explain::select(&analysis.report, package).ok_or_else(|| Error::NoAuditPackage {
                candidates: super::explain::candidates(&result, package),
            })?;
        select_recommendations(&mut result, &mut selected);
        super::super::write_report(&request.output, out, palette, |out, _| {
            super::explain::write(&result, &analysis.provenance, &selected, request.json, out)
                .map_err(Error::Output)
        })?;
    } else {
        result.analysis = Some(analysis.provenance);
        super::write_result(
            &result,
            request.json,
            request.details,
            &request.output,
            out,
            palette,
        )?;
    }
    Ok(outcome)
}

fn select_recommendations(result: &mut view::View, selected: &mut explain::Explanation<'_>) {
    let view::remediation::State::Present(data) = &mut result.remediation else {
        return;
    };
    data.recommendations = std::mem::take(&mut data.recommendations)
        .into_iter()
        .enumerate()
        .filter_map(|(i, mut r)| {
            if !selected.recommendation_indices.contains(&i) {
                return None;
            }
            r.occurrence_scope = selected.recommendation_scopes.remove(&i);
            Some(r)
        })
        .collect();
}
