//! Experimental dependency comparison; renderers consume facts without owning interpretation.
use super::{Error, Outcome, sbom, upload};
use crate::api::{self, AuditApi, SbomApi, UploadSet, upgrade::UpgradeApi};
use crate::{config, diff, discover, repository::Snapshot, style::Palette};
use clap::ValueEnum;
use std::io::Write;
use std::path::Path;

mod render;

/// Experimental report representation.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    /// Human dependency table.
    Human,
    /// Versioned facts for automation.
    Json,
    /// Escaped table suitable for a pull request comment.
    Markdown,
}

/// A two-point repository comparison; omitted head means actual working-tree bytes.
pub struct Request<'a> {
    /// Git repository root.
    pub root: &'a Path,
    /// Base commit or revision expression.
    pub base: &'a str,
    /// Head revision; absence selects the working tree.
    pub head: Option<&'a str>,
    /// Report representation.
    pub format: Format,
    /// Explicit file exclusions applied to both sides.
    pub exclude: &'a [String],
    /// Whether manifest-only resolution is selected.
    pub include_manifests: bool,
    /// Suppress progress.
    pub quiet: bool,
    /// Report destination.
    pub output: sbom::Output,
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

/// Prepare both sides before networking and render only after the comparison exists.
///
/// `create_api` is lazy: identical/empty inputs need neither credentials nor HTTP.
///
/// # Errors
/// Returns typed input/output errors or API errors when the required inventory is unavailable.
pub fn run<A: SbomApi + AuditApi + UpgradeApi>(
    request: &Request<'_>,
    create_api: impl FnOnce() -> Result<A, Error>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<Outcome, Error> {
    let base = prepare(request, Some(request.base))?;
    let head = prepare(request, request.head)?;
    let identical = base.upload == head.upload;
    let mut notices = [base.notices.clone(), head.notices.clone()].concat();
    let mut report = diff::Report {
        schema_version: 1,
        comparison_scope: "repository_version_union_with_source_local_direct_changes",
        base: base.label.clone(),
        head: head.label.clone(),
        analysis_performed: !identical,
        incomplete: !notices.is_empty(),
        notices: Vec::new(),
        changes: Vec::new(),
    };
    if identical {
        if base.upload.is_some() {
            notices.push("analysis not run: selected package inputs are identical; vulnerabilities were not assessed".into());
        }
    } else {
        let api = create_api()?;
        let inventories = (
            inventory(&base, &api, request, stderr)?,
            inventory(&head, &api, request, stderr)?,
        );
        notices.extend(inventories.0.notices.iter().cloned());
        notices.extend(inventories.1.notices.iter().cloned());
        let audits = audits(
            (&base, &head),
            (&inventories.0, &inventories.1),
            &api,
            request,
            stderr,
            &mut notices,
        )?;
        for (input, audit) in [(&base, &audits.0), (&head, &audits.1)] {
            notices.extend(
                audit
                    .notices
                    .iter()
                    .map(|notice| format!("{}: {notice}", input.label)),
            );
        }
        report.incomplete |= audits.0.incomplete || audits.1.incomplete;
        report.changes = diff::compare(&inventories.0, &inventories.1, (&audits.0, &audits.1));
        enrich(&mut report.changes, &api);
    }
    notices.sort();
    notices.dedup();
    report.incomplete |= !notices.is_empty()
        || report
            .changes
            .iter()
            .any(|c| !c.vulnerabilities.assessed || !c.review_gaps.is_empty());
    report.notices = notices;
    super::write_report(&request.output, stdout, Palette::PLAIN, |out, _| {
        render::write(&report, request.format, out).map_err(Error::Output)
    })?;
    super::saved_report(&request.output, request.quiet, stderr)?;
    Ok(Outcome::Success)
}

fn inventory(
    input: &Input,
    api: &dyn SbomApi,
    request: &Request<'_>,
    stderr: &mut dyn Write,
) -> Result<diff::Inventory, Error> {
    let Some(upload) = &input.upload else {
        return Ok(diff::Inventory::default());
    };
    let document = api.generate(upload.clone(), api::OutputFormat::CycloneDx, &mut |event| {
        progress(request, event, stderr)
    })?;
    diff::Inventory::decode(&document)
}

fn audits<A: AuditApi>(
    inputs: (&Input, &Input),
    inventories: (&diff::Inventory, &diff::Inventory),
    api: &A,
    request: &Request<'_>,
    stderr: &mut dyn Write,
    notices: &mut Vec<String>,
) -> Result<(diff::Audit, diff::Audit), Error> {
    let mut failed = false;
    let mut analyze = |input: &Input, inventory: &diff::Inventory| -> Result<diff::Audit, Error> {
        let Some(upload) = &input.upload else {
            return Ok(diff::Audit::empty());
        };
        if failed {
            return Ok(diff::Audit::default());
        }
        let result = api
            .audit(upload.clone(), &mut |event| {
                progress(request, event, stderr)
            })
            .map_err(Error::from)
            .and_then(|report| diff::Audit::project(&report, inventory));
        match result {
            Ok(audit) => Ok(audit),
            Err(error) => {
                notices.push(format!("{}: audit unavailable: {error}", input.label));
                writeln!(
                    stderr,
                    "warning: audit unavailable; inventory diff retained: {error}"
                )
                .map_err(Error::Output)?;
                failed = true;
                Ok(diff::Audit::default())
            }
        }
    };
    Ok((
        analyze(inputs.0, inventories.0)?,
        analyze(inputs.1, inventories.1)?,
    ))
}

fn progress(
    request: &Request<'_>,
    event: &api::ProgressEvent,
    stderr: &mut dyn Write,
) -> std::io::Result<()> {
    if request.quiet || matches!(request.format, Format::Json) {
        Ok(())
    } else {
        super::progress::write_audit(event, stderr)
    }
}

fn enrich(changes: &mut [diff::Change], api: &dyn UpgradeApi) {
    let mut requests = Vec::new();
    for (index, change) in changes.iter_mut().enumerate() {
        requests.extend(diff::transitions(change).into_iter().map(|p| (index, p)));
    }
    let mut limited = false;
    for chunk in requests.chunks(api::upgrade::MAX_PACKAGES) {
        if limited {
            review_gaps(
                changes,
                chunk,
                "upgrade review not attempted after rate limit",
            );
            continue;
        }
        limited = review_chunk(changes, chunk, api);
    }
}

fn review_chunk(
    changes: &mut [diff::Change],
    chunk: &[(usize, api::upgrade::Package)],
    api: &dyn UpgradeApi,
) -> bool {
    let packages: Vec<_> = chunk.iter().map(|(_, p)| p.clone()).collect();
    let reviews = match api.review(&packages) {
        Ok(reviews) => reviews,
        Err(error) => {
            review_gaps(
                changes,
                chunk,
                &format!("upgrade review unavailable: {error}"),
            );
            return matches!(&error, api::ApiError::Problem { problem, .. } if problem.status == 429)
                || matches!(&error, api::ApiError::Unexpected { status: 429, .. });
        }
    };
    for ((index, _), review) in chunk.iter().zip(reviews) {
        if review.incomplete() {
            changes[*index]
                .review_gaps
                .push("upgrade review contains incomplete evidence".into());
        }
        changes[*index].upgrade_reviews.push(review);
    }
    false
}

fn review_gaps(
    changes: &mut [diff::Change],
    chunk: &[(usize, api::upgrade::Package)],
    message: &str,
) {
    for (index, _) in chunk {
        changes[*index].review_gaps.push(message.into());
    }
}

#[cfg(test)]
mod tests;
