//! Useful upgrade notes and explicit reasons for missing checks.
use super::{Display, View, view};
use std::io;

pub(super) fn write(
    v: &View,
    explanations: &super::explanations::Evidence<'_>,
    d: &mut Display<'_>,
) -> io::Result<()> {
    let Some(rows) = v
        .direct_reviews
        .decode::<Vec<view::Review>>()
        .map_err(io::Error::other)?
    else {
        return d.line(&super::section_message(
            &v.direct_reviews,
            "Upgrade reviews",
        ));
    };
    for r in rows {
        d.heading(&format!(
            "Upgrade review: {} {} → {}",
            r.name, r.current_version, r.target_version
        ))?;
        if !r.source_keys.is_empty() {
            d.item(&format!("Files: {}", r.source_keys.join(", ")))?;
        }
        super::explanations::review_context(explanations, &r, d)?;
        if let Some(failure) = &r.failure {
            write_failure(failure, d)?;
        }
        if let Some(data) = r.evidence() {
            detail(&data, d)?;
        } else if r.failure.is_none() {
            unavailable_detail(&r, d)?;
        }
    }
    Ok(())
}

fn unavailable_detail(review: &view::Review, d: &mut Display<'_>) -> io::Result<()> {
    let text = match review.reason.as_deref() {
        Some("deadline") => {
            "The upgrade review was not completed before the comparison's time limit."
        }
        Some("result_size_limit") => {
            "The upgrade was assessed, but its review could not fit within the report's size limit."
        }
        Some("evidence_unavailable") => {
            "The information required to review this upgrade was unavailable."
        }
        Some("review_failed") => {
            "The upgrade review could not be returned. The service did not supply a failure explanation."
        }
        _ if matches!(review.status.as_str(), "complete" | "partial") => {
            "Scan cannot display this upgrade review because the service returned no review in a format this version supports."
        }
        _ => {
            "No usable upgrade review was returned. The service supplied no reason this version of Scan can display."
        }
    };
    d.item(&format!(
        "{text} Review the release notes and security advisories before accepting this upgrade."
    ))
}

fn write_failure(f: &view::ReviewFailure, d: &mut Display<'_>) -> io::Result<()> {
    let text = match f.scope.as_str() {
        "batch" => {
            "The service could not return the upgrade review because preparing the combined report failed. The review for this package may have finished, but its complete result could not be returned."
        }
        "review" => match f.code.as_str() {
            "unexpected_task_exit" => {
                "The service stopped reviewing this package before it returned a result."
            }
            "argument_error" | "review_structure_error" | "review_exception" => {
                "The upgrade review failed because of an error in the service."
            }
            _ => "The upgrade review failed in the service.",
        },
        _ => {
            "The service could not return the upgrade review. It did not identify whether this package's review or preparation of the combined report failed."
        }
    };
    d.item(text)?;
    if !matches!(
        f.code.as_str(),
        "unexpected_task_exit" | "argument_error" | "review_structure_error" | "review_exception"
    ) && !f.message.trim().is_empty()
    {
        d.item(&format!("  {}", f.message))?;
    }
    d.item("  Review the release notes and security advisories manually before accepting this upgrade.")
}

fn detail(data: &view::ReviewData, d: &mut Display<'_>) -> io::Result<()> {
    if let Some(security) = &data.security {
        security_detail("earlier", security.current.as_ref(), d)?;
        security_detail("later", security.target.as_ref(), d)?;
    } else {
        d.item("  Security information was not returned for this upgrade. Check security advisories before accepting it.")?;
    }
    for gap in &data.unknown_details {
        d.item(&format!("  {}", gap.message))?;
    }
    let Some(log) = &data.changelog else {
        return d.item("  Release notes were not returned. Read the package's release notes before accepting this upgrade.");
    };
    if log
        .coverage
        .as_ref()
        .is_none_or(|c| c.status != "complete" || c.truncated)
    {
        d.item("  Release notes are incomplete; additional changes may need attention. Read the package's release notes before accepting this upgrade.")?;
    }
    if !log.breaking_signals.is_empty() {
        d.item("  This upgrade may require changes to your code because the release notes flag compatibility changes.")?;
    }
    if !log.migration_signals.is_empty() {
        d.item("  The release notes flag migration work. Review the relevant instructions before accepting this upgrade.")?;
    }
    let displayed: Vec<_> = log
        .entries
        .iter()
        .enumerate()
        .filter(|(i, e)| d.markdown || *i < 3 || !e.signals.is_empty())
        .map(|(_, e)| e)
        .collect();
    for entry in &displayed {
        let version = entry
            .version
            .as_deref()
            .unwrap_or("release version not supplied");
        let headline = entry
            .headline
            .as_deref()
            .unwrap_or("Release-note summary was not supplied.");
        d.item(&format!("  {version}: {headline}"))?;
        if !entry.signals.is_empty() {
            d.item(
                "  Review this release for changes that may require attention in your project.",
            )?;
        }
        if let Some(url) = &entry.html_url {
            d.link(&format!("  {version} release notes"), url)?;
        }
    }
    if displayed.len() < log.entries.len() {
        d.item("  Additional release notes are available in the JSON report.")?;
    }
    Ok(())
}

fn security_detail(
    side: &str,
    value: Option<&view::VersionSecurity>,
    d: &mut Display<'_>,
) -> io::Result<()> {
    let Some(v) = value else {
        return d.item(&format!(
            "  The service did not return a security check for the {side} version."
        ));
    };
    let message = match v.assessment_status.as_str() {
        "affected" => Some(
            "is affected by security advisories. Review the advisory findings before accepting this upgrade.",
        ),
        "non_affecting" => None,
        "unknown" => Some(
            "could not be checked conclusively: the service could not determine whether security advisories apply.",
        ),
        "not_assessed" => Some("was not checked for security advisories."),
        "unsupported" => Some(
            "could not be checked for security advisories because the service does not support this package.",
        ),
        _ => Some("has no usable security conclusion in the returned review."),
    };
    if let Some(message) = message {
        d.item(&format!("  The {side} version {message}"))?;
    }
    if v.unknown_vulnerability_count > 0 {
        d.item(&format!("  For the {side} version, the service could not determine whether some advisories apply. Review those advisories manually."))?;
    }
    Ok(())
}
