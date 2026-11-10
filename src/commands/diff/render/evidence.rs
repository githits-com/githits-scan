//! Security changes and file problems in reader-facing language.
use super::{Display, View, package, revision, view};
use serde_json::value::RawValue;
use std::io;

pub(super) fn write(v: &View, d: &mut Display<'_>) -> io::Result<()> {
    let Some(data) = v
        .advisories
        .decode::<view::Advisories>()
        .map_err(io::Error::other)?
    else {
        return d.line(&super::section_message(
            &v.advisories,
            "Security advisory checks",
        ));
    };
    if data.coordinate_transitions.is_empty() && data.exposures.is_empty() {
        return limitations(&v.advisories, d);
    }
    d.heading("Security advisories")?;
    d.line("Both revisions are checked against today's security information, rather than what was known when each revision was created.")?;
    limitations(&v.advisories, d)?;
    for transition in &data.coordinate_transitions {
        let context = v
            .changes
            .iter()
            .find(|c| c.id == transition.change_id)
            .map_or_else(
                || "A changed package whose name and file were not supplied".into(),
                |c| format!("{} in {}", package(&c.package), c.source_key),
            );
        deltas(&context, &transition.deltas, &data.findings, d)?;
    }
    for exposure in &data.exposures {
        let context = scope_label(&exposure.scope);
        if exposure.scope.kind == "repository_union" {
            deltas(&context, &exposure.deltas, &data.findings, d)?;
        }
        for (side, c) in exposure
            .coverage
            .iter()
            .filter(|(_, c)| c.inventory != "complete" || c.assessment != "complete")
        {
            let problem = coverage_problem(c);
            d.item(&format!(
                "For {context} in the {} revision, {problem}. Check security advisories manually.",
                revision(side)
            ))?;
        }
    }
    Ok(())
}

fn limitations(section: &crate::api::diff::Section, d: &mut Display<'_>) -> io::Result<()> {
    let coverage = section
        .coverage
        .as_ref()
        .map(|raw| serde_json::from_str::<view::AdvisoryCoverage>(raw.get()))
        .transpose()
        .map_err(io::Error::other)?;
    let unresolved = coverage
        .as_ref()
        .is_some_and(|c| c.unknown.is_some_and(|n| n > 0));
    let unsupported = coverage
        .as_ref()
        .is_some_and(|c| c.unsupported.is_some_and(|n| n > 0));
    if section.status != "partial" && !unresolved && !unsupported {
        return Ok(());
    }
    let reason = match section.reason.as_deref() {
        Some("deadline") => {
            "Some security checks could not be completed before the comparison's time limit."
        }
        Some("provider_unavailable") => {
            "Some security checks could not be completed because the service's information provider was unavailable."
        }
        _ if unresolved => {
            "The service did not return conclusive security checks for every package version, and did not explain why."
        }
        _ if unsupported => "Some package versions could not be checked for security advisories.",
        _ => {
            "Some security checks could not be completed; the service supplied no explanation this version of Scan can display."
        }
    };
    let support = if unsupported {
        " The service does not support checking some package versions."
    } else {
        ""
    };
    d.line(&format!(
        "{reason}{support} Check security advisories manually before accepting these changes."
    ))
}

fn coverage_problem(c: &view::ScopeCoverage) -> &'static str {
    if c.inventory != "complete" {
        return "not all package information was available";
    }
    if c.unqualified_occurrences.is_some_and(|n| n > 0) {
        return "some package entries could not be identified for security checks";
    }
    "the service did not complete all security checks"
}

fn scope_label(scope: &view::Scope) -> String {
    if let Some(path) = &scope.source_key {
        return path.clone();
    }
    if let Some(path) = &scope.manifest_path {
        return format!("the project declared in {path}");
    }
    match scope.qualifier.as_str() {
        "recorded" => "the supplied project files".into(),
        "resolved" => "packages selected from the supplied dependency requirements".into(),
        _ => "the compared packages (the service did not identify their file grouping)".into(),
    }
}

fn deltas(
    context: &str,
    rows: &[view::Delta],
    findings: &[view::Finding],
    d: &mut Display<'_>,
) -> io::Result<()> {
    for delta in rows.iter().filter(|r| r.kind != "non_affecting") {
        let finding = findings.iter().find(|f| f.id == delta.finding_id);
        let label = finding.map_or_else(
            || "an advisory whose public identifier was not supplied".into(),
            |f| format!("{} ({})", f.osv_id, package(&f.package)),
        );
        let message = match delta.kind.as_str() {
            "fixed" => format!("{context}: no longer affected by {label} after this change."),
            "introduced" => format!("{context}: newly affected by {label} after this change."),
            "unchanged" => format!("{context}: still affected by {label} after this change."),
            _ => format!(
                "For {context}, Scan could not determine how exposure to {label} changed. Review the advisory before accepting this change."
            ),
        };
        d.item(&message)?;
        if let Some(summary) = finding.and_then(|f| f.summary.as_ref()) {
            d.item(&format!("  {summary}"))?;
        }
        assessment_qualifications(delta, d)?;
    }
    Ok(())
}

fn assessment_qualifications(delta: &view::Delta, d: &mut Display<'_>) -> io::Result<()> {
    for (side, a) in [("earlier", &delta.base), ("later", &delta.head)] {
        for reason in &a.reasons {
            d.item(&format!(
                "  In the {side} revision, {}",
                assessment_reason(reason)
            ))?;
        }
    }
    Ok(())
}

fn assessment_reason(reason: &str) -> &'static str {
    match reason {
        "source_scope_incomplete" => {
            "the package information from the supplied files was incomplete, so the service could not establish whether this advisory applies throughout those files."
        }
        "coordinate_assessment_incomplete" => {
            "the service could not finish checking whether this advisory applies to the package versions."
        }
        _ => {
            "the service reported a limitation that this version of Scan cannot explain. Check the advisory manually; this result does not establish that the package is safe."
        }
    }
}

pub(super) fn gaps(
    raw: &RawValue,
    side: &str,
    explanations: &super::explanations::Evidence<'_>,
    d: &mut Display<'_>,
) -> io::Result<()> {
    let c: view::Coverage = serde_json::from_str(raw.get()).map_err(io::Error::other)?;
    if c.partial == Some(true) {
        d.line(&format!(
            "Some dependency information was unavailable {}.",
            super::revision_context(side)
        ))?;
    }
    for rows in [
        &c.sources,
        &c.resolution,
        &c.excluded_dependencies,
        &c.mismatches,
    ] {
        for row in rows {
            write_gap(row, side, d)?;
        }
    }
    for row in c.reachability.iter().filter(|r| !r.complete) {
        d.item(&format!(
            "Scan could not establish how the dependencies in {} connect to the packages in {} {}.",
            row.manifest_path,
            row.source_key,
            super::revision_context(side)
        ))?;
        super::explanations::coverage(explanations, side, row.reachability_id.as_deref(), d)?;
        if side == "Report" {
            d.item("  The service did not attach a revision-specific explanation to this comparison-wide limitation. Review those files manually.")?;
        }
    }
    Ok(())
}

fn write_gap(row: &view::Gap, side: &str, d: &mut Display<'_>) -> io::Result<()> {
    let reasons: std::collections::BTreeSet<_> = row
        .reason
        .iter()
        .chain(&row.reasons)
        .map(String::as_str)
        .collect();
    if reasons.is_empty() {
        return d.item(&gap_message(row, side, None));
    }
    for reason in reasons {
        d.item(&gap_message(row, side, Some(reason)))?;
    }
    Ok(())
}

fn gap_message(row: &view::Gap, side: &str, reason: Option<&str>) -> String {
    let files = row
        .path
        .iter()
        .chain(&row.paths)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let files = if files.is_empty() {
        "files not identified by the service"
    } else {
        &files
    };
    let context = format!("{files} {}", super::revision_context(side));
    let read_context = if matches!(side, "base" | "head") {
        "from that revision"
    } else {
        "for this comparison"
    };
    let presence = if matches!(side, "base" | "head") {
        "that revision"
    } else {
        "the compared revisions"
    };
    let name = row
        .name
        .as_deref()
        .unwrap_or("a dependency whose name was not supplied");
    let version = row
        .version
        .as_ref()
        .map_or(String::new(), |v| format!(" {v}"));
    match reason {
        Some("dependency_scope_unknown") => format!("The service could not determine which packages from {context} belong in this comparison. Review the dependency declarations and lockfile entries manually."),
        Some("required_input_not_supplied") => row.required_path.as_ref().map_or_else(
            || format!("Could not fully compare {context} because a required dependency file was not read. The service did not identify the missing file. Review the dependency files and Scan's exclusions."),
            |path|format!("Could not fully compare {context} because {path} was not among the files read {read_context}. Check that it exists in {presence} and is not excluded from Scan.")),
        Some("non_registry_source") => format!("{name}{version} in {context} comes from outside a public package registry, so it could not be checked against public security advisories. Review its source and security information manually."),
        Some("locked_version_does_not_satisfy_request") => format!("The dependency {name} requires {} in {}, but {files} lists {} {}. Review the dependency requirement and lockfile entries.",row.requested_requirement.as_deref().unwrap_or("a requirement not supplied in this report"),row.declaration_path.as_deref().unwrap_or("a dependency file not identified by the service"),if row.locked_versions.is_empty() {"no matching versions".into()} else {row.locked_versions.join(", ")},super::revision_context(side)),
        Some("recorded_dependency_scope_differs") => format!("For {name} in {context}, the dependency declaration and lockfile disagree about how the dependency is used. Review the corresponding entries."),
        Some("recorded_requirement_differs" | "recorded_provider_requirement_mismatch") => format!("For {name} in {context}, the dependency requirement differs between the declaration and lockfile. Review the corresponding entries."),
        Some("lockfile_not_supplied" | "missing_lockfile") => format!("Could not check {context} because its lockfile was not read. Check that the lockfile exists in {presence} and is not excluded from Scan."),
        _ => format!("Could not fully check {name}{version} in {context}. The service did not supply a reason that this version of Scan can explain. Review these files manually."),
    }
}
