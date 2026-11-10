//! Security changes and file problems in reader-facing language.
use super::{Display, View, package, view};
use std::collections::{BTreeMap, BTreeSet};
use std::io;

type Qualifications = BTreeMap<(String, String), BTreeSet<&'static str>>;

pub(super) fn write(v: &View, d: &mut Display<'_>) -> io::Result<()> {
    let Some(data) = v
        .advisories
        .decode::<view::Advisories>()
        .map_err(io::Error::other)?
    else {
        d.heading("Security advisories")?;
        return d.line(&super::section_message(
            &v.advisories,
            "Security advisory checks",
        ));
    };
    let qualifications = qualifications(&data);
    let limitation = limitation(&v.advisories, !qualifications.is_empty())?;
    let manual_check = limitation.is_none()
        && (!qualifications.is_empty()
            || data
                .coordinate_transitions
                .iter()
                .flat_map(|t| &t.deltas)
                .any(|r| {
                    r.kind != "non_affecting"
                        && (!r.base.reasons.is_empty() || !r.head.reasons.is_empty())
                }));
    let changed: BTreeSet<_> = data
        .coordinate_transitions
        .iter()
        .flat_map(|t| &t.deltas)
        .filter(|r| r.kind != "non_affecting")
        .map(|r| r.finding_id.as_str())
        .collect();
    let project: Vec<_> = data
        .exposures
        .iter()
        .filter(|e| e.scope.kind == "repository_union")
        .collect();
    let material = !changed.is_empty() || project.iter().any(|e| e.deltas.iter().any(project_fact));
    if !material && qualifications.is_empty() && limitation.is_none() {
        return Ok(());
    }
    d.heading("Security advisories")?;
    if material {
        d.line("Advisory results use today's security information, rather than what was known when each revision was created.")?;
    }
    if let Some(message) = limitation {
        d.line(&message)?;
    }
    for transition in &data.coordinate_transitions {
        let context = v
            .changes
            .iter()
            .find(|c| c.id == transition.change_id)
            .map_or_else(
                || "A changed package whose name and file were not supplied".into(),
                |c| format!("{} in {}", package(&c.package), c.source_key),
            );
        coordinate_deltas(&context, &transition.deltas, &data.findings, &project, d)?;
    }
    for exposure in project {
        project_deltas(exposure, &changed, &data, &mut *d)?;
    }
    for ((context, message), sides) in qualifications {
        let phase = if sides.contains("base") && sides.contains("head") {
            "in both revisions"
        } else {
            super::revision_context(sides.first().copied().unwrap_or("Report"))
        };
        d.item(&format!("For {context} {phase}, {message}."))?;
    }
    if manual_check {
        d.line("Check security advisories manually before accepting these changes.")?;
    }
    Ok(())
}

fn coordinate_deltas(
    context: &str,
    rows: &[view::Delta],
    findings: &[view::Finding],
    project: &[&view::Exposure],
    d: &mut Display<'_>,
) -> io::Result<()> {
    for delta in rows.iter().filter(|r| r.kind != "non_affecting") {
        delta_fact(context, delta, findings, d)?;
        assessment_qualifications(delta, d)?;
        project_for_change(delta, project, d)?;
    }
    Ok(())
}

fn project_for_change(
    delta: &view::Delta,
    project: &[&view::Exposure],
    d: &mut Display<'_>,
) -> io::Result<()> {
    for exposure in project {
        let context = scope_label(&exposure.scope);
        for row in exposure
            .deltas
            .iter()
            .filter(|r| r.finding_id == delta.finding_id && attached(r, delta))
        {
            let text = project_message(row);
            d.item(&format!("  Across {context}, {text}."))?;
        }
    }
    Ok(())
}

fn project_message(row: &view::Delta) -> &str {
    match row.kind.as_str() {
        "indeterminate" => project_uncertainty(row),
        "fixed" => "this advisory no longer affects the compared package entries",
        "introduced" => "this advisory affects the compared package entries after the change",
        _ => "this advisory continues to affect the compared package entries",
    }
}

fn attached(project: &view::Delta, coordinate: &view::Delta) -> bool {
    project.kind == "indeterminate"
        || (project.kind == coordinate.kind
            && matches!(project.kind.as_str(), "fixed" | "introduced" | "unchanged"))
}

fn project_fact(delta: &view::Delta) -> bool {
    delta.kind != "non_affecting"
        && (delta.kind != "indeterminate"
            || delta.base.status == "affected"
            || delta.head.status == "affected")
}

fn project_deltas(
    e: &view::Exposure,
    changed: &BTreeSet<&str>,
    data: &view::Advisories,
    d: &mut Display<'_>,
) -> io::Result<()> {
    let context = scope_label(&e.scope);
    for row in e.deltas.iter().filter(|r| project_fact(r)) {
        let shown = changed.contains(row.finding_id.as_str())
            && data
                .coordinate_transitions
                .iter()
                .flat_map(|t| &t.deltas)
                .any(|c| {
                    c.kind != "non_affecting" && c.finding_id == row.finding_id && attached(row, c)
                });
        if !shown {
            delta_fact(&context, row, &data.findings, d)?;
        }
    }
    Ok(())
}

fn project_uncertainty(row: &view::Delta) -> &'static str {
    if row.head.status == "affected" {
        return "this advisory affects the project after the change; the comparison could not be fully confirmed";
    }
    if row.base.status == "affected" {
        return "the project was affected before this change, but the service could not confirm the full comparison";
    }
    "the service could not confirm the full advisory comparison"
}

fn qualifications(data: &view::Advisories) -> Qualifications {
    let mut result = Qualifications::new();
    for exposure in &data.exposures {
        exposure_qualifications(exposure, &mut result);
    }
    result
}

fn exposure_qualifications(e: &view::Exposure, result: &mut Qualifications) {
    let context = scope_label(&e.scope);
    for (side, c) in e.coverage.iter() {
        coverage_qualifications(c, &context, side, result);
    }
    for row in &e.deltas {
        delta_qualifications(row, &context, result);
    }
    if e.deltas.iter().any(|r| r.kind == "indeterminate")
        && !result.keys().any(|(c, _)| c == &context)
    {
        qualify(
            result,
            &context,
            "Report",
            "the service did not explain why some advisory results could not be confirmed",
        );
    }
}

fn delta_qualifications(row: &view::Delta, context: &str, result: &mut Qualifications) {
    for (side, a) in [("base", &row.base), ("head", &row.head)] {
        for reason in &a.reasons {
            qualify(result, context, side, assessment_reason(reason));
        }
    }
}

fn qualify(result: &mut Qualifications, context: &str, side: &'static str, message: &str) {
    result
        .entry((context.into(), message.into()))
        .or_default()
        .insert(side);
}

fn limitation(section: &crate::api::diff::Section, explained: bool) -> io::Result<Option<String>> {
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
        return Ok(None);
    }
    let reason = match section.reason.as_deref() {
        Some("deadline") => {
            Some("Some security checks could not be completed before the comparison's time limit.")
        }
        Some("provider_unavailable") => Some(
            "Some security checks could not be completed because the service's information provider was unavailable.",
        ),
        None if explained || unsupported => None,
        _ => Some(
            "Some security checks could not be completed; the service supplied no explanation this version of Scan can display.",
        ),
    };
    let mut parts = Vec::new();
    if let Some(reason) = reason {
        parts.push(reason);
    }
    if unresolved {
        parts.push("Some advisory results could not be confirmed.");
    }
    if unsupported {
        parts.push("The service does not support checking some package versions.");
    }
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(Some(format!(
        "{} Check security advisories manually before accepting these changes.",
        parts.join(" ")
    )))
}

fn coverage_qualifications(
    c: &view::ScopeCoverage,
    context: &str,
    side: &'static str,
    result: &mut Qualifications,
) {
    for (present, message) in [
        (
            c.inventory != "complete",
            assessment_reason("source_scope_incomplete"),
        ),
        (
            c.assessment != "complete",
            assessment_reason("coordinate_assessment_incomplete"),
        ),
        (
            c.unqualified_occurrences.is_some_and(|n| n > 0),
            "some package entries could not be identified for security checks",
        ),
    ] {
        if present {
            qualify(result, context, side, message);
        }
    }
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

fn delta_fact(
    context: &str,
    delta: &view::Delta,
    findings: &[view::Finding],
    d: &mut Display<'_>,
) -> io::Result<()> {
    let finding = findings.iter().find(|f| f.id == delta.finding_id);
    let label = finding.map_or_else(
        || "an advisory whose public identifier was not supplied".into(),
        |f| format!("{} ({})", f.osv_id, package(&f.package)),
    );
    let message = match delta.kind.as_str() {
        "fixed" => format!("{context}: no longer affected by {label} after this change."),
        "introduced" => format!("{context}: newly affected by {label} after this change."),
        "unchanged" => format!("{context}: still affected by {label} after this change."),
        "indeterminate" if delta.head.status == "affected" => format!(
            "{context}: affected by {label} after this change; the earlier result could not be confirmed."
        ),
        "indeterminate" if delta.base.status == "affected" => format!(
            "{context}: affected by {label} before this change; the later result could not be confirmed."
        ),
        _ => format!(
            "For {context}, Scan could not determine how exposure to {label} changed. Review the advisory before accepting this change."
        ),
    };
    d.item(&message)?;
    if let Some(summary) = finding.and_then(|f| f.summary.as_ref()) {
        d.item(&format!("  {summary}"))?;
    }
    Ok(())
}

fn assessment_qualifications(delta: &view::Delta, d: &mut Display<'_>) -> io::Result<()> {
    for (side, a) in [("earlier", &delta.base), ("later", &delta.head)] {
        for reason in &a.reasons {
            d.item(&format!(
                "  In the {side} revision, {}.",
                assessment_reason(reason)
            ))?;
        }
    }
    Ok(())
}

fn assessment_reason(reason: &str) -> &'static str {
    match reason {
        "source_scope_incomplete" => {
            "the package information was incomplete, so the service could not check every relevant package"
        }
        "coordinate_assessment_incomplete" => {
            "the service could not finish checking every relevant package version"
        }
        _ => "the service reported a limitation that this version of Scan cannot explain",
    }
}

pub(super) fn file_problems(
    v: &View,
    explanations: &super::explanations::Evidence<'_>,
    d: &mut Display<'_>,
) -> io::Result<()> {
    let base: view::Coverage =
        serde_json::from_str(v.snapshots.base.coverage.get()).map_err(io::Error::other)?;
    let head: view::Coverage =
        serde_json::from_str(v.snapshots.head.coverage.get()).map_err(io::Error::other)?;
    let report: view::Coverage =
        serde_json::from_str(v.coverage.get()).map_err(io::Error::other)?;
    let all = [&base, &head, &report];
    if !all
        .iter()
        .any(|c| c.partial == Some(true) || has_details(c))
    {
        return Ok(());
    }
    d.heading("Files that need attention")?;
    for (left, right) in families(&base).into_iter().zip(families(&head)) {
        paired_gaps(left, right, d)?;
    }
    for rows in families(&report) {
        for row in rows {
            write_gap(row, "Report", d)?;
        }
    }
    partial_without_details(&base, &head, &report, d)?;
    for (side, coverage) in [("base", &base), ("head", &head), ("Report", &report)] {
        reachability_problems(coverage, side, explanations, d)?;
    }
    Ok(())
}

fn families(c: &view::Coverage) -> [&[view::Gap]; 4] {
    [
        &c.sources,
        &c.resolution,
        &c.excluded_dependencies,
        &c.mismatches,
    ]
}

fn has_details(c: &view::Coverage) -> bool {
    families(c).iter().any(|r| !r.is_empty()) || c.reachability.iter().any(|r| !r.complete)
}

fn paired_gaps(left: &[view::Gap], right: &[view::Gap], d: &mut Display<'_>) -> io::Result<()> {
    let left: BTreeSet<_> = left.iter().collect();
    let right: BTreeSet<_> = right.iter().collect();
    for row in &left {
        write_gap(row, if right.contains(row) { "both" } else { "base" }, d)?;
    }
    for row in right.difference(&left) {
        write_gap(row, "head", d)?;
    }
    Ok(())
}

fn partial_without_details(
    base: &view::Coverage,
    head: &view::Coverage,
    report: &view::Coverage,
    d: &mut Display<'_>,
) -> io::Result<()> {
    let before = base.partial == Some(true) && !has_details(base);
    let after = head.partial == Some(true) && !has_details(head);
    let phase = match (before, after) {
        (true, true) => Some("both"),
        (true, false) => Some("base"),
        (false, true) => Some("head"),
        (false, false)
            if report.partial == Some(true)
                && ![base, head, report].iter().any(|c| has_details(c)) =>
        {
            Some("Report")
        }
        _ => None,
    };
    if let Some(phase) = phase {
        d.line(&format!("Some dependency information was unavailable {}; the service did not supply specific file details.",super::revision_context(phase)))?;
    }
    Ok(())
}

fn reachability_problems(
    c: &view::Coverage,
    side: &str,
    explanations: &super::explanations::Evidence<'_>,
    d: &mut Display<'_>,
) -> io::Result<()> {
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
    let read_context = match side {
        "base" | "head" => "from that revision",
        "both" => "from either revision",
        _ => "for this comparison",
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
            |path|format!("Could not fully compare {context} because {path} was not among the files read {read_context}. Check the file, workspace declarations and --exclude settings.")),
        Some("non_registry_source") => format!("{name}{version} in {context} comes from outside a public package registry, so it could not be checked against public security advisories. Review its source and security information manually."),
        Some("locked_version_does_not_satisfy_request") => format!("The dependency {name} requires {} in {}, but {files} lists {} {}. Review the dependency requirement and lockfile entries.",row.requested_requirement.as_deref().unwrap_or("a requirement not supplied in this report"),row.declaration_path.as_deref().unwrap_or("a dependency file not identified by the service"),if row.locked_versions.is_empty() {"no matching versions".into()} else {row.locked_versions.join(", ")},super::revision_context(side)),
        Some("recorded_dependency_scope_differs") => format!("For {name} in {context}, the dependency declaration and lockfile disagree about how the dependency is used. Review the corresponding entries."),
        Some("recorded_requirement_differs" | "recorded_provider_requirement_mismatch") => format!("For {name} in {context}, the dependency requirement differs between the declaration and lockfile. Review the corresponding entries."),
        Some("lockfile_not_supplied" | "missing_lockfile") => format!("Could not check {context} because its lockfile was not read. Check that the lockfile exists in {presence} and is not excluded from Scan."),
        _ => format!("Could not fully check {name}{version} in {context}. The service did not supply a reason that this version of Scan can explain. Review these files manually."),
    }
}
