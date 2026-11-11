//! Compact proposals, with qualifiers kept beside the changes they constrain.
use std::collections::BTreeSet;
use std::io::{self, Write};

use super::{file_list, list, requirement_status, safe};
use crate::api::audit::remediation::{Blocker, Change, Checks};
use crate::commands::audit::view::{
    View,
    remediation::{Change as ChangeView, Finding, Record, Remediation, State, reasons::Reason},
};
use crate::style::Palette;

mod problems;
mod reasons;
pub(in crate::commands::audit) use problems::Context as ProblemContext;
pub(in crate::commands::audit) use reasons::ReasonDetail;

pub(super) fn write(view: &View, out: &mut dyn Write, palette: Palette) -> io::Result<()> {
    let data = match &view.remediation {
        State::Unavailable if !view.vulnerabilities.is_empty() => {
            return writeln!(out, "\nFix guidance is unavailable in this report.");
        }
        State::Present(data) => data,
        State::Unavailable | State::Unverified => return Ok(()),
    };
    if data.recommendations.is_empty()
        && view.vulnerabilities.is_empty()
        && data.status == "completed"
    {
        return Ok(());
    }
    writeln!(out, "\n{}", palette.bold("Fix guidance"))?;
    if data.status != "completed" {
        let message = match data.status.as_str() {
            "limited" => "Fix guidance is incomplete.",
            "not_assessed" => "Fix guidance was not assessed.",
            _ => {
                "The service returned an unfamiliar fix-planning status; see JSON for the supplied value."
            }
        };
        writeln!(out, "  {message}")?;
    }
    if data.recommendations.is_empty() {
        writeln!(
            out,
            "  no recommendations returned; this does not establish that no mitigation exists"
        )?;
    }
    problems::write(
        data,
        matches!(data.status.as_str(), "completed" | "limited"),
        out,
    )?;
    shared_limits(data, out)
}

pub(in crate::commands::audit) fn guidance(
    r: &Record,
    planning_known: bool,
    context: &ProblemContext<'_>,
    reason_detail: ReasonDetail,
    out: &mut dyn Write,
) -> io::Result<()> {
    let supported = supported_fix(r, planning_known);
    if !matches!(r.outcome.as_str(), "proposed" | "partial") || r.changes.is_empty() {
        writeln!(out)?;
        writeln!(out, "    {}", outcome(r, planning_known))?;
    }
    if !r.changes.is_empty() {
        let guidance = match (supported, r.outcome.as_str()) {
            (true, "proposed") => "Suggested fix",
            (true, "partial") => "Suggested fix (partial)",
            (false, "partial") => "Candidate changes (partial)",
            _ => "Candidate changes",
        };
        let together = if r.changes.len() > 1 {
            " — change together"
        } else {
            ""
        };
        writeln!(out, "\n    {guidance}{together}:")?;
    }
    let common = common_paths(&r.changes);
    for change in &r.changes {
        change_line(
            &change.data,
            r,
            planning_known,
            supported,
            common.is_none(),
            out,
        )?;
        reasons::write(change, r, reason_detail, out)?;
    }
    let displayed_files = context.files();
    let own_files = ProblemContext::record(r).files();
    if let Some(files) = common.filter(|files| files != &displayed_files || files != &own_files) {
        file_list("Change in", &files, "    ", out)?;
    }
    let has_boundary = r
        .changes
        .iter()
        .flat_map(|c| c.reasons.iter().flatten())
        .any(|reason| matches!(reason, Reason::Enables { .. } | Reason::Removes { .. }));
    let explained = has_boundary
        && r.changes.iter().all(|c| {
            c.reasons
                .as_ref()
                .is_some_and(|reasons| reasons.iter().any(Reason::known))
        });
    for request in r.recorded_requests.iter().filter(|_| !explained) {
        writeln!(
            out,
            "    recorded request for {}: {}; owner {} [{}]",
            safe(&request.target.to_string()),
            safe(&request.requirement),
            owner(&request.owner_name, request.owner_version.as_deref()),
            safe(&request.path)
        )?;
    }
    impact(r, supported, context, out)?;
    blockers(&r.blockers, out)?;
    if r.changes.iter().any(|c| c.data.strategy == "override")
        && r.checks.native_resolution == "not_checked"
    {
        writeln!(
            out,
            "    override not verified: package-manager support and build not checked"
        )?;
    }
    checks(r, out)?;
    for limitation in &r.limitations {
        if limitation == "withdrawal_not_observed" {
            continue;
        }
        writeln!(out, "    limit: {}", explanation(limitation))?;
    }
    Ok(())
}

fn impact(
    r: &Record,
    supported: bool,
    context: &ProblemContext<'_>,
    out: &mut dyn Write,
) -> io::Result<()> {
    let addressed: BTreeSet<_> = r.addressed_findings.iter().collect();
    let covers_displayed_findings = r.outcome == "proposed"
        && r.remaining_findings.is_empty()
        && r.findings.iter().collect::<BTreeSet<_>>() == addressed
        && context.matches(&r.findings);
    if !(r.addressed_findings.is_empty() || supported && covers_displayed_findings) {
        let benefit = match (covers_displayed_findings, r.addressed_findings.len()) {
            (true, 1) => "would address the listed advisory".into(),
            (true, _) => "would address all listed advisories".into(),
            (false, _) => format!(
                "would address: {}",
                finding_names(&r.addressed_findings, &r.remaining_findings, &r.subject)
            ),
        };
        writeln!(out, "    {benefit}")?;
    }
    if r.outcome == "partial" && r.addressed_findings.is_empty() {
        writeln!(out, "    would address: none reported")?;
    }
    if !r.remaining_findings.is_empty() {
        writeln!(
            out,
            "    still unresolved: {}",
            finding_names(&r.remaining_findings, &r.addressed_findings, &r.subject)
        )?;
    }
    Ok(())
}

fn finding_names(findings: &[Finding], other: &[Finding], subject: &str) -> String {
    let overlapping: BTreeSet<_> = other.iter().map(|f| (&f.package, &f.advisory)).collect();
    findings
        .iter()
        .map(|f| {
            let qualifier = if overlapping.contains(&(&f.package, &f.advisory)) {
                " (partly)"
            } else {
                ""
            };
            if f.package == subject {
                format!("{}{qualifier}", safe(&f.advisory))
            } else {
                format!("{} ({}){qualifier}", safe(&f.advisory), safe(&f.package))
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ")
}

fn outcome(r: &Record, planning_known: bool) -> String {
    match r.outcome.as_str() {
        "proposed" | "partial" | "indeterminate" => safe(&r.outcome),
        "no_upgrade_path" if !planning_known || !known_checks(&r.checks) => {
            "unrecognized planning/check evidence; no conclusion".into()
        }
        "no_upgrade_path"
            if r.search_domain.as_ref().is_some_and(|d| {
                d.constraint_scope == "represented_requests"
                    && d.release_scope == "observed_catalog_upgrades"
            }) =>
        {
            "No upgrade path found among the recorded releases and dependency requirements.".into()
        }
        "no_upgrade_path" => "unrecognized search scope; no conclusion".into(),
        _ => format!("unrecognized outcome: {}", safe(&r.outcome)),
    }
}

fn change_line(
    c: &Change,
    r: &Record,
    planning_known: bool,
    supported: bool,
    show_paths: bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    let known = planning_known
        && matches!(r.outcome.as_str(), "proposed" | "partial")
        && known_checks(&r.checks);
    let action = match (known, c.strategy.as_str()) {
        (true, "upgrade") if supported => "Upgrade".into(),
        (true, "upgrade") => "Upgrade candidate:".into(),
        (true, "override") => "Override candidate:".into(),
        _ => format!("Candidate (strategy: {})", safe(&c.strategy)),
    };
    writeln!(
        out,
        "      {action} {}:{} {} -> {}",
        safe(&c.registry),
        safe(&c.name),
        safe(&c.from_version),
        safe(&c.target_version)
    )?;
    let detail_indent = "        ";
    if show_paths {
        file_list(
            "files",
            &c.paths.iter().cloned().collect(),
            detail_indent,
            out,
        )?;
    }
    if !c.conflicting_target_versions.is_empty() {
        writeln!(
            out,
            "{detail_indent}conflicting targets: {}",
            list(&c.conflicting_target_versions)
        )?;
    }
    for (label, flag) in [
        ("prerelease", c.prerelease_target),
        ("deprecated", c.deprecated_target),
    ] {
        if flag == Some(true) {
            writeln!(out, "{detail_indent}target is {label}")?;
        }
    }
    Ok(())
}

fn common_paths(changes: &[ChangeView]) -> Option<BTreeSet<String>> {
    let paths: BTreeSet<_> = changes.first()?.data.paths.iter().cloned().collect();
    (!paths.is_empty()
        && changes
            .iter()
            .all(|c| c.data.paths.iter().cloned().collect::<BTreeSet<_>>() == paths))
    .then_some(paths)
}

fn owner(name: &str, version: Option<&str>) -> String {
    version.map_or_else(|| safe(name), |v| format!("{}@{}", safe(name), safe(v)))
}

fn request_requirement(name: Option<&str>, range: Option<&str>, status: &str) -> String {
    let mut text = match (name, range) {
        (Some(name), Some(range)) => format!("requires {} {}", safe(name), safe(range)),
        (None, Some(range)) => format!("requires {}", safe(range)),
        (Some(name), None) => format!(
            "requires {} (requirement {})",
            safe(name),
            requirement_status(status)
        ),
        (None, None) => format!("requirement {}", requirement_status(status)),
    };
    if range.is_some() && status != "recorded" {
        text.push_str(" (");
        text.push_str(&requirement_status(status));
        text.push(')');
    }
    text
}

fn blocker_line(b: &Blocker, out: &mut dyn Write) -> io::Result<()> {
    let owner = owner(&b.owner.name, b.owner.version.as_deref());
    let requirement = request_requirement(
        b.dependency_name.as_deref(),
        b.requested_requirement.as_deref(),
        &b.requirement_status,
    );
    if matches!(
        b.reason.as_str(),
        "third_party_request_excludes_target" | "required_request_excludes_target"
    ) {
        writeln!(
            out,
            "    requirement conflict: {owner} {requirement} [{}]",
            safe(&b.path)
        )?;
    } else {
        writeln!(
            out,
            "    constraint: {owner} {requirement} [{}]; {}",
            safe(&b.path),
            explanation(&b.reason)
        )?;
    }
    if !b.other_target_versions.is_empty() {
        writeln!(
            out,
            "      other recommended targets: {}",
            list(&b.other_target_versions)
        )?;
    }
    Ok(())
}

fn blockers(blockers: &[Blocker], out: &mut dyn Write) -> io::Result<()> {
    let mut seen = BTreeSet::new();
    for blocker in blockers {
        let mut text = Vec::new();
        blocker_line(blocker, &mut text)?;
        if seen.insert(text.clone()) {
            out.write_all(&text)?;
        }
    }
    Ok(())
}

fn checks(r: &Record, out: &mut dyn Write) -> io::Result<()> {
    let c = &r.checks;
    for (label, value, normal) in [
        (
            "release availability",
            c.release_availability.as_str(),
            "observed",
        ),
        ("target advisories", c.advisories.as_str(), "non_affecting"),
        ("requirements", c.requirements.as_str(), "matched"),
    ] {
        if r.changes.is_empty() {
            continue;
        }
        if value != normal
            && !(label == "requirements" && value == "blocked" && !r.blockers.is_empty())
        {
            writeln!(out, "    {label}: {}", check_text(value))?;
        }
    }
    for (label, value, ordinary) in [
        (
            "release withdrawal",
            c.withdrawal.as_str(),
            &["not_withdrawn", "unknown"][..],
        ),
        (
            "native resolution",
            c.native_resolution.as_str(),
            &["not_checked"][..],
        ),
        (
            "catalog freshness",
            c.catalog_freshness.as_str(),
            &["unknown"][..],
        ),
    ] {
        if !ordinary.contains(&value) {
            writeln!(out, "    {label}: {}", check_text(value))?;
        }
    }
    parent_search(&c.parent_search, out)?;
    if !matches!(
        c.availability_source.as_str(),
        "catalog" | "exact_metadata" | "mixed" | "not_assessed"
    ) {
        writeln!(
            out,
            "    availability source: {}",
            check_text(&c.availability_source)
        )?;
    }
    if c.preference_differences != 0 {
        writeln!(
            out,
            "    requests with different preferences: {}",
            c.preference_differences
        )?;
    }
    if c.prerelease_target
        && !r
            .changes
            .iter()
            .any(|c| c.data.prerelease_target == Some(true))
    {
        writeln!(out, "    action includes a prerelease target")?;
    }
    if c.deprecated_target
        && !r
            .changes
            .iter()
            .any(|c| c.data.deprecated_target == Some(true))
    {
        writeln!(out, "    action includes a deprecated target")?;
    }
    Ok(())
}

fn supported_fix(r: &Record, planning_known: bool) -> bool {
    planning_known
        && matches!(r.outcome.as_str(), "proposed" | "partial")
        && known_checks(&r.checks)
        && !r.addressed_findings.is_empty()
        && r.checks.release_availability == "observed"
        && r.checks.advisories == "non_affecting"
        && r.checks.requirements == "matched"
        && r.changes.iter().all(|c| c.data.strategy == "upgrade")
}

fn known_checks(c: &Checks) -> bool {
    matches!(c.release_availability.as_str(), "observed" | "unverified")
        && matches!(
            c.availability_source.as_str(),
            "catalog" | "exact_metadata" | "not_assessed" | "mixed"
        )
        && matches!(c.withdrawal.as_str(), "not_withdrawn" | "unknown")
        && matches!(
            c.advisories.as_str(),
            "non_affecting" | "unknown" | "unsupported" | "not_assessed" | "affected"
        )
        && matches!(
            c.requirements.as_str(),
            "matched" | "blocked" | "unchecked" | "preference_differs" | "not_assessed"
        )
        && c.native_resolution == "not_checked"
        && c.catalog_freshness == "unknown"
        && matches!(
            c.parent_search.as_str(),
            "not_assessed" | "completed" | "limited"
        )
}

pub(in crate::commands::audit) fn shared_limits(
    data: &Remediation,
    out: &mut dyn Write,
) -> io::Result<()> {
    let limits = &data.limits;
    if limits.omitted_recommendations != 0 {
        writeln!(
            out,
            "  omitted recommendations: {}",
            limits.omitted_recommendations
        )?;
    }
    for reason in &limits.reasons {
        writeln!(out, "  planning limit: {}", explanation(reason))?;
    }
    Ok(())
}

fn parent_search(value: &str, out: &mut dyn Write) -> io::Result<()> {
    let message = match value {
        "completed" | "not_assessed" => return Ok(()),
        "limited" => "Upgrades to packages using this dependency were not fully checked.",
        _ => {
            "The service returned an unfamiliar result for upgrades to packages using this dependency; see JSON for the supplied value."
        }
    };
    writeln!(out, "    {message}")
}

fn check_text(value: &str) -> String {
    match value {
        "not_checked" => "not checked (project resolver/build not run)".into(),
        "not_assessed" => "not assessed".into(),
        "not_retained" => "not retained".into(),
        "preference_differs" => "preference differs".into(),
        "affected" => "still affected by known advisories".into(),
        "blocked" => "blocked by dependency requirements".into(),
        "unchecked" => "not checked".into(),
        "unverified" => "not verified".into(),
        _ => safe(value),
    }
}

fn explanation(value: &str) -> String {
    match value {
        "planning_deadline" => "mitigation planning time limit reached".into(),
        "change_reason_deadline" => "time limit reached while checking change reasons".into(),
        "change_reason_membership_limit" => {
            "requirement-check limit reached while checking change reasons".into()
        }
        "planning_failed" => "mitigation planning failed; original findings retained".into(),
        "output_limit" => "mitigation data omitted to fit result limit".into(),
        "withdrawal_not_observed" => "withdrawal status unavailable".into(),
        "incompatible_recommendations" => {
            "conflicting recommendation targets; do not combine them".into()
        }
        "checked_occurrence_changed_by_other_recommendation" => {
            "another recommendation changes a checked dependency; recheck combined changes".into()
        }
        "manifest_lock_disagreement" => "manifest and lockfile disagree".into(),
        "project_request_change" => "project requirement must change".into(),
        "third_party_request_excludes_target" => "parent dependency excludes the target".into(),
        "required_request_excludes_target" => "dependency requirement excludes the target".into(),
        "parent_candidate_limit" => "upgrade checks stopped at the service's search limit".into(),
        "assignment_limit" => "not all combinations of dependency changes could be checked".into(),
        "parent_evidence_incomplete" => {
            "some dependency information needed to check related upgrades was unavailable".into()
        }
        "parent_exact_lookup_limit" => {
            "metadata checks for related upgrades reached the service limit".into()
        }
        "introduction_not_recorded" => "how the dependency was introduced is not recorded".into(),
        "unsupported_selector" => "dependency requirement could not be evaluated".into(),
        "release_existence_unverified" => "target release availability not verified".into(),
        "new_dependency_not_checked" => "a new dependency was not checked".into(),
        "represented_routes_cut" => "proposal removes represented dependency paths".into(),
        "no_checked_parent_upgrade" => {
            "no upgrade of the package requiring this dependency was verified".into()
        }
        "no_checked_leaf" => "no upgrade of this vulnerable dependency was verified".into(),
        "project_preference_change" => "project preference must change".into(),
        "unresolved_manifest_activation" => "manifest applicability is unresolved".into(),
        _ => safe(value),
    }
}
