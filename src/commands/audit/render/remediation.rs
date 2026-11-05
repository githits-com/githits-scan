//! Compact proposals, with qualifiers kept beside the changes they constrain.
use std::collections::BTreeSet;
use std::io::{self, Write};

use super::{file_list, heading, list, requirement_status, safe};
use crate::api::audit::remediation::{Blocker, Change, Checks};
use crate::commands::audit::view::{
    View,
    remediation::{Finding, Record, Remediation, State},
};
use crate::style::Palette;

mod problems;
pub(in crate::commands::audit) use problems::Context as ProblemContext;

pub(super) fn write(view: &View, out: &mut dyn Write, palette: Palette) -> io::Result<()> {
    let data = match &view.remediation {
        State::Unavailable if !view.vulnerabilities.is_empty() => {
            return writeln!(out, "\nMitigation planning unavailable in this report.");
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
    heading(
        "Mitigation recommendations",
        data.recommendations.len(),
        out,
        palette,
    )?;
    if data.status != "completed" {
        writeln!(
            out,
            "  planning: {}",
            status(&data.status, &["limited", "not_assessed"])
        )?;
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
    out: &mut dyn Write,
) -> io::Result<()> {
    let supported = supported_fix(r, planning_known);
    if !matches!(r.outcome.as_str(), "proposed" | "partial") || r.changes.is_empty() {
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
        change_line(change, r, planning_known, supported, common.is_none(), out)?;
    }
    let displayed_files = context.files();
    let own_files = ProblemContext::record(r).files();
    if let Some(files) = common.filter(|files| files != &displayed_files || files != &own_files) {
        file_list("Change in", &files, "    ", out)?;
    }
    let addressed: BTreeSet<_> = r.addressed_findings.iter().collect();
    let fully_addressed = r.outcome == "proposed"
        && r.remaining_findings.is_empty()
        && r.findings.iter().collect::<BTreeSet<_>>() == addressed
        && context.matches(&r.findings);
    if !fully_addressed && !r.addressed_findings.is_empty() {
        writeln!(
            out,
            "    would address: {}",
            finding_names(&r.addressed_findings, &r.subject)
        )?;
    }
    if !r.remaining_findings.is_empty() {
        writeln!(
            out,
            "    remaining: {}",
            finding_names(&r.remaining_findings, &r.subject)
        )?;
    }
    blockers(&r.blockers, out)?;
    checks(r, out)?;
    for limitation in &r.limitations {
        if limitation == "withdrawal_not_observed" {
            continue;
        }
        writeln!(out, "    limit: {}", explanation(limitation))?;
    }
    Ok(())
}

fn finding_names(findings: &[Finding], subject: &str) -> String {
    findings
        .iter()
        .map(|f| {
            if f.package == subject {
                safe(&f.advisory)
            } else {
                format!("{} ({})", safe(&f.advisory), safe(&f.package))
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
            "no upgrade path within observed releases and represented requests".into()
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

fn common_paths(changes: &[Change]) -> Option<BTreeSet<String>> {
    let paths: BTreeSet<_> = changes.first()?.paths.iter().cloned().collect();
    (!paths.is_empty()
        && changes
            .iter()
            .all(|c| c.paths.iter().cloned().collect::<BTreeSet<_>>() == paths))
    .then_some(paths)
}

fn blocker_line(b: &Blocker, out: &mut dyn Write) -> io::Result<()> {
    let owner = b.owner.version.as_ref().map_or_else(
        || safe(&b.owner.name),
        |v| format!("{}@{}", safe(&b.owner.name), safe(v)),
    );
    let requirement = b.requested_requirement.as_ref().map_or_else(
        || format!("requirement {}", requirement_status(&b.requirement_status)),
        |r| {
            if b.requirement_status == "recorded" {
                return format!("requires {}", safe(r));
            }
            format!(
                "requires {} ({})",
                safe(r),
                requirement_status(&b.requirement_status)
            )
        },
    );
    writeln!(
        out,
        "    blocker: {owner} {requirement} [{}]; {}",
        safe(&b.path),
        explanation(&b.reason)
    )?;
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
            "parent search",
            c.parent_search.as_str(),
            &["completed", "not_assessed"][..],
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
    if c.prerelease_target && !r.changes.iter().any(|c| c.prerelease_target == Some(true)) {
        writeln!(out, "    action includes a prerelease target")?;
    }
    if c.deprecated_target && !r.changes.iter().any(|c| c.deprecated_target == Some(true)) {
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
        && r.changes.iter().all(|c| c.strategy == "upgrade")
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

fn status(value: &str, known: &[&str]) -> String {
    if known.contains(&value) {
        check_text(value)
    } else {
        format!("unrecognized ({})", safe(value))
    }
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
        "parent_candidate_limit" => "parent upgrade search reached its candidate limit".into(),
        "assignment_limit" => "parent upgrade search reached its combination limit".into(),
        "parent_evidence_incomplete" => "parent dependency evidence is incomplete".into(),
        "parent_exact_lookup_limit" => "parent release metadata lookup limit reached".into(),
        "introduction_not_recorded" => "how the dependency was introduced is not recorded".into(),
        "unsupported_selector" => "dependency requirement could not be evaluated".into(),
        "release_existence_unverified" => "target release availability not verified".into(),
        "new_dependency_not_checked" => "a new dependency was not checked".into(),
        "represented_routes_cut" => "proposal removes represented dependency paths".into(),
        "no_checked_parent_upgrade" => "no checked parent upgrade was found".into(),
        "no_checked_leaf" => "no checked upgrade for the vulnerable dependency was found".into(),
        "project_preference_change" => "project preference must change".into(),
        "unresolved_manifest_activation" => "manifest applicability is unresolved".into(),
        _ => safe(value),
    }
}
