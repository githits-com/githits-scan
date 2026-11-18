//! One computation of qualification, impact and the explanations beside changes.
use super::{context::Context, list, requirement_status, safe};
use crate::api::audit::remediation::{Blocker, Checks};
use crate::commands::audit::view::remediation::{
    Change as ChangeView, Finding, Record, Remediation, reasons::Reason,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
mod reasons;
pub(in crate::commands::audit) use reasons::ReasonDetail;

const UNFAMILIAR_REASON: &str =
    "the service supplied an unfamiliar reason; see JSON for the supplied value";

/// Complete qualified guidance for one independent recommendation.
#[derive(Serialize)]
pub(in crate::commands::audit) struct Plan {
    /// Shared title for joint changes; a single change carries its own qualification.
    pub heading: Option<String>,
    /// Separate outcome explanation when the title cannot express it.
    pub outcome: Option<String>,
    /// Ordered changes that belong together within this alternative.
    pub changes: Vec<Change>,
    /// Common change paths not already expressed by the displayed finding context.
    pub files: BTreeSet<String>,
    /// Recorded requests needed to understand the changes.
    pub context: Vec<String>,
    /// Reported addressed and remaining advisory impact.
    pub impact: Vec<String>,
    /// Required edits, exclusions and their supporting targets.
    pub constraints: Vec<Constraint>,
    /// Material qualifications of supplied checks.
    pub checks: Vec<String>,
    /// Whole-search obstacles, associated with the fact record independently of changes.
    pub search_explanations: Vec<super::search::Explanation>,
    /// Per-plan planning limitations.
    pub limitations: Vec<String>,
}

/// Explanation of one change, linked to its position in the owning fact record.
#[derive(Serialize)]
pub(in crate::commands::audit) struct Change {
    /// Position in the owning fact record’s changes array.
    #[serde(rename = "change_index")]
    pub index: usize,
    /// Plain-text explanation; control characters are escaped.
    pub summary: String,
    /// Additional qualifications that belong with this explanation.
    pub details: Vec<String>,
    /// Common change paths not already expressed by the displayed finding context.
    pub files: BTreeSet<String>,
    /// Checked effects and supporting request evidence.
    pub reasons: Vec<reasons::Explanation>,
}

/// One constraint explanation with the requests it qualifies.
#[derive(Serialize)]
pub(in crate::commands::audit) struct Constraint {
    /// Plain-text explanation; control characters are escaped.
    pub summary: String,
    /// Sorted unique owner, requirement and path contexts for this explanation.
    pub details: Vec<String>,
}

impl Plan {
    /// Compute meaning once for the exact displayed finding context.
    pub(in crate::commands::audit) fn new(
        r: &Record,
        status: &str,
        context: &Context<'_>,
        detail: ReasonDetail,
    ) -> Self {
        let planning_known = matches!(status, "completed" | "limited");
        let supported = supported_fix(r, planning_known);
        let common = common_paths(&r.changes);
        let files = common
            .clone()
            .filter(|files| files != &context.files() || files != &Context::record(r).files())
            .unwrap_or_default();
        let constraints = constraints(&r.blockers, detail);
        let mut seen_limits = BTreeSet::new();
        let mut limitations: Vec<_> = r
            .limitations
            .iter()
            .filter(|l| l.as_str() != "withdrawal_not_observed")
            .filter_map(|l| {
                let message = explanation(l);
                (!constraints.iter().any(|c| c.summary == message))
                    .then(|| format!("limit: {message}"))
            })
            .filter(|message| seen_limits.insert(message.clone()))
            .collect();
        if let Some(message) = super::search::retention(r) {
            limitations.push(message);
        }
        let checks = checks(r);
        let search_explanations = super::search::explain(r);
        let has_details = !constraints.is_empty()
            || !checks.is_empty()
            || !limitations.is_empty()
            || !search_explanations.is_empty();
        Self {
            heading: heading(r, supported),
            outcome: (!matches!(r.outcome.as_str(), "proposed" | "partial")
                || r.changes.is_empty())
            .then(|| outcome(r, planning_known, has_details)),
            changes: r
                .changes
                .iter()
                .enumerate()
                .map(|(index, c)| {
                    change(
                        c,
                        index,
                        r,
                        planning_known,
                        supported,
                        common.is_none(),
                        detail,
                    )
                })
                .collect(),
            files,
            context: recorded_requests(r),
            impact: impact(r, supported, context),
            constraints,
            checks,
            limitations,
            search_explanations,
        }
    }
}

fn heading(r: &Record, supported: bool) -> Option<String> {
    if r.changes.len() < 2 {
        return None;
    }
    let label = match (supported, r.outcome.as_str()) {
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
    Some(format!("{label}{together}"))
}

fn change(
    c: &ChangeView,
    index: usize,
    r: &Record,
    planning_known: bool,
    supported: bool,
    show_files: bool,
    detail: ReasonDetail,
) -> Change {
    let data = &c.data;
    let known = planning_known
        && matches!(r.outcome.as_str(), "proposed" | "partial")
        && known_checks(&r.checks);
    let action = match (known, data.strategy.as_str()) {
        (true, "upgrade") if supported && r.changes.len() == 1 => "Suggested fix: Upgrade",
        (true, "upgrade") if supported => "Upgrade",
        (true, "upgrade") => "Candidate upgrade:",
        _ => "Candidate change:",
    };
    let partial = if r.changes.len() == 1 && r.outcome == "partial" {
        " (partial)"
    } else {
        ""
    };
    let mut details = Vec::new();
    match data.strategy.as_str() {
        "unknown" => {
            details.push(
                "The report lists version changes but does not specify how to apply them.".into(),
            );
        }
        "upgrade" | "override" => {}
        _ => {
            details.push("The service returned an unfamiliar change strategy; applicability could not be determined.".into());
        }
    }
    if !data.conflicting_target_versions.is_empty() {
        details.push(format!(
            "conflicting targets: {}",
            list(&data.conflicting_target_versions)
        ));
    }
    for (label, flag) in [
        ("prerelease", data.prerelease_target),
        ("deprecated", data.deprecated_target),
    ] {
        if flag == Some(true) {
            details.push(format!("target is {label}"));
        }
    }
    Change {
        index,
        summary: format!(
            "{action} {}:{} {} -> {}{partial}",
            safe(&data.registry),
            safe(&data.name),
            safe(&data.from_version),
            safe(&data.target_version)
        ),
        details,
        files: data.paths.iter().filter(|_| show_files).cloned().collect(),
        reasons: reasons::explain(c, r, detail),
    }
}

fn recorded_requests(r: &Record) -> Vec<String> {
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
    r.recorded_requests
        .iter()
        .filter(|_| !explained)
        .map(|request| {
            format!(
                "recorded request for {}: {}; owner {} [{}]",
                safe(&request.target.to_string()),
                safe(&request.requirement),
                owner(&request.owner_name, request.owner_version.as_deref()),
                safe(&request.path)
            )
        })
        .collect()
}

fn impact(r: &Record, supported: bool, context: &Context<'_>) -> Vec<String> {
    let addressed: BTreeSet<_> = r.addressed_findings.iter().collect();
    let covers = r.outcome == "proposed"
        && r.remaining_findings.is_empty()
        && r.findings.iter().collect::<BTreeSet<_>>() == addressed
        && context.matches(&r.findings);
    let mut lines = Vec::new();
    let required_edit = r.checks.release_availability == "observed"
        && r.checks.advisories == "non_affecting"
        && known_checks(&r.checks)
        && r.changes.iter().all(|c| c.data.strategy == "upgrade")
        && !r.blockers.is_empty()
        && r.blockers.iter().all(project_edit);
    if !(r.addressed_findings.is_empty() || (supported || required_edit) && covers) {
        lines.push(match (covers, r.addressed_findings.len()) {
            (true, 1) => "would address the listed advisory".into(),
            (true, _) => "would address all listed advisories".into(),
            (false, _) => format!(
                "would address: {}",
                finding_names(&r.addressed_findings, &r.remaining_findings, &r.subject)
            ),
        });
    }
    if r.outcome == "partial" && r.addressed_findings.is_empty() {
        lines.push("would address: none reported".into());
    }
    if !r.remaining_findings.is_empty() {
        lines.push(format!(
            "still unresolved: {}",
            finding_names(&r.remaining_findings, &r.addressed_findings, &r.subject)
        ));
    }
    lines
}

// Group only visible explanations: this finite Scan-owned phrase mapping never
// determines applicability or policy. Facts retain every original reason and request.
fn project_edit(b: &Blocker) -> bool {
    b.owner_role == "project" && b.reason == "project_request_change"
}
fn edit_instruction(b: &Blocker) -> Option<String> {
    if !project_edit(b) || b.requirement_status != "recorded" {
        return None;
    }
    Some(format!(
        "Update the {} requirement in {}. Current requirement: {}.",
        safe(b.dependency_name.as_deref()?),
        safe(&b.path),
        safe(b.requested_requirement.as_deref()?)
    ))
}
fn constraints(blockers: &[Blocker], detail: ReasonDetail) -> Vec<Constraint> {
    let mut groups: Vec<Constraint> = Vec::new();
    for b in blockers {
        let instruction = edit_instruction(b);
        let is_edit = instruction.is_some();
        let summary = instruction.unwrap_or_else(|| constraint_reason(b));
        let request = format!(
            "{} {} [{}]",
            owner(&b.owner.name, b.owner.version.as_deref()),
            request_requirement(
                b.dependency_name.as_deref(),
                b.requested_requirement.as_deref(),
                &b.requirement_status
            ),
            safe(&b.path)
        );
        let details = if is_edit && detail == ReasonDetail::Summary {
            Vec::new()
        } else {
            vec![request]
        };
        if let Some(group) = groups.iter_mut().find(|c| c.summary == summary) {
            group.details.extend(details);
            continue;
        }
        groups.push(Constraint { summary, details });
    }
    for group in &mut groups {
        group.details.sort();
        group.details.dedup();
    }
    groups
}

fn checks(r: &Record) -> Vec<String> {
    let c = &r.checks;
    let mut lines = Vec::new();
    for (label, value, normal) in [
        (
            "release availability",
            c.release_availability.as_str(),
            "observed",
        ),
        ("target advisories", c.advisories.as_str(), "non_affecting"),
        ("requirements", c.requirements.as_str(), "matched"),
    ] {
        if !r.changes.is_empty()
            && value != normal
            && !(label == "requirements" && value == "blocked" && !r.blockers.is_empty())
        {
            lines.push(format!("{label}: {}", check_text(value)));
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
            lines.push(format!("{label}: {}", check_text(value)));
        }
    }
    match c.parent_search.as_str() {
        "completed" | "not_assessed" => {}
        "limited" => {
            lines.push("Upgrades to packages using this dependency were not fully checked.".into());
        }
        _ => {
            lines.push(
                concat!(
                    "The service returned an unfamiliar result for upgrades to packages ",
                    "using this dependency; see JSON for the supplied value."
                )
                .into(),
            );
        }
    }
    if !matches!(
        c.availability_source.as_str(),
        "catalog" | "exact_metadata" | "mixed" | "not_assessed"
    ) {
        lines.push(format!(
            "availability source: {}",
            check_text(&c.availability_source)
        ));
    }
    if c.preference_differences != 0 {
        lines.push(format!(
            "requests with different preferences: {}",
            c.preference_differences
        ));
    }
    if c.prerelease_target
        && !r
            .changes
            .iter()
            .any(|c| c.data.prerelease_target == Some(true))
    {
        lines.push("action includes a prerelease target".into());
    }
    if c.deprecated_target
        && !r
            .changes
            .iter()
            .any(|c| c.data.deprecated_target == Some(true))
    {
        lines.push("action includes a deprecated target".into());
    }
    lines
}

/// Explain shared limits without changing findings or command outcome.
pub(in crate::commands::audit) fn limits(data: &Remediation) -> Vec<String> {
    let mut lines = Vec::new();
    if data.limits.omitted_recommendations != 0 {
        lines.push(format!(
            "omitted recommendations: {}",
            data.limits.omitted_recommendations
        ));
    }
    if data.limits.omitted_search_details.is_some_and(|n| n != 0) {
        lines.push("Search explanations were omitted from this report; the report does not identify which recommendations or alternatives they belonged to.".into());
    }
    let mut seen = BTreeSet::new();
    lines.extend(
        data.limits
            .reasons
            .iter()
            .map(|r| format!("planning limit: {}", explanation(r)))
            .filter(|message| seen.insert(message.clone())),
    );
    lines
}
fn finding_names(findings: &[Finding], other: &[Finding], subject: &str) -> String {
    let overlapping: BTreeSet<_> = other.iter().map(|f| (&f.package, &f.advisory)).collect();
    let mut groups: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for f in findings {
        let qualifier = if overlapping.contains(&(&f.package, &f.advisory)) {
            " (partly)"
        } else {
            ""
        };
        groups
            .entry(&f.package)
            .or_default()
            .insert(format!("{}{qualifier}", safe(&f.advisory)));
    }
    let mut labels = Vec::new();
    if let Some(advisories) = groups.remove(subject) {
        labels.push(advisories.into_iter().collect::<Vec<_>>().join(", "));
    }
    labels.extend(groups.into_iter().map(|(package, advisories)| {
        format!(
            "{} — {}",
            safe(package),
            advisories.into_iter().collect::<Vec<_>>().join(", ")
        )
    }));
    labels.join("; ")
}

fn outcome(r: &Record, planning_known: bool, has_details: bool) -> String {
    match r.outcome.as_str() {
        "proposed" | "partial" => "The service returned a proposal without any changes.".into(),
        "indeterminate" if !has_details => {
            "The service could not determine a mitigation; no further reason was supplied.".into()
        }
        "indeterminate" => "The service could not determine a mitigation.".into(),
        "no_upgrade_path" if !planning_known || !known_checks(&r.checks) => {
            "The planning or check evidence is unfamiliar, so no conclusion about an upgrade path can be drawn.".into()
        }
        "no_upgrade_path"
            if r.search_domain.as_ref().is_some_and(|d| {
                d.constraint_scope == "represented_requests"
                    && d.release_scope == "observed_catalog_upgrades"
            }) =>
        {
            "No upgrade path found among releases known to the service, under the dependency requirements considered.".into()
        }
        "no_upgrade_path" => {
            "The upgrade search scope is unfamiliar, so no conclusion about an upgrade path can be drawn.".into()
        }
        _ => {
            "The service returned an unfamiliar mitigation outcome; no conclusion about a fix can be drawn.".into()
        }
    }
}

fn common_paths(changes: &[ChangeView]) -> Option<BTreeSet<String>> {
    let paths: BTreeSet<_> = changes.first()?.data.paths.iter().cloned().collect();
    (!paths.is_empty()
        && changes
            .iter()
            .all(|c| c.data.paths.iter().cloned().collect::<BTreeSet<_>>() == paths))
    .then_some(paths)
}

pub(super) fn owner(name: &str, version: Option<&str>) -> String {
    version.map_or_else(|| safe(name), |v| format!("{}@{}", safe(name), safe(v)))
}

pub(super) fn request_requirement(name: Option<&str>, range: Option<&str>, status: &str) -> String {
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

fn supported_fix(r: &Record, planning_known: bool) -> bool {
    planning_known
        && matches!(r.outcome.as_str(), "proposed" | "partial")
        && known_checks(&r.checks)
        && !r.addressed_findings.is_empty()
        && r.checks.release_availability == "observed"
        && r.checks.advisories == "non_affecting"
        && r.checks.requirements == "matched"
        && r.changes.iter().all(|c| c.data.strategy == "upgrade")
        && !((r.outcome == "partial" || !r.remaining_findings.is_empty())
            && (r.checks.prerelease_target
                || r.changes
                    .iter()
                    .any(|c| c.data.prerelease_target == Some(true))))
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
        "unknown" => "not determined from the supplied evidence".into(),
        "unsupported" => "advisory checking is not supported for this target".into(),
        _ => "the service returned an unfamiliar check result; see JSON for the supplied value"
            .into(),
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
        "project_request_change" => "applying this change requires updating the project requirement".into(),
        "third_party_request_excludes_target" => "parent dependency excludes the target".into(),
        "required_request_excludes_target" => "dependency requirement excludes the target".into(),
        "parent_candidate_limit" => "the service reached its limit for checking upgrades of packages that depend on this dependency".into(),
        "assignment_limit" => "the service reached its limit for checking combinations of dependency upgrades".into(),
        "parent_evidence_incomplete" => {
            "metadata needed to check upgrades of packages that depend on this dependency was unavailable; this limitation does not identify the affected packages".into()
        }
        "parent_exact_lookup_limit" => {
            "the service reached its limit for looking up metadata for packages that depend on this dependency".into()
        }
        "introduction_not_recorded" => "how the dependency was introduced is not recorded".into(),
        "unsupported_selector" => "dependency requirement could not be evaluated".into(),
        "release_existence_unverified" => "target release availability not verified".into(),
        "new_dependency_not_checked" => "a new dependency was not checked".into(),
        "represented_routes_cut" => "this candidate removes dependency routes recorded in this report".into(),
        "native_applicability_not_checked" => "whether the dependency requirements apply to this project was not checked".into(),
        "no_checked_parent_upgrade" => {
            "no upgrade of a package that depends on this dependency was verified".into()
        }
        "no_checked_leaf" => "no upgrade of this vulnerable dependency was verified".into(),
        "project_preference_change" => "applying this change requires updating the project preference".into(),
        "unresolved_manifest_activation" => "manifest applicability is unresolved".into(),
        _ => UNFAMILIAR_REASON.into(),
    }
}

fn constraint_reason(b: &Blocker) -> String {
    match b.reason.as_str() {
        "third_party_request_excludes_target" | "required_request_excludes_target" => {
            "Dependency requirements conflict with this candidate.".into()
        }
        _ => explanation(&b.reason),
    }
}
