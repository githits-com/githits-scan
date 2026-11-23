//! One computation of qualification, impact and the explanations beside changes.
use super::{added::CompactAddition, context::Context, list, requirement_status, safe};
use crate::api::audit::remediation::{Blocker, Checks};
use crate::catalog::{self, Role};
use crate::commands::audit::view::remediation::{
    Change as ChangeView, Finding, Record, Remediation, reasons::Reason,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
mod reasons;
pub(in crate::commands::audit) use reasons::ReasonDetail;

const UNFAMILIAR_REASON: &str =
    "the service supplied an unfamiliar reason; see JSON for the supplied value";

/// Complete qualified guidance for one independent recommendation.
#[derive(Serialize)]
pub(in crate::commands::audit) struct Plan {
    #[serde(skip)]
    supported: bool,
    #[serde(skip)]
    clear_project_edit: bool,
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
    #[serde(skip)]
    compact: String,
    #[serde(skip)]
    application_issue: Option<String>,
    #[serde(skip)]
    target_caveat: bool,
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
    #[serde(skip)]
    compact_edit: Option<String>,
    #[serde(skip)]
    excludes_target: bool,
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
        let checked_upgrade = upgrade_evidence(r, planning_known);
        let supported = checked_upgrade && r.checks.requirements == "matched";
        let common = common_paths(&r.changes);
        let files = common
            .clone()
            .filter(|files| files != &context.files() || files != &Context::record(r).files())
            .unwrap_or_default();
        let constraints = constraints(&r.blockers, detail);
        let clear_project_edit = checked_upgrade && clear_project_edit(r, &constraints);
        let mut limitations: Vec<_> = limitations(r, &constraints)
            .map(|(_, message)| format!("limit: {message}"))
            .collect();
        if let Some(message) = super::search::retention(r) {
            limitations.push(message);
        }
        let checks = checks(r, false);
        let mut installer_note_pending = true;
        let changes = r
            .changes
            .iter()
            .enumerate()
            .map(|(index, c)| {
                let mut change = change(
                    c,
                    index,
                    r,
                    planning_known,
                    supported,
                    common.is_none(),
                    detail,
                );
                let branches = c.data.added_dependencies.as_deref().unwrap_or_default();
                change.details.extend(super::added::change_lines(branches));
                change.details.extend(super::added::installer_note(
                    branches,
                    &mut installer_note_pending,
                ));
                change
            })
            .collect();
        let search_explanations = super::search::explain(r, &mut installer_note_pending);
        let has_details = !constraints.is_empty()
            || !checks.is_empty()
            || !limitations.is_empty()
            || !search_explanations.is_empty();
        Self {
            supported,
            clear_project_edit,
            heading: heading(r, supported),
            outcome: (!matches!(r.outcome.as_str(), "proposed" | "partial")
                || r.changes.is_empty())
            .then(|| outcome(r, planning_known, has_details)),
            changes,
            files,
            context: recorded_requests(r),
            impact: impact(r, addressed_display(r, supported, context)),
            constraints,
            checks,
            limitations,
            search_explanations,
        }
    }

    /// Compose the inline summary and indicate whether a Details link is useful.
    pub(super) fn compact(&self, r: &Record) -> (String, bool) {
        let addition = super::added::compact_changes(
            r.changes
                .iter()
                .filter_map(|c| c.data.added_dependencies.as_deref())
                .flatten(),
        );
        let added_problem = addition.as_ref().is_some_and(CompactAddition::is_problem);
        let mut sentences = Vec::new();
        if let Some(changes) = self.compact_changes(r, addition.as_ref()) {
            sentences.push(changes);
        }
        sentences.extend(self.outcome.iter().cloned());
        let mut target_warnings = action_target_warnings(r).peekable();
        let target_caveat = target_warnings.peek().is_some()
            || self.changes.iter().any(|change| change.target_caveat);
        let clear_edit = self.clear_project_edit && !target_caveat && !added_problem;
        let mut target_problems = confirmed_target_problems(r).peekable();
        let confirmed_problem = added_problem || target_problems.peek().is_some();
        let mut issue = self.compact_issue(r, clear_edit, confirmed_problem);
        let has_changes = !self.changes.is_empty();
        let has_remaining_findings = !r.remaining_findings.is_empty();
        let details_recommended = !(self.supported || clear_edit)
            || self.outcome.is_some()
            || r.outcome == "partial"
            || has_remaining_findings
            || (issue.is_some() && !clear_edit)
            || target_caveat
            || addition.is_some();
        sentences.extend(target_warnings.map(|label| format!("Includes a {label} target")));
        if clear_edit {
            sentences.extend(issue.take());
        }
        if self.supported
            || clear_edit
            || (issue.is_none() && !confirmed_problem)
            || (has_remaining_findings && has_changes)
        {
            sentences.extend(impact(
                r,
                AddressedDisplay::Compact {
                    supported: self.supported || clear_edit,
                },
            ));
        }
        match addition {
            Some(CompactAddition::Problem(problem)) => sentences.push(problem),
            Some(CompactAddition::Description(description))
                if issue.is_none() && !confirmed_problem =>
            {
                sentences.push(description);
            }
            _ => {}
        }
        sentences.extend(target_problems);
        sentences.extend(issue);
        let summary = sentences
            .into_iter()
            .map(sentence)
            .collect::<Vec<_>>()
            .join(" ");
        (summary, details_recommended)
    }

    fn compact_issue(
        &self,
        r: &Record,
        clear_edit: bool,
        confirmed_problem: bool,
    ) -> Option<String> {
        let constraint = self
            .constraints
            .iter()
            .find(|constraint| constraint.excludes_target)
            .map(|constraint| constraint.compact_text(clear_edit))
            .or_else(|| self.compact_limit(r, "incompatible_recommendations"))
            .or_else(|| {
                self.constraints
                    .iter()
                    .find(|constraint| constraint.compact_edit.is_some())
                    .map(|constraint| constraint.compact_text(clear_edit))
            })
            .or_else(|| self.constraints.first().map(|c| c.compact_text(clear_edit)));
        if confirmed_problem || constraint.is_some() {
            return constraint;
        }
        target_checks(r)
            .next()
            .map(|(label, value)| check_line(label, value, true))
            .or_else(|| self.search_obstacle(r))
            .or_else(|| {
                self.changes
                    .iter()
                    .find_map(|change| change.application_issue.as_deref())
                    .map(str::to_owned)
            })
            .or_else(|| self.compact_check(r))
            .or_else(|| {
                limitations(r, &self.constraints)
                    .find(|(code, _)| !self.supported || !search_only_limit(code))
                    .map(compact_limitation)
            })
            .or_else(|| {
                self.changes
                    .is_empty()
                    .then(|| super::search::retention(r))
                    .flatten()
            })
    }

    fn compact_check(&self, r: &Record) -> Option<String> {
        if self.supported {
            return None;
        }
        checks(r, true).into_iter().next()
    }

    fn compact_limit(&self, r: &Record, reason: &str) -> Option<String> {
        limitations(r, &self.constraints)
            .find(|(code, _)| *code == reason)
            .map(compact_limitation)
    }

    fn search_obstacle(&self, r: &Record) -> Option<String> {
        if !self.changes.is_empty() {
            return None;
        }
        super::search::compact_obstacle(r, &self.search_explanations)
    }

    fn compact_changes(&self, r: &Record, addition: Option<&CompactAddition>) -> Option<String> {
        if self.changes.is_empty() {
            return None;
        }
        let added_advisory = match addition {
            Some(CompactAddition::Advisory(text)) => Some(text.as_str()),
            _ => None,
        };
        let paths = self.compact_location(r);
        if let (Some(advisory), [change], [text]) = (
            added_advisory,
            r.changes.as_slice(),
            self.changes.as_slice(),
        ) && change.data.strategy == "upgrade"
            && !text.target_caveat
        {
            let data = &change.data;
            return Some(format!(
                "The registry check found that upgrading {}:{} from {} to {}{paths} introduces {advisory}",
                safe(&data.registry),
                safe(&data.name),
                safe(&data.from_version),
                safe(&data.target_version),
            ));
        }
        let changes = self
            .changes
            .iter()
            .map(|change| change.compact.as_str())
            .collect::<Vec<_>>()
            .join(" and ");
        let action = if self.supported && !addition.is_some_and(CompactAddition::is_problem) {
            "Bump "
        } else {
            ""
        };
        let together = if self.changes.len() > 1 {
            " together"
        } else {
            ""
        };
        let summary = format!("{action}{changes}{together}{paths}");
        Some(match added_advisory {
            Some(advisory) => format!("{summary}. The registry check found {advisory}"),
            None => summary,
        })
    }

    fn compact_location(&self, r: &Record) -> String {
        if !self.supported || !self.constraints.is_empty() || !self.files.is_empty() {
            return location(&self.files);
        }
        common_paths(&r.changes)
            .filter(|paths| {
                paths
                    .iter()
                    .all(|path| matches!(file_role(path), Some(Role::Lockfile(_))))
            })
            .map_or_else(String::new, |paths| location(&paths))
    }
}

fn file_role(path: &str) -> Option<Role> {
    catalog::classify(Path::new(path)).map(|file| file.role)
}

fn sentence(mut text: String) -> String {
    if !text.ends_with('.') {
        text.push('.');
    }
    text
}

fn capitalize(mut text: String) -> String {
    if let Some(initial) = text.get_mut(..1) {
        initial.make_ascii_uppercase();
    }
    text
}

fn location(paths: &BTreeSet<String>) -> String {
    if paths.is_empty() {
        return String::new();
    }
    format!(" in {}", list(paths))
}

impl Constraint {
    fn compact_text(&self, clear_edit: bool) -> String {
        match (&self.compact_edit, clear_edit) {
            (Some(edit), true) => return format!("Update {edit}"),
            (Some(edit), false) => {
                return format!("Applying the proposal requires updating the {edit}");
            }
            (None, _) => {}
        }
        let requests = self.details.join(") and (");
        let label = match (self.excludes_target, self.details.len()) {
            (true, 1) => "Upgrade conflict on a requirement",
            (true, _) => "Upgrade conflict on requirements",
            (false, _) => self.summary.trim_end_matches('.'),
        };
        capitalize(format!("{label} ({requests})"))
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
    Some(format!("{label} — change together"))
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
    let action = match (known, data.strategy.as_str(), r.changes.len() > 1) {
        (true, "upgrade", true) if supported => "Upgrade",
        (true, "upgrade", true) => "Upgrade of",
        (_, _, true) => "Change",
        (true, "upgrade", false) if supported => "Suggested fix: Upgrade",
        (true, "upgrade", false) => "Candidate upgrade:",
        _ => "Candidate change:",
    };
    let partial = if r.changes.len() == 1 && r.outcome == "partial" {
        " (partial)"
    } else {
        ""
    };
    let (applicability, qualification) = change_strategy(&data.strategy);
    let mut details: Vec<String> = applicability.into_iter().map(str::to_owned).collect();
    let mut qualifiers = Vec::new();
    if !data.conflicting_target_versions.is_empty() {
        let targets = data
            .conflicting_target_versions
            .iter()
            .map(|target| safe(target))
            .collect::<Vec<_>>();
        details.push(format!("conflicting targets: {}", targets.join(", ")));
        qualifiers.push(format!("conflicts with {}", targets.join(" and ")));
    }
    for (label, flag) in [
        ("prerelease", data.prerelease_target),
        ("deprecated", data.deprecated_target),
    ] {
        if flag == Some(true) {
            details.push(format!("target is {label}"));
            qualifiers.push(label.into());
        }
    }
    if data.strategy == "override" {
        qualifiers.push("override proposal".into());
    }
    let files = data.paths.iter().filter(|_| show_files).cloned().collect();
    let package = format!("{}:{}", safe(&data.registry), safe(&data.name));
    let version_change = format!(
        "{package} {} -> {}",
        safe(&data.from_version),
        safe(&data.target_version)
    );
    let note = if qualifiers.is_empty() {
        String::new()
    } else {
        format!(" ({})", qualifiers.join(", "))
    };
    Change {
        index,
        compact: format!("{version_change}{note}{}", location(&files)),
        application_issue: qualification
            .map(|issue| application_issue(issue, &package, r.changes.len() > 1)),
        target_caveat: !details.is_empty(),
        summary: format!("{action} {version_change}{partial}"),
        details,
        files,
        reasons: reasons::explain(c, r, detail),
    }
}

fn change_strategy(strategy: &str) -> (Option<&'static str>, Option<&'static str>) {
    match strategy {
        "unknown" => (
            Some("The report lists version changes but does not specify how to apply them."),
            Some("The report does not specify how to update"),
        ),
        "override" | "upgrade" => (None, None),
        _ => (
            Some(
                "The service returned an unfamiliar change strategy; applicability could not be determined.",
            ),
            Some("Scan does not recognize the update method for"),
        ),
    }
}

fn application_issue(issue: &str, package: &str, joint: bool) -> String {
    let target = if joint { package } else { "this dependency" };
    format!("{issue} {target}")
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

#[derive(Clone, Copy)]
enum AddressedDisplay {
    Named,
    Listed,
    Omitted,
    Compact { supported: bool },
}

fn addressed_display(r: &Record, supported: bool, context: &Context<'_>) -> AddressedDisplay {
    if r.outcome == "proposed"
        && r.remaining_findings.is_empty()
        && context.matches(&r.findings)
        && r.findings.iter().collect::<BTreeSet<_>>()
            == r.addressed_findings.iter().collect::<BTreeSet<_>>()
    {
        return if supported {
            AddressedDisplay::Omitted
        } else {
            AddressedDisplay::Listed
        };
    }
    AddressedDisplay::Named
}

fn impact(r: &Record, display: AddressedDisplay) -> Vec<String> {
    let mut lines = Vec::new();
    if !r.addressed_findings.is_empty() {
        match display {
            AddressedDisplay::Compact { supported: true } => lines.push(format!(
                "Addresses {}",
                finding_names(&r.addressed_findings, &r.remaining_findings, &r.subject)
            )),
            AddressedDisplay::Named => lines.push(format!(
                "would address: {}",
                finding_names(&r.addressed_findings, &r.remaining_findings, &r.subject)
            )),
            AddressedDisplay::Listed if r.addressed_findings.len() == 1 => {
                lines.push("would address the listed advisory".into());
            }
            AddressedDisplay::Listed => lines.push("would address all listed advisories".into()),
            AddressedDisplay::Omitted | AddressedDisplay::Compact { supported: false } => {}
        }
    }
    match display {
        AddressedDisplay::Compact { supported: false }
            if r.remaining_findings.is_empty() && !r.changes.is_empty() =>
        {
            lines.push("Upgrade not verified".into());
        }
        AddressedDisplay::Compact { .. } => {}
        _ if r.outcome == "partial" && r.addressed_findings.is_empty() => {
            lines.push("would address: none reported".into());
        }
        _ => {}
    }
    if !r.remaining_findings.is_empty() {
        let remaining = finding_names(&r.remaining_findings, &r.addressed_findings, &r.subject);
        lines.push(format!(
            "{}{remaining}",
            if matches!(display, AddressedDisplay::Compact { .. }) {
                "Still open: "
            } else {
                "still unresolved: "
            }
        ));
    }
    lines
}

// Group only visible explanations: this finite Scan-owned phrase mapping never
// determines applicability or policy. Facts retain every original reason and request.
fn project_edit(b: &Blocker) -> bool {
    b.owner_role == "project" && b.reason == "project_request_change"
}
fn edit_instruction(b: &Blocker) -> Option<(String, String)> {
    if !project_edit(b) || b.requirement_status != "recorded" {
        return None;
    }
    let name = safe(b.dependency_name.as_deref()?);
    let path = safe(&b.path);
    let current = safe(b.requested_requirement.as_deref()?);
    Some((
        format!(
            "Applying the candidate requires updating the {name} requirement in {path}. Current requirement: {current}."
        ),
        format!("version constraint for {name} in {path} (currently {current})"),
    ))
}
fn constraints(blockers: &[Blocker], detail: ReasonDetail) -> Vec<Constraint> {
    let mut groups: Vec<Constraint> = Vec::new();
    for b in blockers {
        let excludes_target = matches!(
            b.reason.as_str(),
            "third_party_request_excludes_target" | "required_request_excludes_target"
        );
        let (summary, compact_edit) = match edit_instruction(b) {
            Some((full, compact)) => (full, Some(compact)),
            None if excludes_target => (
                "Dependency requirements conflict with this candidate.".into(),
                None,
            ),
            None => (explanation(&b.reason), None),
        };
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
        let details = if compact_edit.is_some() && detail == ReasonDetail::Summary {
            Vec::new()
        } else {
            vec![request]
        };
        if let Some(group) = groups.iter_mut().find(|c| c.summary == summary) {
            group.details.extend(details);
            continue;
        }
        groups.push(Constraint {
            summary,
            details,
            compact_edit,
            excludes_target,
        });
    }
    for group in &mut groups {
        group.details.sort();
        group.details.dedup();
    }
    groups
}

fn limitations<'a>(
    r: &'a Record,
    constraints: &'a [Constraint],
) -> impl Iterator<Item = (&'a str, String)> + 'a {
    let mut seen = BTreeSet::new();
    r.limitations
        .iter()
        .filter(|l| l.as_str() != "withdrawal_not_observed")
        .map(|l| (l.as_str(), explanation(l)))
        .filter(move |(_, message)| {
            !constraints.iter().any(|c| c.summary == *message) && seen.insert(message.clone())
        })
}

fn compact_limitation((code, message): (&str, String)) -> String {
    match code {
        "incompatible_recommendations" => "Do not combine conflicting recommendations".into(),
        "checked_occurrence_changed_by_other_recommendation" => {
            "Recheck before combining recommendations".into()
        }
        _ => capitalize(message),
    }
}

// These limits describe the wider search rather than the supported change.
fn search_only_limit(code: &str) -> bool {
    matches!(
        code,
        "parent_candidate_limit"
            | "parent_evidence_incomplete"
            | "parent_exact_lookup_limit"
            | "assignment_limit"
    )
}

fn check_line(label: &str, value: &str, compact: bool) -> String {
    // Target check statuses carry no reason. Constraints and search details explain their own scope.
    let gap = match (label, value) {
        ("release availability", "unverified" | "unknown" | "not_assessed") => Some((
            "The report did not confirm that the proposed versions are available",
            "The release check gives no reason for the missing confirmation.",
        )),
        ("target advisories", "unknown" | "not_assessed") => Some((
            "The report does not establish whether known advisories affect the proposed versions",
            "The advisory check gives no reason for this gap.",
        )),
        ("requirements", "not_checked" | "unchecked" | "not_assessed") => Some((
            "The audit did not check whether the project's dependency requirements allow this change",
            "The requirement check gives no reason.",
        )),
        ("requirements", "unknown") => Some((
            "The report does not establish whether the project's dependency requirements allow this change",
            "The requirement check gives no reason for this gap.",
        )),
        _ => None,
    };
    if let Some((scope, reason)) = gap {
        return if compact {
            scope.into()
        } else {
            format!("{scope}. {reason}")
        };
    }
    match (compact, label, value) {
        (_, "requirements", "blocked") => {
            "The upgrade conflicts with dependency requirements.".into()
        }
        (_, "target advisories", "affected") => {
            "A proposed version is still affected by known advisories.".into()
        }
        (true, _, _) => capitalize(format!("{label}: {}", check_text(value))),
        (false, _, _) => format!("{label}: {}", check_text(value)),
    }
}

fn target_checks(r: &Record) -> impl Iterator<Item = (&'static str, &str)> {
    let c = &r.checks;
    let mut checks = [
        (
            "release availability",
            c.release_availability.as_str(),
            "observed",
        ),
        ("target advisories", c.advisories.as_str(), "non_affecting"),
        ("requirements", c.requirements.as_str(), "matched"),
    ];
    checks.sort_by_key(|(label, value, _)| !confirmed_target_problem(label, value));
    checks
        .into_iter()
        .filter(move |(label, value, normal)| {
            !r.changes.is_empty()
                && value != normal
                && !(*label == "requirements" && *value == "blocked" && !r.blockers.is_empty())
        })
        .map(|(label, value, _)| (label, value))
}

fn confirmed_target_problem(label: &str, value: &str) -> bool {
    matches!(
        (label, value),
        ("target advisories", "affected") | ("requirements", "blocked")
    )
}

fn confirmed_target_problems(r: &Record) -> impl Iterator<Item = String> + '_ {
    target_checks(r)
        .filter(|(label, value)| confirmed_target_problem(label, value))
        .map(|(label, value)| check_line(label, value, true))
}

fn checks(r: &Record, compact: bool) -> Vec<String> {
    let c = &r.checks;
    let mut lines: Vec<_> = target_checks(r)
        .map(|(label, value)| check_line(label, value, compact))
        .collect();
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
            lines.push(check_line(label, value, compact));
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
        lines.push(check_line(
            "availability source",
            &c.availability_source,
            compact,
        ));
    }
    if c.preference_differences != 0 {
        lines.push("Some dependency requests have different version preferences.".into());
    }
    if !compact {
        lines.extend(
            action_target_warnings(r).map(|label| format!("action includes a {label} target")),
        );
    }
    lines
}

fn action_target_warnings(r: &Record) -> impl Iterator<Item = &'static str> {
    let prerelease = r.checks.prerelease_target
        && !r
            .changes
            .iter()
            .any(|c| c.data.prerelease_target == Some(true));
    let deprecated = r.checks.deprecated_target
        && !r
            .changes
            .iter()
            .any(|c| c.data.deprecated_target == Some(true));
    [("prerelease", prerelease), ("deprecated", deprecated)]
        .into_iter()
        .filter_map(|(label, warning)| warning.then_some(label))
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

fn upgrade_evidence(r: &Record, planning_known: bool) -> bool {
    planning_known
        && matches!(r.outcome.as_str(), "proposed" | "partial")
        && known_checks(&r.checks)
        && !r.addressed_findings.is_empty()
        && r.checks.release_availability == "observed"
        && r.checks.advisories == "non_affecting"
        && r.changes.iter().all(|c| c.data.strategy == "upgrade")
        && !((r.outcome == "partial" || !r.remaining_findings.is_empty())
            && (r.checks.prerelease_target
                || r.changes
                    .iter()
                    .any(|c| c.data.prerelease_target == Some(true))))
}

fn clear_project_edit(r: &Record, constraints: &[Constraint]) -> bool {
    let ([change], [blocker], [constraint]) =
        (r.changes.as_slice(), r.blockers.as_slice(), constraints)
    else {
        return false;
    };
    r.outcome == "proposed"
        && r.remaining_findings.is_empty()
        && r.checks.requirements == "blocked"
        && constraint.compact_edit.is_some()
        && blocker.dependency_name.as_deref() == Some(change.data.name.as_str())
        && file_role(&blocker.path) == Some(Role::Manifest)
        && limitations(r, constraints).all(|(code, _)| search_only_limit(code))
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
        "not_assessed" => "not assessed".into(),
        "not_retained" => "not retained".into(),
        "preference_differs" => "preference differs".into(),
        "affected" => "still affected by known advisories".into(),
        "blocked" => "blocked by dependency requirements".into(),
        "not_checked" | "unchecked" => "not checked".into(),
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
