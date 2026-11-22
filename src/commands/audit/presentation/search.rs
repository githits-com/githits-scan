//! Explanations of whole-search obstacles, never selected-action verdicts.
use super::{
    remediation::{owner, request_requirement},
    safe,
};
use crate::api::audit::remediation::{
    reasons::Request,
    search::{
        Detail,
        witness::{SearchWitness, Source},
    },
};
use crate::commands::audit::view::remediation::Record;
use serde::Serialize;
use std::collections::BTreeSet;

/// An explanation associated with one detail in the matching fact record.
#[derive(Serialize)]
pub(in crate::commands::audit) struct Explanation {
    /// Position in that fact record's `search_details` array.
    pub search_detail_index: usize,
    /// The unavailable answer or observed work stop and its reported cause.
    pub summary: String,
    /// Supporting request, source and condition evidence, as plain text.
    pub details: Vec<String>,
}

pub(super) fn explain(record: &Record) -> Vec<Explanation> {
    record
        .search_details
        .iter()
        .flatten()
        .enumerate()
        .map(|(index, detail)| explanation(index, detail))
        .collect()
}

pub(super) fn compact_obstacle(record: &Record, explanations: &[Explanation]) -> Option<String> {
    explanations
        .iter()
        .zip(record.search_details.iter().flatten())
        .find_map(|(explanation, detail)| match detail {
            Detail::AddedDependency(detail) => super::added::compact_search(detail),
            _ => Some(explanation.summary.clone()),
        })
}

fn explanation(index: usize, detail: &Detail) -> Explanation {
    let (summary, details) = match detail {
        Detail::Unavailable(d) => (
            unavailable(&d.operation, &d.reasons, &d.witness),
            context(&d.witness, subject(&d.witness, Some(&d.operation))),
        ),
        Detail::Stopped(d) => (
            stopped(&d.stage, &d.reason, &d.witness),
            context(&d.witness, subject(&d.witness, None)),
        ),
        Detail::AddedDependency(d) => super::added::search(d),
        Detail::Unrecognized { .. } => (
            "Scan cannot interpret this search detail; its kind is not supported by this version."
                .into(),
            Vec::new(),
        ),
    };
    Explanation {
        search_detail_index: index,
        summary,
        details,
    }
}

pub(super) fn retention(record: &Record) -> Option<String> {
    match record.search_detail_status.as_deref() {
        None if record.checks.parent_search == "limited" => Some("This report does not include detailed search explanations for the incomplete upgrade search.".into()),
        None | Some("retained") => None,
        Some("not_retained") => Some("Search explanations were omitted from this report.".into()),
        Some(_) => Some("Scan cannot interpret whether this report retained its search explanations; see JSON for the supplied status.".into()),
    }
}

fn unavailable(operation: &str, reasons: &[String], w: &SearchWitness) -> String {
    let check = match operation {
        "source" => "Dependency source",
        "catalog" => "Available package versions",
        "release" => "Release metadata",
        "inventory" => "Dependency list",
        "boundary" => "Dependency relationship",
        "request" => "Dependency requirement",
        "membership" => "Requirement comparison",
        "advisories" => "Advisory applicability",
        "ordering" => "Version comparison",
        "maven_policy" => "Maven dependency requirement",
        _ => {
            return format!(
                "Scan cannot identify which check failed{}: {}. See JSON for the operation and reasons.",
                subject(w, None).text(),
                reasons
                    .iter()
                    .map(|r| known_cause(r).unwrap_or("Scan cannot explain the supplied reason"))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
    };
    let causes = reasons
        .iter()
        .map(|r| incomplete_cause(r))
        .chain(
            w.acquisition
                .iter()
                .filter(|_| operation == "release")
                .map(|r| incomplete_cause(r)),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("; ");
    let scope = subject(w, Some(operation)).text();
    format!("{check}{scope}: {causes}.")
}

fn stopped(stage: &str, reason: &str, w: &SearchWitness) -> String {
    let work = match stage {
        "leaf_evaluation" => "Checking candidate versions",
        "domain_construction" => "Collecting upgrade versions",
        "domain_sampling" => "Selecting upgrade versions",
        "domain_reservation" => "Allocating upgrade checks",
        "seed_admission" => "Starting upgrade combinations",
        "frontier_admission" => "Exploring upgrade combinations",
        "parent_evaluation" => "Checking upgrades",
        _ => {
            return format!(
                "Scan cannot identify which part of the upgrade search stopped{}: {}. See JSON for the stage and reason.",
                subject(w, None).text(),
                known_cause(reason).unwrap_or("Scan cannot explain the supplied reason")
            );
        }
    };
    let scope = match w.budget_scope.as_deref() {
        Some("shared" | "local") => "",
        _ => " Scan cannot interpret which searches the limit applies to; see JSON.",
    };
    format!(
        "{work}{}: {}.{scope}",
        subject(w, None).text(),
        incomplete_cause(reason)
    )
}

// Keep the selected subject with its context so renderers do not repeat it.
#[derive(Clone, Copy)]
enum Subject<'a> {
    Coordinate(&'a crate::api::audit::wire::Coordinate),
    Package(&'a crate::api::audit::remediation::search::witness::WitnessPackage),
    Versions(
        &'a crate::api::audit::wire::Coordinate,
        &'a crate::api::audit::wire::Coordinate,
    ),
    Request(&'a Request),
    Boundary(&'a crate::api::audit::remediation::search::witness::Boundary),
    Source(&'a Source),
    None,
}
impl Subject<'_> {
    fn text(self) -> String {
        match self {
            Self::Coordinate(c) => format!(" for {}", safe(&c.to_string())),
            Self::Package(p) => format!(" for {}:{}", safe(&p.registry), safe(&p.name)),
            Self::Versions(a, b) => {
                format!(" from {} to {}", safe(&a.to_string()), safe(&b.to_string()))
            }
            Self::Request(r) => format!(" for {}", request_text(r)),
            Self::Boundary(b) => format!(" from {} to {}", source(&b.from), source(&b.to)),
            Self::Source(s) => format!(" for {}", source(s)),
            Self::None => String::new(),
        }
    }
}
fn subject<'a>(w: &'a SearchWitness, operation: Option<&str>) -> Subject<'a> {
    if operation == Some("request")
        && let Some(r) = &w.request
    {
        return Subject::Request(r);
    }
    if operation == Some("ordering")
        && let (Some(a), Some(b)) = (&w.current, &w.target)
    {
        return Subject::Versions(a, b);
    }
    if let Some(Some(c)) = &w.coordinate {
        return Subject::Coordinate(c);
    }
    if let Some(p) = &w.package {
        return Subject::Package(p);
    }
    if let (Some(a), Some(b)) = (&w.current, &w.target) {
        return Subject::Versions(a, b);
    }
    if let Some(c) = &w.target {
        return Subject::Coordinate(c);
    }
    if let Some(r) = &w.request {
        return Subject::Request(r);
    }
    if let Some(b) = &w.boundary {
        return Subject::Boundary(b);
    }
    w.source.as_ref().map_or(Subject::None, Subject::Source)
}

fn cause(value: &str) -> &'static str {
    known_cause(value)
        .unwrap_or("Scan cannot explain the supplied reason; see JSON for the original value")
}
fn incomplete_cause(value: &str) -> &'static str {
    known_cause(value).unwrap_or("the check could not be completed; Scan cannot explain the supplied reason; see JSON for the original value")
}
pub(super) fn known_cause(value: &str) -> Option<&'static str> {
    if let Some(reason) = crate::commands::evidence::reason(value) {
        return Some(reason);
    }
    Some(match value {
        "lookup_failed" => "lookup failed",
        "release_row_unavailable" => "no release metadata was available",
        "release_row_unsuitable" => "the available release metadata could not be used",
        "exact_release_lookup_timed_out" => "the registry lookup timed out",
        "exact_release_lookup_not_started" => {
            "the time limit expired before the registry lookup started"
        }
        "exact_metadata_authorization_deadline" => {
            "the time limit expired while checking access to release metadata"
        }
        "exact_stored_metadata_read_deadline" => {
            "the time limit expired while reading stored release metadata"
        }
        "exact_metadata_deadline_before_start" => {
            "the time limit expired before release metadata checking started"
        }
        "chunk_task_timeout" => "lookup timed out",
        "phase_deadline" | "planning_deadline" => "time limit reached",
        "lookup_limit" | "parent_exact_lookup_limit" => "metadata lookup limit reached",
        "parent_candidate_limit" => "dependency upgrade check limit reached",
        "assignment_limit" => "upgrade combination check limit reached",
        "unsupported_selector" => "the requirement uses a selector this check cannot evaluate",
        "request_unavailable" => "the service did not provide a requirement assessment",
        "membership_unavailable" => "the service did not provide a requirement comparison",
        "native_applicability_not_checked" => {
            "whether the dependency requirement applies to this project was not checked"
        }
        _ => return None,
    })
}

fn source(source: &Source) -> String {
    source.coordinate.as_ref().map_or_else(
        || safe(&source.path),
        |c| format!("{} [{}]", safe(&c.to_string()), safe(&source.path)),
    )
}
fn request_text(r: &Request) -> String {
    format!(
        "{} {} [{}]",
        owner(&r.owner.name, r.owner.version.as_deref()),
        request_requirement(
            r.dependency_name.as_deref(),
            r.requested_requirement.as_deref(),
            &r.requirement_status
        ),
        safe(&r.path)
    )
}

fn context(w: &SearchWitness, subject: Subject<'_>) -> Vec<String> {
    let mut lines = Vec::new();
    if !matches!(subject, Subject::Request(_))
        && let Some(request) = &w.request
    {
        lines.push(request_text(request));
    }
    lines.extend(w.requests.iter().flatten().map(request_text));
    qualification(w, &mut lines);
    request_checks(w, &mut lines);
    if let Some(coverage) = &w.coverage {
        if coverage.status == "missing" {
            lines.push("The report contains no dependency inventory for this check.".into());
        }
        if coverage.complete == Some(false) && coverage.reasons.is_empty() {
            lines.push("The dependency list used for this check is incomplete.".into());
        }
        lines.extend(
            coverage
                .reasons
                .iter()
                .map(|r| format!("Dependency list: {}.", cause(r))),
        );
    }
    if let Some(policy) = &w.policy {
        lines.push(format!(
            "{} {}.",
            safe(&policy.name),
            request_requirement(
                None,
                policy.effective_requirement.as_deref(),
                &policy.effective_requirement_status
            )
        ));
        lines.extend(
            policy
                .diagnostics
                .iter()
                .map(|d| format!("{}: {}.", safe(&d.field), cause(&d.code))),
        );
    }
    lines.extend(w.declarations.iter().flatten().map(|d| {
        format!(
            "{} {}.",
            safe(&d.name),
            request_requirement(
                None,
                d.requested_requirement.as_deref(),
                &d.requirement_status
            )
        )
    }));
    if let Some(o) = &w.observation {
        lines.push(format!(
            "{} {} [{}].",
            safe(&o.name),
            request_requirement(
                None,
                o.requested_requirement.as_deref(),
                &o.requirement_status
            ),
            safe(&o.path)
        ));
    }
    if !matches!(subject, Subject::Boundary(_))
        && let Some(boundary) = &w.boundary
    {
        lines.push(format!(
            "Dependency relationship: {} → {}.",
            source(&boundary.from),
            source(&boundary.to)
        ));
    }
    if !matches!(subject, Subject::Versions(..))
        && let (Some(current), Some(target)) = (&w.current, &w.target)
    {
        lines.push(format!(
            "Versions compared: {} → {}.",
            safe(&current.to_string()),
            safe(&target.to_string())
        ));
    }
    if !matches!(subject, Subject::Source(_))
        && let Some(s) = &w.source
    {
        lines.push(format!("Source: {}.", source(s)));
    }
    lines.extend(
        w.paths
            .iter()
            .flatten()
            .map(|p| format!("Source: {}.", safe(p))),
    );
    let mut seen = BTreeSet::new();
    lines.retain(|l| seen.insert(l.clone()));
    lines
}
fn participation(value: &str, lines: &mut Vec<String>) {
    let message = match value {
        "required" => return,
        "conditional" => "This dependency request is conditional.",
        "unestablished" => concat!(
            "The report could not establish whether this dependency request ",
            "participates in the project."
        ),
        _ => concat!(
            "Scan cannot interpret the reported dependency participation; ",
            "see JSON for the supplied value."
        ),
    };
    lines.push(message.into());
}

fn qualification(w: &SearchWitness, lines: &mut Vec<String>) {
    if let Some(q) = &w.qualification {
        participation(&q.participation, lines);
        if q.binding == "possible" {
            lines.push(
                "The report did not establish the binding of this request to the dependency."
                    .into(),
            );
        }
        if q.capture == "unavailable" {
            lines.push("Complete request evidence was unavailable to this check.".into());
        }
        if q.capture == "filtered" {
            lines.push("Request evidence was filtered from the report.".into());
        }
        if let Some(message) = declaration_capture(&q.declaration_capture) {
            lines.push(message.into());
        }
        for c in &q.conditions {
            lines.push(c.expression.as_ref().map_or_else(
                || "The report does not include the dependency condition expression.".into(),
                |expression| format!("Recorded condition: {}. Its activation was not established by this search evidence.", safe(expression))));
        }
        lines.extend(
            q.policy_reasons
                .iter()
                .map(|r| format!("Requirement policy: {}.", cause(r))),
        );
    }
}

fn request_checks(w: &SearchWitness, lines: &mut Vec<String>) {
    for check in w.request_checks.iter().flatten() {
        let result = match check.result.as_str() {
            "matched" => "requirements match",
            "blocked" => "requirements conflict",
            "unchecked" => "requirements were not fully compared",
            "preference_differs" => "dependency preferences differ",
            _ => "Scan cannot interpret the supplied requirement check result; see JSON",
        };
        lines.push(format!(
            "Requirement check for {}: {result}.",
            safe(&check.target.to_string())
        ));
        lines.extend(
            check
                .clauses
                .iter()
                .map(|c| request_clause(c, &check.target)),
        );
    }
}
fn request_clause(
    clause: &crate::api::audit::remediation::search::witness::Clause,
    target: &crate::api::audit::wire::Coordinate,
) -> String {
    let m = &clause.effective_membership;
    let comparison = match (m.status.as_str(), m.strength.as_deref()) {
        ("matched", Some("required")) => "requirement matches",
        ("matched", Some("preference")) => "preference matches",
        ("mismatched", Some("required")) => "requirement excludes",
        ("mismatched", Some("preference")) => "preference differs from",
        ("unchecked", _) => "requirement was not compared with",
        _ => "Scan cannot interpret the supplied comparison with",
    };
    let qualifier = match clause.participation.status.as_str() {
        "required" => "",
        "conditional" => "; conditional request",
        "unestablished" => "; whether this request participates in the project was not established",
        _ => "; Scan cannot interpret the supplied request participation; see JSON",
    };
    let reason = m
        .reason
        .as_ref()
        .map(|r| format!(": {}", cause(r)))
        .unwrap_or_default();
    format!(
        "{}; {comparison} {}{reason}{qualifier}.",
        request_text(&clause.request),
        safe(&target.to_string())
    )
}

fn declaration_capture(value: &str) -> Option<&'static str> {
    match value {
        "complete" => None,
        "incomplete" => Some("The dependency declarations for this request are incomplete."),
        "unavailable" => {
            Some("Dependency declarations for this request were unavailable to this check.")
        }
        _ => Some(concat!(
            "Scan cannot interpret whether dependency declarations were captured ",
            "for this request; see JSON."
        )),
    }
}
