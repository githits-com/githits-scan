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
fn explanation(index: usize, detail: &Detail) -> Explanation {
    let (summary, details) = match detail {
        Detail::Unavailable(d) => (
            unavailable(&d.operation, &d.reasons, &d.witness),
            context(&d.witness),
        ),
        Detail::Stopped(d) => (
            stopped(&d.stage, &d.reason, &d.witness),
            context(&d.witness),
        ),
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
        "source" => "identify the dependency source",
        "catalog" => "check available package versions",
        "release" => "check release metadata",
        "inventory" => "check the dependency list",
        "boundary" => "check the dependency relationship",
        "request" => "assess the dependency requirement",
        "membership" => "compare dependency requirements with the candidate version",
        "advisories" => "check advisory applicability",
        "ordering" => "compare the current and candidate versions",
        "maven_policy" => "evaluate the Maven dependency requirement",
        _ => {
            return format!(
                "Upgrade search: Scan cannot identify the reported check{}: {}. See JSON for its operation.",
                location(w),
                reasons
                    .iter()
                    .map(|r| cause(r))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
    };
    let causes = reasons
        .iter()
        .map(|r| cause(r))
        .chain(
            w.acquisition
                .iter()
                .filter(|_| operation == "release")
                .map(|r| cause(r)),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("; ");
    let scope = match operation {
        "request" => w
            .request
            .as_ref()
            .map(|r| format!(" for {}", request_text(r))),
        "ordering" => match (&w.current, &w.target) {
            (Some(current), Some(target)) => Some(format!(
                " from {} to {}",
                safe(&current.to_string()),
                safe(&target.to_string())
            )),
            _ => None,
        },
        _ => None,
    }
    .unwrap_or_else(|| location(w));
    format!("Upgrade search: could not {check}{scope}: {causes}.")
}

fn stopped(stage: &str, reason: &str, w: &SearchWitness) -> String {
    let work = match stage {
        "leaf_evaluation" => "checking candidate dependency versions",
        "domain_construction" => "collecting candidate upgrade versions",
        "domain_sampling" => "selecting candidate upgrade versions",
        "domain_reservation" => "allocating candidate upgrade checks",
        "seed_admission" => "starting upgrade combinations",
        "frontier_admission" => "exploring further upgrade combinations",
        "parent_evaluation" => "checking upgrades to packages that depend on this dependency",
        _ => {
            return format!(
                "Upgrade search: Scan cannot identify the stage that stopped{}: {}. See JSON for the supplied stage.",
                location(w),
                cause(reason)
            );
        }
    };
    let scope = match w.budget_scope.as_deref() {
        Some("shared") => " The limit is shared across upgrade searches.",
        Some("local") => " The limit applies to this search.",
        _ => " Scan cannot interpret the supplied limit scope; see JSON.",
    };
    format!(
        "Upgrade search: stopped {work}{}: {}.{scope}",
        location(w),
        cause(reason)
    )
}

fn location(w: &SearchWitness) -> String {
    if let Some(Some(c)) = &w.coordinate {
        return format!(" for {}", safe(&c.to_string()));
    }
    if let Some(package) = &w.package {
        return format!(" for {}:{}", safe(&package.registry), safe(&package.name));
    }
    if let (Some(current), Some(target)) = (&w.current, &w.target) {
        return format!(
            " from {} to {}",
            safe(&current.to_string()),
            safe(&target.to_string())
        );
    }
    if let Some(target) = &w.target {
        return format!(" for {}", safe(&target.to_string()));
    }
    if let Some(request) = &w.request {
        return format!(" for {}", request_text(request));
    }
    if let Some(boundary) = &w.boundary {
        return format!(
            " from {} to {}",
            source(&boundary.from),
            source(&boundary.to)
        );
    }
    if let Some(source_witness) = &w.source {
        return format!(" for {}", source(source_witness));
    }
    String::new()
}

fn cause(value: &str) -> &'static str {
    if let Some(reason) = crate::commands::evidence::reason(value) {
        return reason;
    }
    match value {
        "lookup_failed" => "the metadata lookup failed",
        "release_row_unavailable" => "the service had no release metadata",
        "release_row_unsuitable" => {
            "the available release metadata could not be used for this check"
        }
        "chunk_task_timeout" => "the metadata lookup timed out",
        "phase_deadline" | "planning_deadline" => "the search reached its time limit",
        "lookup_limit" | "parent_exact_lookup_limit" => {
            "the service reached its metadata lookup limit"
        }
        "parent_candidate_limit" => {
            "the service reached its limit for checking dependency upgrades"
        }
        "assignment_limit" => "the service reached its limit for checking upgrade combinations",
        "unsupported_selector" => "the requirement uses a selector this check cannot evaluate",
        "request_unavailable" => "the service did not provide a requirement assessment",
        "membership_unavailable" => "the service did not provide a requirement comparison",
        "native_applicability_not_checked" => {
            "whether the dependency requirement applies to this project was not checked"
        }
        _ => "Scan cannot explain the supplied reason; see JSON for the original value",
    }
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

fn context(w: &SearchWitness) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(request) = &w.request {
        lines.push(request_text(request));
    }
    lines.extend(w.requests.iter().flatten().map(request_text));
    qualification(w, &mut lines);
    request_checks(w, &mut lines);
    if let Some(coverage) = &w.coverage {
        if coverage.status == "missing" {
            lines.push("The report contains no dependency inventory for this check.".into());
        }
        if coverage.complete == Some(false) {
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
    if let Some(boundary) = &w.boundary {
        lines.push(format!(
            "Dependency relationship: {} → {}.",
            source(&boundary.from),
            source(&boundary.to)
        ));
    }
    if let (Some(current), Some(target)) = (&w.current, &w.target) {
        lines.push(format!(
            "Versions compared: {} → {}.",
            safe(&current.to_string()),
            safe(&target.to_string())
        ));
    }
    if let Some(s) = &w.source {
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
        for clause in &check.clauses {
            request_clause(clause, &check.target, lines);
        }
    }
}

fn request_clause(
    clause: &crate::api::audit::remediation::search::witness::Clause,
    target: &crate::api::audit::wire::Coordinate,
    lines: &mut Vec<String>,
) {
    lines.push(format!(
        "{}; compared with {}.",
        request_text(&clause.request),
        safe(&target.to_string())
    ));
    participation(&clause.participation.status, lines);
    if let Some(reason) = &clause.effective_membership.reason {
        lines.push(format!("Requirement comparison: {}.", cause(reason)));
    }
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
