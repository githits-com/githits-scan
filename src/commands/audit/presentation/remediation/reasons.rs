//! Checked effects and supporting evidence at their owning change.
use super::{owner, request_requirement, safe};
use crate::api::audit::remediation::reasons::Request;
use crate::commands::audit::view::remediation::{Change, Finding, Record, reasons::Reason};
use serde::Serialize;
use std::collections::BTreeSet;

/// Selects concise report explanations or their supporting evidence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::commands::audit) enum ReasonDetail {
    /// Show checked effects without a request inventory.
    Summary,
    /// Also show request evidence, unavailable and unknown reason states.
    Evidence,
}

/// A checked effect or an explicit reason-evidence gap.
#[derive(Serialize)]
pub(in crate::commands::audit) struct Explanation {
    /// Concise explanation owned by the changed package.
    pub summary: String,
    /// Supporting requests, included for detailed output.
    pub evidence: Vec<String>,
}

pub(super) fn explain(change: &Change, record: &Record, detail: ReasonDetail) -> Vec<Explanation> {
    let mut seen = BTreeSet::new();
    change
        .reasons
        .iter()
        .flatten()
        .filter_map(|r| explanation(r, change, record, detail))
        .filter(|r| seen.insert((r.summary.clone(), r.evidence.clone())))
        .collect()
}

fn explanation(
    reason: &Reason,
    change: &Change,
    record: &Record,
    detail: ReasonDetail,
) -> Option<Explanation> {
    let mut requests = Vec::new();
    let summary = match reason {
        Reason::Advisory { findings } => {
            if findings.is_empty() || redundant(findings, record, detail) {
                return None;
            }
            let changed = format!(
                "{}:{}@{}",
                change.data.registry, change.data.name, change.data.from_version
            );
            format!(
                "why: addresses {}",
                super::finding_names(findings, &[], &changed)
            )
        }
        Reason::Enables {
            dependency,
            path,
            original_requests,
            replacement_requests,
        } => {
            requests.extend(evidence("original request", original_requests, detail));
            requests.extend(evidence(
                "replacement request",
                replacement_requests,
                detail,
            ));
            format!(
                "why: accepts {}, which the current requested range excludes{}",
                safe(&dependency.to_string()),
                file(path, change)
            )
        }
        Reason::Removes {
            dependency,
            path,
            original_requests,
        } => {
            requests.extend(evidence("original request", original_requests, detail));
            format!(
                "why: removes a route to {}{}",
                safe(&dependency.to_string()),
                file(path, change)
            )
        }
        Reason::Unavailable if detail == ReasonDetail::Evidence => "reason unavailable".into(),
        Reason::Unknown { code } if detail == ReasonDetail::Evidence => {
            format!("unrecognized reason: {}", safe(code))
        }
        Reason::Unavailable | Reason::Unknown { .. } => return None,
    };
    Some(Explanation {
        summary,
        evidence: requests,
    })
}
fn redundant(findings: &[Finding], record: &Record, detail: ReasonDetail) -> bool {
    detail == ReasonDetail::Summary
        && record.changes.len() == 1
        && findings.iter().collect::<BTreeSet<_>>() == record.addressed_findings.iter().collect()
}
fn file(path: &str, change: &Change) -> String {
    if change.data.paths.len() == 1 && change.data.paths[0] == path {
        String::new()
    } else {
        format!(" [{}]", safe(path))
    }
}
fn evidence(label: &str, requests: &[Request], detail: ReasonDetail) -> Vec<String> {
    if detail != ReasonDetail::Evidence {
        return Vec::new();
    }
    requests
        .iter()
        .map(|request| {
            format!(
                "{label}: {} {} [{}]",
                owner(&request.owner.name, request.owner.version.as_deref()),
                request_requirement(
                    request.dependency_name.as_deref(),
                    request.requested_requirement.as_deref(),
                    &request.requirement_status
                ),
                safe(&request.path)
            )
        })
        .collect()
}
