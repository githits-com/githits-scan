//! Scan-owned audit remediation explanations, independent of output layout.
use super::view::{
    View,
    remediation::{Finding, State},
};
use crate::commands::safe;
use serde::Serialize;

pub(super) mod context;
pub(super) mod remediation;
pub(super) use remediation::{Plan, ReasonDetail};

/// Separate presentation contract; facts retain their existing schema and meaning.
#[derive(Serialize)]
pub(super) struct Document<'a> {
    schema_version: u8,
    kind: &'static str,
    audit: &'a View,
    remediation: Remediation<'a>,
}

impl<'a> Document<'a> {
    pub(super) fn new(view: &'a View) -> Self {
        Self {
            schema_version: 1,
            kind: "audit_presentation",
            audit: view,
            remediation: Remediation::new(view),
        }
    }
}

#[derive(Serialize)]
struct Remediation<'a> {
    messages: Vec<String>,
    recommendations: Vec<Recommendation<'a>>,
    limits: Vec<String>,
}

#[derive(Serialize)]
struct Recommendation<'a> {
    #[serde(rename = "recommendation_index")]
    index: usize,
    subject: &'a str,
    findings: &'a [Finding],
    addressed_findings: &'a [Finding],
    remaining_findings: &'a [Finding],
    #[serde(flatten)]
    explanation: Plan,
}

impl<'a> Remediation<'a> {
    fn new(view: &'a View) -> Self {
        let mut result = Self {
            messages: messages(view),
            recommendations: Vec::new(),
            limits: Vec::new(),
        };
        let State::Present(data) = &view.remediation else {
            return result;
        };
        result.limits = remediation::limits(data);
        result.recommendations = data
            .recommendations
            .iter()
            .enumerate()
            .map(|(index, r)| Recommendation {
                index,
                subject: &r.subject,
                findings: &r.findings,
                addressed_findings: &r.addressed_findings,
                remaining_findings: &r.remaining_findings,
                explanation: Plan::new(
                    r,
                    &data.status,
                    &context::Context::record(r),
                    ReasonDetail::Evidence,
                ),
            })
            .collect();
        result
    }
}

/// Section meaning is shared; native output alone decides section visibility.
pub(super) fn messages(view: &View) -> Vec<String> {
    let State::Present(data) = &view.remediation else {
        return match &view.remediation {
            State::Unavailable if !view.vulnerabilities.is_empty() => vec!["Fix guidance is unavailable in this report.".into()],
            State::Unverified => vec!["Fix guidance could not be verified; original findings are retained in the audit report.".into()],
            _ => Vec::new(),
        };
    };
    if data.recommendations.is_empty()
        && view.vulnerabilities.is_empty()
        && data.status == "completed"
    {
        return Vec::new();
    }
    let mut messages = Vec::new();
    if data.status != "completed" {
        messages.push(match data.status.as_str() {
            "limited" => "Fix guidance is incomplete.",
            "not_assessed" => "Fix guidance was not assessed.",
            _ => "The service returned an unfamiliar fix-planning status; see JSON for the supplied value.",
        }.into());
    }
    if data.recommendations.is_empty() {
        messages.push(
            "no recommendations returned; this does not establish that no mitigation exists".into(),
        );
    }
    messages
}

fn list<'a>(values: impl IntoIterator<Item = &'a String>) -> String {
    values
        .into_iter()
        .map(|s| safe(s))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn requirement_status(value: &str) -> String {
    match value {
        "not_recorded" => "not recorded".into(),
        "provider_requirement" => "bound to a provider package".into(),
        _ => safe(value),
    }
}

#[cfg(test)]
mod tests;
