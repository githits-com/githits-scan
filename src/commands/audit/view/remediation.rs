//! Curated action records; report-local indices are resolved before either output.
use std::collections::BTreeSet;

use serde::Serialize;

pub(in crate::commands::audit) mod reasons;
use reasons::Reason;

use super::coordinate;
use crate::api::audit::{Report, remediation as wire, report::Vulnerability};
use crate::audit::{Assessment, remediation::UNVERIFIED};

#[derive(Serialize)]
#[serde(untagged)]
pub(in crate::commands::audit) enum State {
    Unavailable,
    Unverified,
    Present(Box<Remediation>),
}

impl State {
    pub(in crate::commands::audit) fn covers_finding(&self, index: usize) -> bool {
        matches!(self, Self::Present(data) if data.problem_indices.contains(&index))
    }

    pub(in crate::commands::audit) const fn omitted(&self) -> bool {
        !matches!(self, Self::Present(_))
    }

    pub(super) fn new(report: &Report, assessment: &Assessment) -> Self {
        if assessment.unverified.contains(UNVERIFIED) {
            return Self::Unverified;
        }
        let r = &report.data;
        let Some(data) = &r.remediation else {
            return Self::Unavailable;
        };
        Self::Present(Box::new(Remediation {
            problem_indices: data
                .recommendations
                .iter()
                .flat_map(|r| {
                    r.finding_refs
                        .iter()
                        .chain(&r.addressed_finding_refs)
                        .chain(&r.remaining_finding_refs)
                })
                .copied()
                .collect(),
            status: data.status.clone(),
            recommendations: data
                .recommendations
                .iter()
                .map(|record| Record::new(record, &r.findings.vulnerabilities, &data.trace))
                .collect(),
            trace_status: data.trace.status.clone(),
            limits: data.limits.clone(),
        }))
    }
}

#[derive(Serialize)]
pub(in crate::commands::audit) struct Remediation {
    // Positions address the unchanged advisory finding order; never export them.
    #[serde(skip)]
    problem_indices: BTreeSet<usize>,
    pub status: String,
    pub recommendations: Vec<Record>,
    pub trace_status: String,
    pub limits: wire::Limits,
}

#[derive(Serialize)]
pub(in crate::commands::audit) struct Record {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrence_scope: Option<crate::audit::explain::OccurrenceScope>,
    pub subject: String,
    #[serde(skip)]
    pub recorded_requests: Vec<crate::audit::explain::RecordedRequest>,
    pub findings: Vec<Finding>,
    pub outcome: String,
    #[serde(serialize_with = "compact_changes")]
    pub changes: Vec<Change>,
    pub blockers: Vec<wire::Blocker>,
    pub checks: wire::Checks,
    pub addressed_findings: Vec<Finding>,
    pub remaining_findings: Vec<Finding>,
    pub limitations: Vec<String>,
    pub detail_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_domain: Option<wire::SearchDomain>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(in crate::commands::audit) struct Finding {
    pub package: String,
    pub advisory: String,
    pub files: BTreeSet<String>,
    // Problem context is human-only; compact JSON keeps its established identity.
    #[serde(skip)]
    pub title: Option<String>,
    #[serde(skip)]
    pub severity: Option<String>,
    #[serde(skip)]
    pub malicious: bool,
    #[serde(skip)]
    pub aliases: Vec<String>,
    #[serde(skip)]
    pub proposed_fixes: Vec<String>,
    #[serde(skip)]
    pub verified_advisory_fixes: Vec<String>,
}

/// A change retains wire facts while projecting its reason references separately.
pub(in crate::commands::audit) struct Change {
    /// Original consumed change, including archive-only data.
    pub data: wire::Change,
    /// Compact checked effects; None preserves optional evidence absence.
    pub reasons: Option<Vec<Reason>>,
}

impl Record {
    fn new(r: &wire::Recommendation, findings: &[Vulnerability], trace: &wire::Trace) -> Self {
        Self {
            occurrence_scope: None,
            subject: coordinate(&r.subject),
            recorded_requests: crate::audit::explain::recorded_requests(trace, r),
            findings: resolve(&r.finding_refs, findings),
            outcome: r.outcome.clone(),
            changes: r
                .changes
                .iter()
                .map(|change| Change {
                    data: change.clone(),
                    reasons: change.reasons.as_ref().map(|reasons| {
                        reasons
                            .iter()
                            .map(|reason| Reason::new(reason, findings))
                            .collect()
                    }),
                })
                .collect(),
            blockers: r.blockers.clone(),
            checks: r.checks.clone(),
            addressed_findings: resolve(&r.addressed_finding_refs, findings),
            remaining_findings: resolve(&r.remaining_finding_refs, findings),
            limitations: r.limitations.clone(),
            detail_status: r.detail_status.clone(),
            search_domain: r.search_domain.clone(),
        }
    }
}

fn resolve(refs: &[usize], findings: &[Vulnerability]) -> Vec<Finding> {
    // Bounds are verified by the pure interpreter; no raw index is published.
    refs.iter()
        .filter_map(|&index| findings.get(index))
        .map(|f| Finding {
            package: coordinate(&f.coordinate),
            advisory: f.advisory_id.clone(),
            files: f.paths.iter().cloned().collect(),
            title: f.summary.clone().filter(|s| !s.is_empty()),
            severity: super::human_severity(f.severity_score, f.severity_type.as_deref()),
            malicious: f.malicious,
            aliases: f.aliases.clone(),
            proposed_fixes: f.fixed_in_versions.clone(),
            verified_advisory_fixes: f.verified_remedies.clone(),
        })
        .collect()
}

// The API DTO also carries saved trace references; compact output owns a narrower contract.
fn compact_changes<S: serde::Serializer>(
    changes: &[Change],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq as _;
    let mut sequence = serializer.serialize_seq(Some(changes.len()))?;
    for change in changes {
        sequence.serialize_element(&CompactChange(change))?;
    }
    sequence.end()
}

struct CompactChange<'a>(&'a Change);
impl Serialize for CompactChange<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let wire::Change {
            _additional: _,
            occurrence_refs: _,
            registry,
            name,
            from_version,
            target_version,
            strategy,
            paths,
            conflicting_target_versions,
            availability_source,
            prerelease_target,
            deprecated_target,
            reasons: _,
        } = &self.0.data;
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in [
            ("registry", registry),
            ("name", name),
            ("from_version", from_version),
            ("target_version", target_version),
            ("strategy", strategy),
        ] {
            map.serialize_entry(key, value)?;
        }
        if !paths.is_empty() {
            map.serialize_entry("paths", paths)?;
        }
        if !conflicting_target_versions.is_empty() {
            map.serialize_entry("conflicting_target_versions", conflicting_target_versions)?;
        }
        if let Some(value) = availability_source {
            map.serialize_entry("availability_source", value)?;
        }
        if let Some(value) = prerelease_target {
            map.serialize_entry("prerelease_target", value)?;
        }
        if let Some(value) = deprecated_target {
            map.serialize_entry("deprecated_target", value)?;
        }
        if let Some(reasons) = &self.0.reasons {
            map.serialize_entry("reasons", reasons)?;
        }
        map.end()
    }
}
