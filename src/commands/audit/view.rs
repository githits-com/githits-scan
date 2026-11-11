//! Focused command results shared by human and JSON output, without wire telemetry.
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::api::audit::report::{ManifestLockMismatch, NativeConditions};
use crate::api::audit::{
    Report,
    wire::{Coordinate, MetadataCoverage, VulnerabilityCoverage},
};
use crate::audit::Assessment;

pub(super) mod remediation;
mod report;

#[derive(Serialize)]
pub(super) struct View {
    schema_version: u8,
    pub incomplete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<crate::audit::saved::Provenance>,
    pub summary: Summary,
    pub lifecycle: crate::api::audit::lifecycle::Lifecycle,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub outdated: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub duplicates: Vec<Duplicate>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub manifest_lock_mismatches: Vec<ManifestLockMismatch>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<Issue>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub manifests: BTreeSet<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
    #[serde(skip_serializing_if = "remediation::State::omitted")]
    pub remediation: remediation::State,
}
#[derive(Serialize)]
pub(super) struct Summary {
    pub dependencies: u64,
    pub vulnerabilities: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignored_vulnerabilities: Option<u64>,
    pub lifecycle: u64,
    pub retained_lifecycle_warnings: u64,
    pub outdated: u64,
    pub duplicates: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_lock_mismatches: Option<usize>,
}
#[derive(Default, Serialize)]
pub(super) struct Finding {
    pub package: String,
    pub files: BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ignored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore: Option<crate::config::AdvisoryIgnore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proposed_fixes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verified_advisory_fixes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub malicious: bool,
}
#[derive(Serialize)]
pub(super) struct Duplicate {
    pub package: String,
    pub versions: Vec<DuplicateVersion>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub unattributed_requirements: BTreeSet<Unattributed>,
}
#[derive(Serialize)]
pub(super) struct DuplicateVersion {
    pub version: String,
    pub files: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub origins: BTreeSet<Origin>,
}
#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Origin {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_requirement: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution_basis: Option<String>,
}
#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Unattributed {
    pub file: String,
    pub requester: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_requirement: Option<String>,
    pub requirement_status: String,
    pub target_status: String,
}
#[derive(Default, Serialize)]
pub(super) struct Issue {
    pub check: String,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub packages: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub files: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub required_files: BTreeSet<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_requests: Vec<MissingRequest>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub advisories: BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_count: Option<usize>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub registries: BTreeSet<String>,
}

#[derive(Serialize)]
pub(super) struct MissingRequest {
    pub name: String,
    pub requester: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_requirement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirement_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<NativeConditions>,
}

pub(super) fn coordinate(c: &Coordinate) -> String {
    c.to_string()
}

fn severity(score: f64, kind: Option<&str>) -> String {
    // Preserve source spelling in JSON independently of human severity labels.
    format!("{} {score}", kind.unwrap_or("score"))
}

fn human_severity(score: Option<f64>, kind: Option<&str>) -> Option<String> {
    let score = score?;
    Some(match kind {
        Some("CVSS" | "CVSS_V2" | "CVSS_V3" | "CVSS_V4") => format!("CVSS {score}"),
        None | Some("" | "SEVERITY_LABEL") => format!("severity {score}"),
        Some(source) => format!("severity {score}; source: {source}"),
    })
}

impl Finding {
    pub(super) fn human_severity(&self) -> Option<String> {
        human_severity(self.severity_score, self.severity_type.as_deref())
    }
}

type IssueKey = (String, String, String, BTreeSet<String>, BTreeSet<String>);
type Issues = BTreeMap<IssueKey, Issue>;

fn add_issue(groups: &mut Issues, mut issue: Issue) {
    let key = (
        issue.check.clone(),
        issue.status.clone(),
        issue.reason.clone(),
        issue.advisories.clone(),
        issue.files.clone(),
    );
    let group = groups.entry(key).or_default();
    group.check = issue.check;
    group.status = issue.status;
    group.reason = issue.reason;
    group.advisories = issue.advisories;
    group.registries.append(&mut issue.registries);
    group.packages.append(&mut issue.packages);
    group.files.append(&mut issue.files);
    group.required_files.append(&mut issue.required_files);
    group.missing_requests.append(&mut issue.missing_requests);
}
impl View {
    pub(super) fn new(
        report: &Report,
        a: &Assessment,
        manifests: Vec<String>,
        policy: &crate::config::Audit,
    ) -> Self {
        let s = &a.summary;
        let mut view = Self {
            schema_version: 2,
            incomplete: a.incomplete,
            analysis: None,
            summary: Summary {
                dependencies: s.dependencies,
                vulnerabilities: s.vulnerabilities,
                ignored_vulnerabilities: None,
                lifecycle: s.lifecycle,
                retained_lifecycle_warnings: s.retained_lifecycle_warnings,
                outdated: s.outdated,
                duplicates: s.duplicates,
                manifest_lock_mismatches: None,
            },
            lifecycle: report.data.lifecycle.clone(),
            vulnerabilities: Vec::new(),
            outdated: Vec::new(),
            duplicates: Vec::new(),
            manifest_lock_mismatches: Vec::new(),
            issues: Vec::new(),
            manifests: manifests.into_iter().collect(),
            limitations: coverage_notices(report),
            remediation: remediation::State::Unavailable,
        };
        report::populate(&mut view, &report.data, a);
        for finding in &mut view.vulnerabilities {
            finding.ignore = finding
                .advisory
                .as_deref()
                .and_then(|id| crate::audit::ignored(policy, id))
                .cloned();
            finding.ignored = finding.ignore.is_some();
        }
        let ignored = view.vulnerabilities.iter().filter(|f| f.ignored).count();
        view.summary.ignored_vulnerabilities = (ignored != 0).then_some(ignored as u64);
        view.remediation = remediation::State::new(report, a);
        view
    }
}

fn compact_issue(mut issue: Issue) -> Issue {
    if matches!(issue.status.as_str(), "unsupported" | "not_collected")
        && issue.advisories.is_empty()
    {
        issue.package_count = Some(issue.packages.len());
        issue.packages.clear();
    }
    issue
}

fn report_issues(a: &Assessment, groups: &mut Issues) {
    for reason in &a.unverified {
        add_issue(
            groups,
            Issue {
                check: "report".into(),
                status: "unverified".into(),
                reason: (*reason).into(),
                ..Issue::default()
            },
        );
    }
}

fn coverage_issues(v: &VulnerabilityCoverage, outdated: &MetadataCoverage, groups: &mut Issues) {
    coverage_issue(
        "vulnerabilities",
        v.checked_count,
        v.candidates_count,
        v.checked_count != v.candidates_count,
        groups,
    );
    coverage_issue(
        "outdated",
        outdated.checked_count,
        outdated.candidates_count,
        crate::audit::metadata_gap(outdated),
        groups,
    );
}

fn coverage_issue(check: &str, checked: u64, total: u64, incomplete: bool, groups: &mut Issues) {
    if !incomplete {
        return;
    }
    let reason = format!("{checked} of {total} packages checked");
    add_issue(
        groups,
        Issue {
            check: check.into(),
            status: "incomplete".into(),
            reason,
            ..Issue::default()
        },
    );
}

fn coverage_notices(report: &Report) -> Vec<String> {
    let mut notices = Vec::new();
    for (check, facet) in report.data.lifecycle.coverage.facets() {
        let check = lifecycle_check(check);
        let uncollected_noun = if facet.not_collected_count == 1 {
            "dependency"
        } else {
            "dependencies"
        };
        let inapplicable_noun = if facet.not_applicable_count == 1 {
            "dependency"
        } else {
            "dependencies"
        };
        if facet.not_collected_count != 0 {
            notices.push(format!(
                "{check} was not collected for {} {uncollected_noun} ({}).",
                facet.not_collected_count,
                facet.not_collected_registries.join(", ")
            ));
        }
        if facet.not_applicable_count != 0 {
            notices.push(format!(
                "{check} does not apply to {} {inapplicable_noun} ({}); this is not a checked negative.",
                facet.not_applicable_count,
                facet.not_applicable_registries.join(", ")
            ));
        }
    }
    notices
}

pub(super) fn lifecycle_check(value: &str) -> &'static str {
    match value {
        "deprecation" => "deprecation",
        "withdrawal" => "withdrawal",
        "registry_archival" => "registry archival",
        "repository_archival" => "repository archival",
        _ => "an unfamiliar lifecycle check",
    }
}

fn lifecycle_reason(value: &str) -> &'static str {
    match value {
        "lookup_failed" => "the service could not obtain the package metadata",
        "metadata_unavailable" => "the package metadata was unavailable",
        "native_evidence_unavailable" => {
            "the stored metadata does not include the native observation needed for this check"
        }
        _ => "the service supplied no recognized explanation for this outcome",
    }
}

fn reason(value: &str) -> &str {
    crate::commands::evidence::reason(value).unwrap_or(value)
}

fn reasons(values: &[String]) -> String {
    values
        .iter()
        .map(|v| reason(v))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ")
}
