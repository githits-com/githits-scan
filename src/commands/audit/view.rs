//! Focused command results shared by human and JSON output, without wire telemetry.
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::api::audit::v2::{ManifestLockMismatch, NativeConditions};
use crate::api::audit::{
    Body, Report,
    wire::{Coordinate, MetadataCoverage, V1, VulnerabilityCoverage},
};
use crate::audit::Assessment;

pub(super) mod remediation;
mod v2;

#[derive(Serialize)]
pub(super) struct View {
    schema_version: u8,
    pub incomplete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<crate::audit::saved::Provenance>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub resolved_from_manifests: BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<Summary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deprecated: Vec<Finding>,
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
    pub deprecated: u64,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    // Schema 1's legacy JSON string keeps its spelling independently of human labels.
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

type Locations = BTreeMap<String, (String, BTreeSet<String>)>;
type IssueKey = (String, String, String, BTreeSet<String>, BTreeSet<String>);
type Issues = BTreeMap<IssueKey, Issue>;

fn locations(r: &V1) -> Locations {
    let mut locations = Locations::new();
    for o in &r.occurrences {
        let name = o.coordinate.as_ref().map_or_else(
            || {
                o.version
                    .as_ref()
                    .map_or_else(|| o.name.clone(), |v| format!("{}@{v}", o.name))
            },
            coordinate,
        );
        let files = o
            .lockfile_path
            .iter()
            .chain(&o.resolution_manifest_paths)
            .cloned()
            .collect();
        locations.insert(o.id.clone(), (name, files));
    }
    for m in &r.inputs.manifests {
        locations.insert(
            m.id.clone(),
            (m.name.clone(), BTreeSet::from([m.path.clone()])),
        );
    }
    for s in &r.inputs.subjects {
        locations.insert(
            s.id.clone(),
            (s.name.clone(), BTreeSet::from([s.lockfile_path.clone()])),
        );
    }
    locations
}
fn files(ids: &[String], locations: &Locations) -> BTreeSet<String> {
    ids.iter()
        .filter_map(|id| locations.get(id))
        .flat_map(|(_, files)| files.iter().cloned())
        .collect()
}
fn finding(c: &Coordinate, ids: &[String], locations: &Locations) -> Finding {
    Finding {
        package: coordinate(c),
        files: files(ids, locations),
        ..Finding::default()
    }
}
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
fn owner_issue(
    check: &str,
    status: &str,
    reason: String,
    id: &str,
    locations: &Locations,
) -> Issue {
    let mut issue = Issue {
        check: check.into(),
        status: status.into(),
        reason,
        ..Issue::default()
    };
    if let Some((name, paths)) = locations.get(id) {
        issue.packages.insert(name.clone());
        issue.files.clone_from(paths);
    }
    issue
}

impl View {
    pub(super) fn new(
        report: &Report,
        assessment: Option<&Assessment>,
        manifests: Vec<String>,
    ) -> Self {
        let mut view = Self {
            schema_version: 1,
            incomplete: false,
            analysis: None,
            resolved_from_manifests: BTreeSet::new(),
            summary: None,
            vulnerabilities: Vec::new(),
            deprecated: Vec::new(),
            outdated: Vec::new(),
            duplicates: Vec::new(),
            manifest_lock_mismatches: Vec::new(),
            issues: Vec::new(),
            manifests: BTreeSet::new(),
            limitations: Vec::new(),
            remediation: remediation::State::Unavailable,
        };
        let Some(a) = assessment else {
            view.incomplete = true;
            view.issues.push(Issue {
                check: "report".into(),
                status: "unsupported".into(),
                reason: format!(
                    "Audit API schema version {} is not supported",
                    report.version()
                ),
                ..Issue::default()
            });
            return view;
        };
        view.manifests = manifests.into_iter().collect();
        view.incomplete = a.incomplete;
        let s = &a.summary;
        view.summary = Some(Summary {
            dependencies: s.dependencies,
            vulnerabilities: s.vulnerabilities,
            deprecated: s.deprecated,
            outdated: s.outdated,
            duplicates: s.duplicates,
            manifest_lock_mismatches: None,
        });
        match &report.body {
            Body::V1(r) => view.populate_v1(r, a),
            Body::V2(r) => v2::populate(&mut view, r, a),
            Body::Future(_) => (),
        }
        view.remediation = remediation::State::new(report, a);
        view
    }

    fn populate_v1(&mut self, r: &V1, a: &Assessment) {
        let view = self;
        view.resolved_from_manifests = r
            .occurrences
            .iter()
            .flat_map(|o| o.resolution_manifest_paths.iter().cloned())
            .collect();
        let locations = locations(r);
        for f in &r.findings.vulnerabilities {
            let mut item = finding(&f.coordinate, &f.occurrence_ids, &locations);
            item.advisory = Some(f.advisory_id.clone());
            item.title = f.summary.clone().filter(|s| !s.is_empty());
            item.severity = f
                .severity_score
                .map(|score| severity(score, f.severity_type.as_deref()));
            item.severity_score = f.severity_score;
            item.severity_type.clone_from(&f.severity_type);
            item.aliases.clone_from(&f.aliases);
            item.proposed_fixes.clone_from(&f.fixed_in_versions);
            item.verified_advisory_fixes
                .clone_from(&f.verified_remedies);
            item.malicious = f.malicious;
            view.vulnerabilities.push(item);
        }
        for f in &r.findings.deprecated {
            let mut item = finding(&f.coordinate, &f.occurrence_ids, &locations);
            item.reason = Some(f.reason.clone());
            view.deprecated.push(item);
        }
        for f in &r.findings.outdated {
            let mut item = finding(&f.coordinate, &f.occurrence_ids, &locations);
            item.latest = Some(f.latest_version.clone());
            item.change = Some(f.change_type.clone());
            view.outdated.push(item);
        }
        for f in &r.findings.duplicates {
            view.duplicates.push(Duplicate {
                package: format!("{}:{}", f.registry, f.name),
                versions: f
                    .versions
                    .iter()
                    .map(|v| DuplicateVersion {
                        version: v.version.clone(),
                        files: files(&v.occurrence_ids, &locations),
                        origins: BTreeSet::new(),
                    })
                    .collect(),
                unattributed_requirements: BTreeSet::new(),
            });
        }
        view.issues = issues(r, a, &locations)
            .into_values()
            .map(compact_issue)
            .collect();
        if !view.duplicates.is_empty() {
            view.limitations.push(
                "Required ranges and requesting dependencies are not provided by this API.".into(),
            );
        }
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

fn issues(r: &V1, a: &Assessment, locations: &Locations) -> Issues {
    let mut groups = Issues::new();
    report_issues(a, &mut groups);
    for f in &r.unknowns.vulnerabilities {
        add_issue(
            &mut groups,
            Issue {
                check: f.check.clone(),
                status: f.status.clone(),
                reason: reasons(&f.reasons),
                packages: BTreeSet::from([coordinate(&f.coordinate)]),
                registries: BTreeSet::from([f.coordinate.registry.clone()]),
                files: files(&f.occurrence_ids, locations),
                advisories: f.advisory_ids.iter().cloned().collect(),
                ..Issue::default()
            },
        );
    }
    for f in &r.unknowns.metadata {
        add_issue(
            &mut groups,
            Issue {
                check: f.check.clone(),
                status: f.status.clone(),
                reason: f
                    .reason
                    .as_deref()
                    .map_or_else(String::new, |r| reason(r).into()),
                packages: BTreeSet::from([coordinate(&f.coordinate)]),
                registries: BTreeSet::from([f.coordinate.registry.clone()]),
                files: files(&f.occurrence_ids, locations),
                ..Issue::default()
            },
        );
    }
    for s in r
        .coverage
        .sources
        .iter()
        .chain(&r.unknowns.sources)
        .filter(|s| s.state != "complete")
    {
        add_issue(
            &mut groups,
            owner_issue(
                "dependency information",
                &s.state,
                reasons(&s.reasons),
                &s.owner_id,
                locations,
            ),
        );
    }
    for f in &r.unknowns.excluded_occurrences {
        add_issue(
            &mut groups,
            owner_issue(
                "package checks",
                "excluded",
                reason(&f.reason).into(),
                &f.occurrence_id,
                locations,
            ),
        );
    }
    resolution_issues(r, &mut groups);
    coverage_issues(
        &r.coverage.vulnerabilities,
        &r.coverage.deprecation,
        &r.coverage.outdated,
        &mut groups,
    );
    groups
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

fn resolution_issues(r: &V1, groups: &mut Issues) {
    for resolution in r
        .inputs
        .resolutions
        .iter()
        .filter(|s| s.status != "complete" || !s.diagnostics.is_empty())
    {
        if resolution.diagnostics.is_empty() {
            add_issue(
                groups,
                Issue {
                    check: "resolution".into(),
                    status: resolution.status.clone(),
                    files: BTreeSet::from([resolution.path.clone()]),
                    ..Issue::default()
                },
            );
        }
        for d in &resolution.diagnostics {
            add_issue(
                groups,
                Issue {
                    check: "resolution".into(),
                    status: resolution.status.clone(),
                    reason: reason(&d.reason).into(),
                    packages: BTreeSet::from([d.name.clone()]),
                    files: BTreeSet::from([resolution.path.clone()]),
                    ..Issue::default()
                },
            );
        }
    }
}

fn coverage_issues(
    v: &VulnerabilityCoverage,
    deprecation: &MetadataCoverage,
    outdated: &MetadataCoverage,
    groups: &mut Issues,
) {
    let checks = [
        ("vulnerabilities", v.checked_count, v.candidates_count),
        (
            "deprecation",
            deprecation.checked_count,
            deprecation.candidates_count,
        ),
        (
            "outdated",
            outdated.checked_count,
            outdated.candidates_count,
        ),
    ];
    for (check, checked, total) in checks {
        if checked != total {
            add_issue(
                groups,
                Issue {
                    check: check.into(),
                    status: "incomplete".into(),
                    reason: format!("{checked} of {total} packages checked"),
                    ..Issue::default()
                },
            );
        }
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
