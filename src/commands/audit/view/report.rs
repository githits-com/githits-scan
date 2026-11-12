//! Native compact report projection; only useful evidence enters the shared output.
use std::collections::BTreeSet;

use super::{
    Duplicate, DuplicateVersion, Finding, Issue, Issues, MissingRequest, Origin, Unattributed,
    View, add_issue, compact_issue, coordinate, coverage_issues, reason, reasons, report_issues,
};
use crate::api::audit::report::{Data, Requester, ResolutionGap, SourceGap};
use crate::api::audit::wire::Coordinate;
use crate::audit::Assessment;
use crate::coverage::{self, Attention};

pub(super) fn populate(view: &mut View, r: &Data, a: &Assessment) {
    for f in &r.findings.vulnerabilities {
        let mut item = finding(&f.coordinate, &f.paths);
        item.advisory = Some(f.advisory_id.clone());
        item.title = f.summary.clone().filter(|s| !s.is_empty());
        item.severity = f
            .severity_score
            .map(|score| super::severity(score, f.severity_type.as_deref()));
        item.severity_score = f.severity_score;
        item.severity_type.clone_from(&f.severity_type);
        item.aliases.clone_from(&f.aliases);
        item.proposed_fixes.clone_from(&f.fixed_in_versions);
        item.verified_advisory_fixes
            .clone_from(&f.verified_remedies);
        item.malicious = f.malicious;
        view.vulnerabilities.push(item);
    }
    for f in &r.findings.outdated {
        let mut item = finding(&f.coordinate, &f.paths);
        item.latest = Some(f.latest_version.clone());
        item.change = Some(f.change_type.clone());
        view.outdated.push(item);
    }
    for d in &r.findings.duplicates {
        view.duplicates.push(Duplicate {
            package: format!("{}:{}", d.registry, d.name),
            versions: d
                .versions
                .iter()
                .map(|v| DuplicateVersion {
                    version: v.version.clone(),
                    files: v.paths.iter().cloned().collect(),
                    origins: v
                        .origins
                        .iter()
                        .map(|o| Origin {
                            file: o.path.clone(),
                            requester: o.requester.as_ref().map(requester),
                            requested_requirement: o.requested_requirement.clone(),
                            status: o.status.clone(),
                            attribution_basis: o.attribution_basis.clone(),
                        })
                        .collect(),
                })
                .collect(),
            unattributed_requirements: d
                .unattributed_requirements
                .iter()
                .map(|u| Unattributed {
                    file: u.path.clone(),
                    requester: requester(&u.requester),
                    requested_requirement: u.requested_requirement.clone(),
                    requirement_status: u.requirement_status.clone(),
                    target_status: u.target_status.clone(),
                })
                .collect(),
        });
    }
    view.manifest_lock_mismatches
        .clone_from(&r.findings.manifest_lock_mismatches);
    view.summary.manifest_lock_mismatches =
        (!view.manifest_lock_mismatches.is_empty()).then_some(view.manifest_lock_mismatches.len());
    view.issues = issues(r, a).into_values().map(compact_issue).collect();
}

fn requester(r: &Requester) -> String {
    r.version
        .as_ref()
        .map_or_else(|| r.name.clone(), |v| format!("{}@{v}", r.name))
}

fn finding(c: &Coordinate, paths: &[String]) -> Finding {
    Finding {
        package: coordinate(c),
        files: paths.iter().cloned().collect(),
        ..Finding::default()
    }
}

fn issues(r: &Data, a: &Assessment) -> Issues {
    let mut groups = Issues::new();
    report_issues(a, &mut groups);
    for g in &r.unknowns.vulnerabilities {
        add_issue(
            &mut groups,
            Issue {
                check: g.check.clone(),
                status: g.status.clone(),
                reason: reasons(&g.reasons),
                packages: BTreeSet::from([coordinate(&g.coordinate)]),
                registries: BTreeSet::from([g.coordinate.registry.clone()]),
                files: g.paths.iter().cloned().collect(),
                advisories: g.advisory_ids.iter().cloned().collect(),
                ..Issue::default()
            },
        );
    }
    for g in &r.unknowns.metadata {
        add_issue(
            &mut groups,
            Issue {
                check: g.check.clone(),
                status: g.status.clone(),
                reason: g
                    .reason
                    .as_deref()
                    .map_or_else(String::new, |s| reason(s).into()),
                packages: BTreeSet::from([coordinate(&g.coordinate)]),
                registries: BTreeSet::from([g.coordinate.registry.clone()]),
                files: g.paths.iter().cloned().collect(),
                ..Issue::default()
            },
        );
    }
    for g in &r.unknowns.sources {
        source_gap(g, &mut groups);
    }
    for g in &r.unknowns.resolution {
        let source = r.unknowns.sources.iter().find(|s| {
            (g.name.is_none() || (g.reason == "unmet_dependency" && g.requester.is_some()))
                && s.path == g.path
                && s.reasons.contains(&g.reason)
                && (!coverage::expected_git(&g.reason) || s.reasons.len() == 1)
                && s.reasons
                    .iter()
                    .all(|r| coverage::attention(r) == coverage::attention(&g.reason))
        });
        let (check, diagnostic) = source.map_or_else(
            || ("resolution", reason(&g.reason).into()),
            |s| ("dependency information", reasons(&s.reasons)),
        );
        let missing = missing_request(g);
        add_issue(
            &mut groups,
            Issue {
                attention: coverage::attention(&g.reason),
                check: check.into(),
                status: "incomplete".into(),
                reason: diagnostic,
                required_files: g.required_path.iter().cloned().collect(),
                packages: if missing.is_some() {
                    BTreeSet::new()
                } else {
                    g.name.iter().cloned().collect()
                },
                missing_requests: missing.into_iter().collect(),
                files: BTreeSet::from([g.path.clone()]),
                ..Issue::default()
            },
        );
    }
    for g in &r.unknowns.excluded_dependencies {
        let package = g
            .version
            .as_ref()
            .map_or_else(|| g.name.clone(), |v| format!("{}@{v}", g.name));
        add_issue(
            &mut groups,
            Issue {
                attention: coverage::exclusion_attention(&g.reason),
                check: "package checks".into(),
                status: "excluded".into(),
                reason: coverage::exclusion_note(&g.reason)
                    .unwrap_or_else(|| reason(&g.reason))
                    .into(),
                packages: BTreeSet::from([package]),
                files: g.paths.iter().cloned().collect(),
                ..Issue::default()
            },
        );
    }
    lifecycle_issues(&r.lifecycle, &mut groups);
    coverage_issues(
        &r.coverage.vulnerabilities,
        &r.coverage.outdated,
        &mut groups,
    );
    groups
}

fn source_gap(g: &SourceGap, groups: &mut Issues) {
    let (informational, actionable): (Vec<_>, Vec<_>) = g
        .reasons
        .iter()
        .cloned()
        .partition(|r| coverage::expected_git(r));
    let mut rows: Vec<_> = informational
        .iter()
        .map(|r| (Attention::Informational, reason(r).to_owned()))
        .collect();
    if !actionable.is_empty() || g.reasons.is_empty() {
        rows.push((Attention::Actionable, reasons(&actionable)));
    }
    for (attention, reason) in rows {
        add_issue(
            groups,
            Issue {
                attention,
                check: "dependency information".into(),
                status: "incomplete".into(),
                reason,
                files: BTreeSet::from([g.path.clone()]),
                ..Issue::default()
            },
        );
    }
}

fn lifecycle_issues(data: &crate::api::audit::lifecycle::Lifecycle, groups: &mut Issues) {
    for g in &data.unknowns {
        add_issue(
            groups,
            Issue {
                check: super::lifecycle_check(&g.check).into(),
                status: "unknown".into(),
                reason: super::lifecycle_reason(&g.reason).into(),
                packages: BTreeSet::from([coordinate(&g.coordinate)]),
                registries: BTreeSet::from([g.coordinate.registry.clone()]),
                files: g.paths.iter().cloned().collect(),
                ..Issue::default()
            },
        );
    }
}

fn missing_request(g: &ResolutionGap) -> Option<MissingRequest> {
    if g.reason != "unmet_dependency" {
        return None;
    }
    Some(MissingRequest {
        name: g.name.clone()?,
        requester: requester(g.requester.as_ref()?),
        requested_requirement: g.requested_requirement.clone(),
        requirement_status: g.requirement_status.clone(),
        kind: g.kind.clone(),
        requester_scope: g.requester_scope.clone(),
        conditions: g.context.clone().filter(|c| !c.is_empty()),
    })
}
