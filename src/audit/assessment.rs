//! Checks possible from compact evidence, without reconstructing an inventory.
use std::collections::BTreeSet;

use super::{Assessment, Summary, metadata_gap};
use crate::api::audit::report::{Data, Duplicate};
use crate::api::audit::wire::Coordinate;

type Warnings = BTreeSet<&'static str>;

pub(crate) fn assess(
    report: &crate::api::audit::Report,
    policy: &crate::config::Audit,
) -> Assessment {
    let r = &report.data;
    let mut unverified = Warnings::new();
    coverage(r, &mut unverified);
    counts(r, &mut unverified);
    attribution(r, &mut unverified);
    if !super::lifecycle::verified(&r.lifecycle, r.summary.dependencies) {
        unverified.insert("native lifecycle coverage or attribution is inconsistent");
    }
    if !super::remediation::verified(r) {
        unverified.insert(super::remediation::UNVERIFIED);
    }
    let incomplete = !unverified.is_empty() || has_gaps(r);
    let summary = Summary {
        dependencies: r.summary.dependencies,
        vulnerabilities: r.findings.vulnerabilities.len() as u64,
        lifecycle: r.lifecycle.findings.len() as u64,
        retained_lifecycle_warnings: r.lifecycle.retained_warnings.len() as u64,
        outdated: r.findings.outdated.len() as u64,
        duplicates: r.findings.duplicates.len() as u64,
    };
    let attention = incomplete
        || r.findings
            .vulnerabilities
            .iter()
            .any(|finding| super::ignored(policy, &finding.advisory_id).is_none())
        || summary.lifecycle != 0
        || summary.retained_lifecycle_warnings != 0
        || summary.outdated != 0
        || summary.duplicates != 0
        || !r.findings.manifest_lock_mismatches.is_empty();
    Assessment {
        summary,
        unverified,
        attention,
        incomplete,
    }
}

const fn has_gaps(r: &Data) -> bool {
    let u = &r.unknowns;
    !u.vulnerabilities.is_empty()
        || !u.metadata.is_empty()
        || !u.sources.is_empty()
        || !u.resolution.is_empty()
        || !u.excluded_dependencies.is_empty()
        || r.coverage.vulnerabilities.checked_count != r.coverage.vulnerabilities.candidates_count
        || !r.coverage.vulnerabilities.unsupported_registries.is_empty()
        || !r.lifecycle.unknowns.is_empty()
        || metadata_gap(&r.coverage.outdated)
}

fn coverage(r: &Data, warnings: &mut Warnings) {
    let v = &r.coverage.vulnerabilities;
    let total = v
        .checked_count
        .checked_add(v.unknown_count)
        .and_then(|n| n.checked_add(v.unsupported_count));
    if v.candidates_count != r.summary.dependencies || total != Some(v.candidates_count) {
        warnings.insert("vulnerability coverage does not account for eligible packages");
    }
    let c = &r.coverage.outdated;
    let total = super::metadata_total(c);
    if c.candidates_count != r.summary.dependencies || total != Some(c.candidates_count) {
        warnings.insert("metadata coverage does not account for eligible packages");
    }
}

fn counts(r: &Data, warnings: &mut Warnings) {
    let s = &r.summary;
    let f = &r.findings;
    let sources: BTreeSet<_> = r.unknowns.sources.iter().map(|g| &g.path).collect();
    let excluded: BTreeSet<_> = r
        .unknowns
        .excluded_dependencies
        .iter()
        .map(|g| (&g.name, &g.version, &g.reason))
        .collect();
    let v = &r.coverage.vulnerabilities;
    let checks = v
        .unknown_count
        .checked_add(v.unsupported_count)
        .and_then(|n| n.checked_add(r.unknowns.metadata.len() as u64))
        .and_then(|n| n.checked_add(r.lifecycle.unknowns.len() as u64));
    if s.vulnerabilities != f.vulnerabilities.len() as u64
        || s.lifecycle != r.lifecycle.findings.len() as u64
        || s.retained_lifecycle_warnings != r.lifecycle.retained_warnings.len() as u64
        || s.outdated != f.outdated.len() as u64
        || s.duplicates != f.duplicates.len() as u64
        || s.manifest_lock_mismatches
            .is_some_and(|n| n != f.manifest_lock_mismatches.len() as u64)
        || s.incomplete_sources != sources.len() as u64
        || s.excluded_dependencies != excluded.len() as u64
        || checks != Some(s.incomplete_checks)
        || sources.len() != r.unknowns.sources.len()
        || excluded.len() != r.unknowns.excluded_dependencies.len()
    {
        warnings.insert("producer summary does not match report evidence");
    }
}

pub(super) fn paths_valid(paths: &[String]) -> bool {
    !paths.is_empty()
        && paths.iter().all(|p| !p.is_empty())
        && paths.iter().collect::<BTreeSet<_>>().len() == paths.len()
}

fn attribution(r: &Data, warnings: &mut Warnings) {
    let f = &r.findings;
    let u = &r.unknowns;
    let paths = f
        .vulnerabilities
        .iter()
        .map(|x| &x.paths)
        .chain(f.outdated.iter().map(|x| &x.paths))
        .chain(u.vulnerabilities.iter().map(|x| &x.paths))
        .chain(u.metadata.iter().map(|x| &x.paths))
        .chain(u.excluded_dependencies.iter().map(|x| &x.paths));
    if paths.into_iter().any(|p| !paths_valid(p))
        || u.sources.iter().any(|x| x.path.is_empty())
        || u.resolution.iter().any(|x| x.path.is_empty())
        || f.manifest_lock_mismatches
            .iter()
            .any(|x| x.path.is_empty() || x.declaration_path.is_empty())
    {
        warnings.insert("finding or gap file attribution is empty or repeated");
    }
    if u.resolution.iter().any(|x| {
        !requirement_valid(
            x.requirement_status.as_deref(),
            x.requested_requirement.as_deref(),
        )
    }) || f.manifest_lock_mismatches.iter().any(|x| {
        !requirement_valid(
            Some(&x.requirement_status),
            x.requested_requirement.as_deref(),
        )
    }) {
        warnings.insert("native requests or declarations lack a recorded requirement");
    }
    let groups: BTreeSet<_> = f
        .duplicates
        .iter()
        .map(|d| (&d.registry, &d.name))
        .collect();
    if groups.len() != f.duplicates.len() || f.duplicates.iter().any(|d| !duplicate_valid(d)) {
        warnings.insert("duplicate versions or requesting origins have inconsistent attribution");
    }
    // The native compact report deliberately omits the full inventory.
    let mut coordinates: BTreeSet<_> = f
        .vulnerabilities
        .iter()
        .map(|x| &x.coordinate)
        .chain(f.outdated.iter().map(|x| &x.coordinate))
        .chain(u.vulnerabilities.iter().map(|x| &x.coordinate))
        .chain(u.metadata.iter().map(|x| &x.coordinate))
        .map(key)
        .collect();
    coordinates.extend(super::lifecycle::coordinates(&r.lifecycle).map(key));
    for d in &f.duplicates {
        coordinates.extend(
            d.versions
                .iter()
                .map(|v| (d.registry.as_str(), d.name.as_str(), v.version.as_str())),
        );
    }
    if coordinates.len() as u64 > r.summary.dependencies {
        warnings.insert("reported package coordinates exceed the dependency count");
    }
}

fn requirement_valid(status: Option<&str>, requirement: Option<&str>) -> bool {
    status != Some("recorded") || requirement.is_some_and(|r| !r.is_empty())
}

fn key(c: &Coordinate) -> (&str, &str, &str) {
    (&c.registry, &c.name, &c.version)
}

fn duplicate_valid(d: &Duplicate) -> bool {
    let versions: BTreeSet<_> = d.versions.iter().map(|v| &v.version).collect();
    if versions.len() < 2 || versions.len() != d.versions.len() {
        return false;
    }
    d.versions.iter().all(|v| {
        let paths: BTreeSet<_> = v.paths.iter().collect();
        let origin_paths: BTreeSet<_> = v.origins.iter().map(|o| &o.path).collect();
        paths_valid(&v.paths)
            && paths == origin_paths
            && v.origins.iter().all(|o| {
                o.status != "recorded"
                    || (o.requester.is_some()
                        && o.requested_requirement
                            .as_ref()
                            .is_some_and(|s| !s.is_empty()))
            })
    }) && d.unattributed_requirements.iter().all(|u| {
        !u.path.is_empty()
            && (u.requirement_status != "recorded"
                || u.requested_requirement
                    .as_ref()
                    .is_some_and(|s| !s.is_empty()))
    })
}
