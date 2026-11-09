//! Pure interpretation of audit evidence, never advisory or upgrade assessment.

use std::collections::{BTreeMap, BTreeSet};

use crate::api::audit::wire::{
    Coordinate, DuplicateFinding, MetadataCoverage, Occurrence, Summary as WireSummary, V1,
};

type Occurrences<'a> = BTreeMap<&'a str, &'a Occurrence>;
type Versions<'a> = BTreeMap<&'a str, BTreeSet<&'a str>>;
type Duplicates<'a> = BTreeMap<(&'a str, &'a str), Versions<'a>>;

pub(crate) mod explain;
pub(crate) mod remediation;
pub(crate) mod saved;
#[cfg(test)]
mod test_support;
mod v2;

pub(crate) struct Summary {
    pub dependencies: u64,
    pub vulnerabilities: u64,
    pub deprecated: u64,
    pub outdated: u64,
    pub duplicates: u64,
}

/// Interpret known producer versions without treating future payloads as v1/v2.
pub(crate) fn assess(
    report: &crate::api::audit::Report,
    policy: &crate::config::Audit,
) -> Option<Assessment> {
    use crate::api::audit::Body;
    match &report.body {
        Body::V1(r) => Some(assess_v1(r, policy)),
        Body::V2(r) => Some(v2::assess(r, policy)),
        Body::Future(_) => None,
    }
}

/// Only exact producer advisory IDs select local ignores; aliases stay evidence.
pub(crate) fn ignored<'a>(
    policy: &'a crate::config::Audit,
    id: &str,
) -> Option<&'a crate::config::AdvisoryIgnore> {
    policy.ignore.iter().find(|ignore| ignore.id == id)
}

pub(crate) struct Assessment {
    pub summary: Summary,
    pub unverified: BTreeSet<&'static str>,
    pub attention: bool,
    pub incomplete: bool,
}

/// Reconcile report attribution and coverage without changing producer assessments.
fn assess_v1(report: &V1, policy: &crate::config::Audit) -> Assessment {
    let occurrences: Occurrences<'_> = report
        .occurrences
        .iter()
        .map(|o| (o.id.as_str(), o))
        .collect();
    let coordinates: BTreeSet<_> = report
        .occurrences
        .iter()
        .filter_map(|o| o.coordinate.as_ref())
        .collect();
    let duplicates = duplicate_groups(report);
    let mut unverified = BTreeSet::new();
    if occurrences.len() != report.occurrences.len() || occurrences.contains_key("") {
        unverified.insert("package entry identities are empty or repeated");
    }
    check_inputs(report, &mut unverified);
    check_references(report, &occurrences, &mut unverified);
    check_sources(report, &occurrences, &mut unverified);
    check_coverage(report, coordinates.len() as u64, &mut unverified);
    if !duplicates_match(report, &duplicates) {
        unverified.insert("duplicate groups do not account for the package versions");
    }
    let v = &report.coverage.vulnerabilities;
    let summary = WireSummary {
        _additional: crate::api::audit::wire::Additional,
        dependencies: coordinates.len() as u64,
        occurrences: report.occurrences.len() as u64,
        vulnerabilities: report.findings.vulnerabilities.len() as u64,
        deprecated: report.findings.deprecated.len() as u64,
        outdated: report.findings.outdated.len() as u64,
        duplicates: duplicates.len() as u64,
        excluded_occurrences: report
            .occurrences
            .iter()
            .filter(|o| o.coordinate.is_none())
            .count() as u64,
        incomplete_sources: report
            .coverage
            .sources
            .iter()
            .filter(|s| s.state != "complete")
            .count() as u64,
        incomplete_checks: v
            .unknown_count
            .checked_add(v.unsupported_count)
            .and_then(|n| n.checked_add(report.unknowns.metadata.len() as u64))
            .unwrap_or(u64::MAX),
    };
    if summary != report.summary {
        unverified.insert("producer summary does not match report evidence");
    }
    let incomplete = has_gaps(report) || !unverified.is_empty();
    let attention = incomplete
        || report
            .findings
            .vulnerabilities
            .iter()
            .any(|finding| ignored(policy, &finding.advisory_id).is_none())
        || !report.findings.deprecated.is_empty()
        || !report.findings.outdated.is_empty()
        || !duplicates.is_empty();
    Assessment {
        summary: Summary {
            dependencies: summary.dependencies,
            vulnerabilities: summary.vulnerabilities,
            deprecated: summary.deprecated,
            outdated: summary.outdated,
            duplicates: summary.duplicates,
        },
        unverified,
        attention,
        incomplete,
    }
}

fn has_gaps(r: &V1) -> bool {
    let v = &r.coverage.vulnerabilities;
    !r.unknowns.vulnerabilities.is_empty()
        || !r.unknowns.metadata.is_empty()
        || !r.unknowns.sources.is_empty()
        || !r.unknowns.excluded_occurrences.is_empty()
        || v.checked_count != v.candidates_count
        || !v.unsupported_registries.is_empty()
        || metadata_gap(&r.coverage.deprecation)
        || metadata_gap(&r.coverage.outdated)
        || r.coverage.sources.iter().any(|s| s.state != "complete")
        || r.inputs
            .resolutions
            .iter()
            .any(|s| s.status != "complete" || !s.diagnostics.is_empty())
}

const fn metadata_gap(c: &MetadataCoverage) -> bool {
    c.checked_count != c.candidates_count || !c.not_collected_registries.is_empty()
}

fn check_coverage(r: &V1, candidates: u64, warnings: &mut BTreeSet<&'static str>) {
    let v = &r.coverage.vulnerabilities;
    let sum = v
        .checked_count
        .checked_add(v.unknown_count)
        .and_then(|n| n.checked_add(v.unsupported_count));
    if v.candidates_count != candidates || sum != Some(candidates) {
        warnings.insert("vulnerability coverage does not account for eligible packages");
    }
    for c in [&r.coverage.deprecation, &r.coverage.outdated] {
        let sum = c
            .checked_count
            .checked_add(c.unknown_count)
            .and_then(|n| n.checked_add(c.not_collected_count));
        if c.candidates_count != candidates || sum != Some(candidates) {
            warnings.insert("metadata coverage does not account for eligible packages");
        }
    }
    let excluded: BTreeSet<_> = r
        .occurrences
        .iter()
        .filter(|o| o.coordinate.is_none())
        .map(|o| o.id.as_str())
        .collect();
    let listed: BTreeSet<_> = r
        .unknowns
        .excluded_occurrences
        .iter()
        .map(|o| o.occurrence_id.as_str())
        .collect();
    if excluded != listed
        || listed.len() != r.unknowns.excluded_occurrences.len()
        || r.coverage.duplicates.candidates_count != candidates
        || r.coverage.duplicates.excluded_occurrences_count != excluded.len() as u64
    {
        warnings.insert("excluded package coverage does not match the inventory");
    }
}

fn check_sources(r: &V1, occurrences: &Occurrences<'_>, warnings: &mut BTreeSet<&'static str>) {
    let owners: BTreeSet<_> = occurrences
        .keys()
        .copied()
        .chain(r.inputs.manifests.iter().map(|m| m.id.as_str()))
        .chain(r.inputs.subjects.iter().map(|s| s.id.as_str()))
        .collect();
    let sources: BTreeMap<_, _> = r
        .coverage
        .sources
        .iter()
        .map(|s| (s.owner_id.as_str(), s))
        .collect();
    if sources.len() != r.coverage.sources.len()
        || sources.keys().any(|id| !owners.contains(id))
        || occurrences.keys().any(|id| !sources.contains_key(id))
    {
        warnings.insert("source coverage has missing, repeated or unfamiliar sources");
    }
    let incomplete: BTreeMap<_, _> = sources
        .iter()
        .filter(|(_, s)| s.state != "complete")
        .map(|(id, s)| (*id, *s))
        .collect();
    let unknown: BTreeMap<_, _> = r
        .unknowns
        .sources
        .iter()
        .map(|s| (s.owner_id.as_str(), s))
        .collect();
    if incomplete != unknown || unknown.len() != r.unknowns.sources.len() {
        warnings.insert("incomplete source evidence does not match source coverage");
    }
}

fn references_match(c: &Coordinate, ids: &[String], occurrences: &Occurrences<'_>) -> bool {
    !ids.is_empty()
        && ids.iter().all(|id| {
            occurrences
                .get(id.as_str())
                .is_some_and(|o| o.coordinate.as_ref() == Some(c))
        })
        && ids.iter().collect::<BTreeSet<_>>().len() == ids.len()
}

fn check_references(r: &V1, occurrences: &Occurrences<'_>, warnings: &mut BTreeSet<&'static str>) {
    let refs = r
        .findings
        .vulnerabilities
        .iter()
        .map(|f| (&f.coordinate, &f.occurrence_ids))
        .chain(
            r.findings
                .deprecated
                .iter()
                .map(|f| (&f.coordinate, &f.occurrence_ids)),
        )
        .chain(
            r.findings
                .outdated
                .iter()
                .map(|f| (&f.coordinate, &f.occurrence_ids)),
        )
        .chain(
            r.unknowns
                .vulnerabilities
                .iter()
                .map(|f| (&f.coordinate, &f.occurrence_ids)),
        )
        .chain(
            r.unknowns
                .metadata
                .iter()
                .map(|f| (&f.coordinate, &f.occurrence_ids)),
        );
    if refs
        .into_iter()
        .any(|(c, ids)| !references_match(c, ids, occurrences))
    {
        warnings.insert("finding or unknown attribution does not match package entries");
    }
}

fn check_inputs(r: &V1, warnings: &mut BTreeSet<&'static str>) {
    let manifests: BTreeSet<_> = r.inputs.manifests.iter().map(|m| m.path.as_str()).collect();
    let locks: BTreeSet<_> = r.inputs.lockfiles.iter().map(|l| l.path.as_str()).collect();
    let manifest_refs = r
        .inputs
        .declarations
        .iter()
        .map(|d| d.manifest_path.as_str())
        .chain(r.inputs.resolutions.iter().map(|s| s.path.as_str()))
        .chain(
            r.inputs
                .lockfiles
                .iter()
                .flat_map(|l| l.manifest_paths.iter().map(String::as_str)),
        )
        .chain(
            r.occurrences
                .iter()
                .flat_map(|o| o.resolution_manifest_paths.iter().map(String::as_str)),
        )
        .chain(r.inputs.manifest_associations.keys().map(String::as_str));
    let lock_refs = r
        .occurrences
        .iter()
        .filter_map(|o| o.lockfile_path.as_deref())
        .chain(r.inputs.subjects.iter().map(|s| s.lockfile_path.as_str()))
        .chain(
            r.inputs
                .manifest_associations
                .values()
                .flatten()
                .map(String::as_str),
        );
    if manifest_refs.into_iter().any(|p| !manifests.contains(p))
        || lock_refs.into_iter().any(|p| !locks.contains(p))
    {
        warnings.insert("input file attribution refers to absent files");
    }
}

fn duplicate_groups(r: &V1) -> Duplicates<'_> {
    let mut groups: Duplicates<'_> = BTreeMap::new();
    for o in &r.occurrences {
        let Some(c) = &o.coordinate else {
            continue;
        };
        groups
            .entry((&c.registry, &c.name))
            .or_default()
            .entry(&c.version)
            .or_default()
            .insert(&o.id);
    }
    groups.retain(|_, versions| versions.len() > 1);
    groups
}

fn duplicates_match(r: &V1, expected: &Duplicates<'_>) -> bool {
    let mut listed: Duplicates<'_> = BTreeMap::new();
    for group in &r.findings.duplicates {
        let Some(versions) = listed_versions(group) else {
            return false;
        };
        if listed
            .insert((&group.registry, &group.name), versions)
            .is_some()
        {
            return false;
        }
    }
    listed == *expected
}

fn listed_versions(group: &DuplicateFinding) -> Option<Versions<'_>> {
    let mut versions = BTreeMap::new();
    for version in &group.versions {
        let ids: BTreeSet<_> = version.occurrence_ids.iter().map(String::as_str).collect();
        if ids.len() != version.occurrence_ids.len()
            || versions.insert(version.version.as_str(), ids).is_some()
        {
            return None;
        }
    }
    Some(versions)
}

#[cfg(test)]
mod tests;
