//! Consistency of supplied native evidence; never registry classification.
use std::collections::BTreeSet;

use crate::api::audit::lifecycle::{Event, Facet, Lifecycle, Observation};
use crate::api::audit::wire::Coordinate;

use super::assessment::paths_valid;

pub(super) fn coordinates(data: &Lifecycle) -> impl Iterator<Item = &Coordinate> {
    data.findings
        .iter()
        .flat_map(|e| &e.observations)
        .flat_map(|o| &o.affected)
        .map(|r| &r.coordinate)
        .chain(data.retained_warnings.iter().map(|w| &w.coordinate))
        .chain(data.unknowns.iter().map(|u| &u.coordinate))
}

pub(super) fn verified(data: &Lifecycle, dependencies: u64) -> bool {
    facets_valid(data, dependencies)
        && events_valid(data)
        && warnings_valid(data)
        && data.unknowns.iter().all(|u| paths_valid(&u.paths))
}

fn facets_valid(data: &Lifecycle, dependencies: u64) -> bool {
    let mut unknowns = BTreeSet::new();
    if !data
        .unknowns
        .iter()
        .all(|u| unknowns.insert((&u.check, &u.coordinate)))
    {
        return false;
    }
    data.coverage.facets().into_iter().all(|(name, facet)| {
        let count = data.unknowns.iter().filter(|u| u.check == name).count() as u64;
        facet_valid(facet, dependencies, count)
    })
}

fn facet_valid(f: &Facet, dependencies: u64, unknowns: u64) -> bool {
    let total = f
        .checked_count
        .checked_add(f.unknown_count)
        .and_then(|n| n.checked_add(f.not_collected_count))
        .and_then(|n| n.checked_add(f.not_applicable_count));
    f.candidates_count == dependencies
        && total == Some(dependencies)
        && f.unknown_count == unknowns
        && registry_list_valid(f.not_collected_count, &f.not_collected_registries)
        && registry_list_valid(f.not_applicable_count, &f.not_applicable_registries)
}

fn registry_list_valid(count: u64, registries: &[String]) -> bool {
    (count == 0) == registries.is_empty()
        && registries.iter().collect::<BTreeSet<_>>().len() == registries.len()
}

fn events_valid(data: &Lifecycle) -> bool {
    let mut events = BTreeSet::new();
    data.findings.iter().all(|e| {
        events.insert((
            &e.registry,
            &e.name,
            &e.version,
            &e.category,
            &e.kind,
            &e.scope,
            &e.source,
        )) && event_valid(e)
    })
}

fn event_valid(e: &Event) -> bool {
    let version_valid = match e.scope.as_str() {
        "package" => e.version.is_none(),
        "release" | "files" => e.version.is_some(),
        _ => true,
    };
    let mut observations = BTreeSet::new();
    version_valid
        && !e.observations.is_empty()
        && e.observations.iter().all(|o| {
            observations.insert((
                &o.source_version,
                &o.observed_at,
                &o.reason,
                &o.replacement,
                &o.reason_codes,
            )) && observation_valid(o)
        })
}

fn observation_valid(o: &Observation) -> bool {
    let mut coordinates = BTreeSet::new();
    !o.affected.is_empty()
        && o.affected
            .iter()
            .all(|r| coordinates.insert(&r.coordinate) && paths_valid(&r.paths))
}

fn warnings_valid(data: &Lifecycle) -> bool {
    let mut warnings = BTreeSet::new();
    data.retained_warnings.iter().all(|w| {
        warnings.insert((&w.coordinate, &w.paths, &w.classification, &w.reason))
            && paths_valid(&w.paths)
    })
}
