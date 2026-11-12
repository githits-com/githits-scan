//! Owner-local interpretation of exhaustive expected coverage causes, without changing facts.
use std::collections::{BTreeMap, BTreeSet};
use std::io;

use crate::api::diff::view::{self, View};
use crate::coverage::{exclusions_only, expected_git, git_only};

pub(super) fn gap_is_git(row: &view::Gap) -> bool {
    let reasons: Vec<_> = row.reason.iter().chain(&row.reasons).cloned().collect();
    git_only(&reasons)
}

pub(super) fn gap_is_expected(row: &view::Gap, exclusion: bool) -> bool {
    let reasons: Vec<_> = row.reason.iter().chain(&row.reasons).cloned().collect();
    if exclusion {
        exclusions_only(&reasons)
    } else {
        git_only(&reasons)
    }
}

pub(super) fn scope_is_expected(c: &view::ScopeCoverage) -> bool {
    (c.inventory == "complete"
        || (c.inventory == "partial"
            && c.reasons.as_ref().is_some_and(|r| {
                git_only(r)
                    || r.iter()
                        .any(|cause| cause == "git_dependency_graph_unavailable")
            })))
        && matches!(c.assessment.as_str(), "complete" | "partial")
        && c.checked == c.coordinates
        && c.reasons.as_ref().is_some_and(|r| exclusions_only(r))
}

pub(super) fn delta_is_expected(e: &view::Exposure, row: &view::Delta) -> bool {
    if row.kind == "indeterminate" && row.base.reasons.is_empty() && row.head.reasons.is_empty() {
        return false;
    }
    [
        (e.coverage.base.as_ref(), &row.base),
        (e.coverage.head.as_ref(), &row.head),
    ]
    .iter()
    .all(|(coverage, assessment)| {
        matches!(
            assessment.status.as_str(),
            "affected" | "non_affecting" | "unknown"
        ) && (assessment.status != "unknown" || !assessment.reasons.is_empty())
            && assessment
                .reasons
                .iter()
                .all(|r| r == "source_scope_incomplete" && coverage.is_some_and(scope_is_expected))
    })
}

fn coverage_is_expected(c: &view::Coverage, v: &View) -> bool {
    c.mismatches.is_empty()
        && c.reachability
            .iter()
            .all(|r| r.complete || root_is_git(r, v))
        && [&c.sources, &c.resolution]
            .iter()
            .all(|rows| rows.iter().all(gap_is_git))
        && c.excluded_dependencies
            .iter()
            .all(|r| gap_is_expected(r, true))
}

pub(super) fn informational_only(v: &View) -> io::Result<bool> {
    if v.outcome != "partial" || v.snapshots.iter().any(|(side, s)| side != s.side) {
        return Ok(false);
    }
    let top: view::Coverage = serde_json::from_str(v.coverage.get()).map_err(io::Error::other)?;
    let base: view::Coverage =
        serde_json::from_str(v.snapshots.base.coverage.get()).map_err(io::Error::other)?;
    let head: view::Coverage =
        serde_json::from_str(v.snapshots.head.coverage.get()).map_err(io::Error::other)?;
    if unexplained_partial(&base, &head, &top).is_some()
        || ![&base, &head, &top]
            .iter()
            .all(|c| coverage_is_expected(c, v))
        || !reviews_complete(v)?
    {
        return Ok(false);
    }
    if !matches!(v.advisories.status.as_str(), "complete" | "partial")
        || v.advisories.reason.is_some()
    {
        return Ok(false);
    }
    let Some(raw) = &v.advisories.coverage else {
        return Ok(false);
    };
    let c: view::AdvisoryCoverage = serde_json::from_str(raw.get()).map_err(io::Error::other)?;
    if c.checked.is_none()
        || c.checked != c.coordinates
        || c.unknown != Some(0)
        || c.unsupported != Some(0)
        || !c.reasons.as_ref().is_some_and(|r| exclusions_only(r))
    {
        return Ok(false);
    }
    let Some(data) = v
        .advisories
        .decode::<view::Advisories>()
        .map_err(io::Error::other)?
    else {
        return Ok(false);
    };
    Ok(data
        .coordinate_transitions
        .iter()
        .all(|t| transition_is_expected(v, &data, t))
        && data.exposures.iter().all(exposure_is_expected))
}

pub(super) fn transition_is_expected(
    v: &View,
    data: &view::Advisories,
    t: &view::Transition,
) -> bool {
    let changes: Vec<_> = v.changes.iter().filter(|c| c.id == t.change_id).collect();
    let [change] = changes.as_slice() else {
        return false;
    };
    let owners: Vec<_> = data
        .exposures
        .iter()
        .filter(|e| {
            e.scope.kind == "source" && e.scope.source_key.as_deref() == Some(&change.source_key)
        })
        .collect();
    t.deltas.iter().all(|d| {
        if d.base.reasons.is_empty() && d.head.reasons.is_empty() {
            return matches!(
                d.kind.as_str(),
                "introduced" | "fixed" | "unchanged" | "non_affecting"
            );
        }
        let [owner] = owners.as_slice() else {
            return false;
        };
        delta_is_expected(owner, d)
    })
}

fn exposure_is_expected(e: &view::Exposure) -> bool {
    e.coverage.base.is_some()
        && e.coverage.head.is_some()
        && e.coverage.iter().all(|(_, c)| {
            scope_is_expected(c)
                || (c.inventory == "complete"
                    && c.assessment == "complete"
                    && c.checked == c.coordinates
                    && c.unqualified_occurrences == Some(0)
                    && c.reasons.as_ref().is_none_or(Vec::is_empty))
        })
        && e.deltas.iter().all(|d| {
            matches!(
                d.kind.as_str(),
                "introduced" | "fixed" | "unchanged" | "non_affecting" | "indeterminate"
            ) && delta_is_expected(e, d)
        })
}

fn reviews_complete(v: &View) -> io::Result<bool> {
    if v.direct_reviews.status != "complete" || v.direct_reviews.reason.is_some() {
        return Ok(false);
    }
    let Some(raw) = &v.direct_reviews.coverage else {
        return Ok(false);
    };
    let c: view::ReviewCoverage = serde_json::from_str(raw.get()).map_err(io::Error::other)?;
    let rows = v
        .direct_reviews
        .decode::<Vec<view::Review>>()
        .map_err(io::Error::other)?;
    Ok(c.eligible == c.completed
        && c.completed == c.returned
        && c.not_assessed == 0
        && c.unavailable == 0
        && c.omitted == 0
        && rows.is_some_and(|r| {
            r.len() as u64 == c.returned && r.iter().all(|r| r.status == "complete")
        }))
}

// This phase is shared by headline qualification and the missing-details explanation.
pub(super) fn unexplained_partial(
    base: &view::Coverage,
    head: &view::Coverage,
    report: &view::Coverage,
) -> Option<&'static str> {
    let before = base.partial == Some(true) && !has_details(base);
    let after = head.partial == Some(true) && !has_details(head);
    match (before, after) {
        (true, true) => Some("both"),
        (true, false) => Some("base"),
        (false, true) => Some("head"),
        (false, false)
            if report.partial == Some(true)
                && ![base, head, report].iter().any(|c| has_details(c)) =>
        {
            Some("Report")
        }
        _ => None,
    }
}

fn has_details(c: &view::Coverage) -> bool {
    [
        &c.sources,
        &c.resolution,
        &c.excluded_dependencies,
        &c.mismatches,
    ]
    .iter()
    .any(|rows| !rows.is_empty())
        || c.reachability.iter().any(|r| !r.complete)
}

pub(super) fn notes(v: &View) -> io::Result<BTreeMap<String, BTreeSet<String>>> {
    let mut result = BTreeMap::<_, BTreeSet<String>>::new();
    if matches!(v.advisories.status.as_str(), "complete" | "partial")
        && let Some(raw) = &v.advisories.coverage
    {
        let c: view::AdvisoryCoverage =
            serde_json::from_str(raw.get()).map_err(io::Error::other)?;
        for note in c
            .reasons
            .iter()
            .flatten()
            .filter_map(|r| crate::coverage::exclusion_note(r))
        {
            result.entry(note.into()).or_default();
        }
    }
    for raw in std::iter::once(&v.coverage).chain(v.snapshots.iter().map(|(_, s)| &s.coverage)) {
        let c: view::Coverage = serde_json::from_str(raw.get()).map_err(io::Error::other)?;
        for row in c.sources.iter().chain(&c.resolution) {
            add_gap_notes(row, &mut result);
        }
        for row in &c.excluded_dependencies {
            add_exclusion_notes(row, &mut result);
        }
    }
    Ok(result)
}

fn add_exclusion_notes(row: &view::Gap, notes: &mut BTreeMap<String, BTreeSet<String>>) {
    add_gap_notes(row, notes);
    if !row
        .reason
        .iter()
        .chain(&row.reasons)
        .any(|r| r == "non_registry_source")
    {
        return;
    }
    notes.remove(crate::coverage::NON_REGISTRY_NOTE);
    let name = row
        .name
        .as_deref()
        .unwrap_or("A dependency whose name was not supplied");
    let version = row
        .version
        .as_ref()
        .map_or(String::new(), |v| format!(" {v}"));
    notes.entry(format!("{name}{version} comes from outside a public package registry and is excluded from registry vulnerability and update checks."))
        .or_default().extend(row.path.iter().chain(&row.paths).cloned());
}

fn add_gap_notes(row: &view::Gap, notes: &mut BTreeMap<String, BTreeSet<String>>) {
    for note in row
        .reason
        .iter()
        .chain(&row.reasons)
        .filter_map(|r| crate::coverage::note(r))
    {
        notes
            .entry(note.into())
            .or_default()
            .extend(row.path.iter().chain(&row.paths).cloned());
    }
}

pub(super) fn actionable_reason(reason: &str, exclusion: bool) -> bool {
    !(if exclusion {
        crate::coverage::expected_exclusion(reason)
    } else {
        expected_git(reason)
    })
}

// Summary rows do not carry causes: join only their exact owner-scoped proof.
pub(super) fn root_is_git(row: &view::ReachabilityGap, v: &View) -> bool {
    let Some(id) = row.reachability_id.as_deref() else {
        return false;
    };
    let proofs: Vec<_> = v
        .snapshots
        .iter()
        .flat_map(|(_, s)| &s.reachability)
        .filter(|p| p.id.as_deref() == Some(id))
        .collect();
    let [proof] = proofs.as_slice() else {
        return false;
    };
    proof.manifest_path.as_deref() == Some(&row.manifest_path)
        && proof.source_key.as_deref() == Some(&row.source_key)
        && !proof.reasons.is_empty()
        && proof.reasons.iter().all(cause_is_git)
}

pub(super) fn cause_is_git(cause: &view::Cause) -> bool {
    expected_git(&cause.code)
        || (cause.code == "root_dependency_coverage_incomplete"
            && git_only(&cause.coverage_reasons))
}
