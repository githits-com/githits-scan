//! Source-local request context for a joint action, never causal planner reasoning.
use std::collections::BTreeSet;

use crate::api::audit::{
    remediation::{Change, Recommendation, Trace},
    trace,
    wire::Coordinate,
};

/// A supplied request attached to a validated relationship between changed occurrences.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RecordedRequest {
    /// Actual request owner, which need not equal the relationship's source occurrence.
    pub owner_name: String,
    /// Supplied owner version, preserving an unknown version separately.
    pub owner_version: Option<String>,
    /// Canonical coordinate of the relationship's recorded target occurrence.
    pub target: Coordinate,
    /// Recorded request value, without matching it against any target release.
    pub requirement: String,
    /// Authored request location; it can differ from the relationship's lockfile.
    pub path: String,
}

/// Select current requests for a joint action without guessing its causal reason.
pub(crate) fn recorded_requests(
    trace: &Trace,
    recommendation: &Recommendation,
) -> Vec<RecordedRequest> {
    if trace.status != "retained"
        || recommendation.detail_status != "retained"
        || recommendation.changes.len() < 2
    {
        return Vec::new();
    }
    let changed: BTreeSet<_> = recommendation
        .changes
        .iter()
        .flat_map(|change| matching_refs(trace, change))
        .collect();
    let mut seen = BTreeSet::new();
    trace
        .relations
        .iter()
        .filter(|r| {
            r.disposition == "standard_dependency" && super::relation_issue(trace, r).is_none()
        })
        .filter(|r| {
            r.from_ref.is_some_and(|i| changed.contains(&i))
                && r.to_ref.is_some_and(|i| changed.contains(&i))
        })
        .flat_map(|r| {
            r.requests
                .iter()
                .filter_map(|request| recorded_request(trace, r, request))
        })
        .filter(|r| seen.insert(r.clone()))
        .collect()
}

fn matching_refs<'a>(trace: &'a Trace, change: &'a Change) -> impl Iterator<Item = usize> + 'a {
    change
        .occurrence_refs
        .iter()
        .flatten()
        .filter_map(|&index| {
            let Coordinate {
                registry,
                name,
                version,
                ..
            } = trace.occurrences.get(index)?.coordinate.as_ref()?;
            (registry == &change.registry
                && name == &change.name
                && version == &change.from_version)
                .then_some(index)
        })
}

fn recorded_request(
    trace: &Trace,
    relation: &trace::Relation,
    request: &trace::Request,
) -> Option<RecordedRequest> {
    if request.requirement_status != "recorded" {
        return None;
    }
    Some(RecordedRequest {
        owner_name: request.owner.name.clone(),
        owner_version: request.owner.version.clone(),
        target: trace
            .occurrences
            .get(relation.to_ref?)?
            .coordinate
            .as_ref()?
            .clone(),
        requirement: request.requested_requirement.clone()?,
        path: request.path.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::{report, value};
    use serde_json::{Value, json};

    fn selected(input: &Value) -> Vec<RecordedRequest> {
        let body = report(input).data;
        let remediation = body.remediation.expect("remediation");
        recorded_requests(&remediation.trace, &remediation.recommendations[0])
    }

    #[test]
    fn audit_current_requests_preserve_the_explicit_owner_and_distinct_paths() {
        let mut input = value();
        let request = &mut input["remediation"]["trace"]["relations"][1]["requests"][0];
        request["owner"]["name"] = "actual-owner".into();
        request["owner"]["version"] = Value::Null;
        let duplicate = input["remediation"]["trace"]["relations"][1].clone();
        input["remediation"]["trace"]["relations"]
            .as_array_mut()
            .expect("relations")
            .push(duplicate);
        let requests = selected(&input);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].owner_name, "actual-owner");
        assert_eq!(requests[0].owner_version, None);
        assert_eq!(requests[0].target.to_string(), "npm:demo@1.0.0");
        let mut distinct = input["remediation"]["trace"]["relations"][1].clone();
        distinct["requests"][0]["path"] = "other/package.json".into();
        input["remediation"]["trace"]["relations"]
            .as_array_mut()
            .expect("relations")
            .push(distinct);
        let requests = selected(&input);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].path, "package-lock.json");
        assert_eq!(requests[1].path, "other/package.json");
    }

    #[test]
    fn audit_current_requests_link_exact_references_not_raw_alias_or_package_name() {
        let mut input = value();
        input["remediation"]["trace"]["occurrences"][0]["name"] = "authored-alias".into();
        assert_eq!(selected(&input).len(), 1);
        let node = input["remediation"]["trace"]["occurrences"][0].clone();
        input["remediation"]["trace"]["occurrences"]
            .as_array_mut()
            .expect("nodes")
            .push(node);
        input["remediation"]["recommendations"][0]["changes"][0]["occurrence_refs"] = json!([3]);
        assert!(
            selected(&input).is_empty(),
            "equal coordinates do not establish an occurrence edge"
        );
        input["remediation"]["recommendations"][0]["changes"][0]["occurrence_refs"] = json!([0]);
        input["remediation"]["recommendations"][0]["changes"][0]["from_version"] = "9.0.0".into();
        assert!(
            selected(&input).is_empty(),
            "a change must identify the referenced occurrence"
        );
    }
}
