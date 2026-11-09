//! Consumed recommendation facts; compact output and saved analysis have distinct projections.
use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

use super::wire::{Additional, Coordinate, nullable};

/// Checked reason DTOs used by recommendation changes.
pub(crate) mod reasons;
/// The wire reason type attached to a recommendation change.
pub(crate) use reasons::Reason;

// Absence is supported; a supplied null is not an optional object in the contract.
pub(super) fn optional<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Remediation {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub status: String,
    pub recommendations: Vec<Recommendation>,
    pub trace: Trace,
    pub limits: Limits,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Recommendation {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub subject: Coordinate,
    pub finding_refs: Vec<usize>,
    pub occurrence_refs: Vec<usize>,
    pub outcome: String,
    pub changes: Vec<Change>,
    pub blockers: Vec<Blocker>,
    pub checks: Checks,
    pub addressed_finding_refs: Vec<usize>,
    pub remaining_finding_refs: Vec<usize>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub remaining_occurrence_refs: Option<Vec<usize>>,
    pub limitations: Vec<String>,
    pub detail_status: String,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub search_domain: Option<SearchDomain>,
}

// These selected facts have identical meanings in the command's compact JSON.
// Explicit fields and skipped Additional prevent raw producer data escaping.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Change {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub registry: String,
    pub name: String,
    pub from_version: String,
    pub target_version: String,
    pub strategy: String,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub occurrence_refs: Option<Vec<usize>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicting_target_versions: Vec<String>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub availability_source: Option<String>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub prerelease_target: Option<bool>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub deprecated_target: Option<bool>,
    /// Optional checked explanations for the recommended change.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub reasons: Option<Vec<Reason>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Blocker {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub owner: Owner,
    pub owner_role: String,
    pub path: String,
    pub kind: String,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub dependency_name: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub requested_requirement: Option<String>,
    pub requirement_status: String,
    pub basis: String,
    pub context: BTreeMap<String, serde_json::Value>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other_target_versions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Owner {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub name: String,
    #[serde(deserialize_with = "nullable")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Checks {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub release_availability: String,
    pub availability_source: String,
    pub withdrawal: String,
    pub advisories: String,
    pub requirements: String,
    pub preference_differences: u64,
    pub native_resolution: String,
    pub parent_search: String,
    pub catalog_freshness: String,
    pub prerelease_target: bool,
    pub deprecated_target: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct SearchDomain {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub constraint_scope: String,
    pub release_scope: String,
    pub packages: Vec<SearchPackage>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct SearchPackage {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub coordinate: Coordinate,
    pub versions: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Trace {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub status: String,
    pub occurrences: Vec<super::trace::Occurrence>,
    pub relations: Vec<super::trace::Relation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Limits {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub reasons: Vec<String>,
    pub omitted_recommendations: u64,
    pub omitted_occurrences: u64,
    pub omitted_relations: u64,
}
