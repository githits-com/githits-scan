//! Compact version-two fields used by interpretation and presentation.
use serde::{Deserialize, Serialize};

use super::wire::{Additional, Coordinate, MetadataCoverage, VulnerabilityCoverage, nullable};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct V2 {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    pub summary: Summary,
    pub findings: Findings,
    pub coverage: Coverage,
    pub unknowns: Unknowns,
    #[serde(
        default,
        deserialize_with = "super::remediation::optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub remediation: Option<super::remediation::Remediation>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Summary {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub dependencies: u64,
    pub vulnerabilities: u64,
    pub deprecated: u64,
    pub outdated: u64,
    pub duplicates: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_lock_mismatches: Option<u64>,
    pub excluded_dependencies: u64,
    pub incomplete_sources: u64,
    pub incomplete_checks: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Coverage {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub vulnerabilities: VulnerabilityCoverage,
    pub deprecation: MetadataCoverage,
    pub outdated: MetadataCoverage,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Findings {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub vulnerabilities: Vec<Vulnerability>,
    pub deprecated: Vec<Deprecated>,
    pub outdated: Vec<Outdated>,
    pub duplicates: Vec<Duplicate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manifest_lock_mismatches: Vec<ManifestLockMismatch>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Vulnerability {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub coordinate: Coordinate,
    pub paths: Vec<String>,
    pub advisory_id: String,
    pub aliases: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub summary: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub severity_score: Option<f64>,
    #[serde(deserialize_with = "nullable")]
    pub severity_type: Option<String>,
    pub malicious: bool,
    pub fixed_in_versions: Vec<String>,
    pub verified_remedies: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Deprecated {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub coordinate: Coordinate,
    pub paths: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Outdated {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub coordinate: Coordinate,
    pub paths: Vec<String>,
    pub latest_version: String,
    pub change_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Duplicate {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub registry: String,
    pub name: String,
    pub versions: Vec<DuplicateVersion>,
    pub unattributed_requirements: Vec<Unattributed>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct DuplicateVersion {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub version: String,
    pub paths: Vec<String>,
    pub origins: Vec<Origin>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Requester {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub name: String,
    #[serde(deserialize_with = "nullable")]
    pub version: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Origin {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub path: String,
    #[serde(deserialize_with = "nullable")]
    pub requester: Option<Requester>,
    #[serde(deserialize_with = "nullable")]
    pub requested_requirement: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution_basis: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Unattributed {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub path: String,
    pub requester: Requester,
    #[serde(deserialize_with = "nullable")]
    pub requested_requirement: Option<String>,
    pub requirement_status: String,
    pub target_status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Unknowns {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub vulnerabilities: Vec<VulnerabilityGap>,
    pub metadata: Vec<MetadataGap>,
    pub sources: Vec<SourceGap>,
    pub resolution: Vec<ResolutionGap>,
    pub excluded_dependencies: Vec<Excluded>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct VulnerabilityGap {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub coordinate: Coordinate,
    pub paths: Vec<String>,
    pub check: String,
    pub status: String,
    pub reasons: Vec<String>,
    pub advisory_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct MetadataGap {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub coordinate: Coordinate,
    pub paths: Vec<String>,
    pub check: String,
    pub status: String,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct SourceGap {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub path: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ResolutionGap {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub path: String,
    #[serde(deserialize_with = "nullable")]
    pub name: Option<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<Requester>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_requirement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirement_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "no_conditions")]
    pub context: Option<NativeConditions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_scope: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Excluded {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub name: String,
    #[serde(deserialize_with = "nullable")]
    pub version: Option<String>,
    pub paths: Vec<String>,
    pub reason: String,
}

/// Consumed native declaration/lock disagreement; opaque remediation text is ignored.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ManifestLockMismatch {
    pub path: String,
    pub declaration_path: String,
    pub name: String,
    #[serde(deserialize_with = "nullable")]
    pub requested_requirement: Option<String>,
    pub requirement_status: String,
    pub locked_versions: Vec<String>,
    pub recorded_requirements: Vec<String>,
    pub declared_scope: String,
    pub recorded_scopes: Vec<String>,
    pub reason: String,
}

/// Known native conditions, retained as facts without inferring activation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct NativeConditions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_python: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker_unavailable: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_extras: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundler_source_pinned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bun_bundled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paket_restriction: Option<NativeRestriction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct NativeRestriction {
    pub syntax: String,
    pub expression: String,
}

impl NativeConditions {
    /// Whether the native context contains no consumed condition facts.
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[expect(
    clippy::ref_option,
    reason = "serde skip_serializing_if borrows the optional field"
)]
fn no_conditions(value: &Option<NativeConditions>) -> bool {
    value.as_ref().is_none_or(NativeConditions::is_empty)
}
