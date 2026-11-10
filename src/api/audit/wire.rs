//! Version-one wire fields from the public `AuditReport` contract. Response strings stay open.
use serde::{Deserialize, Serialize};

// Flatten forces map-shaped objects, rather than serde's positional struct arrays.
// Additional fields are ignored and not retained in the report.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Additional;
impl<'de> Deserialize<'de> for Additional {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let _ = serde::de::IgnoredAny::deserialize(d)?;
        Ok(Self)
    }
}

use std::collections::BTreeMap;

pub(super) fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

/// Decode a supplied non-null value; combine with serde default for legacy omission.
pub(super) fn optional<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Coordinate {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub name: String,
    pub registry: String,
    pub version: String,
}

impl std::fmt::Display for Coordinate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}@{}", self.registry, self.name, self.version)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct Coverage {
    #[serde(flatten)]
    pub _additional: Additional,
    pub deprecation: MetadataCoverage,
    pub duplicates: DuplicateCoverage,
    pub outdated: MetadataCoverage,
    pub sources: Vec<SourceCoverage>,
    pub vulnerabilities: VulnerabilityCoverage,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeclarationInput {
    #[serde(flatten)]
    pub _additional: Additional,
    pub manifest_path: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeprecatedFinding {
    #[serde(flatten)]
    pub _additional: Additional,
    pub coordinate: Coordinate,
    pub occurrence_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DuplicateCoverage {
    #[serde(flatten)]
    pub _additional: Additional,
    pub candidates_count: u64,
    pub excluded_occurrences_count: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DuplicateFinding {
    #[serde(flatten)]
    pub _additional: Additional,
    pub name: String,
    pub registry: String,
    pub versions: Vec<DuplicateVersion>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DuplicateVersion {
    #[serde(flatten)]
    pub _additional: Additional,
    pub occurrence_ids: Vec<String>,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Findings {
    #[serde(flatten)]
    pub _additional: Additional,
    pub deprecated: Vec<DeprecatedFinding>,
    pub duplicates: Vec<DuplicateFinding>,
    pub outdated: Vec<OutdatedFinding>,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Inputs {
    #[serde(flatten)]
    pub _additional: Additional,
    pub declarations: Vec<DeclarationInput>,
    pub lockfiles: Vec<LockfileInput>,
    pub manifest_associations: BTreeMap<String, Vec<String>>,
    pub manifests: Vec<ManifestInput>,
    pub resolutions: Vec<ManifestResolution>,
    pub subjects: Vec<SubjectInput>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LockfileInput {
    #[serde(flatten)]
    pub _additional: Additional,
    pub manifest_paths: Vec<String>,
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ManifestInput {
    #[serde(flatten)]
    pub _additional: Additional,
    pub id: String,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ManifestResolution {
    #[serde(flatten)]
    pub _additional: Additional,
    pub diagnostics: Vec<ResolutionDiagnostic>,
    pub path: String,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct MetadataCoverage {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub candidates_count: u64,
    pub checked_count: u64,
    /// Candidates explicitly outside this check; absent in immutable older reports.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub not_applicable_count: Option<u64>,
    /// Registries with not-applicable candidates; preserve legacy absence when saving.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub not_applicable_registries: Option<Vec<String>>,
    pub not_collected_count: u64,
    pub not_collected_registries: Vec<String>,
    pub unknown_count: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MetadataUnknown {
    #[serde(flatten)]
    pub _additional: Additional,
    pub check: String,
    pub coordinate: Coordinate,
    pub occurrence_ids: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<String>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Occurrence {
    #[serde(flatten)]
    pub _additional: Additional,
    #[serde(deserialize_with = "nullable")]
    pub coordinate: Option<Coordinate>,
    pub id: String,
    #[serde(deserialize_with = "nullable")]
    pub lockfile_path: Option<String>,
    pub name: String,
    pub resolution_manifest_paths: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OutdatedFinding {
    #[serde(flatten)]
    pub _additional: Additional,
    pub change_type: String,
    pub coordinate: Coordinate,
    pub latest_version: String,
    pub occurrence_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct V1 {
    #[serde(flatten)]
    pub _additional: Additional,
    pub coverage: Coverage,
    pub findings: Findings,
    pub inputs: Inputs,
    pub occurrences: Vec<Occurrence>,
    pub summary: Summary,
    pub unknowns: Unknowns,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ResolutionDiagnostic {
    #[serde(flatten)]
    pub _additional: Additional,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct SourceCoverage {
    #[serde(flatten)]
    pub _additional: Additional,
    pub owner_id: String,
    pub reasons: Vec<String>,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SubjectInput {
    #[serde(flatten)]
    pub _additional: Additional,
    pub id: String,
    pub lockfile_path: String,
    pub name: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct Summary {
    #[serde(flatten)]
    pub _additional: Additional,
    pub dependencies: u64,
    pub deprecated: u64,
    pub duplicates: u64,
    pub excluded_occurrences: u64,
    pub incomplete_checks: u64,
    pub incomplete_sources: u64,
    pub occurrences: u64,
    pub outdated: u64,
    pub vulnerabilities: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Unknowns {
    #[serde(flatten)]
    pub _additional: Additional,
    pub excluded_occurrences: Vec<ExcludedOccurrence>,
    pub metadata: Vec<MetadataUnknown>,
    pub sources: Vec<SourceCoverage>,
    pub vulnerabilities: Vec<VulnerabilityUnknown>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct VulnerabilityCoverage {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub candidates_count: u64,
    pub checked_count: u64,
    pub unknown_count: u64,
    pub unsupported_count: u64,
    pub unsupported_registries: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VulnerabilityFinding {
    #[serde(flatten)]
    pub _additional: Additional,
    pub advisory_id: String,
    pub aliases: Vec<String>,
    pub coordinate: Coordinate,
    pub fixed_in_versions: Vec<String>,
    pub malicious: bool,
    pub occurrence_ids: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub severity_score: Option<f64>,
    #[serde(deserialize_with = "nullable")]
    pub severity_type: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub summary: Option<String>,
    pub verified_remedies: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VulnerabilityUnknown {
    #[serde(flatten)]
    pub _additional: Additional,
    pub advisory_ids: Vec<String>,
    pub check: String,
    pub coordinate: Coordinate,
    pub occurrence_ids: Vec<String>,
    pub reasons: Vec<String>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExcludedOccurrence {
    #[serde(flatten)]
    pub _additional: Additional,
    pub occurrence_id: String,
    pub reason: String,
}
