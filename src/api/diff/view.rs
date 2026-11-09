//! Only presentation fields are retained; canonical comparison remains service-owned.
use super::{Section, invalid};
use crate::api::ApiError;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::BTreeMap;

#[derive(Deserialize)]
pub(crate) struct View {
    pub outcome: String,
    pub snapshots: Snapshots,
    pub changes: Vec<Change>,
    pub declaration_changes: Vec<DeclarationChange>,
    pub advisories: Section,
    pub direct_reviews: Section,
    pub coverage: Box<RawValue>,
    pub summary: BTreeMap<String, u64>,
    pub notices: Vec<String>,
}

impl View {
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        self.advisories.decode::<Advisories>()?;
        self.direct_reviews.decode::<Vec<Review>>()?;
        if let Some(raw) = &self.advisories.coverage
            && matches!(self.advisories.status.as_str(), "complete" | "partial")
        {
            serde_json::from_str::<AdvisoryCoverage>(raw.get()).map_err(|_| invalid())?;
        }
        serde_json::from_str::<Coverage>(self.coverage.get()).map_err(|_| invalid())?;
        for (_, snapshot) in self.snapshots.iter() {
            serde_json::from_str::<Coverage>(snapshot.coverage.get()).map_err(|_| invalid())?;
        }
        if matches!(self.direct_reviews.status.as_str(), "complete" | "partial") {
            let raw = self.direct_reviews.coverage.as_ref().ok_or_else(invalid)?;
            serde_json::from_str::<ReviewCoverage>(raw.get()).map_err(|_| invalid())?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub(crate) struct Snapshot {
    pub side: String,
    pub declarations: Vec<Declaration>,
    pub coverage: Box<RawValue>,
}

#[derive(Deserialize)]
pub(crate) struct Declaration {
    pub id: String,
    pub declared_name: String,
    pub declaring_manifest: String,
}

#[derive(Deserialize)]
pub(crate) struct Package {
    #[serde(deserialize_with = "nullable")]
    pub registry: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub name: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Change {
    pub id: String,
    pub source_key: String,
    pub package: Package,
    pub ownership: String,
    pub kind: String,
    pub before_versions: Vec<Option<String>>,
    pub after_versions: Vec<Option<String>>,
    pub directness: Directness,
    pub retained_elsewhere: Vec<Retained>,
}

#[derive(Deserialize)]
pub(crate) struct Retained {
    pub source_key: String,
    pub versions: Vec<Option<String>>,
}

#[derive(Deserialize)]
pub(crate) struct DeclarationChange {
    pub id: String,
    pub kind: String,
    pub before_id: Option<String>,
    pub after_id: Option<String>,
    pub binding_transitions: Vec<Binding>,
}

#[derive(Deserialize)]
pub(crate) struct Binding {
    pub source_key: String,
    pub package: Option<Package>,
    pub before_versions: Vec<String>,
    pub recorded_before_versions: Vec<String>,
    pub after_versions: Vec<String>,
    pub base_status: String,
    pub head_status: String,
    pub review_eligibility: Eligibility,
    #[serde(deserialize_with = "nullable")]
    pub base_target: Option<Target>,
    #[serde(deserialize_with = "nullable")]
    pub head_target: Option<Target>,
}

fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

#[derive(Deserialize)]
pub(crate) struct Target {
    pub package: Package,
    pub version: String,
}

#[derive(Deserialize)]
pub(crate) struct Eligibility {
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Advisories {
    pub findings: Vec<Finding>,
    pub coordinate_transitions: Vec<Transition>,
    pub exposures: Vec<Exposure>,
}

#[derive(Deserialize)]
pub(crate) struct Finding {
    pub id: String,
    pub osv_id: String,
    pub package: Package,
    pub summary: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Transition {
    pub change_id: String,
    pub deltas: Vec<Delta>,
}

#[derive(Deserialize)]
pub(crate) struct Exposure {
    pub scope: Scope,
    pub deltas: Vec<Delta>,
    pub coverage: ScopeSides,
}

#[derive(Deserialize)]
pub(crate) struct ScopeCoverage {
    pub inventory: String,
    pub assessment: String,
    pub coordinates: u64,
    pub checked: u64,
    pub unqualified_occurrences: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct Scope {
    pub kind: String,
    pub qualifier: String,
    pub source_key: Option<String>,
    pub unit_key: Option<Vec<String>>,
    pub manifest_path: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Delta {
    pub finding_id: String,
    pub kind: String,
    pub base: Assessment,
    pub head: Assessment,
}

#[derive(Deserialize)]
pub(crate) struct Assessment {
    pub status: String,
    pub reasons: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct Review {
    pub registry: String,
    pub name: String,
    pub current_version: String,
    pub target_version: String,
    pub source_keys: Vec<String>,
    pub status: String,
    pub reason: Option<String>,
    pub data: Option<Box<RawValue>>,
}

impl Review {
    // Review detail is an open object, not a pinned report schema. A changed
    // detail shape must remain exportable without implying an assessment.
    pub(crate) fn evidence(&self) -> Option<ReviewData> {
        if !matches!(self.status.as_str(), "complete" | "partial") {
            return None;
        }
        self.data
            .as_ref()
            .and_then(|raw| serde_json::from_str(raw.get()).ok())
    }
}

#[derive(Deserialize)]
pub(crate) struct ReviewData {
    pub security: Option<Security>,
    pub changelog: Option<Changelog>,
    #[serde(default)]
    pub unknown_details: Vec<Unknown>,
}

#[derive(Deserialize)]
pub(crate) struct Security {
    pub current: Option<VersionSecurity>,
    pub target: Option<VersionSecurity>,
}

#[derive(Deserialize)]
pub(crate) struct VersionSecurity {
    pub assessment_status: String,
    pub unknown_vulnerability_count: u64,
}

#[derive(Deserialize)]
pub(crate) struct Unknown {
    pub section: String,
    pub code: String,
    pub message: String,
}

#[derive(Deserialize)]
pub(crate) struct Changelog {
    #[serde(default)]
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub breaking_signals: Vec<String>,
    #[serde(default)]
    pub migration_signals: Vec<String>,
    pub coverage: Option<ChangelogCoverage>,
}

#[derive(Deserialize)]
pub(crate) struct ChangelogCoverage {
    pub status: String,
    pub returned_entries: u64,
    pub total_entries: u64,
    pub truncated: bool,
}

#[derive(Deserialize)]
pub(crate) struct Entry {
    pub version: Option<String>,
    pub headline: Option<String>,
    pub html_url: Option<String>,
    #[serde(default)]
    pub signals: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct Coverage {
    pub partial: Option<bool>,
    #[serde(default)]
    pub sources: Vec<Gap>,
    #[serde(default)]
    pub resolution: Vec<Gap>,
    #[serde(default)]
    pub excluded_dependencies: Vec<Gap>,
    #[serde(default)]
    pub mismatches: Vec<Gap>,
    #[serde(default)]
    pub reachability: Vec<Reachability>,
}

#[derive(Deserialize)]
pub(crate) struct Reachability {
    pub complete: bool,
    pub manifest_path: String,
    pub source_key: String,
    pub basis: String,
}

#[derive(Deserialize)]
pub(crate) struct Gap {
    pub path: Option<String>,
    pub required_path: Option<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub reason: Option<String>,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct ReviewCoverage {
    pub eligible: u64,
    pub completed: u64,
    pub returned: u64,
    pub not_assessed: u64,
    pub unavailable: u64,
    pub omitted: u64,
}
#[derive(Deserialize)]
pub(crate) struct AdvisoryCoverage {
    pub checked: Option<u64>,
    pub coordinates: Option<u64>,
    pub unknown: Option<u64>,
    pub unsupported: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct Snapshots {
    pub base: Snapshot,
    pub head: Snapshot,
}
impl Snapshots {
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'static str, &Snapshot)> {
        [("base", &self.base), ("head", &self.head)].into_iter()
    }
}
#[derive(Deserialize)]
pub(crate) struct Directness {
    pub base: String,
    pub head: String,
}
#[derive(Deserialize)]
pub(crate) struct ScopeSides {
    pub base: Option<ScopeCoverage>,
    pub head: Option<ScopeCoverage>,
}
impl ScopeSides {
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'static str, &ScopeCoverage)> {
        [("base", self.base.as_ref()), ("head", self.head.as_ref())]
            .into_iter()
            .filter_map(|(name, value)| value.map(|v| (name, v)))
    }
}
