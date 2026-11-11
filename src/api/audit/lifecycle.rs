//! Source-qualified native events, independent checks and retained warning evidence.
use serde::{Deserialize, Serialize};

use super::wire::{Additional, Coordinate, nullable};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Lifecycle {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub findings: Vec<Event>,
    pub retained_warnings: Vec<Warning>,
    pub coverage: Coverage,
    pub unknowns: Vec<Unknown>,
    pub content_safety: ContentSafety,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Event {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub registry: String,
    pub name: String,
    #[serde(deserialize_with = "nullable")]
    pub version: Option<String>,
    pub category: String,
    pub kind: String,
    pub scope: String,
    pub source: String,
    pub observations: Vec<Observation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Observation {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    #[serde(deserialize_with = "nullable")]
    pub source_version: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub observed_at: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub replacement: Option<String>,
    pub reason_codes: Vec<String>,
    pub affected: Vec<Reference>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Reference {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub coordinate: Coordinate,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Warning {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub coordinate: Coordinate,
    pub paths: Vec<String>,
    pub classification: String,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Unknown {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub coordinate: Coordinate,
    pub paths: Vec<String>,
    pub check: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Coverage {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub deprecation: Facet,
    pub withdrawal: Facet,
    pub registry_archival: Facet,
    pub repository_archival: Facet,
}

impl Coverage {
    pub(crate) const fn facets(&self) -> [(&'static str, &Facet); 4] {
        [
            ("deprecation", &self.deprecation),
            ("withdrawal", &self.withdrawal),
            ("registry_archival", &self.registry_archival),
            ("repository_archival", &self.repository_archival),
        ]
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Facet {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub candidates_count: u64,
    pub checked_count: u64,
    pub unknown_count: u64,
    pub not_collected_count: u64,
    pub not_collected_registries: Vec<String>,
    pub not_applicable_count: u64,
    pub not_applicable_registries: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ContentSafety {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub filtered: bool,
}
