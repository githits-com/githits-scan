//! Shared wire helpers and exact-coordinate coverage from the public audit contract.
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

pub(super) fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

/// Decode a supplied non-null value; combine with serde default for omitted optional data.
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

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct MetadataCoverage {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub candidates_count: u64,
    pub checked_count: u64,
    pub not_collected_count: u64,
    pub not_collected_registries: Vec<String>,
    pub unknown_count: u64,
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
