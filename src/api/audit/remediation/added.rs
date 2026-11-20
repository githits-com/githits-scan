//! Curated registry branch evidence shared by changes and search details.

use serde::{Deserialize, Serialize};

use crate::api::audit::wire::{Additional, Coordinate, nullable, optional, present_nullable};

/// The authored request and exact coordinates considered under registry resolution.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Branch {
    #[serde(flatten, skip_serializing)]
    _additional: Additional,
    /// Registry of the requested package.
    pub registry: String,
    /// Canonical package name.
    pub name: String,
    /// Package name used by the declaring release, including an alias if present.
    pub authored_name: String,
    /// Literal requirement, explicitly null when not available.
    #[serde(deserialize_with = "nullable")]
    pub requested_requirement: Option<String>,
    /// Whether the requirement text was recorded, absent or withheld.
    pub requirement_status: String,
    /// Dependency scope supplied by the declaration.
    pub scope: String,
    /// The service's basis for selecting this branch.
    pub selection_basis: String,
    /// Selected root version, or explicit null when selection did not complete.
    #[serde(deserialize_with = "nullable")]
    pub selected_version: Option<String>,
    /// Exact selected root and transitive coordinates with advisory results.
    pub coordinates: Vec<CheckedCoordinate>,
    /// Material problems in selecting, traversing or checking this branch.
    pub issues: Vec<Issue>,
}

/// An exact added coordinate with the advisory result for that version.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct CheckedCoordinate {
    /// Registry coordinate assessed by the service.
    #[serde(flatten)]
    pub coordinate: Coordinate,
    /// Service result for advisory applicability.
    pub advisory_status: String,
    /// Applicable advisory identifiers reported for the coordinate.
    pub advisory_ids: Vec<String>,
}

/// An operation and its supplied failure or conflict evidence.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Issue {
    #[serde(flatten, skip_serializing)]
    _additional: Additional,
    /// The operation that reported the issue.
    pub operation: String,
    /// The producer's reason for the issue.
    pub reason: String,
    /// Exact coordinate for a release or advisory issue.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub coordinate: Option<Coordinate>,
    /// Registry for a version selection conflict.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub registry: Option<String>,
    /// Declaring release for a transitive or activation issue.
    #[serde(
        default,
        deserialize_with = "present_nullable",
        skip_serializing_if = "Option::is_none"
    )]
    #[expect(
        clippy::option_option,
        reason = "The wire field can be omitted or explicitly null"
    )]
    pub owner: Option<Option<String>>,
    /// Dependency named by the issue.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    /// Literal dependency requirement associated with the issue.
    #[serde(
        default,
        deserialize_with = "present_nullable",
        skip_serializing_if = "Option::is_none"
    )]
    #[expect(
        clippy::option_option,
        reason = "The wire field can be omitted or explicitly null"
    )]
    pub requested_requirement: Option<Option<String>>,
    /// Whether the literal requirement was captured.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub requirement_status: Option<String>,
    /// Versions selected by the registry branch checks.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub selected_versions: Option<Vec<String>>,
    /// Versions retained by the project assignment that was checked.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub represented_versions: Option<Vec<String>>,
    /// Literal requirements involved in a version conflict.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub requirements: Option<Vec<Option<String>>>,
    /// HTTP status returned by the registry, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub http_status: Option<u16>,
    /// Cargo feature group associated with the issue.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub feature: Option<String>,
    /// Explicit Cargo feature names requested by the declaration.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub requested_features: Option<Vec<String>>,
    /// Whether the request enables Cargo default features.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_features: Option<bool>,
    /// Exact Python marker for the declaration.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub marker: Option<String>,
    /// Python extras requested by the declaration.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub requested_extras: Option<Vec<String>>,
}
