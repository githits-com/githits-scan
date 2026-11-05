//! Source-local recorded dependency evidence; opaque contexts are deliberately ignored.
use serde::{Deserialize, Serialize};

use super::remediation::Owner;
use super::wire::{Additional, Coordinate, nullable};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Occurrence {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub path: String,
    pub name: String,
    #[serde(deserialize_with = "nullable")]
    pub version: Option<String>,
    pub kind: String,
    #[serde(deserialize_with = "nullable")]
    pub coordinate: Option<Coordinate>,
    pub project_root: bool,
    #[serde(deserialize_with = "nullable")]
    pub dependency_coverage: Option<Coverage>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Coverage {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub state: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Relation {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    #[serde(deserialize_with = "nullable")]
    pub from_ref: Option<usize>,
    #[serde(deserialize_with = "nullable")]
    pub to_ref: Option<usize>,
    pub path: String,
    pub kind: String,
    pub basis: String,
    pub disposition: String,
    pub requests: Vec<Request>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Request {
    #[serde(flatten, skip_serializing)]
    pub _additional: Additional,
    pub owner: Owner,
    pub owner_role: String,
    pub path: String,
    pub kind: String,
    #[serde(deserialize_with = "nullable")]
    pub requested_requirement: Option<String>,
    pub requirement_status: String,
    pub basis: String,
}
