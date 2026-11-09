//! Typed wire subset for checked recommendation explanations.
use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;

use super::{Owner, optional};
use crate::api::audit::wire::{Additional, Coordinate, nullable};

/// A checked explanation attached to a recommended change.
#[derive(Debug, Clone)]
pub(crate) enum Reason {
    /// An advisory is addressed by the change.
    Advisory(Advisory),
    /// The change enables a dependency target for recorded requests.
    Enables(Enables),
    /// The change removes a dependency route for recorded requests.
    Removes(Removes),
    /// The service could not provide a checked explanation.
    Unavailable,
    /// An unrecognized service reason, retained for saved-report replay.
    Unknown {
        /// The service's open-ended reason code.
        code: String,
        /// Opaque evidence fields other than `code`.
        evidence: BTreeMap<String, Value>,
    },
}

impl Reason {
    /// Returns the service reason code, including codes not known to this version.
    pub(crate) fn code(&self) -> &str {
        match self {
            Self::Advisory(_) => "advisory_remediation",
            Self::Enables(_) => "enables_dependency_target",
            Self::Removes(_) => "removes_dependency_route",
            Self::Unavailable => "unavailable",
            Self::Unknown { code, .. } => code,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "code")]
enum KnownReason {
    #[serde(rename = "advisory_remediation")]
    Advisory(Advisory),
    #[serde(rename = "enables_dependency_target")]
    Enables(Enables),
    #[serde(rename = "removes_dependency_route")]
    Removes(Removes),
    #[serde(rename = "unavailable")]
    Unavailable,
}

#[derive(Serialize)]
#[serde(tag = "code")]
enum KnownReasonRef<'a> {
    #[serde(rename = "advisory_remediation")]
    Advisory(&'a Advisory),
    #[serde(rename = "enables_dependency_target")]
    Enables(&'a Enables),
    #[serde(rename = "removes_dependency_route")]
    Removes(&'a Removes),
    #[serde(rename = "unavailable")]
    Unavailable,
}

impl<'de> Deserialize<'de> for Reason {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let Value::Object(mut object) = Value::deserialize(deserializer)? else {
            return Err(D::Error::custom("reason must be an object"));
        };
        let Some(Value::String(code)) = object.get("code") else {
            return Err(D::Error::custom("reason code must be a string"));
        };
        let code = code.clone();

        match code.as_str() {
            "advisory_remediation"
            | "enables_dependency_target"
            | "removes_dependency_route"
            | "unavailable" => {
                let known = serde_json::from_value::<KnownReason>(Value::Object(object))
                    .map_err(D::Error::custom)?;
                Ok(match known {
                    KnownReason::Advisory(value) => Self::Advisory(value),
                    KnownReason::Enables(value) => Self::Enables(value),
                    KnownReason::Removes(value) => Self::Removes(value),
                    KnownReason::Unavailable => Self::Unavailable,
                })
            }
            _ => {
                object.remove("code");
                let evidence = object.into_iter().collect();
                Ok(Self::Unknown { code, evidence })
            }
        }
    }
}

#[derive(Serialize)]
struct UnknownReason<'a> {
    code: &'a str,
    #[serde(flatten)]
    evidence: &'a BTreeMap<String, Value>,
}

impl Serialize for Reason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Advisory(value) => KnownReasonRef::Advisory(value).serialize(serializer),
            Self::Enables(value) => KnownReasonRef::Enables(value).serialize(serializer),
            Self::Removes(value) => KnownReasonRef::Removes(value).serialize(serializer),
            Self::Unavailable => KnownReasonRef::Unavailable.serialize(serializer),
            Self::Unknown { code, evidence } => {
                UnknownReason { code, evidence }.serialize(serializer)
            }
        }
    }
}

/// Advisory references consumed from an advisory remediation reason.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Advisory {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// Indices of findings addressed by this change.
    pub(crate) finding_refs: Vec<usize>,
}

/// A dependency target enabled for recorded requests.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Enables {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The resulting dependency coordinate.
    pub(crate) dependency: Coordinate,
    /// The input file path checked by the service.
    pub(crate) path: String,
    /// Requests recorded before the change.
    pub(crate) original_requests: Vec<Request>,
    /// Requests accepted for the resulting target.
    pub(crate) replacement_requests: Vec<Request>,
}

/// A dependency route removed for recorded requests.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Removes {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The dependency coordinate on the removed route.
    pub(crate) dependency: Coordinate,
    /// The input file path checked by the service.
    pub(crate) path: String,
    /// Requests recorded before the change.
    pub(crate) original_requests: Vec<Request>,
}

/// A recorded request associated with a dependency change.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Request {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The package that owns the request.
    pub(crate) owner: Owner,
    /// The owner category recorded by the service.
    pub(crate) owner_role: String,
    /// The input file path containing the request.
    pub(crate) path: String,
    /// The dependency kind recorded by the service.
    pub(crate) kind: String,
    /// The authored dependency alias, if one was recorded.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) dependency_name: Option<String>,
    /// The recorded requirement, which may be explicitly unknown.
    #[serde(deserialize_with = "nullable")]
    pub(crate) requested_requirement: Option<String>,
    /// The service's open-ended requirement status.
    pub(crate) requirement_status: String,
    /// The source used to establish the request.
    pub(crate) basis: String,
}

#[cfg(test)]
mod tests;
