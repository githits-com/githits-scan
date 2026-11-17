//! Whole-search obstacles, independent of selected-action checks and findings.
use crate::api::audit::wire::{Additional, optional};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;
use std::num::NonZeroU64;
/// Screened witness fields used by Scan's explanations.
pub(crate) mod witness;
use witness::SearchWitness;

/// An unavailable answer, observed work stop, or uninterpretable future kind.
/// Detailed payloads are boxed so a future-kind entry does not reserve a full witness.
#[derive(Debug, Clone)]
pub(crate) enum Detail {
    /// A search answer could not be obtained.
    Unavailable(Box<Unavailable>),
    /// Work stopped at a reported search stage.
    Stopped(Box<Stopped>),
    /// An unfamiliar kind, without interpreting its payload.
    Unrecognized {
        /// The service kind, retained without interpreting its additional fields.
        kind: String,
    },
}
/// Consumed evidence for an unavailable search answer.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Unavailable {
    #[serde(flatten, skip_serializing)]
    _additional: Additional,
    /// The operation whose answer is missing.
    pub operation: String,
    /// Producer-supplied causes, not inferred from plan limitations.
    pub reasons: Vec<String>,
    /// The affected source, request or candidate.
    pub witness: SearchWitness,
}
/// Consumed evidence for an observed search stop.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Stopped {
    #[serde(flatten, skip_serializing)]
    _additional: Additional,
    /// The stage at which work stopped.
    pub stage: String,
    /// The producer-supplied reason.
    pub reason: String,
    /// Observed use, paired with the allowed count; never invented for deadlines.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub used: Option<u64>,
    /// The producer's positive limit, in its own counting unit.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed: Option<NonZeroU64>,
    /// Coordinate and budget scope of the observed stop.
    pub witness: SearchWitness,
}
impl Detail {
    fn valid(&self) -> bool {
        match self {
            Self::Unavailable(d) => !d.reasons.is_empty() && witness_valid(&d.witness),
            Self::Stopped(d) => {
                d.used.is_some() == d.allowed.is_some()
                    && d.witness.coordinate.is_some()
                    && d.witness.budget_scope.is_some()
                    && witness_valid(&d.witness)
            }
            Self::Unrecognized { .. } => true,
        }
    }
}
impl<'de> Deserialize<'de> for Detail {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let Value::Object(object) = Value::deserialize(d)? else {
            return Err(D::Error::custom("search detail must be an object"));
        };
        let Some(Value::String(kind)) = object.get("kind") else {
            return Err(D::Error::custom("search detail kind must be a string"));
        };
        let detail = match kind.as_str() {
            "unavailable" => Self::Unavailable(
                serde_json::from_value(Value::Object(object)).map_err(D::Error::custom)?,
            ),
            "stopped" => Self::Stopped(
                serde_json::from_value(Value::Object(object)).map_err(D::Error::custom)?,
            ),
            _ => Self::Unrecognized { kind: kind.clone() },
        };
        if !detail.valid() {
            return Err(D::Error::custom("invalid search detail relationships"));
        }
        Ok(detail)
    }
}
#[derive(Serialize)]
#[serde(tag = "kind")]
enum DetailRef<'a> {
    #[serde(rename = "unavailable")]
    Unavailable(&'a Unavailable),
    #[serde(rename = "stopped")]
    Stopped(&'a Stopped),
}
impl Serialize for Detail {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unavailable(d) => DetailRef::Unavailable(d).serialize(s),
            Self::Stopped(d) => DetailRef::Stopped(d).serialize(s),
            Self::Unrecognized { kind } => {
                use serde::ser::SerializeMap as _;
                let mut object = s.serialize_map(Some(1))?;
                object.serialize_entry("kind", kind)?;
                object.end()
            }
        }
    }
}

#[cfg(test)]
mod tests;

fn witness_valid(w: &SearchWitness) -> bool {
    w.request_checks
        .iter()
        .flatten()
        .flat_map(|c| &c.clauses)
        .all(|c| {
            c.effective_membership.reason.is_some() || c.effective_membership.strength.is_some()
        })
}
