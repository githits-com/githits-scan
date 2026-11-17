//! Typed, loss-limited witness fields used by search explanations.

use serde::{Deserialize, Serialize};

use super::super::Owner;
use super::super::reasons::Request;
use crate::api::audit::wire::{Additional, Coordinate, nullable, optional};

/// The consumed portion of a whole-search witness.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct SearchWitness {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// A coordinate that may be absent or explicitly unavailable.
    #[serde(
        default,
        deserialize_with = "present_nullable",
        skip_serializing_if = "Option::is_none"
    )]
    #[expect(
        clippy::option_option,
        reason = "The wire field distinguishes absence, explicit null and a coordinate"
    )]
    pub(crate) coordinate: Option<Option<Coordinate>>,
    /// The current package coordinate, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) current: Option<Coordinate>,
    /// The target package coordinate, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) target: Option<Coordinate>,
    /// The registry and package name, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) package: Option<WitnessPackage>,
    /// A source path and its optional coordinate, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) source: Option<Source>,
    /// Source and destination of a boundary, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) boundary: Option<Boundary>,
    /// One recorded request, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) request: Option<Request>,
    /// Recorded requests, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) requests: Option<Vec<Request>>,
    /// Qualification evidence for a dependency relationship, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) qualification: Option<Qualification>,
    /// Request-level checks associated with this witness, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) request_checks: Option<Vec<RequestCheck>>,
    /// Dependency coverage associated with this witness, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) coverage: Option<Coverage>,
    /// The acquisition result, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) acquisition: Option<String>,
    /// The witness status, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) status: Option<String>,
    /// The scope in which a search budget applies, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) budget_scope: Option<String>,
    /// Paths associated with this witness, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) paths: Option<Vec<String>>,
    /// Requirement policy evidence, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) policy: Option<Policy>,
    /// Dependency declarations, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) declarations: Option<Vec<Declaration>>,
    /// A recorded dependency observation, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) observation: Option<Observation>,
}

#[expect(
    clippy::option_option,
    reason = "The wire field distinguishes absence, explicit null and a coordinate"
)]
fn present_nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// A package identity without a version.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WitnessPackage {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The package registry.
    pub(crate) registry: String,
    /// The package name.
    pub(crate) name: String,
}

/// A source path and nullable package coordinate.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Source {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The path used by the search.
    pub(crate) path: String,
    /// The package coordinate, which may be explicitly unavailable.
    #[serde(deserialize_with = "nullable")]
    pub(crate) coordinate: Option<Coordinate>,
}

/// The endpoints of a represented dependency relationship.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Boundary {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The requesting source.
    pub(crate) from: Source,
    /// The dependency source.
    pub(crate) to: Source,
}

/// Qualification evidence associated with a dependency request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Qualification {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// How the request is bound to the package.
    pub(crate) binding: String,
    /// The request capture status.
    pub(crate) capture: String,
    /// The declaration capture status.
    pub(crate) declaration_capture: String,
    /// The membership policy status.
    pub(crate) membership_policy: String,
    /// The participation state.
    pub(crate) participation: String,
    /// Conditions recorded for the qualification.
    pub(crate) conditions: Vec<Condition>,
    /// Reasons supplied for the policy state.
    pub(crate) policy_reasons: Vec<String>,
}

/// A condition attached to a qualification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Condition {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The kind of condition.
    pub(crate) kind: String,
    /// The condition capture status.
    pub(crate) status: String,
    /// The condition expression, which may be explicitly unavailable.
    #[serde(deserialize_with = "nullable")]
    pub(crate) expression: Option<String>,
}

/// A requirement check for one recorded package request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct RequestCheck {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The package that owns the request.
    pub(crate) owner: Owner,
    /// The path containing the request.
    pub(crate) path: String,
    /// The authored dependency name, which may be explicitly unavailable.
    #[serde(deserialize_with = "nullable")]
    pub(crate) dependency_name: Option<String>,
    /// The package coordinate checked for the request.
    pub(crate) target: Coordinate,
    /// The check result.
    pub(crate) result: String,
    /// The request clauses checked for this target.
    pub(crate) clauses: Vec<Clause>,
}

/// A clause and its membership and participation results.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Clause {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The request represented by this clause.
    pub(crate) request: Request,
    /// Membership result for the request.
    pub(crate) effective_membership: EffectiveMembership,
    /// Participation result for the request.
    pub(crate) participation: Participation,
}

/// Membership evidence for a request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct EffectiveMembership {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The membership result.
    pub(crate) status: String,
    /// The membership strength, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) strength: Option<String>,
    /// The reason for the membership result, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) reason: Option<String>,
}

/// Participation evidence for a request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Participation {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The participation result.
    pub(crate) status: String,
}

/// Coverage state for a dependency search.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Coverage {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The coverage state.
    pub(crate) status: String,
    /// Whether the dependency list is complete, when supplied.
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) complete: Option<bool>,
    /// Reasons for the coverage state.
    pub(crate) reasons: Vec<String>,
}

/// Requirement policy evidence for a package.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Policy {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The policy or capability name.
    pub(crate) name: String,
    /// The requested requirement, which may be explicitly unavailable.
    #[serde(deserialize_with = "nullable")]
    pub(crate) requested_requirement: Option<String>,
    /// The requested requirement status.
    pub(crate) requirement_status: String,
    /// The effective requirement, which may be explicitly unavailable.
    #[serde(deserialize_with = "nullable")]
    pub(crate) effective_requirement: Option<String>,
    /// The effective requirement status.
    pub(crate) effective_requirement_status: String,
    /// Diagnostics supplied for the policy.
    pub(crate) diagnostics: Vec<Diagnostic>,
}

/// A diagnostic attached to a requirement policy.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Diagnostic {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The diagnostic code.
    pub(crate) code: String,
    /// The field associated with the diagnostic.
    pub(crate) field: String,
}

/// A declared dependency requirement.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Declaration {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The declared dependency name.
    pub(crate) name: String,
    /// The requested requirement, which may be explicitly unavailable.
    #[serde(deserialize_with = "nullable")]
    pub(crate) requested_requirement: Option<String>,
    /// The requirement status.
    pub(crate) requirement_status: String,
    /// The declaration scope.
    pub(crate) scope: String,
}

/// A dependency observation recorded from a source path.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Observation {
    /// Fields outside Scan's consumed subset.
    #[serde(flatten, skip_serializing)]
    pub(crate) _additional: Additional,
    /// The observed dependency name.
    pub(crate) name: String,
    /// The path where the dependency was observed.
    pub(crate) path: String,
    /// The observation status.
    pub(crate) status: String,
    /// The requested requirement, which may be explicitly unavailable.
    #[serde(deserialize_with = "nullable")]
    pub(crate) requested_requirement: Option<String>,
    /// The requirement status.
    pub(crate) requirement_status: String,
}

#[cfg(test)]
mod tests;
