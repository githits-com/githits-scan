//! Shared attention policy for producer-authored coverage causes.
use serde::{Serialize, Serializer};

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Attention {
    Informational,
    #[default]
    Actionable,
}

/// Only explicit producer causes identify ordinary Git coverage limits.
pub(crate) fn expected_git(reason: &str) -> bool {
    note(reason).is_some()
}

/// An absent or empty explanation cannot establish informational-only coverage.
pub(crate) fn git_only(reasons: &[String]) -> bool {
    !reasons.is_empty() && reasons.iter().all(|r| expected_git(r))
}

/// Registry ineligibility is neutral only for explicitly excluded packages.
pub(crate) fn expected_exclusion(reason: &str) -> bool {
    reason == "non_registry_source" || expected_git(reason)
}

/// Exhaustive causes for registry assessment; this does not prove graph completeness.
pub(crate) fn exclusions_only(reasons: &[String]) -> bool {
    !reasons.is_empty() && reasons.iter().all(|r| expected_exclusion(r))
}

/// Attention for an explicitly excluded package, independent of report consistency.
pub(crate) fn exclusion_attention(reason: &str) -> Attention {
    if expected_exclusion(reason) {
        Attention::Informational
    } else {
        Attention::Actionable
    }
}

/// Human wording for an expected public-registry exclusion.
pub(crate) fn exclusion_note(reason: &str) -> Option<&'static str> {
    if reason == "non_registry_source" {
        Some(
            "Dependencies from outside public package registries are excluded from registry vulnerability and update checks.",
        )
    } else {
        note(reason)
    }
}

pub(crate) fn attention(reason: &str) -> Attention {
    if expected_git(reason) {
        Attention::Informational
    } else {
        Attention::Actionable
    }
}

pub(crate) fn note(reason: &str) -> Option<&'static str> {
    match reason {
        "git_registry_checks_not_supported" => Some(
            "Git-sourced dependencies are not checked for vulnerabilities or available updates.",
        ),
        "git_dependency_graph_unavailable" => Some(
            "Dependencies used by Git-sourced packages cannot be fully traced; change-impact results may be incomplete.",
        ),
        "git_source_binding_unavailable" => Some(
            "Some Git dependencies could not be matched between manifest and lockfile; source and revision agreement remains unverified.",
        ),
        _ => None,
    }
}

impl Serialize for Attention {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(*self == Self::Actionable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_registry_exclusion_policy_is_contextual_and_exhaustive() {
        assert!(expected_exclusion("non_registry_source"));
        assert!(exclusions_only(&["non_registry_source".into()]));
        assert!(attention("non_registry_source") == Attention::Actionable);
        assert!(exclusion_attention("non_registry_source") == Attention::Informational);
        assert!(!exclusions_only(&[]));
        assert!(!exclusions_only(&[
            "non_registry_source".into(),
            "future_reason".into()
        ]));
    }

    #[test]
    fn exact_git_causes_do_not_classify_unexplained_or_mixed_evidence() {
        assert!(!git_only(&[]));
        for reason in [
            "git_registry_checks_not_supported",
            "git_dependency_graph_unavailable",
            "git_source_binding_unavailable",
        ] {
            assert!(git_only(&[reason.into()]));
            assert!(!git_only(&[
                reason.into(),
                "recorded_git_source_differs".into()
            ]));
        }
        for reason in [
            "",
            "missing_coordinate",
            "future_reason",
            "non_registry_source",
        ] {
            assert!(!expected_git(reason));
        }
    }
}
