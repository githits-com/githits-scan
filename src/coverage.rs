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

pub(crate) fn attention(reason: &str) -> Attention {
    if expected_git(reason) {
        Attention::Informational
    } else {
        Attention::Actionable
    }
}

pub(crate) fn note(reason: &str) -> Option<&'static str> {
    match reason {
        "git_registry_checks_not_supported" => {
            Some("Registry checks do not cover Git-based dependencies")
        }
        "git_dependency_graph_unavailable" => {
            Some("Git dependency relationships are not recorded in this lockfile")
        }
        "git_source_binding_unavailable" => {
            Some("Some Git source bindings cannot be established from the supplied evidence")
        }
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
