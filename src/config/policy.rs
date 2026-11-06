//! Strict selectors for local policy decisions, separate from producer evidence.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One package exempted from license policy, never a license declaration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(
    untagged,
    deny_unknown_fields,
    expecting = "a license exception with purl and reason, or name, git, optional rev and reason"
)]
pub enum Exception {
    /// Every release of an unscoped registry package.
    Package {
        /// Package URL without version, qualifiers or subpath.
        purl: String,
        /// Why this exception exists.
        reason: String,
    },
    /// One named package from an exact recorded Git repository.
    Git {
        /// Exact component name, including for multi-package repositories.
        name: String,
        /// Exact source repository URL, without revision or credentials.
        git: String,
        /// Exact recorded revision; absence covers every revision of this source.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rev: Option<String>,
        /// Why this exception exists.
        reason: String,
    },
}

impl Exception {
    pub(crate) fn reason(&self) -> &str {
        match self {
            Self::Package { reason, .. } | Self::Git { reason, .. } => reason,
        }
    }
}

/// Local advisory policy; producer findings and coverage stay intact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    /// Advisory IDs whose findings do not contribute to failure.
    #[serde(default)]
    pub ignore: Vec<AdvisoryIgnore>,
}

/// An explicit decision to ignore one reported advisory ID across packages.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryIgnore {
    /// Exact, case-sensitive advisory ID; aliases are not selectors.
    pub id: String,
    /// Why the advisory is ignored; retained in reports and saved analysis.
    pub reason: String,
}

impl Audit {
    pub(crate) const fn is_empty(&self) -> bool {
        self.ignore.is_empty()
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_audit(self)
    }
}

fn validate_audit(policy: &Audit) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    for (index, ignore) in policy.ignore.iter().enumerate() {
        if ignore.id.is_empty() || ignore.id.chars().any(char::is_whitespace) {
            return Err(format!(
                "audit.ignore[{index}].id must be a nonempty advisory ID without whitespace"
            ));
        }
        if ignore.reason.trim().is_empty() {
            return Err(format!("audit.ignore[{index}].reason must not be blank"));
        }
        if !ids.insert(&ignore.id) {
            return Err(format!("audit.ignore[{index}].id repeats an advisory ID"));
        }
    }
    Ok(())
}
