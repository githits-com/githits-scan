//! Narrow public upgrade-review contract, independent of repository diff interpretation.
use super::ApiError;
use serde::{Deserialize, Serialize};

/// Maximum package transitions accepted by one upgrade review.
pub const MAX_PACKAGES: usize = 30;
/// Public endpoint; no experimental or invented upgrade route.
pub const PATH: &str = "/v1/package-upgrade-reviews";

/// One exact direct-dependency transition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Package {
    /// Canonical public registry spelling.
    pub registry: String,
    /// Actual package name, not a manifest alias.
    pub name: String,
    /// Previously resolved direct version.
    pub current_version: String,
    /// Newly resolved direct version.
    pub target_version: String,
}

impl Package {
    /// Whether this transition fits the public endpoint's registry and tag-prefix rules.
    #[must_use]
    pub fn supported(&self) -> bool {
        let registry = matches!(
            self.registry.as_str(),
            "npm"
                | "pypi"
                | "hex"
                | "crates"
                | "vcpkg"
                | "zig"
                | "nuget"
                | "maven"
                | "packagist"
                | "rubygems"
                | "go"
                | "swift"
        );
        registry
            && [&self.current_version, &self.target_version]
                .iter()
                .all(|version| {
                    let tagged = version.as_bytes().get(1).is_some_and(u8::is_ascii_digit)
                        && version.starts_with(['v', 'V']);
                    !version.is_empty()
                        && (!tagged
                            || self.registry == "swift"
                            || (self.registry == "go" && version.starts_with('v')))
                })
    }
}

/// Existing public operation, mocked without networking in command tests.
pub trait UpgradeApi {
    /// Review at most thirty ordered transitions without retries.
    ///
    /// # Errors
    /// Returns transport, admission or malformed/oversized response errors.
    fn review(&self, packages: &[Package]) -> Result<Vec<Review>, ApiError>;
}

/// Producer evidence for one ordered transition; unknown fields remain extensible.
#[derive(Debug, Deserialize, Serialize)]
pub struct Review {
    /// Source-owned registry.
    pub registry: String,
    /// Source-owned canonical name, potentially different from the request spelling.
    pub name: String,
    /// Requested current version.
    pub current_version: String,
    /// Requested target version.
    pub target_version: String,
    /// Open producer ordering vocabulary.
    pub version_delta: String,
    /// Mandatory qualifications, including unfamiliar codes.
    pub unknown_details: Vec<Unknown>,
    /// Direct security evidence, if available.
    pub security: Option<Security>,
    /// Changelog summaries, if available.
    pub changelog: Option<Changelog>,
}

impl Review {
    /// Whether selected security or changelog evidence is incomplete.
    #[must_use]
    pub fn incomplete(&self) -> bool {
        let Some(security) = &self.security else {
            return true;
        };
        !self.unknown_details.is_empty()
            || self.changelog.as_ref().is_none_or(|c| c.truncated)
            || security.fixed.is_none()
            || security.introduced.is_none()
            || security.unchanged.is_none()
            || security
                .current
                .as_ref()
                .is_none_or(VersionSecurity::incomplete)
            || security
                .target
                .as_ref()
                .is_none_or(VersionSecurity::incomplete)
    }
}

/// Missing producer evidence; no interpretation of open codes is imposed.
#[derive(Debug, Deserialize, Serialize)]
pub struct Unknown {
    /// Evidence section.
    pub section: String,
    /// Open producer code.
    pub code: String,
    /// Safe-to-serialize producer explanation; human renderers escape it.
    pub message: String,
    /// Whether the producer considers the gap retryable.
    pub retryable: Option<bool>,
}

/// Direct upgrade-security lists, distinct from repository audit deltas.
#[derive(Debug, Deserialize, Serialize)]
pub struct Security {
    /// Current release assessment.
    pub current: Option<VersionSecurity>,
    /// Target release assessment.
    pub target: Option<VersionSecurity>,
    /// Fixed advisory evidence; absent means unavailable.
    pub fixed: Option<Vec<Advisory>>,
    /// Introduced advisory evidence; absent means unavailable.
    pub introduced: Option<Vec<Advisory>>,
    /// Unchanged advisory evidence; absent means unavailable.
    pub unchanged: Option<Vec<Advisory>>,
}

/// Assessment qualification retained without treating unfamiliar statuses as clean.
#[derive(Debug, Deserialize, Serialize)]
pub struct VersionSecurity {
    /// Concrete inspected version.
    pub version: String,
    /// Open assessment status.
    pub assessment_status: String,
    /// Unknown advisory assessments.
    pub unknown_count: u64,
}

impl VersionSecurity {
    fn incomplete(&self) -> bool {
        self.unknown_count > 0
            || !matches!(
                self.assessment_status.as_str(),
                "affected" | "non_affecting"
            )
    }
}

/// Advisory identifier; a null identifier remains unavailable evidence.
#[derive(Debug, Deserialize, Serialize)]
pub struct Advisory {
    /// Source advisory identifier.
    pub id: Option<String>,
}

/// Bounded release-note summaries; only producer-returned URLs may be linked.
#[derive(Debug, Deserialize, Serialize)]
pub struct Changelog {
    /// Open provenance vocabulary.
    pub source: Option<String>,
    /// Returned range entries.
    pub entries: Vec<Entry>,
    /// Total range entries before the public cap.
    pub total_entries: u64,
    /// Whether the returned evidence is truncated.
    pub truncated: bool,
}

/// A release-note link, which may legitimately be unavailable.
#[derive(Debug, Deserialize, Serialize)]
pub struct Entry {
    /// Release version, when known.
    pub version: Option<String>,
    /// Producer link; never fabricated from a repository or version.
    pub html_url: Option<String>,
}

pub(super) fn decode(bytes: &[u8], requested: &[Package]) -> Result<Vec<Review>, ApiError> {
    #[derive(Deserialize)]
    struct Batch {
        total: usize,
        reviews: Vec<Review>,
    }
    let batch: Batch =
        serde_json::from_slice(bytes).map_err(|_| ApiError::protocol("invalid upgrade review"))?;
    if batch.total != requested.len() || batch.reviews.len() != requested.len() {
        return Err(ApiError::protocol("upgrade review batch count mismatch"));
    }
    for (review, input) in batch.reviews.iter().zip(requested) {
        if review.registry != input.registry
            || review.current_version != input.current_version
            || review.target_version != input.target_version
        {
            return Err(ApiError::protocol(
                "upgrade review order or version mismatch",
            ));
        }
    }
    Ok(batch.reviews)
}

#[cfg(test)]
mod tests;
