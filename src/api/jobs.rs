//! Public job snapshots and canonical relative links. Wire values are never diagnostics.

use serde::Deserialize;
use url::Url;

use super::{ApiError, JOBS_PATH, Operation};

/// The actual execution stage; no overall percentage is implied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Waiting for execution.
    Queued,
    /// Resolving manifest dependency evidence.
    Resolving,
    /// Enriching package coordinates.
    Enriching,
    /// Assessing vulnerability and metadata evidence.
    Assessing,
    /// Rendering the document.
    Rendering,
    /// The document is available.
    Succeeded,
    /// Execution failed.
    Failed,
    /// Unfamiliar display-only execution stage.
    #[serde(other)]
    Unknown,
}

impl Phase {
    /// The public stage name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Resolving => "resolving",
            Self::Enriching => "enriching",
            Self::Assessing => "assessing",
            Self::Unknown => "unknown",
            Self::Rendering => "rendering",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

/// Measured stage counters. Absent or null means unavailable, distinct from zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Counts {
    /// Manifests resolved so far.
    pub manifests_done: Option<u64>,
    /// Manifests currently known to resolution.
    pub manifests_total: Option<u64>,
    /// Dependencies resolved so far.
    pub resolved: Option<u64>,
    /// Coordinates waiting for enrichment.
    pub queued_packages: Option<u64>,
    /// Coordinates enriched so far.
    pub coordinates_done: Option<u64>,
    /// Coordinates currently known to enrichment; may grow.
    pub coordinates_total: Option<u64>,
    /// Assessments completed so far.
    pub assessments_done: Option<u64>,
    /// Assessments currently known; may grow.
    pub assessments_total: Option<u64>,
    /// Coordinates served from cache.
    pub cached: Option<u64>,
    /// Coordinates fetched from metadata sources.
    pub fetched: Option<u64>,
    /// Coordinate fetches that failed.
    pub fetch_failed: Option<u64>,
}

/// Displayable progress from one full replacement snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Progress {
    /// Actual execution stage.
    pub phase: Phase,
    /// Current attempt, which may change without a new revision.
    pub attempt: u64,
    /// Only measurements supplied in this snapshot.
    pub counts: Counts,
}

/// Allowlisted job failure codes; never raw executor diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    /// Resolution exceeded its execution budget.
    ResolutionTimeout,
    /// Dependency resolution failed.
    ResolutionFailed,
    /// The document exceeded the output cap.
    OutputTooLarge,
    /// The inventory cannot be represented as SPDX.
    UnrepresentableSpdx,
    /// The parser contract changed.
    ParserContractChanged,
    /// Execution failed.
    ExecutionFailed,
    /// Execution metadata is no longer available.
    ExecutionRecordUnavailable,
    /// An upstream response was invalid.
    InvalidResponse,
    /// No usable package evidence was found.
    NoManifestEvidence,
    /// A future failure code, rendered with a static diagnostic only.
    #[serde(other)]
    Unknown,
}

impl FailureCode {
    /// The safe wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResolutionTimeout => "resolution_timeout",
            Self::ResolutionFailed => "resolution_failed",
            Self::OutputTooLarge => "output_too_large",
            Self::UnrepresentableSpdx => "unrepresentable_spdx",
            Self::ParserContractChanged => "parser_contract_changed",
            Self::ExecutionFailed => "execution_failed",
            Self::ExecutionRecordUnavailable => "execution_record_unavailable",
            Self::InvalidResponse => "invalid_response",
            Self::NoManifestEvidence => "no_manifest_evidence",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireState {
    Queued,
    Running,
    Succeeded,
    Failed,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
pub(super) struct Accepted {
    pub id: String,
    state: WireState,
    // Expiry is authoritative at the service; a reconnect returns 404 after expiry.
    #[serde(rename = "expires_at")]
    _expires_at: String,
    pub status_url: String,
    pub events_url: String,
    pub result_url: String,
}

impl Accepted {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, ApiError> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| ApiError::protocol("invalid job acceptance"))?;
        if value.state != WireState::Queued || !valid_id(&value.id) {
            return Err(ApiError::protocol("invalid job acceptance"));
        }
        value.check_link(&value.status_url, "")?;
        value.check_link(&value.events_url, "/events")?;
        value.check_link(&value.result_url, "/result")?;
        Ok(value)
    }

    pub(super) fn check_link(&self, link: &str, suffix: &str) -> Result<(), ApiError> {
        if link != format!("{JOBS_PATH}/{}{suffix}", self.id) {
            return Err(ApiError::protocol("invalid job resource link"));
        }
        Ok(())
    }

    pub(super) fn resolve(origin: &Url, link: &str) -> Result<Url, ApiError> {
        // Links were checked against canonical relative paths, never arbitrary URLs.
        origin
            .join(link)
            .map_err(|_| ApiError::protocol("invalid job resource link"))
    }
}

// A custom field deserializer makes a missing nullable field an error.
fn required_failure<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<FailureCode>, D::Error> {
    Option::<FailureCode>::deserialize(deserializer)
}

#[derive(Deserialize)]
struct WireSnapshot {
    id: String,
    kind: String,
    format: String,
    state: WireState,
    #[serde(flatten)]
    pub progress: Progress,
    #[serde(deserialize_with = "required_failure")]
    error: Option<FailureCode>,
    result_url: String,
    #[serde(rename = "expires_at")]
    _expires_at: String,
    pub revision: u64,
}

/// Control outcome carries only already-validated failure data.
pub(super) enum State {
    Pending,
    Succeeded,
    Failed(FailureCode),
}

pub(super) struct Snapshot {
    pub state: State,
    pub progress: Progress,
    pub revision: u64,
}

impl Snapshot {
    pub(super) fn parse(
        bytes: &[u8],
        event_id: &str,
        job: &Accepted,
        operation: Operation,
        previous: Option<u64>,
    ) -> Result<Self, ApiError> {
        let snapshot: WireSnapshot = serde_json::from_slice(bytes)
            .map_err(|_| ApiError::protocol("invalid job snapshot"))?;
        let event_revision = event_id.parse::<u64>().ok();
        if snapshot.id != job.id
            || snapshot.kind != operation.kind()
            || snapshot.format != operation.format()
        {
            return Err(ApiError::protocol("job snapshot does not match submission"));
        }
        if event_revision != Some(snapshot.revision)
            || previous.is_some_and(|revision| snapshot.revision < revision)
        {
            return Err(ApiError::protocol("invalid job revision"));
        }
        job.check_link(&snapshot.result_url, "/result")?;
        let state = match (snapshot.state, snapshot.error) {
            (WireState::Queued | WireState::Running, None) => State::Pending,
            (WireState::Succeeded, None) => State::Succeeded,
            (WireState::Failed, Some(code)) => State::Failed(code),
            (WireState::Unknown, _) => {
                return Err(ApiError::protocol(
                    "unfamiliar job state cannot establish completion",
                ));
            }
            _ => return Err(ApiError::protocol("invalid job failure state")),
        };
        Ok(Self {
            state,
            progress: snapshot.progress,
            revision: snapshot.revision,
        })
    }
}

fn valid_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests;
