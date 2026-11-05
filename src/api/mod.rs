//! Boundary with GitHits SBOM, audit and license-report operations, `POST /v1/experimental/lockfile-jobs`.
//!
//! Everything the service's contract dictates lives here and nowhere else:
//! upload limits and filename rules ([`upload`]), the problem-document shape
//! ([`problem`]), request construction and status interpretation ([`http`]),
//! and the little the client needs to know about a returned document. Other
//! modules reach the network only through [`SbomApi`], [`AuditApi`] or [`LicensesApi`] so tests
//! substitute a fake. See `docs/implementation/sbom-api-contract.md` for the
//! client rules this module honors.

use std::fmt;
use std::io;
use std::time::Duration;

use thiserror::Error;

pub mod audit;
pub mod http;
pub mod jobs;
pub mod licenses;
pub mod problem;
mod sse;
pub mod upload;

pub use problem::{Code, FileFailure, FileStatus, Problem};
pub use upload::{UploadError, UploadFile, UploadSet};

/// Production API origin.
pub const DEFAULT_ORIGIN: &str = "https://api.githits.dev";
/// Path for asynchronous SBOM/audit job submission.
pub const JOBS_PATH: &str = "/v1/experimental/lockfile-jobs";
const LICENSES_PATH: &str = "/v1/experimental/license-reports";
/// Maximum number of files in one upload.
pub const MAX_FILES: usize = 256;
/// Maximum size of one uploaded file.
pub const MAX_FILE_BYTES: u64 = 5_242_880;
/// Maximum size of the whole multipart body including framing.
pub const MAX_BODY_BYTES: u64 = 8_000_000;
/// Maximum length of an upload filename in UTF-8 bytes.
pub const MAX_PATH_BYTES: usize = 1_024;
/// Maximum size of a successful response body.
pub const MAX_RESPONSE_BYTES: usize = 16_777_216;
/// How much of an error body the client reads before parsing it.
pub const MAX_PROBLEM_BYTES: usize = 65_536;
/// Maximum acceptance body and SSE framing budget (field lines and delimiters).
pub const MAX_EVENT_BYTES: usize = 65_536;
/// Per-header and per-read allowance for events, above the public keepalive/opening budgets.
pub const STREAM_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum time to establish a connection, independent of response read budgets.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Finite submission/result allowance, sized for submission: 30 seconds for
/// upload collection, 150 seconds for upstream admission, 30 for delivery.
///
/// Applies through response headers, then independently to each body read;
/// this is not a single deadline through the complete response body.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(210);
/// Attribution sent as `X-GitHits-Client-Name` and in the user agent.
pub const CLIENT_NAME: &str = "githits-scan";
/// Attribution sent as `X-GitHits-Client-Version` and in the user agent.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Document format requested from the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum OutputFormat {
    /// CycloneDX 1.7 JSON, `application/vnd.cyclonedx+json`.
    #[serde(rename = "cyclonedx")]
    CycloneDx,
    /// SPDX 2.3 tag-value, `text/spdx`.
    #[serde(rename = "spdx")]
    Spdx,
    /// Human-readable inventory report, `text/plain`.
    #[serde(rename = "text")]
    Text,
}

impl OutputFormat {
    /// The `format` query value.
    #[must_use]
    pub const fn query_value(self) -> &'static str {
        match self {
            Self::CycloneDx => "cyclonedx",
            Self::Spdx => "spdx",
            Self::Text => "text",
        }
    }
}

/// A document returned by the service, kept as the exact bytes received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// The response body, unchanged.
    pub bytes: Vec<u8>,
}

impl Document {
    /// The `githits:completeness` property of a CycloneDX document, looked up
    /// by name because the schema is an extensible subset that must never be
    /// deserialized into a closed struct. `None` for other formats or when the
    /// property is absent.
    #[must_use]
    pub fn completeness(&self) -> Option<String> {
        let value: serde_json::Value = serde_json::from_slice(&self.bytes).ok()?;
        value
            .get("properties")?
            .as_array()?
            .iter()
            .find(|property| {
                property.get("name").and_then(|n| n.as_str()) == Some("githits:completeness")
            })?
            .get("value")?
            .as_str()
            .map(str::to_owned)
    }
}

/// A validated snapshot or an actual client transport transition.
///
/// Commands own human wording; transport transitions are not server phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressEvent {
    /// Full replacement measurements from the service.
    Snapshot(jobs::Progress),
    /// An established stream was lost; the next operation is a fresh opening.
    Reconnecting,
    /// Execution succeeded; the next operation retrieves the document.
    Downloading,
}

/// The one operation the tool needs from the service.
pub trait SbomApi {
    /// Upload the set and return the generated document.
    ///
    /// Submit exactly once, consume current snapshots and download only after success.
    /// Established stream loss reopens with authentication; no submission or result
    /// retry occurs. The callback receives snapshots plus reconnection and download
    /// transitions before the corresponding request. A callback error releases the
    /// stream and stops before the next request without cancelling the job.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] for a problem document, an unexpected status, an
    /// oversized document, or a transport failure.
    fn generate(
        &self,
        upload: UploadSet,
        format: OutputFormat,
        progress: &mut dyn FnMut(&ProgressEvent) -> io::Result<()>,
    ) -> Result<Document, ApiError>;
}

/// Audit submission using the same single-submit progress/result contract as [`SbomApi`].
pub trait AuditApi {
    /// Submit one combined analysis, observe snapshots and return a typed audit report.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] for admission, stream/result, size or report-decoding failure.
    fn audit(
        &self,
        upload: UploadSet,
        progress: &mut dyn FnMut(&ProgressEvent) -> io::Result<()>,
    ) -> Result<audit::Report, ApiError>;
}

/// Dependency-license reporting through the shared asynchronous analysis flow.
pub trait LicensesApi {
    /// Submit one CycloneDX analysis and retrieve its licenses view after success.
    ///
    /// # Errors
    /// Returns an [`ApiError`] for admission, stream, download or report failure.
    fn report(
        &self,
        upload: UploadSet,
        progress: &mut dyn FnMut(&ProgressEvent) -> io::Result<()>,
    ) -> Result<licenses::Report, ApiError>;
}

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Sbom(OutputFormat),
    Audit,
    Licenses,
}

impl Operation {
    const fn kind(self) -> &'static str {
        match self {
            Self::Sbom(_) | Self::Licenses => "sbom",
            Self::Audit => "audit",
        }
    }
    const fn format(self) -> &'static str {
        match self {
            Self::Sbom(format) => format.query_value(),
            Self::Audit => "json",
            Self::Licenses => "cyclonedx",
        }
    }
}

/// Why a request did not yield a document.
#[derive(Debug, Error)]
pub enum ApiError {
    /// The service answered with a problem document.
    #[error("{}", describe(problem, retry_after.as_deref()))]
    Problem {
        /// The parsed problem, boxed to keep the error small.
        problem: Box<Problem>,
        /// The raw `Retry-After` header, present with `RATE_LIMITED`.
        retry_after: Option<String>,
    },
    /// A status without a parsable problem document: a redirect (never
    /// followed, so the token stays with the configured origin), the
    /// documented empty 500, or a proxy response.
    #[error("unexpected HTTP status {status}{}{}", request_suffix(request_id.as_deref()), status_action(*status))]
    Unexpected {
        /// The HTTP status.
        status: u16,
        /// The `X-Request-ID` header when present.
        request_id: Option<String>,
    },
    /// The document exceeded the documented output limit.
    #[error("the document exceeds the {MAX_RESPONSE_BYTES}-byte response limit")]
    ResponseTooLarge,
    /// The public job protocol was malformed; raw payloads are never displayed.
    #[error("invalid analysis response: {reason}{}", request_suffix(request_id.as_deref()))]
    Protocol {
        /// Static, client-authored explanation.
        reason: &'static str,
        /// Response request ID when available.
        request_id: Option<String>,
    },
    /// A terminal failed snapshot; only the authored allowlisted code is shown.
    #[error("analysis failed: {}{}\n  action: {}", code.as_str(), request_suffix(request_id.as_deref()), failure_action(*code))]
    JobFailed {
        /// Allowlisted execution failure.
        code: jobs::FailureCode,
        /// Event response request ID when available.
        request_id: Option<String>,
    },
    /// Writing progress failed; the stream is released.
    #[error("cannot write analysis progress")]
    Progress(#[source] io::Error),
    /// The request could not be sent or the connection failed.
    #[error(
        "request to the GitHits API failed; check GITHITS_API_URL, network connectivity and proxy settings"
    )]
    Transport(#[source] reqwest::Error),
    /// The response body could not be read.
    #[error(
        "cannot read the API response; check GITHITS_API_URL, network connectivity and proxy settings"
    )]
    Read(#[source] io::Error),
}

impl ApiError {
    /// Whether repeating this invocation requires changing caller inputs or access.
    #[must_use]
    pub fn is_caller_error(&self) -> bool {
        match self {
            Self::Problem { problem, .. } => match problem.code {
                Code::AuthenticationRequired
                | Code::Forbidden
                | Code::AccountInactive
                | Code::TermsAcceptanceRequired
                | Code::FeatureFlagRequired
                | Code::ValidationError
                | Code::MethodNotAllowed
                | Code::InputTooLarge
                | Code::UnsupportedMediaType
                | Code::UnusableManifest
                | Code::NoManifestEvidence
                | Code::UnrepresentableSpdx
                | Code::SbomOutputTooLarge
                | Code::LicenseReportTooLarge
                | Code::IncompatibleAnalysis => true,
                Code::AnalysisFailed => problem.failure_code.is_some_and(caller_failure),
                Code::Other(_) => caller_status(problem.status),
                _ => false,
            },
            Self::Unexpected { status, .. } => caller_status(*status),
            Self::JobFailed { code, .. } => caller_failure(*code),
            _ => false,
        }
    }

    pub(super) const fn protocol(reason: &'static str) -> Self {
        Self::Protocol {
            reason,
            request_id: None,
        }
    }

    pub(super) fn with_request_id(mut self, id: Option<String>) -> Self {
        if let Self::Protocol { request_id, .. } = &mut self {
            *request_id = id;
        }
        self
    }
}

const fn caller_status(status: u16) -> bool {
    matches!(status, 400..=499) && !matches!(status, 408 | 429)
}

const fn caller_failure(code: jobs::FailureCode) -> bool {
    matches!(
        code,
        jobs::FailureCode::UnrepresentableSpdx
            | jobs::FailureCode::NoManifestEvidence
            | jobs::FailureCode::OutputTooLarge
    )
}

fn status_action(status: u16) -> String {
    match status {
        401 => "\n  action: the supplied token was not accepted; check GITHITS_API_TOKEN or proxy authentication".into(),
        405 => format!("\n  action: {}", Code::MethodNotAllowed.action()),
        _ => String::new(),
    }
}

fn request_suffix(request_id: Option<&str>) -> String {
    request_id.map_or_else(String::new, |id| format!(" (request id {id})"))
}

const fn failure_action(code: jobs::FailureCode) -> &'static str {
    use jobs::FailureCode;
    match code {
        FailureCode::OutputTooLarge => {
            "scan a smaller tree or exclude unneeded lockfiles with --exclude"
        }
        FailureCode::UnrepresentableSpdx => Code::UnrepresentableSpdx.action(),
        FailureCode::Unknown => {
            "the service returned an unfamiliar failure code; report with the request id"
        }
        FailureCode::NoManifestEvidence => Code::NoManifestEvidence.action(),
        FailureCode::ResolutionTimeout => {
            "dependency resolution exceeded the service deadline; try scanning a smaller tree"
        }
        FailureCode::ResolutionFailed => {
            "inspect the selected manifests; report persistent resolution failures with the request id"
        }
        FailureCode::ExecutionRecordUnavailable => {
            "the service no longer has the execution record; run again"
        }
        FailureCode::ParserContractChanged
        | FailureCode::ExecutionFailed
        | FailureCode::InvalidResponse => {
            "the service could not complete analysis; report the failure code and request id to GitHits"
        }
    }
}

/// Multi-line description of a problem: what happened, the request id for
/// support, and the documented caller action.
fn describe(problem: &Problem, retry_after: Option<&str>) -> String {
    let mut text = format!(
        "{} (HTTP {}): {}",
        problem.code.as_str(),
        problem.status,
        problem.detail
    );
    if !problem.instance.is_empty() {
        let _ = fmt::Write::write_fmt(
            &mut text,
            format_args!("\n  request id: {}", problem.instance),
        );
    }
    for failure in &problem.files {
        let _ = fmt::Write::write_fmt(
            &mut text,
            format_args!("\n  {}: {}", failure.path, failure.status.as_str()),
        );
    }
    if let Some(code) = problem.failure_code {
        let _ = fmt::Write::write_fmt(&mut text, format_args!("\n  failure: {}", code.as_str()));
    }
    if let Some(value) = retry_after {
        let suffix = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
            "s"
        } else {
            ""
        };
        let _ = fmt::Write::write_fmt(&mut text, format_args!("\n  retry after: {value}{suffix}"));
    }
    if let Some(url) = &problem.terms_url {
        let _ = fmt::Write::write_fmt(&mut text, format_args!("\n  terms: {url}"));
    }
    if let Some(url) = &problem.acceptance_url {
        let _ = fmt::Write::write_fmt(&mut text, format_args!("\n  accept at: {url}"));
    }
    let _ = fmt::Write::write_fmt(
        &mut text,
        format_args!("\n  action: {}", problem.code.action()),
    );
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completeness_is_read_by_property_name() {
        let document = Document {
            bytes: br#"{"bomFormat":"CycloneDX","properties":[{"name":"x","value":"y"},{"name":"githits:completeness","value":"recorded_lockfile_inventory"}]}"#.to_vec(),
        };
        assert_eq!(
            document.completeness().as_deref(),
            Some("recorded_lockfile_inventory")
        );

        let without = Document {
            bytes: br#"{"bomFormat":"CycloneDX","properties":[]}"#.to_vec(),
        };
        assert_eq!(without.completeness(), None);

        let spdx = Document {
            bytes: b"SPDXVersion: SPDX-2.3\n".to_vec(),
        };
        assert_eq!(spdx.completeness(), None);
    }

    #[test]
    fn problem_errors_describe_code_request_id_files_and_action() {
        let problem = problem::parse(
            br#"{"status":422,"code":"UNUSABLE_MANIFEST","title":"t","detail":"One file is unusable.","instance":"req-1","files":[{"path":"a/b.lock","status":"unparsed"}]}"#,
        )
        .expect("problem");
        let error = ApiError::Problem {
            problem: Box::new(problem),
            retry_after: None,
        };

        let text = error.to_string();

        assert_eq!(
            text,
            "UNUSABLE_MANIFEST (HTTP 422): One file is unusable.\n  request id: req-1\n  a/b.lock: unparsed\n  action: exclude unrelated projects with --exclude <glob>, or fix the listed files and run again"
        );
    }

    #[test]
    fn rate_limit_errors_show_the_retry_after_header() {
        let problem = problem::parse(
            br#"{"status":429,"code":"RATE_LIMITED","detail":"Slow down.","instance":"req-2"}"#,
        )
        .expect("problem");
        let huge = "9".repeat(128);
        let cases = [
            ("1".to_owned(), "1s".to_owned()),
            ("0".to_owned(), "0s".to_owned()),
            ("0007".to_owned(), "0007s".to_owned()),
            (huge.clone(), format!("{huge}s")),
            (
                "Wed, 21 Oct 2015 07:28:00 GMT".to_owned(),
                "Wed, 21 Oct 2015 07:28:00 GMT".to_owned(),
            ),
            ("tomorrow".to_owned(), "tomorrow".to_owned()),
            (String::new(), String::new()),
        ];

        for (header, expected_retry_after) in cases {
            let error = ApiError::Problem {
                problem: Box::new(problem.clone()),
                retry_after: Some(header.clone()),
            };

            assert_eq!(
                error.to_string(),
                format!(
                    "RATE_LIMITED (HTTP 429): Slow down.\n  request id: req-2\n  retry after: {expected_retry_after}\n  action: wait for the retry-after period and run again"
                ),
                "Retry-After {header:?}"
            );
        }
    }

    #[test]
    fn unexpected_status_names_the_request_id_when_present() {
        let with = ApiError::Unexpected {
            status: 502,
            request_id: Some("req-3".into()),
        };
        let without = ApiError::Unexpected {
            status: 500,
            request_id: None,
        };
        assert_eq!(
            with.to_string(),
            "unexpected HTTP status 502 (request id req-3)"
        );
        assert_eq!(without.to_string(), "unexpected HTTP status 500");
    }
}

#[cfg(test)]
mod caller_error_tests {
    use super::*;

    #[test]
    fn caller_action_classification_matches_problem_and_terminal_forms() {
        for (code, status, failure, caller) in [
            (Code::AuthenticationRequired, 401, None, true),
            (Code::Forbidden, 403, None, true),
            (Code::TermsAcceptanceRequired, 403, None, true),
            (Code::AnalysisPending, 409, None, false),
            (Code::AnalysisNotFound, 404, None, false),
            (Code::AnalysisFailed, 409, None, false),
            (
                Code::AnalysisFailed,
                409,
                Some(jobs::FailureCode::NoManifestEvidence),
                true,
            ),
            (Code::RateLimited, 429, None, false),
            (Code::UnrepresentableSpdx, 422, None, true),
        ] {
            let problem = Problem {
                status,
                code,
                title: String::new(),
                detail: String::new(),
                instance: String::new(),
                files: vec![],
                failure_code: failure,
                terms_url: None,
                acceptance_url: None,
            };
            assert_eq!(
                ApiError::Problem {
                    problem: Box::new(problem),
                    retry_after: None
                }
                .is_caller_error(),
                caller
            );
        }
        for (code, caller) in [
            (jobs::FailureCode::NoManifestEvidence, true),
            (jobs::FailureCode::UnrepresentableSpdx, true),
            (jobs::FailureCode::OutputTooLarge, true),
            (jobs::FailureCode::ResolutionTimeout, false),
            (jobs::FailureCode::ExecutionRecordUnavailable, false),
        ] {
            assert_eq!(
                ApiError::JobFailed {
                    code,
                    request_id: None
                }
                .is_caller_error(),
                caller
            );
        }
    }
}
