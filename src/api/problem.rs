//! RFC 9457 problem documents as the GitHits API returns them.
//!
//! Clients branch on the stable `code`, never on `detail`. Every documented
//! code has a variant and a caller action; codes this version does not know
//! are preserved as [`Code::Other`] so a newer service still produces a
//! readable error.

use serde::Deserialize;

use super::jobs::FailureCode;

/// A problem document. Fields other than `status` and `code` default when
/// absent so a truncated or minimal document still yields a typed error.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Problem {
    /// HTTP status carried in the document.
    pub status: u16,
    /// Stable error code.
    pub code: Code,
    /// Short title.
    #[serde(default)]
    pub title: String,
    /// Client-safe explanation.
    #[serde(default)]
    pub detail: String,
    /// Request trace id, equal to the `X-Request-ID` header.
    #[serde(default)]
    pub instance: String,
    /// Side of a paired dependency-diff request associated with the problem.
    #[serde(default)]
    pub side: Option<Side>,
    /// Rejected files; present only with `UNUSABLE_MANIFEST`.
    #[serde(default)]
    pub files: Vec<FileFailure>,
    /// Allowlisted execution failure, present with `ANALYSIS_FAILED`.
    #[serde(default)]
    pub failure_code: Option<FailureCode>,
    /// Terms URL, present with some 403 problems.
    #[serde(default)]
    pub terms_url: Option<String>,
    /// Acceptance URL, present with some 403 problems.
    #[serde(default)]
    pub acceptance_url: Option<String>,
}

/// Side of a paired dependency-diff request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "String")]
pub enum Side {
    /// The base input.
    Base,
    /// The head input.
    Head,
    /// A side this version does not know.
    Other(String),
}

impl Side {
    /// The wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Base => "base",
            Self::Head => "head",
            Self::Other(value) => value,
        }
    }
}

impl From<String> for Side {
    fn from(value: String) -> Self {
        match value.as_str() {
            "base" => Self::Base,
            "head" => Self::Head,
            _ => Self::Other(value),
        }
    }
}

/// One rejected upload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FileFailure {
    /// The repository-relative filename as uploaded.
    pub path: String,
    /// Why the file could not contribute evidence.
    pub status: FileStatus,
}

/// Why the service rejected one file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "String")]
pub enum FileStatus {
    /// Not a supported lockfile or manifest.
    Unsupported,
    /// Contents are not UTF-8.
    InvalidUtf8,
    /// Recognized but could not be parsed.
    Unparsed,
    /// A status this version does not know.
    Other(String),
}

impl FileStatus {
    /// The wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Unsupported => "unsupported",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::Unparsed => "unparsed",
            Self::Other(value) => value,
        }
    }
}

impl From<String> for FileStatus {
    fn from(value: String) -> Self {
        match value.as_str() {
            "unsupported" => Self::Unsupported,
            "invalid_utf8" => Self::InvalidUtf8,
            "unparsed" => Self::Unparsed,
            _ => Self::Other(value),
        }
    }
}

/// Stable error codes reported by the service.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "String")]
pub enum Code {
    /// 400: the request shape was wrong.
    ValidationError,
    /// 401: no valid bearer token.
    AuthenticationRequired,
    /// 403: the token's account may not use the operation.
    Forbidden,
    /// 403: the account is inactive.
    AccountInactive,
    /// 403: terms must be accepted first.
    TermsAcceptanceRequired,
    /// 403: the operation is behind a feature flag.
    FeatureFlagRequired,
    /// 405: wrong HTTP method.
    MethodNotAllowed,
    /// 408: the upload did not finish within the service's deadline.
    UploadTimeout,
    /// 413: the upload exceeded a limit.
    InputTooLarge,
    /// 415: the request was not multipart.
    UnsupportedMediaType,
    /// 422: at least one file could not be used; see `files`.
    UnusableManifest,
    /// 422: the files contained no package evidence.
    NoManifestEvidence,
    /// 422: one or more selected dependency groups are not available.
    InvalidDependencyGroups,
    /// 422: the inventory cannot be expressed as SPDX.
    UnrepresentableSpdx,
    /// 422: the document would exceed the output limit.
    SbomOutputTooLarge,
    /// 422: the dependency-license report exceeds the result limit.
    LicenseReportTooLarge,
    /// 409: the selected job cannot supply a licenses view.
    IncompatibleAnalysis,
    /// 429: rate limited; `Retry-After` may be present.
    RateLimited,
    /// 502: the upstream service failed.
    UpstreamError,
    /// 503: the SBOM operation is disabled.
    SbomUnavailable,
    /// 503: the upstream service is unavailable.
    UpstreamUnavailable,
    /// 504: generation exceeded the service deadline.
    Timeout,
    /// 409: the analysis result is not ready.
    AnalysisPending,
    /// 409: analysis ended in failure.
    AnalysisFailed,
    /// 404: absent, expired or owned by someone else.
    AnalysisNotFound,
    /// 503: asynchronous analysis admission is unavailable.
    AnalysisUnavailable,
    /// A code this version does not know.
    Other(String),
}

impl Code {
    /// The wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::ValidationError => "VALIDATION_ERROR",
            Self::AuthenticationRequired => "AUTHENTICATION_REQUIRED",
            Self::Forbidden => "FORBIDDEN",
            Self::AccountInactive => "ACCOUNT_INACTIVE",
            Self::TermsAcceptanceRequired => "TERMS_ACCEPTANCE_REQUIRED",
            Self::FeatureFlagRequired => "FEATURE_FLAG_REQUIRED",
            Self::MethodNotAllowed => "METHOD_NOT_ALLOWED",
            Self::UploadTimeout => "UPLOAD_TIMEOUT",
            Self::InputTooLarge => "INPUT_TOO_LARGE",
            Self::UnsupportedMediaType => "UNSUPPORTED_MEDIA_TYPE",
            Self::UnusableManifest => "UNUSABLE_MANIFEST",
            Self::NoManifestEvidence => "NO_MANIFEST_EVIDENCE",
            Self::InvalidDependencyGroups => "INVALID_DEPENDENCY_GROUPS",
            Self::UnrepresentableSpdx => "UNREPRESENTABLE_SPDX",
            Self::SbomOutputTooLarge => "SBOM_OUTPUT_TOO_LARGE",
            Self::LicenseReportTooLarge => "LICENSE_REPORT_TOO_LARGE",
            Self::IncompatibleAnalysis => "INCOMPATIBLE_ANALYSIS",
            Self::RateLimited => "RATE_LIMITED",
            Self::UpstreamError => "UPSTREAM_ERROR",
            Self::SbomUnavailable => "SBOM_UNAVAILABLE",
            Self::UpstreamUnavailable => "UPSTREAM_UNAVAILABLE",
            Self::Timeout => "TIMEOUT",
            Self::AnalysisPending => "ANALYSIS_PENDING",
            Self::AnalysisFailed => "ANALYSIS_FAILED",
            Self::AnalysisNotFound => "ANALYSIS_NOT_FOUND",
            Self::AnalysisUnavailable => "ANALYSIS_UNAVAILABLE",
            Self::Other(value) => value,
        }
    }

    /// What the documentation tells the caller to do for this code.
    #[must_use]
    pub const fn action(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed => {
                "check GITHITS_API_URL points to the API origin and the proxy permits API requests"
            }
            Self::ValidationError | Self::UnsupportedMediaType => {
                "this is a client bug; report it with the request id"
            }
            Self::AuthenticationRequired => {
                "set GITHITS_API_TOKEN to a valid token from https://app.githits.com/settings/tokens"
            }
            Self::Forbidden => {
                "resolve account access at https://app.githits.com before running again"
            }
            Self::AccountInactive => {
                "sign in at https://app.githits.com and contact support to reactivate your account before running again"
            }
            Self::FeatureFlagRequired => {
                "sign in at https://app.githits.com and request access to this feature before running again"
            }
            Self::TermsAcceptanceRequired => {
                "sign in at https://app.githits.com and accept the terms before running again"
            }
            Self::UploadTimeout => {
                "the upload did not finish in 30 seconds; check connectivity or scan a smaller tree"
            }
            Self::InputTooLarge => {
                "the client's limit check missed a case; report it with the request id"
            }
            Self::UnusableManifest => {
                "exclude unrelated projects with --exclude <glob>, or fix the listed files and run again"
            }
            Self::NoManifestEvidence => {
                "inspect the selected lockfiles and manifests for package evidence"
            }
            Self::InvalidDependencyGroups => {
                "select dependency groups available in the uploaded evidence"
            }
            Self::UnrepresentableSpdx => "run again with --format cyclonedx",
            Self::SbomOutputTooLarge => "scan a smaller tree",
            Self::LicenseReportTooLarge => {
                "scan a smaller tree or exclude unneeded package evidence"
            }
            Self::IncompatibleAnalysis => {
                "the analysis must be a CycloneDX SBOM job; report with the request id"
            }
            Self::RateLimited => "wait for the retry-after period and run again",
            Self::UpstreamError
            | Self::SbomUnavailable
            | Self::UpstreamUnavailable
            | Self::AnalysisUnavailable => "the service is unavailable; run again later",
            Self::Timeout => "generation exceeded the service deadline; run again later",
            Self::AnalysisPending => {
                "the analysis is still pending; wait for its terminal snapshot"
            }
            Self::AnalysisFailed => {
                "analysis failed; inspect the failure code before running again"
            }
            Self::AnalysisNotFound => {
                "the analysis is absent, expired, or belongs to another owner"
            }
            Self::Other(_) => "see https://docs.githits.com/api/errors",
        }
    }
}

impl From<String> for Code {
    fn from(value: String) -> Self {
        match value.as_str() {
            "VALIDATION_ERROR" => Self::ValidationError,
            "AUTHENTICATION_REQUIRED" => Self::AuthenticationRequired,
            "FORBIDDEN" => Self::Forbidden,
            "ACCOUNT_INACTIVE" => Self::AccountInactive,
            "TERMS_ACCEPTANCE_REQUIRED" => Self::TermsAcceptanceRequired,
            "FEATURE_FLAG_REQUIRED" => Self::FeatureFlagRequired,
            "METHOD_NOT_ALLOWED" => Self::MethodNotAllowed,
            "UPLOAD_TIMEOUT" => Self::UploadTimeout,
            "INPUT_TOO_LARGE" => Self::InputTooLarge,
            "UNSUPPORTED_MEDIA_TYPE" => Self::UnsupportedMediaType,
            "UNUSABLE_MANIFEST" => Self::UnusableManifest,
            "NO_MANIFEST_EVIDENCE" => Self::NoManifestEvidence,
            "INVALID_DEPENDENCY_GROUPS" => Self::InvalidDependencyGroups,
            "UNREPRESENTABLE_SPDX" => Self::UnrepresentableSpdx,
            "SBOM_OUTPUT_TOO_LARGE" => Self::SbomOutputTooLarge,
            "LICENSE_REPORT_TOO_LARGE" => Self::LicenseReportTooLarge,
            "INCOMPATIBLE_ANALYSIS" => Self::IncompatibleAnalysis,
            "RATE_LIMITED" => Self::RateLimited,
            "UPSTREAM_ERROR" => Self::UpstreamError,
            "SBOM_UNAVAILABLE" => Self::SbomUnavailable,
            "UPSTREAM_UNAVAILABLE" => Self::UpstreamUnavailable,
            "TIMEOUT" => Self::Timeout,
            "ANALYSIS_PENDING" => Self::AnalysisPending,
            "ANALYSIS_FAILED" => Self::AnalysisFailed,
            "ANALYSIS_NOT_FOUND" => Self::AnalysisNotFound,
            "ANALYSIS_UNAVAILABLE" => Self::AnalysisUnavailable,
            _ => Self::Other(value),
        }
    }
}

/// Parse a problem document. `None` when the body is not one, for example an
/// HTML page from a proxy or the documented empty 500.
#[must_use]
pub fn parse(body: &[u8]) -> Option<Problem> {
    serde_json::from_slice(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENTED: &[(&str, u16)] = &[
        ("VALIDATION_ERROR", 400),
        ("AUTHENTICATION_REQUIRED", 401),
        ("FORBIDDEN", 403),
        ("ACCOUNT_INACTIVE", 403),
        ("TERMS_ACCEPTANCE_REQUIRED", 403),
        ("FEATURE_FLAG_REQUIRED", 403),
        ("METHOD_NOT_ALLOWED", 405),
        ("UPLOAD_TIMEOUT", 408),
        ("INPUT_TOO_LARGE", 413),
        ("UNSUPPORTED_MEDIA_TYPE", 415),
        ("UNUSABLE_MANIFEST", 422),
        ("NO_MANIFEST_EVIDENCE", 422),
        ("INVALID_DEPENDENCY_GROUPS", 422),
        ("UNREPRESENTABLE_SPDX", 422),
        ("SBOM_OUTPUT_TOO_LARGE", 422),
        ("LICENSE_REPORT_TOO_LARGE", 422),
        ("INCOMPATIBLE_ANALYSIS", 409),
        ("RATE_LIMITED", 429),
        ("UPSTREAM_ERROR", 502),
        ("SBOM_UNAVAILABLE", 503),
        ("UPSTREAM_UNAVAILABLE", 503),
        ("TIMEOUT", 504),
        ("ANALYSIS_PENDING", 409),
        ("ANALYSIS_FAILED", 409),
        ("ANALYSIS_NOT_FOUND", 404),
        ("ANALYSIS_UNAVAILABLE", 503),
    ];

    #[test]
    fn every_documented_code_round_trips_to_a_known_variant() {
        for (code, status) in DOCUMENTED {
            let body = format!(
                r#"{{"type":"about:blank","title":"t","status":{status},"detail":"d","instance":"i","code":"{code}"}}"#
            );
            let problem = parse(body.as_bytes()).expect(code);
            assert!(!matches!(problem.code, Code::Other(_)), "{code}");
            assert_eq!(problem.code.as_str(), *code);
            assert_eq!(problem.status, *status);
            assert!(
                !problem.code.action().is_empty(),
                "expected a non-empty value"
            );
        }
    }

    #[test]
    fn unknown_codes_and_statuses_are_preserved() {
        let problem =
            parse(br#"{"status":422,"code":"BRAND_NEW","files":[{"path":"x","status":"weird"}]}"#)
                .expect("problem");

        assert_eq!(problem.code, Code::Other("BRAND_NEW".into()));
        assert_eq!(problem.code.as_str(), "BRAND_NEW");
        assert_eq!(problem.files[0].status, FileStatus::Other("weird".into()));
        assert_eq!(problem.files[0].status.as_str(), "weird");
    }

    #[test]
    fn unusable_manifest_lists_every_rejected_file() {
        let problem = parse(
            br#"{"status":422,"code":"UNUSABLE_MANIFEST","title":"Unusable","detail":"d","instance":"req","files":[{"path":"a/manifest.txt","status":"unsupported"},{"path":"b.lock","status":"invalid_utf8"},{"path":"c.lock","status":"unparsed"}]}"#,
        )
        .expect("problem");

        assert_eq!(
            problem.files,
            vec![
                FileFailure {
                    path: "a/manifest.txt".into(),
                    status: FileStatus::Unsupported
                },
                FileFailure {
                    path: "b.lock".into(),
                    status: FileStatus::InvalidUtf8
                },
                FileFailure {
                    path: "c.lock".into(),
                    status: FileStatus::Unparsed
                },
            ]
        );
    }

    #[test]
    fn optional_urls_and_unknown_fields_are_tolerated() {
        let problem = parse(
            br#"{"status":403,"code":"TERMS_ACCEPTANCE_REQUIRED","terms_url":"https://t","acceptance_url":"https://a","extra":1}"#,
        )
        .expect("problem");

        assert_eq!(problem.terms_url.as_deref(), Some("https://t"));
        assert_eq!(problem.acceptance_url.as_deref(), Some("https://a"));
        assert!(problem.files.is_empty(), "{:?}", problem.files);
    }

    #[test]
    fn non_problem_bodies_do_not_parse() {
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"<html>502</html>"), None);
        assert_eq!(parse(br#"{"status":"x"}"#), None);
    }
}
