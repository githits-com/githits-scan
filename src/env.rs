//! Process-environment settings: the API token and origin.
//!
//! Values are read through an injected source so tests exercise validation
//! without mutating the process environment (Rust 2024 makes that unsafe, and
//! this crate forbids unsafe code). `src/cli.rs` passes `std::env::var_os`.
//! The token is the only credential the tool handles; it never appears in
//! `Debug` output, error messages, or logs.

use std::ffi::OsString;
use std::fmt;

use thiserror::Error;
use url::{Host, Url};

use crate::api;

/// Environment variable that holds the bearer token.
pub const TOKEN_VARIABLE: &str = "GITHITS_API_TOKEN";
/// Environment variable that overrides the API origin.
pub const ORIGIN_VARIABLE: &str = "GITHITS_API_URL";

/// The bearer token. `Debug` redacts it; only the HTTP client reads it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// The raw token for the `Authorization` header. Do not log or display
    /// the returned value.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// Settings resolved from the environment.
#[derive(Debug, Clone)]
pub struct Environment {
    /// Bearer token for the GitHits API.
    pub token: Token,
    /// API origin; only scheme, host, and port are used.
    pub origin: Url,
}

/// Why the environment could not be resolved.
///
/// Messages never include the token value, and never the raw origin value
/// either: an origin could carry userinfo or a query that the caller did not
/// mean to publish in a log.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EnvError {
    /// The token variable is unset or blank.
    #[error(
        "{TOKEN_VARIABLE} is not set; create a token at https://app.githits.com/settings/tokens and export it"
    )]
    MissingToken,
    /// The token contains characters that cannot travel in an HTTP header.
    #[error("{TOKEN_VARIABLE} must be printable ASCII without spaces")]
    InvalidToken,
    /// The origin variable is not exactly `scheme://host[:port]`.
    #[error(
        "{ORIGIN_VARIABLE} must be an origin of the form https://host[:port] with no path, credentials, query, or fragment"
    )]
    InvalidOrigin,
    /// The origin is not HTTPS and not a loopback host.
    #[error(
        "{ORIGIN_VARIABLE} must use https (http is accepted only for localhost, 127.0.0.1, and [::1]): {scheme}://{host}"
    )]
    InsecureOrigin {
        /// The rejected scheme.
        scheme: String,
        /// The host, the only part of the value that is safe to print.
        host: String,
    },
}

/// Resolve the environment through `source`, which yields a variable's value.
///
/// # Errors
///
/// Returns an [`EnvError`] when the token is missing or malformed, or when the
/// origin override is not a valid, secure URL.
pub fn from_source(source: impl Fn(&str) -> Option<OsString>) -> Result<Environment, EnvError> {
    let token = parse_token(source(TOKEN_VARIABLE))?;
    let origin = match source(ORIGIN_VARIABLE) {
        Some(value) => parse_origin(&value.to_string_lossy())?,
        None => parse_origin(api::DEFAULT_ORIGIN)?,
    };
    Ok(Environment { token, origin })
}

fn parse_token(value: Option<OsString>) -> Result<Token, EnvError> {
    let Some(value) = value else {
        return Err(EnvError::MissingToken);
    };
    let value = value.into_string().map_err(|_| EnvError::InvalidToken)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(EnvError::MissingToken);
    }
    if !trimmed.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(EnvError::InvalidToken);
    }
    Ok(Token(trimmed.to_owned()))
}

/// Parse and validate an origin: scheme, host, and optional port only, so no
/// credential or query can ride along into a request or a message. HTTPS is
/// required except for loopback hosts, which allow a local mock server during
/// development and tests.
fn parse_origin(value: &str) -> Result<Url, EnvError> {
    let value = value.trim();
    // Check the raw text, not the parsed URL: parsing normalizes `/a/..` to
    // `/`, which would let a path through the "origin only" rule.
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest.strip_suffix('/').unwrap_or(rest))
        .ok_or(EnvError::InvalidOrigin)?;
    if authority.contains(['/', '\\', '?', '#', '@']) {
        return Err(EnvError::InvalidOrigin);
    }
    let url = Url::parse(value).map_err(|_| EnvError::InvalidOrigin)?;
    let host = url.host().ok_or(EnvError::InvalidOrigin)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(EnvError::InvalidOrigin);
    }
    let loopback = match host {
        Host::Domain(name) => name == "localhost",
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    };
    if url.scheme() == "https" || (url.scheme() == "http" && loopback) {
        return Ok(url);
    }
    Err(EnvError::InsecureOrigin {
        scheme: url.scheme().to_owned(),
        host: host.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    #[test]
    fn resolves_the_token_and_the_default_origin() {
        let environment =
            from_source(source(&[(TOKEN_VARIABLE, " secret-value \n")])).expect("env");

        assert_eq!(environment.token.expose(), "secret-value");
        assert_eq!(environment.origin.as_str(), "https://api.githits.dev/");
    }

    #[test]
    fn a_missing_or_blank_token_is_an_error_that_names_the_variable() {
        assert_eq!(
            from_source(source(&[])).unwrap_err(),
            EnvError::MissingToken
        );
        assert_eq!(
            from_source(source(&[(TOKEN_VARIABLE, "  ")])).unwrap_err(),
            EnvError::MissingToken
        );
        assert!(EnvError::MissingToken.to_string().contains(TOKEN_VARIABLE));
    }

    #[test]
    fn a_token_with_unsendable_characters_is_rejected_without_being_echoed() {
        let error = from_source(source(&[(TOKEN_VARIABLE, "secret value")])).unwrap_err();

        assert_eq!(error, EnvError::InvalidToken);
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn debug_output_redacts_the_token() {
        let environment = from_source(source(&[(TOKEN_VARIABLE, "secret-value")])).expect("env");

        let debug = format!("{environment:?}");

        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains("secret-value"), "{debug}");
    }

    #[test]
    fn accepts_https_origins_and_loopback_http_origins() {
        for origin in [
            "https://api.example.com",
            "http://localhost:8080",
            "http://127.0.0.1:8080/",
            "http://[::1]:8080",
        ] {
            let environment =
                from_source(source(&[(TOKEN_VARIABLE, "t"), (ORIGIN_VARIABLE, origin)]))
                    .expect(origin);
            assert!(environment.origin.host().is_some(), "{origin}");
        }
    }

    #[test]
    fn rejects_insecure_origins_and_prints_only_scheme_and_host() {
        let insecure = from_source(source(&[
            (TOKEN_VARIABLE, "t"),
            (ORIGIN_VARIABLE, "http://api.githits.dev:8443"),
        ]))
        .unwrap_err();

        assert_eq!(
            insecure,
            EnvError::InsecureOrigin {
                scheme: "http".into(),
                host: "api.githits.dev".into()
            }
        );
        assert!(insecure.to_string().ends_with(": http://api.githits.dev"));
    }

    #[test]
    fn rejects_origins_that_are_not_bare_and_never_echoes_them() {
        for value in [
            "not a url",
            "api.githits.dev",
            "file:///tmp",
            "https://user:hunter2@api.githits.dev",
            "https://api.githits.dev/v1",
            "https://api.githits.dev/?token=hunter2",
            "https://api.githits.dev/#hunter2",
            "https://api.githits.dev/private/..",
            "https://api.githits.dev/.",
            "https://api.githits.dev\\private",
        ] {
            let error = from_source(source(&[(TOKEN_VARIABLE, "t"), (ORIGIN_VARIABLE, value)]))
                .unwrap_err();
            assert_eq!(error, EnvError::InvalidOrigin, "{value}");
            assert!(!error.to_string().contains("hunter2"), "{value}");
        }
    }
}
