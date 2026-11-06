//! Recorded Git identity, never publisher repository metadata or license proof.
use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;

use super::string;

/// An unambiguous, credential-safe Git source recorded in the input document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitSource {
    /// Exact source-owned repository URL as recorded, without normalization.
    pub git: String,
    /// Exact recorded revision, when unambiguous and present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
}

pub(super) fn valid_url(git: &str) -> bool {
    let Ok(url) = url::Url::parse(git) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https" | "ssh" | "git")
        && url.host_str().is_some()
        && url.password().is_none()
        && (url.username().is_empty() || url.scheme() == "ssh")
        && url.query().is_none()
        && url.fragment().is_none()
        && !git.chars().any(char::is_whitespace)
}

pub(super) fn recorded(component: &Value) -> Option<GitSource> {
    if unique_property(component, "githits:source_kind")? != "LOCKED_PACKAGE_SOURCE_KIND_GIT" {
        return None;
    }
    let locations: Value =
        serde_json::from_str(unique_property(component, "githits:source_locations")?).ok()?;
    let repositories: BTreeSet<_> = locations
        .as_array()?
        .iter()
        .filter(|location| {
            string(location, "kind") == Some("vcs_repository")
                && location
                    .get("owner")
                    .and_then(|owner| string(owner, "type"))
                    == Some("source")
        })
        .map(|location| string(location, "url"))
        .collect();
    // Judge ambiguity before validation: an unsafe or malformed alternative
    // must not be discarded to manufacture a unique matching source.
    if repositories.len() != 1 {
        return None;
    }
    let git = repositories.first().copied().flatten()?;
    if !valid_url(git) {
        return None;
    }
    Some(GitSource {
        git: git.to_owned(),
        rev: unique_property(component, "githits:source_revision")
            .filter(|rev| !rev.trim().is_empty())
            .map(str::to_owned),
    })
}

fn unique_property<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    let mut values = value
        .get("properties")?
        .as_array()?
        .iter()
        .filter(|p| string(p, "name") == Some(name))
        .map(|p| string(p, "value"));
    let first = values.next()??;
    values.all(|value| value == Some(first)).then_some(first)
}
