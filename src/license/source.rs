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
    let kind = unique_property(component, "githits:source_kind").ok()??;
    if kind != "LOCKED_PACKAGE_SOURCE_KIND_GIT" {
        return None;
    }
    // Only an absent legacy property permits reading the condensed carriers.
    let git = match unique_property(component, "githits:source_locations").ok()? {
        Some(locations) => legacy_repository(locations)?,
        None => reference_repository(component)?.to_owned(),
    };
    Some(GitSource {
        git,
        rev: unique_property(component, "githits:source_revision")
            .ok()
            .flatten()
            .filter(|rev| !rev.trim().is_empty())
            .map(str::to_owned),
    })
}

fn legacy_repository(locations: &str) -> Option<String> {
    let locations: Value = serde_json::from_str(locations).ok()?;
    let repositories = locations
        .as_array()?
        .iter()
        .filter(|location| is_source_repository(location))
        .map(|location| string(location, "url"))
        .collect();
    unique_repository(&repositories).map(str::to_owned)
}

fn reference_repository(component: &Value) -> Option<&str> {
    let mut repositories: BTreeSet<_> = component
        .get("externalReferences")?
        .as_array()?
        .iter()
        .filter(|reference| string(reference, "type") == Some("vcs"))
        .filter_map(|reference| {
            let comment: Value = serde_json::from_str(string(reference, "comment")?).ok()?;
            is_source_repository(&comment).then(|| string(reference, "url"))
        })
        .collect();

    if let Some(omissions) = unique_property(component, "githits:source_location_omissions").ok()? {
        let omissions: Value = serde_json::from_str(omissions).ok()?;
        if omissions.as_array()?.iter().any(is_source_repository) {
            repositories.insert(None);
        }
    }
    unique_repository(&repositories)
}

fn is_source_repository(evidence: &Value) -> bool {
    string(evidence, "kind") == Some("vcs_repository")
        && evidence
            .get("owner")
            .and_then(|owner| string(owner, "type"))
            == Some("source")
}

fn unique_repository<'a>(repositories: &BTreeSet<Option<&'a str>>) -> Option<&'a str> {
    // Judge ambiguity before validation, including withheld and malformed URLs.
    if repositories.len() != 1 {
        return None;
    }
    let git = repositories.first().copied().flatten()?;
    valid_url(git).then_some(git)
}

// Absent properties are distinct from conflicting or non-string values.
fn unique_property<'a>(value: &'a Value, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = value
        .get("properties")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| string(p, "name") == Some(name))
        .map(|p| string(p, "value"));
    let Some(first) = values.next() else {
        return Ok(None);
    };
    let first = first.ok_or(())?;
    values
        .all(|value| value == Some(first))
        .then_some(Some(first))
        .ok_or(())
}
