//! Dependency-license report contract. Original bytes remain the JSON representation.

use serde::Deserialize;
use serde::de::IgnoredAny;
use thiserror::Error;

use super::MAX_RESPONSE_BYTES;

#[expect(
    clippy::redundant_pub_crate,
    reason = "wire DTOs stay explicitly crate-private; Rust unreachable_pub rejects pub in this module"
)]
pub(crate) mod compact;

/// A validated version-1 or version-2 dependency-license report with its original bytes.
pub struct Report {
    bytes: Vec<u8>,
    view: View,
}

impl Report {
    /// Validate the public report without reconstructing its JSON representation.
    ///
    /// # Errors
    /// Returns [`ReportError`] for invalid, oversized or unsupported reports.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ReportError> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ReportError::TooLarge);
        }
        let view = decode(&bytes)?;
        Ok(Self { bytes, view })
    }

    /// Exact accepted bytes, including unfamiliar additive evidence.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn view(&self) -> &View {
        &self.view
    }
}

/// Safe report diagnostics, without excerpts from untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ReportError {
    /// The document does not have the supported report structure.
    #[error("invalid dependency-license report")]
    Invalid,
    /// A different report version needs an updated consumer.
    #[error("unsupported dependency-license report version; upgrade githits-scan")]
    UnsupportedVersion,
    /// The input exceeds the public result limit.
    #[error("dependency-license report exceeds the {MAX_RESPONSE_BYTES}-byte limit")]
    TooLarge,
}

impl ReportError {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Invalid => "invalid dependency-license report",
            Self::UnsupportedVersion => {
                "unsupported dependency-license report version; upgrade githits-scan"
            }
            Self::TooLarge => "dependency-license report exceeds the response limit",
        }
    }
}

#[derive(Deserialize)]
struct Version {
    schema_version: u64,
}

fn decode(bytes: &[u8]) -> Result<View, ReportError> {
    // The public envelope is an object; preserve this before Serde's struct-sequence support.
    if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
        return Err(ReportError::Invalid);
    }
    let version: Version = serde_json::from_slice(bytes).map_err(|_| ReportError::Invalid)?;
    match version.schema_version {
        1 => serde_json::from_slice(bytes).map(View::Legacy),
        2 => serde_json::from_slice(bytes).map(View::Compact),
        _ => return Err(ReportError::UnsupportedVersion),
    }
    .map_err(|_| ReportError::Invalid)
}

pub(crate) enum View {
    Legacy(LegacyView),
    Compact(compact::View),
}

impl View {
    pub(crate) fn completeness(&self) -> Option<&str> {
        match self {
            Self::Legacy(view) => view.inventory.completeness.as_deref(),
            Self::Compact(view) => view.inventory.completeness.as_deref(),
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct LegacyView {
    pub inventory: Inventory,
    pub components: Vec<Component>,
}

#[derive(Deserialize)]
pub(crate) struct Inventory {
    pub completeness: Option<String>,
    pub properties: Vec<Property>,
    pub compositions: Vec<Composition>,
    #[serde(rename = "dependencies")]
    _dependencies: Vec<IgnoredAny>,
}

#[derive(Deserialize)]
pub(crate) struct Composition {
    pub aggregate: Option<String>,
    pub assemblies: Option<IgnoredAny>,
    pub dependencies: Option<IgnoredAny>,
}

#[derive(Deserialize)]
pub(crate) struct Property {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Component {
    pub bom_ref: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    pub scope: Option<String>,
    pub record_kind: Option<String>,
    pub licenses: Vec<Choice>,
    pub observed_licenses: Vec<Choice>,
    pub publisher_evidence: Option<Publisher>,
    pub source_evidence: Option<Source>,
    pub external_references: Vec<Reference>,
    #[serde(rename = "hashes")]
    _hashes: Vec<IgnoredAny>,
    pub properties: Vec<Property>,
}

#[derive(Deserialize)]
pub(crate) struct Choice {
    pub expression: Option<String>,
    pub license: Option<License>,
    pub acknowledgement: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct License {
    pub id: Option<String>,
    pub name: Option<String>,
    pub acknowledgement: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Publisher {
    pub capture_status: Option<String>,
    pub coverage: Option<String>,
    pub reason: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub observations: Vec<Observation>,
}

#[derive(Deserialize)]
pub(crate) struct Observation {
    pub interpretation: Option<Interpretation>,
    pub relationship: Option<String>,
    #[serde(rename = "observation")]
    pub statement: Option<Statement>,
}

#[derive(Deserialize)]
pub(crate) struct Interpretation {
    pub status: Option<String>,
    pub issues: Option<Vec<Issue>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Issue {
    Code {
        code: String,
        offset: Option<u64>,
        identifier: Option<String>,
    },
    Other(IgnoredAny),
}

#[derive(Deserialize)]
pub(crate) struct Statement {
    pub version: Option<String>,
    pub scope: Option<String>,
    pub field: Option<String>,
    #[serde(default)]
    pub statements: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct Source {
    pub url: Option<String>,
    pub module: Option<String>,
    pub version: Option<String>,
    pub status: Option<String>,
    pub last_attempt_status: Option<String>,
    #[serde(default)]
    pub files: Vec<SourceFile>,
}

#[derive(Deserialize)]
pub(crate) struct SourceFile {
    pub path: String,
    pub detected_licenses: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct Reference {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy(report: &Report) -> Option<&LegacyView> {
        match report.view() {
            View::Legacy(view) => Some(view),
            View::Compact(_) => None,
        }
    }

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/licenses/report-v1.json");

    #[test]
    fn license_report_retains_bytes_and_separate_occurrences() {
        let report = Report::from_bytes(FIXTURE.to_vec()).expect("report");
        assert_eq!(report.bytes(), FIXTURE);
        let view = legacy(&report).expect("legacy view");
        assert_eq!(view.components.len(), 3);
        assert_eq!(view.components[1].name, view.components[2].name);
        assert_eq!(view.components[1].version, view.components[2].version);
        assert_ne!(view.components[1].bom_ref, view.components[2].bom_ref);
        assert_eq!(
            view.components[2]
                .source_evidence
                .as_ref()
                .expect("source")
                .status
                .as_deref(),
            Some("future_observation")
        );
    }

    #[test]
    fn license_report_reads_optional_purl_without_changing_bytes() {
        let mut known: serde_json::Value = serde_json::from_slice(FIXTURE).expect("json");
        known["components"][1]["future_component_field"] = true.into();

        let mut null_purl = known.clone();
        null_purl["components"][1]["purl"] = serde_json::Value::Null;

        let mut missing_purl = known.clone();
        missing_purl["components"][1]
            .as_object_mut()
            .expect("component object")
            .remove("purl");

        for (value, expected_purl) in [
            (known, Some("pkg:npm/same-package@1.2.3")),
            (null_purl, None),
            (missing_purl, None),
        ] {
            let bytes = serde_json::to_vec(&value).expect("json");
            let report = Report::from_bytes(bytes.clone()).expect("report");
            assert_eq!(report.bytes(), bytes.as_slice());

            let view = legacy(&report).expect("legacy view");
            assert_eq!(view.components[1].purl.as_deref(), expected_purl);
            assert_eq!(view.components[1].name, "same-package");
            assert_eq!(view.components[1].version.as_deref(), Some("1.2.3"));
            assert_eq!(view.components[1].name, view.components[2].name);
            assert_eq!(view.components[1].version, view.components[2].version);
            assert_ne!(view.components[1].bom_ref, view.components[2].bom_ref);
        }
    }

    #[test]
    fn license_report_rejects_invalid_versions_shapes_and_size() {
        assert!(matches!(
            Report::from_bytes(b"{}".to_vec()),
            Err(ReportError::Invalid)
        ));
        assert!(matches!(Report::from_bytes(br#"[1,{"completeness":null,"properties":[],"compositions":[],"dependencies":[]},[]]"#.to_vec()), Err(ReportError::Invalid)));
        assert!(matches!(
            Report::from_bytes(br#"{"schema_version":3}"#.to_vec()),
            Err(ReportError::UnsupportedVersion)
        ));
        let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).expect("json");
        value["schema_version"] = 3.into();
        assert!(matches!(
            Report::from_bytes(serde_json::to_vec(&value).expect("json")),
            Err(ReportError::UnsupportedVersion)
        ));
        value["schema_version"] = 1.into();
        value["components"][0]["licenses"] = "invalid".into();
        assert!(matches!(
            Report::from_bytes(serde_json::to_vec(&value).expect("json")),
            Err(ReportError::Invalid)
        ));
        assert!(matches!(
            Report::from_bytes(vec![b' '; MAX_RESPONSE_BYTES + 1]),
            Err(ReportError::TooLarge)
        ));
    }

    #[test]
    fn license_report_accepts_escaped_strings_and_unknown_choices() {
        let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).expect("json");
        value["components"][0]["name"] = "quoted\nname".into();
        value["components"][0]["licenses"] = serde_json::json!([{"future_choice": {"kept": true}}]);
        value["inventory"]["completeness"] = "future_inventory".into();
        let report = Report::from_bytes(serde_json::to_vec(&value).expect("json")).expect("report");
        let view = legacy(&report).expect("legacy view");
        assert_eq!(view.components[0].name, "quoted\nname");
        assert_eq!(
            view.inventory.completeness.as_deref(),
            Some("future_inventory")
        );
        assert_eq!(view.components[0].licenses.len(), 1);
        assert!(view.components[0].licenses[0].expression.is_none());
    }
}
