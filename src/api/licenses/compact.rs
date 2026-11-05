//! Narrow schema-2 view; original bytes retain fields not used for presentation.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::IgnoredAny;

use super::{Choice, Issue, Publisher, Reference, Source};

#[derive(Deserialize)]
pub(crate) struct View {
    pub inventory: Inventory,
    pub components: Vec<Component>,
}

#[derive(Deserialize)]
pub(crate) struct Inventory {
    pub completeness: Option<String>,
    pub resolution_basis: Option<String>,
    pub component_type_basis: Option<String>,
    pub notices: Vec<String>,
    pub coverage: Vec<Coverage>,
    #[serde(default)]
    pub resolutions: Vec<Resolution>,
    #[serde(default)]
    pub declarations: Vec<Declaration>,
    #[serde(default)]
    pub declaration_agreement: Vec<Agreement>,
    #[serde(default)]
    pub dependency_coverage: BTreeMap<String, DependencyCoverage>,
    #[serde(default)]
    pub lockfiles: Vec<Lockfile>,
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
    pub inputs: Inputs,
    pub metadata_status: Option<String>,
    pub metadata_reason: Option<String>,
    pub purl_omission_reason: Option<String>,
    pub resolution_basis: Option<String>,
    pub resolution_limitation: Option<String>,
    #[serde(rename = "component_type_basis")]
    pub type_basis: Option<String>,
    pub source_kind: Option<String>,
    pub source_revision: Option<String>,
    pub source_revision_omission_reason: Option<String>,
    pub source_selector: Option<String>,
    pub source_selector_basis: Option<String>,
    pub source_selector_kind: Option<String>,
    pub source_selector_omission_reason: Option<String>,
    pub source_locator_omission_reason: Option<String>,
    pub license_evidence: Option<Evidence>,
}

#[derive(Deserialize)]
pub(crate) struct Inputs {
    pub manifest_paths: Vec<String>,
    pub lockfile_paths: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct Evidence {
    pub source: Option<String>,
    pub lookup_basis: Option<String>,
    pub artifact_verification: Option<String>,
    pub applicability_reason: Option<String>,
    pub raw: Option<String>,
    pub status: Option<String>,
    pub syntax: Option<String>,
    pub origin_scope: Option<String>,
    #[serde(default)]
    pub interpretation_methods: Vec<String>,
    #[serde(default)]
    pub issues: Vec<Issue>,
}

#[derive(Deserialize)]
pub(crate) struct Coverage {
    pub aggregate: Option<String>,
    pub assemblies: Option<Vec<String>>,
    pub dependencies: Option<Vec<String>>,
    pub services: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub(crate) struct DependencyCoverage {
    pub state: Option<String>,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct Resolution {
    pub path: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
}

// Diagnostics are open objects, including unfamiliar field types. Never reject
// a valid charged report merely because this consumer cannot explain one item.
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Diagnostic {
    Known {
        name: Option<String>,
        reason: Option<String>,
    },
    Other(IgnoredAny),
}

#[derive(Deserialize)]
pub(crate) struct Declaration {
    pub name: Option<String>,
    pub manifest_path: Option<String>,
    pub declared_requirement: Option<String>,
    pub declared_scope: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Lockfile {
    pub path: Option<String>,
    pub completeness: Option<String>,
    pub association_status: Option<String>,
    pub manifest_lock_consistency: Option<String>,
    #[serde(default)]
    pub manifest_paths: Vec<String>,
    #[serde(default)]
    pub association_diagnostics: Vec<Diagnostic>,
    #[serde(default)]
    pub projection_notices: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct Agreement {
    pub name: Option<String>,
    pub path: Option<String>,
    pub declaration_path: Option<String>,
    pub declared_scope: Option<String>,
    pub requested_requirement: Option<String>,
    pub status: Option<String>,
    pub requirement_status: Option<String>,
    #[serde(default)]
    pub recorded_scopes: Vec<String>,
    #[serde(default)]
    pub matched_versions: Vec<Option<String>>,
    #[serde(default)]
    pub locked_versions: Vec<Option<String>>,
}

#[cfg(test)]
mod tests {
    use crate::api::licenses::{Report, ReportError, View};

    const FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/licenses/report-v2.json");

    #[test]
    fn compact_report_preserves_bytes_and_typed_inputs() {
        let report = Report::from_bytes(FIXTURE.to_vec()).expect("compact report");
        assert_eq!(report.bytes(), FIXTURE);
        let view = match report.view() {
            View::Compact(view) => Some(view),
            View::Legacy(_) => None,
        }
        .expect("compact view");
        assert_eq!(view.components.len(), 8);
        assert_eq!(
            view.components[0].inputs.manifest_paths,
            ["app/package.json"]
        );
        assert_eq!(
            view.inventory.declarations[0].name.as_deref(),
            Some("never-resolved-dependency")
        );
    }

    #[test]
    fn compact_report_accepts_open_diagnostics_nullable_versions_and_additions() {
        let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).expect("fixture");
        value["inventory"]["resolutions"][0]["diagnostics"] =
            serde_json::json!([{}, {"name":5,"reason":[]}, {"future":true}]);
        value["inventory"]["declaration_agreement"][0]["matched_versions"] =
            serde_json::json!([null, "1.0"]);
        value["future"] = serde_json::json!({"retained":[true]});
        let bytes = serde_json::to_vec(&value).expect("json");
        let report = Report::from_bytes(bytes.clone()).expect("open report");
        assert_eq!(report.bytes(), bytes);
    }

    #[test]
    fn compact_report_rejects_known_shape_errors_and_does_not_relax_legacy() {
        for pointer in [
            "/components/0/inputs/manifest_paths",
            "/components/0/licenses",
            "/inventory/coverage",
            "/inventory/declaration_agreement/0/locked_versions",
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).expect("fixture");
            *value.pointer_mut(pointer).expect("known field") = serde_json::json!(false);
            assert!(
                matches!(
                    Report::from_bytes(serde_json::to_vec(&value).expect("json")),
                    Err(ReportError::Invalid)
                ),
                "{pointer}"
            );
        }
        for bytes in [br#"{"schema_version":2}"#.as_slice(), br#"{"schema_version":1,"inventory":{"completeness":null,"properties":[],"compositions":[]},"components":[]}"#.as_slice()] {
            assert!(matches!(Report::from_bytes(bytes.to_vec()), Err(ReportError::Invalid)));
        }
    }
}
