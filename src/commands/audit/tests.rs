use super::*;
use crate::api::{ApiError, ProgressEvent, UploadSet, audit::Report};
use crate::test_support::repository;

struct Fake;
impl AuditApi for Fake {
    fn audit(
        &self,
        upload: UploadSet,
        _: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
    ) -> Result<Report, ApiError> {
        assert_eq!(
            upload
                .files()
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            ["package-lock.json", "package.json"]
        );
        Report::from_bytes(include_bytes!(
            "../../../tests/fixtures/audit/native-findings.json"
        ))
    }
}

#[test]
fn audit_trait_boundary_curates_json_and_reports_selection_scope() {
    let repo = repository(&[
        ("package-lock.json", "{}"),
        ("package.json", "{}"),
        ("other/Cargo.lock", ""),
    ]);
    let request = Request {
        quiet: false,
        save_analysis: None,
        root: repo.path(),
        config: None,
        no_check: false,
        include_manifests: true,
        exclude: &["other/**".into()],
        json: true,
        details: true,
        output: sbom::Output::Stdout,
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert!(matches!(
        run(
            &request,
            &Fake,
            &mut out,
            &mut err,
            Palette::PLAIN,
            Palette::PLAIN
        ),
        Ok(Outcome::Findings)
    ));
    let result: serde_json::Value = serde_json::from_slice(&out).expect("compact JSON");
    assert_eq!(result["manifests"], serde_json::json!(["package.json"]));
    assert!(result.get("inputs").is_none() && result.get("occurrences").is_none());
    let err = String::from_utf8(err).expect("utf8");
    assert!(!err.contains("preparing") && !err.contains("downloading"));
}

#[test]
fn audit_scope_keeps_nested_manifests_with_the_selected_covering_lockfile() {
    let repo = repository(&[
        ("package-lock.json", "{}"),
        ("package.json", "{}"),
        ("packages/member/package.json", "{}"),
    ]);
    let request = Request {
        quiet: false,
        save_analysis: None,
        root: repo.path(),
        config: None,
        no_check: false,
        include_manifests: true,
        exclude: &[],
        json: true,
        details: true,
        output: sbom::Output::Stdout,
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert!(matches!(
        run(
            &request,
            &Fake,
            &mut out,
            &mut err,
            Palette::PLAIN,
            Palette::PLAIN
        ),
        Ok(Outcome::Findings)
    ));
    assert!(
        !String::from_utf8(err)
            .expect("utf8")
            .contains("outside audit scope")
    );
}

#[test]
fn audit_scope_names_only_selected_manifests_without_listing_excluded_files() {
    let repo = repository(&[
        ("package-lock.json", "{}"),
        ("package.json", "{}"),
        ("legacy/Cargo.lock", ""),
        ("legacy/member/Cargo.toml", ""),
    ]);
    let request = Request {
        quiet: false,
        save_analysis: None,
        root: repo.path(),
        config: None,
        no_check: false,
        include_manifests: true,
        exclude: &["legacy/**".into()],
        json: true,
        details: true,
        output: sbom::Output::Stdout,
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert!(matches!(
        run(
            &request,
            &Fake,
            &mut out,
            &mut err,
            Palette::PLAIN,
            Palette::PLAIN
        ),
        Ok(Outcome::Findings)
    ));
    let result: serde_json::Value = serde_json::from_slice(&out).expect("compact JSON");
    assert_eq!(result["manifests"], serde_json::json!(["package.json"]));
    assert!(result.get("skipped_files").is_none());
}
