//! Narrow release-only comparisons of the two human file-output paths.
#![expect(
    clippy::expect_used,
    reason = "benchmark setup and measurements fail closed"
)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher as _};
use std::io;
use std::path::Path;
use std::time::Instant;

use githits_scan::api::{self, ApiError, AuditApi, LicensesApi, ProgressEvent, UploadSet};
use githits_scan::commands::{Outcome, audit, license::report, sbom};
use githits_scan::style::Palette;

struct FixtureApi(Vec<u8>);
impl LicensesApi for FixtureApi {
    fn report(
        &self,
        _: UploadSet,
        _: &mut dyn FnMut(&ProgressEvent) -> io::Result<()>,
    ) -> Result<api::licenses::Report, ApiError> {
        api::licenses::Report::from_bytes(self.0.clone()).map_err(|_| ApiError::Protocol {
            reason: "invalid benchmark fixture",
            request_id: None,
        })
    }
}
impl AuditApi for FixtureApi {
    fn audit(
        &self,
        _: UploadSet,
        _: &mut dyn FnMut(&ProgressEvent) -> io::Result<()>,
    ) -> Result<api::audit::Report, ApiError> {
        api::audit::Report::from_bytes(include_bytes!("fixtures/audit/findings.json"))
    }
}

fn licenses() -> Vec<u8> {
    let components: Vec<_> = (0..10_000).map(|i| serde_json::json!({
        "bom_ref":format!("locked-{i}"), "name":format!("demo-{i}"), "version":"1.0.0", "purl":format!("pkg:npm/demo-{i}@1.0.0"),
        "type":"library", "scope":null, "record_kind":"locked_package", "licenses":[{"expression":"MIT"}], "observed_licenses":[],
        "publisher_evidence":null, "source_evidence":null, "external_references":[], "hashes":[],
        "properties":[{"name":"githits:lockfile_path","value":"package-lock.json"}]
    })).collect();
    let bytes = serde_json::to_vec(&serde_json::json!({"schema_version":1,"inventory":{"completeness":"recorded_lockfile_inventory","properties":[],"compositions":[],"dependencies":[]},"components":components})).expect("benchmark JSON");
    assert!(bytes.len() <= api::MAX_RESPONSE_BYTES);
    bytes
}

fn report_case(root: &Path, output: &Path, api: &FixtureApi) {
    let request = report::Request {
        root,
        config: None,
        no_check: false,
        include_manifests: true,
        exclude: &[],
        json: false,
        details: true,
        quiet: true,
        output: sbom::Output::File(output.into()),
        source: report::Source::Generate(api),
    };
    let outcome = report::run(
        &request,
        &mut io::sink(),
        &mut io::sink(),
        Palette::PLAIN,
        Palette::PLAIN,
    )
    .expect("report output");
    assert!(matches!(outcome, Outcome::Success));
}

fn audit_case(root: &Path, output: &Path, api: &FixtureApi) {
    let request = audit::Request {
        root,
        config: None,
        no_check: false,
        include_manifests: true,
        exclude: &[],
        json: false,
        details: true,
        quiet: true,
        output: sbom::Output::File(output.into()),
        save_analysis: None,
    };
    let outcome = audit::run(
        &request,
        api,
        &mut io::sink(),
        &mut io::sink(),
        Palette::PLAIN,
        Palette::PLAIN,
    )
    .expect("audit output");
    assert!(matches!(outcome, Outcome::Findings));
}

fn measure(label: &str, iterations: usize, path: &Path, mut run: impl FnMut()) {
    run();
    let expected = std::fs::read(path).expect("output");
    let mut samples = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        for _ in 0..iterations {
            run();
        }
        samples.push(start.elapsed().as_micros());
        assert_eq!(std::fs::read(path).expect("output"), expected);
    }
    let mut hash = DefaultHasher::new();
    expected.hash(&mut hash);
    println!(
        "BENCH {label} iterations={iterations} samples_us={samples:?} output_bytes={} digest={:016x}",
        expected.len(),
        hash.finish()
    );
}

#[test]
#[ignore = "release-only file-output measurement; no network or credentials"]
fn license_and_audit_file_output_benchmark() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("run this measurement with --release");
    }
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::write(root.path().join("package-lock.json"), "{}").expect("input");
    let api = FixtureApi(licenses());
    let output = root.path().join("report.txt");
    measure("licenses-file-10000-occurrences", 1, &output, || {
        report_case(root.path(), &output, &api);
    });
    measure("audit-file-findings", 100, &output, || {
        audit_case(root.path(), &output, &api);
    });
    Ok(())
}
