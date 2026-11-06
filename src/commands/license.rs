//! `githits-scan license check`: evaluate a CycloneDX document against the
//! configured license policy.
//!
//! The document is generated through the same pipeline as `sbom generate`
//! (inventory, drift gate, one job) or read from `--sbom FILE`, which
//! needs no token. The policy comes from the configuration's `[licenses]`
//! table. A missing file and an existing file without the table are distinct
//! usage errors that explain how to configure the policy.

mod display;
mod occurrences;
/// Full dependency-license inventory, without policy evaluation.
pub mod report;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use super::sbom::{self, Generated, Generation};
use super::{Error, Outcome, config_path, plural};
use crate::api::{OutputFormat, SbomApi};
use crate::config;
use crate::license::{self, Policy, Report};
use crate::style::Palette;

/// Version of the JSON report. Additive changes keep it; removals or renames
/// bump it.
const SCHEMA_VERSION: u32 = 1;

/// Where the document comes from.
pub enum Source<'a> {
    /// Generate it through the API, exactly like `sbom generate`.
    Generate(&'a dyn SbomApi),
    /// Read an existing CycloneDX document; no token or network needed.
    File(&'a Path),
}

/// What the caller asked for.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent command-line switches"
)]
pub struct Request<'a> {
    /// Directory to scan; the configuration is read from here.
    pub root: &'a Path,
    /// Configuration file; defaults to `githits-scan.toml` in `root`.
    pub config: Option<&'a Path>,
    /// Generate despite inventory drift.
    pub no_check: bool,
    /// Upload manifest-only projects when generating.
    pub include_manifests: bool,
    /// Invocation `--exclude` globs; same language as `lockfiles.exclude`.
    pub exclude: &'a [String],
    /// Emit JSON instead of the human report.
    pub json: bool,
    /// Include violation component references and package URLs.
    pub details: bool,
    /// Suppress progress and success diagnostics.
    pub quiet: bool,
    /// Report destination.
    pub output: sbom::Output,
    /// The document.
    pub source: Source<'a>,
}

/// Check the document and write the report.
///
/// `palette` styles the report on `stdout`; `stderr_palette` styles the
/// generation summary on `stderr`, since the two streams may differ in
/// whether they are terminals.
/// Coverage warnings go to `stderr` even in quiet and JSON modes.
///
/// Returns [`Outcome::Findings`] on any violation, and also when generation
/// stopped before a request (drift, or nothing to upload), in which case the
/// pipeline has already explained why on `stderr`.
///
/// # Errors
///
/// Returns [`Error::MissingLicenseConfig`] when the configuration is absent,
/// [`Error::NoLicensePolicy`] when it has no `[licenses]` table, the generation
/// or read error, [`Error::Document`] for a file that is not a
/// CycloneDX document, or [`Error::Output`] when the report cannot be written.
pub fn run(
    request: &Request<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    palette: Palette,
    stderr_palette: Palette,
) -> Result<Outcome, Error> {
    let (bytes, policy) = match request.source {
        // Explicit offline inputs are checked before implicit policy prerequisites.
        Source::File(file) => {
            let bytes = super::read_selected(file)?;
            if bytes.len() > crate::api::MAX_RESPONSE_BYTES {
                return Err(Error::DocumentTooLarge {
                    path: file.to_path_buf(),
                    limit: crate::api::MAX_RESPONSE_BYTES,
                });
            }
            let policy = load_policy(request)?;
            (bytes, policy)
        }
        Source::Generate(api) => {
            let policy = load_policy(request)?;
            let generation = Generation {
                root: request.root,
                config: request.config,
                no_check: request.no_check,
                include_manifests: request.include_manifests,
                exclude: request.exclude,
                format: OutputFormat::CycloneDx,
                progress: !request.json && !request.quiet,
            };
            let Generated::Document { document, summary } =
                sbom::generate(&generation, api, stderr, stderr_palette)?
            else {
                return Ok(Outcome::Findings);
            };
            if !request.quiet {
                writeln!(stderr, "{summary}").map_err(Error::Output)?;
            }
            (document.bytes, policy)
        }
    };
    if !request.json && !request.quiet {
        super::progress::message("checking licenses...", stderr).map_err(Error::Output)?;
    }
    let report = license::check(&bytes, &policy)?;
    let occurrences = if !request.json
        && report
            .violations
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name && pair[0].version == pair[1].version)
    {
        occurrences::Occurrences::new(
            &bytes,
            occurrences::Format::Sbom,
            report
                .violations
                .chunk_by(|a, b| a.name == b.name && a.version == b.version)
                .filter(|group| group.len() > 1)
                .flatten()
                .map(|v| v.bom_ref.as_str()),
        )
    } else {
        occurrences::Occurrences::default()
    };
    write_coverage_warnings(&report, &request.source, stderr).map_err(Error::Output)?;
    super::write_report(&request.output, stdout, palette, |out, palette| {
        if request.json {
            write_json(&report, out)
        } else {
            write_human(&report, &occurrences, out, palette, request.details).map_err(Error::Output)
        }
    })?;
    super::saved_report(&request.output, request.quiet, stderr)?;
    Ok(
        if report.violations.is_empty() && report.unresolved.is_empty() {
            Outcome::Success
        } else {
            Outcome::Findings
        },
    )
}

fn write_coverage_warnings(
    report: &Report,
    source: &Source<'_>,
    stderr: &mut dyn Write,
) -> std::io::Result<()> {
    if report.components == 0 {
        writeln!(
            stderr,
            "warning: no components were evaluated; no license coverage was established"
        )?;
    }
    if report.completeness.is_none() && matches!(source, Source::File(_)) {
        writeln!(
            stderr,
            "warning: SBOM has no githits:completeness property; inventory completeness is unknown"
        )?;
    }
    display::warn_incomplete(report.completeness.as_deref(), stderr)?;
    Ok(())
}

fn load_policy(request: &Request<'_>) -> Result<Policy, Error> {
    let path = config_path(request.root, request.config);
    let config =
        config::load(&path)?.ok_or_else(|| Error::MissingLicenseConfig { path: path.clone() })?;
    let licenses = config
        .licenses
        .as_ref()
        .ok_or_else(|| Error::NoLicensePolicy { path: path.clone() })?;
    Policy::new(licenses).map_err(|source| Error::LicensePolicy { path, source })
}

#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    components: usize,
    local_packages: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    completeness: Option<&'a str>,
    violations: Vec<ViolationEntry<'a>>,
    exceptions_applied: Vec<AppliedEntry<'a>>,
    unresolved_projects: Vec<UnresolvedEntry<'a>>,
}

#[derive(Serialize)]
struct UnresolvedEntry<'a> {
    path: &'a str,
    status: &'a str,
    reasons: &'a [String],
}

#[derive(Serialize)]
struct ViolationEntry<'a> {
    bom_ref: &'a str,
    name: &'a str,
    version: Option<&'a str>,
    purl: Option<&'a str>,
    expression: Option<&'a str>,
    reason: &'static str,
}

#[derive(Serialize)]
struct AppliedEntry<'a> {
    purl: &'a str,
    reason: &'a str,
    components: &'a [String],
}

fn write_json(report: &Report, out: &mut dyn Write) -> Result<(), Error> {
    let json = JsonReport {
        schema_version: SCHEMA_VERSION,
        components: report.components,
        local_packages: report.local_packages,
        completeness: report.completeness.as_deref(),
        violations: report
            .violations
            .iter()
            .map(|v| ViolationEntry {
                bom_ref: &v.bom_ref,
                name: &v.name,
                version: v.version.as_deref(),
                purl: v.purl.as_deref(),
                expression: v.expression.as_deref(),
                reason: v.reason.id(),
            })
            .collect(),
        exceptions_applied: report
            .exceptions_applied
            .iter()
            .map(|a| AppliedEntry {
                purl: &a.purl,
                reason: &a.reason,
                components: &a.components,
            })
            .collect(),
        unresolved_projects: report
            .unresolved
            .iter()
            .map(|u| UnresolvedEntry {
                path: &u.path,
                status: &u.status,
                reasons: &u.reasons,
            })
            .collect(),
    };
    serde_json::to_writer_pretty(&mut *out, &json)?;
    writeln!(out).map_err(Error::Output)
}

fn write_human(
    report: &Report,
    occurrences: &occurrences::Occurrences,
    out: &mut dyn Write,
    palette: Palette,
    details: bool,
) -> std::io::Result<()> {
    let completeness = report
        .completeness
        .as_deref()
        .map(|v| display::Text::new(&display::completeness(v), display::DETAIL));
    let mut headline = if report.components == 0 {
        "no components evaluated (no license coverage established)".to_owned()
    } else if report.violations.is_empty() {
        format!(
            "no violations in {}",
            plural(report.components, "component")
        )
    } else {
        format!(
            "{} in {}",
            plural(
                report.violations.len(),
                if report
                    .violations
                    .iter()
                    .any(|v| occurrences.combined(&v.bom_ref))
                {
                    "occurrence violation"
                } else {
                    "violation"
                }
            ),
            plural(report.components, "component")
        )
    };
    if report.local_packages > 0 {
        let _ = write!(
            headline,
            ", {} skipped",
            plural(report.local_packages, "local package")
        );
    }
    if !report.unresolved.is_empty() {
        let _ = write!(
            headline,
            ", {} not fully resolved",
            plural(report.unresolved.len(), "project")
        );
    }
    if let Some(completeness) = &completeness {
        let _ = write!(headline, " (inventory: {})", completeness.value);
    }
    writeln!(out, "{}", palette.bold(&headline))?;
    let mut shortened = completeness.is_some_and(|v| v.shortened);
    if !report.violations.is_empty() {
        writeln!(out)?;
        shortened |= write_violations(report, occurrences, out, palette)?;
    }
    if !report.unresolved.is_empty() {
        writeln!(out)?;
        shortened |= write_unresolved(report, out, palette)?;
    }
    shortened |= write_exceptions(report, out, palette)?;
    if details {
        shortened |= write_component_details(report, occurrences, out)?;
    }
    if shortened {
        writeln!(out, "\nAbbreviated evidence; use --json for full values.")?;
    }
    Ok(())
}

fn write_component_details(
    report: &Report,
    occurrences: &occurrences::Occurrences,
    out: &mut dyn Write,
) -> std::io::Result<bool> {
    if report.violations.is_empty() {
        return Ok(false);
    }
    writeln!(out, "\nComponent details:")?;
    let mut shortened = false;
    for violation in &report.violations {
        writeln!(
            out,
            "  {}",
            violation_identity(
                violation,
                false,
                occurrences.label(&violation.bom_ref, false)
            )
            .text
            .value
        )?;
        shortened |= display::field(out, "    component reference: ", &violation.bom_ref, false)?;
        if let Some(purl) = violation.purl.as_deref() {
            shortened |= display::field(out, "    package URL: ", purl, false)?;
        }
        shortened |= occurrences.continuation(&violation.bom_ref, false, out)?;
        shortened |= occurrences.inputs(&violation.bom_ref, out)?;
    }
    Ok(shortened)
}

fn write_exceptions(
    report: &Report,
    out: &mut dyn Write,
    palette: Palette,
) -> std::io::Result<bool> {
    if report.exceptions_applied.is_empty() {
        return Ok(false);
    }
    let mut shortened = false;
    writeln!(out, "\n{}", palette.dim("Exceptions applied:"))?;
    for applied in &report.exceptions_applied {
        let labels = exception_labels(&applied.components);
        let parts = [applied.purl.as_str(), ": ", applied.reason.as_str(), " ("]
            .into_iter()
            .chain(
                labels
                    .iter()
                    .enumerate()
                    .flat_map(|(i, name)| [if i == 0 { "" } else { ", " }, name.as_str()]),
            )
            .chain([")"]);
        let text = display::Text::parts(parts, display::DETAIL);
        writeln!(out, "  {}", text.value)?;
        shortened |= text.shortened;
    }
    Ok(shortened)
}

fn exception_labels(components: &[String]) -> Vec<String> {
    let mut counts = std::collections::BTreeMap::new();
    for component in components {
        *counts.entry(component.as_str()).or_insert(0) += 1;
    }
    components
        .iter()
        .filter_map(|component| {
            let count = counts.remove(component.as_str())?;
            Some(if count == 1 {
                component.clone()
            } else {
                format!("{component} ({})", plural(count, "occurrence"))
            })
        })
        .collect()
}

fn write_unresolved(
    report: &Report,
    out: &mut dyn Write,
    palette: Palette,
) -> std::io::Result<bool> {
    writeln!(
        out,
        "{}",
        palette.warning(
            "Licenses not checked: the service could not fully resolve these projects' dependencies"
        )
    )?;
    let width = report
        .unresolved
        .iter()
        .map(|p| {
            display::Text::new(&p.path, display::PACKAGE)
                .value
                .chars()
                .count()
        })
        .max()
        .unwrap_or(0)
        .min(display::PACKAGE_PADDING);
    let mut shortened = false;
    for project in &report.unresolved {
        let path = display::Text::new(&project.path, display::PACKAGE);
        let reasons: Vec<_> = project
            .reasons
            .iter()
            .map(|r| display::evidence_code(r))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let parts = [
            display::evidence_code(&project.status),
            if reasons.is_empty() { "" } else { " (" },
        ]
        .into_iter()
        .chain(
            reasons
                .iter()
                .enumerate()
                .flat_map(|(i, reason)| [if i == 0 { "" } else { ", " }, *reason]),
        )
        .chain([if reasons.is_empty() { "" } else { ")" }]);
        let detail = display::Text::parts(parts, display::DETAIL);
        writeln!(out, "  {:<width$}  {}", path.value, detail.value)?;
        shortened |= path.shortened || detail.shortened;
    }
    writeln!(
        out,
        "Add a lockfile for each project, or leave it out with --lockfiles-only or --exclude."
    )?;
    Ok(shortened)
}

fn write_violations(
    report: &Report,
    occurrences: &occurrences::Occurrences,
    out: &mut dyn Write,
    palette: Palette,
) -> std::io::Result<bool> {
    let package_width = report
        .violations
        .iter()
        .map(|v| {
            violation_identity(v, false, occurrences.label(&v.bom_ref, true))
                .text
                .value
                .chars()
                .count()
        })
        .max()
        .unwrap_or(0)
        .clamp(7, display::PACKAGE_PADDING);
    let license_width = report
        .violations
        .iter()
        .map(|v| violation_evidence(v).value.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(7, display::LICENSE_PADDING);
    writeln!(
        out,
        "{}",
        palette.dim(&format!(
            "  {:<package_width$}  {:<license_width$}  REASON",
            "PACKAGE", "LICENSE"
        ))
    )?;
    let mut shortened = false;
    for group in report
        .violations
        .chunk_by(|a, b| a.name == b.name && a.version == b.version)
    {
        shortened |= write_violation_group(
            group,
            occurrences,
            package_width,
            license_width,
            out,
            palette,
        )?;
    }

    Ok(shortened)
}

fn write_violation_group(
    group: &[license::Violation],
    occurrences: &occurrences::Occurrences,
    package_width: usize,
    license_width: usize,
    out: &mut dyn Write,
    palette: Palette,
) -> std::io::Result<bool> {
    let mut shortened = false;
    let base = group[0].purl.as_deref().map(display::purl_base);
    let distinguish = group
        .iter()
        .any(|v| v.purl.as_deref().map(display::purl_base) != base);
    let remaining = group
        .iter()
        .filter(|v| !occurrences.skip(&v.bom_ref))
        .count();
    for violation in group {
        if occurrences.skip(&violation.bom_ref) {
            continue;
        }
        let context = occurrences.label(&violation.bom_ref, true);
        shortened |= write_violation(
            violation,
            distinguish,
            context,
            package_width,
            license_width,
            out,
            palette,
        )?;
        shortened |= occurrences.continuation(&violation.bom_ref, true, out)?;
        if remaining > 1 && context.is_some() {
            shortened |= occurrences.inputs(&violation.bom_ref, out)?;
        }
    }
    Ok(shortened)
}

fn violation_identity(
    v: &license::Violation,
    distinguish: bool,
    context: Option<&str>,
) -> display::Identity {
    display::identity(
        &v.name,
        v.version.as_deref(),
        v.purl.as_deref(),
        "",
        distinguish,
        context,
    )
}

fn violation_evidence(v: &license::Violation) -> display::Text {
    let value = v.expression.as_deref().unwrap_or("-");
    if v.reason == license::Reason::NonSpdxName {
        display::Text::prose(value, display::LICENSE)
    } else {
        display::Text::new(value, display::LICENSE)
    }
}

fn write_violation(
    violation: &license::Violation,
    distinguish: bool,
    context: Option<&str>,
    package_width: usize,
    license_width: usize,
    out: &mut dyn Write,
    palette: Palette,
) -> std::io::Result<bool> {
    let id = violation_identity(violation, distinguish, context);
    let text = violation_evidence(violation);
    writeln!(
        out,
        "  {:<package_width$}  {:<license_width$}  {}",
        id.text.value,
        text.value,
        palette.warning(violation.reason.describe())
    )?;
    display::continuation(out, &id)?;
    if text.shortened {
        display::field(
            out,
            "  license evidence: ",
            violation.expression.as_deref().unwrap_or("-"),
            violation.reason == license::Reason::NonSpdxName,
        )?;
    }
    Ok(id.text.shortened
        || text.shortened
        || id
            .continuation
            .as_ref()
            .is_some_and(|(_, value)| value.shortened))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::api::{ApiError, Document, UploadSet};
    use crate::commands::ErrorKind;
    use crate::license::DocumentError;

    const CONFIG: &str = "\
version = 1

[lockfiles]
include = [\"Cargo.lock\"]

[licenses]
allow = [\"MIT\", \"Apache-2.0\"]

[[licenses.exceptions]]
purl = \"pkg:cargo/ring\"
reason = \"reviewed\"
";

    const DOCUMENT: &[u8] = br#"{"bomFormat":"CycloneDX","specVersion":"1.7","properties":[{"name":"githits:completeness","value":"recorded_lockfile_inventory"}],"components":[
{"bom-ref":"1","name":"serde","version":"1.0.0","purl":"pkg:cargo/serde@1.0.0","licenses":[{"expression":"MIT OR Apache-2.0"}]},
{"bom-ref":"2","name":"ring","version":"0.17.8","purl":"pkg:cargo/ring@0.17.8","licenses":[{"expression":"OpenSSL"}]},
{"bom-ref":"3","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0","licenses":[{"expression":"WTFPL"}]},
{"bom-ref":"4","name":"mystery","version":"0.1.0","purl":"pkg:cargo/mystery@0.1.0"},
{"bom-ref":"5","name":"my-app","version":"0.1.0","properties":[{"name":"githits:source_kind","value":"LOCKED_PACKAGE_SOURCE_KIND_LOCAL"}]}
]}"#;

    struct FakeApi {
        called: Cell<bool>,
    }

    impl SbomApi for FakeApi {
        fn generate(
            &self,
            _: UploadSet,
            format: OutputFormat,
            _: &mut dyn FnMut(&crate::api::ProgressEvent) -> std::io::Result<()>,
        ) -> Result<Document, ApiError> {
            assert_eq!(format, OutputFormat::CycloneDx);
            self.called.set(true);
            Ok(Document {
                bytes: DOCUMENT.to_vec(),
            })
        }
    }

    fn repository(files: &[(&str, &str)]) -> TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (relative, contents) in files {
            let path = dir.path().join(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(path, contents).expect("write");
        }
        dir
    }

    struct Run {
        result: Result<Outcome, Error>,
        stdout: String,
        stderr: String,
    }

    fn check(request: &Request<'_>) -> Run {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = run(
            request,
            &mut stdout,
            &mut stderr,
            Palette::PLAIN,
            Palette::PLAIN,
        );
        Run {
            result,
            stdout: String::from_utf8(stdout).expect("utf-8"),
            stderr: String::from_utf8(stderr).expect("utf-8"),
        }
    }

    fn request<'a>(root: &'a Path, source: Source<'a>) -> Request<'a> {
        Request {
            root,
            config: None,
            no_check: false,
            include_manifests: false,
            quiet: false,
            details: false,
            output: sbom::Output::Stdout,
            exclude: &[],
            json: false,
            source,
        }
    }

    #[test]
    fn reports_violations_and_exceptions_from_a_generated_document() {
        let repo = repository(&[("githits-scan.toml", CONFIG), ("Cargo.lock", "")]);
        let api = FakeApi {
            called: Cell::new(false),
        };

        let run = check(&request(repo.path(), Source::Generate(&api)));

        assert!(api.called.get());
        assert!(
            matches!(run.result, Ok(Outcome::Findings)),
            "{:?}",
            run.result
        );
        assert_eq!(
            run.stderr,
            "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 0 manifests...\nuploaded 1 lockfile and 0 manifests\nchecking licenses...\n"
        );
        let expected = "\
2 violations in 4 components, 1 local package skipped (inventory: recorded lockfile inventory)

  PACKAGE         LICENSE  REASON
  left-pad 1.3.0  WTFPL    not allowed
  mystery 0.1.0   -        license not reported

Exceptions applied:
  pkg:cargo/ring: reviewed (ring 0.17.8)
";
        assert_eq!(run.stdout, expected);
    }

    #[test]
    fn unresolved_projects_fail_the_check_and_say_what_to_do() {
        let repo = repository(&[("githits-scan.toml", CONFIG), ("bom.cdx.json", "")]);
        let file = repo.path().join("bom.cdx.json");
        let resolutions = r#"[{"status":"partial","path":"app/Package.swift","diagnostics":[{"name":"","reason":"unsupported_ecosystem"}]}]"#;
        let document = serde_json::json!({
            "bomFormat": "CycloneDX",
            "properties": [
                {"name": "githits:completeness", "value": "partial_manifest_inventory"},
                {"name": "githits:resolutions", "value": resolutions},
            ],
            "components": [{"bom-ref": "1", "name": "serde", "version": "1.0.0", "licenses": [{"expression": "MIT"}]}],
        });
        fs::write(&file, document.to_string()).expect("write document");

        let run = check(&request(repo.path(), Source::File(&file)));
        assert!(
            matches!(run.result, Ok(Outcome::Findings)),
            "{:?}",
            run.result
        );
        assert_eq!(
            run.stdout,
            "no violations in 1 component, 1 project not fully resolved (inventory: incomplete dependency resolution)\n\
             \n\
             Licenses not checked: the service could not fully resolve these projects' dependencies\n\
             \x20 app/Package.swift  partially resolved (ecosystem not supported by this check)\n\
             Add a lockfile for each project, or leave it out with --lockfiles-only or --exclude.\n"
        );

        let run = check(&Request {
            json: true,
            ..request(repo.path(), Source::File(&file))
        });
        assert!(
            matches!(run.result, Ok(Outcome::Findings)),
            "{:?}",
            run.result
        );
        let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("json");
        assert_eq!(
            value["unresolved_projects"],
            serde_json::json!([{"path": "app/Package.swift", "status": "partial", "reasons": ["unsupported_ecosystem"]}])
        );
    }

    #[test]
    fn rejects_a_document_over_the_size_limit_before_parsing() {
        let repo = repository(&[("githits-scan.toml", CONFIG), ("bom.cdx.json", "")]);
        let file = repo.path().join("bom.cdx.json");
        let at_limit = vec![b' '; crate::api::MAX_RESPONSE_BYTES];
        fs::write(&file, &at_limit).expect("write document");
        let run = check(&request(repo.path(), Source::File(&file)));
        assert!(
            matches!(run.result, Err(Error::Document(DocumentError::NotJson(_)))),
            "a document at the limit is parsed: {:?}",
            run.result
        );

        fs::write(&file, [at_limit.as_slice(), b" "].concat()).expect("write document");
        let run = check(&request(repo.path(), Source::File(&file)));
        assert!(
            matches!(
                run.result,
                Err(Error::DocumentTooLarge { limit, .. }) if limit == crate::api::MAX_RESPONSE_BYTES
            ),
            "{:?}",
            run.result
        );
    }

    #[test]
    fn reads_an_existing_document_and_emits_json() {
        let repo = repository(&[("githits-scan.toml", CONFIG), ("bom.cdx.json", "")]);
        let file = repo.path().join("bom.cdx.json");
        fs::write(&file, DOCUMENT).expect("write document");

        let run = check(&Request {
            json: true,
            ..request(repo.path(), Source::File(&file))
        });

        assert!(
            matches!(run.result, Ok(Outcome::Findings)),
            "{:?}",
            run.result
        );
        assert!(run.stderr.is_empty(), "{:?}", run.stderr);
        let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("json");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["components"], 4);
        assert_eq!(value["local_packages"], 1);
        assert_eq!(value["completeness"], "recorded_lockfile_inventory");
        assert_eq!(value["violations"][0]["name"], "left-pad");
        assert_eq!(value["violations"][0]["reason"], "not_allowed");
        assert_eq!(value["violations"][1]["reason"], "no_license");
        assert_eq!(
            value["violations"][1]["expression"],
            serde_json::Value::Null
        );
        assert_eq!(value["exceptions_applied"][0]["purl"], "pkg:cargo/ring");
        assert_eq!(
            value["exceptions_applied"][0]["components"],
            serde_json::json!(["ring 0.17.8"])
        );
    }

    #[test]
    fn a_clean_document_succeeds() {
        let repo = repository(&[
            (
                "githits-scan.toml",
                "version = 1\n[licenses]\nallow = [\"MIT\"]\n",
            ),
            (
                "bom.cdx.json",
                r#"{"bomFormat":"CycloneDX","components":[{"bom-ref":"1","name":"a","version":"1","licenses":[{"expression":"MIT"}]}]}"#,
            ),
        ]);
        let file = repo.path().join("bom.cdx.json");

        let run = check(&request(repo.path(), Source::File(&file)));

        assert!(
            matches!(run.result, Ok(Outcome::Success)),
            "{:?}",
            run.result
        );
        assert_eq!(run.stdout, "no violations in 1 component\n");
    }

    #[test]
    fn without_a_config_the_command_is_a_usage_error_that_names_the_file() {
        let repo = repository(&[("Cargo.lock", ""), ("bom.cdx.json", "{}")]);
        let file = repo.path().join("bom.cdx.json");

        let run = check(&request(repo.path(), Source::File(&file)));

        let error = run.result.expect_err("no configuration");
        assert_eq!(error.kind(), ErrorKind::Usage);
        assert!(
            error.to_string().contains("githits-scan.toml")
                && error.to_string().contains("not found"),
            "{error}"
        );
    }

    #[test]
    fn without_a_policy_the_command_is_a_usage_error_that_names_the_table() {
        let repo = repository(&[
            ("githits-scan.toml", "version = 1\n"),
            ("bom.cdx.json", "{}"),
        ]);
        let file = repo.path().join("bom.cdx.json");

        let run = check(&request(repo.path(), Source::File(&file)));

        let error = run.result.expect_err("no policy");
        assert!(matches!(error, Error::NoLicensePolicy { .. }));
        assert_eq!(error.kind(), ErrorKind::Usage);
        assert!(error.to_string().contains("has no [licenses] table"));
        assert!(run.stdout.is_empty() && run.stderr.is_empty());
    }

    #[test]
    fn policy_setup_errors_stop_generation_before_any_request() {
        for case in [
            "missing",
            "no-policy",
            "malformed",
            "unreadable",
            "bad-policy",
            "scoped-exception",
        ] {
            let repo = repository(&[]);
            let path = repo.path().join("githits-scan.toml");
            match case {
                "no-policy" => fs::write(&path, "version = 1\n").expect("write config"),
                "malformed" => fs::write(&path, "not TOML").expect("write config"),
                "unreadable" => fs::create_dir(&path).expect("directory as config"),
                "bad-policy" => fs::write(&path, "version=1\n[licenses]\nallow=[\"gnu gpl v2\"]\n").expect("bad policy"),
                "scoped-exception" => fs::write(&path, "version=1\n[licenses]\n[[licenses.exceptions]]\npurl=\"pkg:cargo/name@1\"\nreason=\"reviewed\"\n").expect("scoped exception"),
                _ => (),
            }
            let api = FakeApi {
                called: Cell::new(false),
            };

            let run = check(&request(repo.path(), Source::Generate(&api)));

            let error = run.result.expect_err(case);
            assert_eq!(error.kind(), ErrorKind::Usage, "{case}: {error}");
            let policy_error = matches!(error, Error::LicensePolicy { .. });
            match case {
                "missing" => assert!(error.to_string().contains("not found"), "{error}"),
                "no-policy" => assert!(matches!(error, Error::NoLicensePolicy { .. })),
                "malformed" => assert!(matches!(
                    error,
                    Error::Config(config::ConfigError::Parse { .. })
                )),
                "unreadable" => assert!(matches!(
                    error,
                    Error::Config(config::ConfigError::Read { .. })
                )),
                "bad-policy" | "scoped-exception" => assert!(policy_error, "{case}"),
                _ => unreachable!("all cases covered"),
            }
            assert!(!api.called.get(), "{case}");
            assert!(run.stdout.is_empty() && run.stderr.is_empty(), "{case}");
        }
    }

    #[test]
    fn a_file_that_is_not_cyclonedx_is_a_usage_error() {
        let repo = repository(&[
            (
                "githits-scan.toml",
                "version = 1\n[licenses]\nallow = [\"MIT\"]\n",
            ),
            ("bom.spdx", "SPDXVersion: SPDX-2.3\n"),
        ]);
        let file = repo.path().join("bom.spdx");

        let run = check(&request(repo.path(), Source::File(&file)));

        let error = run.result.expect_err("not cyclonedx");
        assert_eq!(error.kind(), ErrorKind::Usage);
        assert!(error.to_string().contains("not JSON"), "{error}");
    }

    #[test]
    fn drift_stops_generation_before_any_request() {
        let repo = repository(&[
            ("githits-scan.toml", CONFIG),
            ("Cargo.lock", ""),
            ("web/yarn.lock", ""),
        ]);
        let api = FakeApi {
            called: Cell::new(false),
        };

        let run = check(&request(repo.path(), Source::Generate(&api)));

        assert!(
            matches!(run.result, Ok(Outcome::Findings)),
            "{:?}",
            run.result
        );
        assert!(!api.called.get());
        assert!(run.stdout.is_empty(), "{:?}", run.stdout);
        assert!(
            run.stderr
                .starts_with("scanning repository...\ninventory drift against "),
            "{}",
            run.stderr
        );
    }
}
