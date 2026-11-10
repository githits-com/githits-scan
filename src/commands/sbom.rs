//! `githits-scan sbom generate`: upload the inventory and write the document.
//!
//! Orchestration only: discovery produces the inventory, the API boundary
//! validates the plan and runs one job, and this module decides what
//! is uploaded, writes the document only after success, and prints the
//! summary. Manifest-only projects are uploaded unless the run is
//! `--lockfiles-only` or a configuration does not list them; the summary names
//! every one it uploads or reports as skipped, and excluded ones stay silent.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{Error, Outcome};
use crate::api::{Document, OutputFormat, SbomApi};
use crate::style::Palette;

/// Where the document goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// The process's standard output.
    Stdout,
    /// A file, written only after the service returned the whole document.
    File(PathBuf),
}

/// What the caller asked for.
#[derive(Debug)]
pub struct Request<'a> {
    /// Directory to scan.
    pub root: &'a Path,
    /// Configuration file; defaults to `githits-scan.toml` in `root`.
    pub config: Option<&'a Path>,
    /// Upload despite inventory drift.
    pub no_check: bool,
    /// Document format to request.
    pub format: OutputFormat,
    /// Suppress routine progress and success messages; retain actionable diagnostics.
    pub quiet: bool,
    /// Destination of the document.
    pub output: Output,
    /// Upload manifest-only projects for registry resolution.
    pub include_manifests: bool,
    /// Invocation `--exclude` globs; same language as `lockfiles.exclude`.
    pub exclude: &'a [String],
}

/// The inputs of a generation, shared with `license check`.
#[derive(Debug, Clone, Copy)]
pub struct Generation<'a> {
    /// Directory to scan.
    pub root: &'a Path,
    /// Configuration file; defaults to `githits-scan.toml` in `root`.
    pub config: Option<&'a Path>,
    /// Upload despite inventory drift.
    pub no_check: bool,
    /// Upload manifest-only projects for registry resolution.
    pub include_manifests: bool,
    /// Invocation `--exclude` globs; same language as `lockfiles.exclude`.
    pub exclude: &'a [String],
    /// Render live progress to stderr; false for machine license reports.
    pub progress: bool,
    /// Document format to request.
    pub format: OutputFormat,
}

/// How a generation ended.
#[derive(Debug)]
pub enum Generated {
    /// Nothing was requested: drift, or nothing to upload. The reason has
    /// already been written to `stderr`.
    Findings,
    /// The service returned a document. The caller prints the upload
    /// summary once its own work succeeds. Live progress may already have
    /// reached `stderr` even if that later work fails.
    Document {
        /// The document as received.
        document: Document,
        /// The rendered "uploaded ..." line.
        summary: String,
    },
}

/// Scan, gate on drift, upload, and return the document.
///
/// # Errors
///
/// Returns the discovery, configuration, upload-limit, API, or output error
/// that stopped the run.
pub fn generate(
    generation: &Generation<'_>,
    api: &dyn SbomApi,
    stderr: &mut dyn Write,
    palette: Palette,
) -> Result<Generated, Error> {
    let options = super::upload::Options {
        root: generation.root,
        config: generation.config,
        no_check: generation.no_check,
        include_manifests: generation.include_manifests,
        exclude: generation.exclude,
        progress: generation.progress,
    };
    let Some(prepared) = super::upload::prepare(&options, stderr, palette)? else {
        return Ok(Generated::Findings);
    };
    let document = api.generate(prepared.upload, generation.format, &mut |event| {
        if super::progress::visible(event, generation.progress) {
            super::progress::write(event, stderr)
        } else {
            Ok(())
        }
    })?;
    Ok(Generated::Document {
        document,
        summary: prepared.summary,
    })
}

/// Scan, upload, and write the document.
///
/// Returns [`Outcome::Findings`] without contacting the service when nothing
/// would be uploaded. The summary goes to `stderr`; the document goes to
/// `stdout` or the requested file.
///
/// # Errors
///
/// Returns the discovery, upload-limit, API, or output error that stopped the
/// run. Generation failures never write to the document destination; output I/O
/// failures may leave partial writes.
pub fn run(
    request: &Request<'_>,
    api: &dyn SbomApi,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    palette: Palette,
) -> Result<Outcome, Error> {
    let generation = Generation {
        root: request.root,
        config: request.config,
        no_check: request.no_check,
        include_manifests: request.include_manifests,
        exclude: request.exclude,
        format: request.format,
        progress: !request.quiet,
    };
    let (document, summary) = match generate(&generation, api, stderr, palette)? {
        Generated::Findings => return Ok(Outcome::Findings),
        Generated::Document { document, summary } => (document, summary),
    };
    write_document(&document.bytes, &request.output, stdout)?;
    let completeness = match request.format {
        OutputFormat::CycloneDx => document.completeness(),
        OutputFormat::Spdx | OutputFormat::Text => None,
    };
    if request.quiet {
        if completeness.as_deref() == Some("partial_manifest_inventory") {
            writeln!(
                stderr,
                "warning: SBOM dependency resolution is incomplete (partial_manifest_inventory)"
            )
            .map_err(Error::Output)?;
        }
        return Ok(Outcome::Success);
    }
    let written = describe_destination(&request.output, document.bytes.len());
    writeln!(stderr, "{summary}").map_err(Error::Output)?;
    match completeness {
        Some(value) => writeln!(stderr, "inventory: {}; {written}", super::safe(&value)),
        None => writeln!(stderr, "{written}"),
    }
    .map_err(Error::Output)?;
    Ok(Outcome::Success)
}

pub(super) fn write_document(
    bytes: &[u8],
    output: &Output,
    stdout: &mut dyn Write,
) -> Result<(), Error> {
    match output {
        Output::Stdout => {
            stdout.write_all(bytes).map_err(Error::Output)?;
            stdout.flush().map_err(Error::Output)
        }
        Output::File(path) => fs::write(path, bytes).map_err(|source| Error::OutputFile {
            path: path.clone(),
            source,
        }),
    }
}

pub(super) fn describe_destination(output: &Output, bytes: usize) -> String {
    match output {
        Output::Stdout => format!("wrote {bytes} bytes to stdout"),
        Output::File(path) => format!("saved {} ({bytes} bytes)", super::safe_path(path)),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use tempfile::TempDir;

    use super::*;
    use crate::api::{self, ApiError, Document, UploadSet};
    use crate::commands::ErrorKind;

    /// Records the upload it received and answers with a fixed result.
    struct FakeApi {
        received: RefCell<Option<(UploadSet, OutputFormat)>>,
        result: Result<Vec<u8>, fn() -> ApiError>,
    }

    impl FakeApi {
        fn returning(bytes: &[u8]) -> Self {
            Self {
                received: RefCell::new(None),
                result: Ok(bytes.to_vec()),
            }
        }

        fn failing(error: fn() -> ApiError) -> Self {
            Self {
                received: RefCell::new(None),
                result: Err(error),
            }
        }

        fn received_paths(&self) -> Vec<String> {
            let received = self.received.borrow();
            let (upload, _) = received.as_ref().expect("api was called");
            upload.files().iter().map(|f| f.path.clone()).collect()
        }
    }

    impl SbomApi for FakeApi {
        fn generate(
            &self,
            upload: UploadSet,
            format: OutputFormat,
            _: &mut dyn FnMut(&api::ProgressEvent) -> std::io::Result<()>,
        ) -> Result<Document, ApiError> {
            *self.received.borrow_mut() = Some((upload, format));
            match &self.result {
                Ok(bytes) => Ok(Document {
                    bytes: bytes.clone(),
                }),
                Err(error) => Err(error()),
            }
        }
    }

    const CYCLONEDX: &[u8] = br#"{"bomFormat":"CycloneDX","properties":[{"name":"githits:completeness","value":"recorded_lockfile_inventory"}]}"#;

    fn repository(files: &[(&str, &str)]) -> TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (relative, contents) in files {
            write_file(&dir.path().join(relative), contents);
        }
        dir
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, contents).expect("write file");
    }

    struct Run {
        result: Result<Outcome, Error>,
        stdout: Vec<u8>,
        stderr: String,
    }

    fn generate(request: &Request<'_>, api: &dyn SbomApi) -> Run {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = run(request, api, &mut stdout, &mut stderr, Palette::PLAIN);
        Run {
            result,
            stdout,
            stderr: String::from_utf8(stderr).expect("utf-8 stderr"),
        }
    }

    #[test]
    fn uploads_lockfiles_with_companions_and_writes_the_document_to_stdout() {
        let repo = repository(&[
            ("Cargo.lock", "# lock"),
            ("Cargo.toml", "[package]"),
            ("web/package-lock.json", "{}"),
            ("web/yarn.lock", ""),
            ("web/package.json", "{}"),
            ("crates/core/Cargo.toml", "nested"),
            ("legacy/package.json", "{}"),
        ]);
        let api = FakeApi::returning(CYCLONEDX);
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &[],
        };

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Success)),
            "{:?}",
            run.result
        );
        assert_eq!(run.stdout, CYCLONEDX);
        assert_eq!(
            api.received_paths(),
            [
                "Cargo.lock",
                "Cargo.toml",
                "web/package-lock.json",
                "web/package.json",
                "web/yarn.lock"
            ]
        );
        assert_eq!(
            run.stderr,
            format!(
                "scanning repository...\npreparing upload...\nsubmitting 3 lockfiles and 2 manifests...\nuploaded 3 lockfiles and 2 manifests (Cargo.toml, web/package.json); 1 manifest-only project not uploaded (legacy/package.json; --lockfiles-only)\ninventory: recorded_lockfile_inventory; wrote {} bytes to stdout\n",
                CYCLONEDX.len()
            )
        );
    }

    #[test]
    fn uploads_lockfiles_only_with_the_manifests_that_own_them() {
        let repo = repository(&[
            ("py/Pipfile.lock", "{}"),
            ("py/pyproject.toml", "[project]"),
            ("jvm/gradle.lockfile", "x"),
            ("jvm/build.gradle", "y"),
            ("net/packages.lock.json", "{}"),
            ("net/App.csproj", "<a/>"),
            ("net/Tool.csproj", "<t/>"),
        ]);
        let api = FakeApi::returning(CYCLONEDX);
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &[],
        };

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Success)),
            "{:?}",
            run.result
        );
        assert_eq!(
            api.received_paths(),
            ["jvm/gradle.lockfile", "py/Pipfile.lock"]
        );
        assert!(
            run.stderr.starts_with(
                "scanning repository...\nwarning: net/packages.lock.json is not uploaded: net/App.csproj, net/Tool.csproj could each own it, so they are manifest-only projects; exclude the lockfile to accept this\n"
            ),
            "{}",
            run.stderr
        );
        assert!(
            run.stderr.contains(
                "uploaded 2 lockfiles and 0 manifests; 2 manifest-only projects not uploaded (net/App.csproj, net/Tool.csproj; --lockfiles-only)"
            ),
            "{}",
            run.stderr
        );
    }

    #[test]
    fn excluding_an_ambiguous_lockfile_silences_its_warning() {
        let repo = repository(&[
            ("Cargo.lock", "# lock"),
            ("net/packages.lock.json", "{}"),
            ("net/App.csproj", "<a/>"),
            ("net/Tool.csproj", "<t/>"),
        ]);
        let api = FakeApi::returning(CYCLONEDX);
        let exclude = ["net/packages.lock.json".to_string()];
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: true,
            exclude: &exclude,
        };

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Success)),
            "{:?}",
            run.result
        );
        assert!(!run.stderr.contains("warning"), "{}", run.stderr);
        assert_eq!(
            api.received_paths(),
            ["Cargo.lock", "net/App.csproj", "net/Tool.csproj"]
        );
    }

    #[test]
    fn exclude_skips_matching_lockfiles_without_a_configuration() {
        let repo = repository(&[
            ("Cargo.lock", "# lock"),
            ("Cargo.toml", "[package]"),
            ("web/yarn.lock", ""),
        ]);
        let api = FakeApi::returning(CYCLONEDX);
        let exclude = ["web/**".to_string()];
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &exclude,
        };

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Success)),
            "{:?}",
            run.result
        );
        assert_eq!(api.received_paths(), ["Cargo.lock", "Cargo.toml"]);
    }

    #[test]
    fn exclude_does_not_upload_manifest_only_projects_without_the_flag() {
        let repo = repository(&[
            ("Cargo.lock", "# lock"),
            ("Cargo.toml", "[package]"),
            ("legacy/package.json", "{}"),
        ]);
        let api = FakeApi::returning(CYCLONEDX);
        let exclude = ["vendor/**".to_string()];
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &exclude,
        };

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Success)),
            "{:?}",
            run.result
        );
        assert_eq!(api.received_paths(), ["Cargo.lock", "Cargo.toml"]);
        assert!(run.stderr.contains("legacy/package.json"), "{}", run.stderr);
    }

    #[test]
    fn excluding_every_lockfile_is_a_finding_that_does_not_claim_an_empty_tree() {
        let repo = repository(&[("Cargo.lock", ""), ("Cargo.toml", "")]);
        let api = FakeApi::returning(CYCLONEDX);
        let exclude = ["*".to_string()];
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &exclude,
        };

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Findings)),
            "{:?}",
            run.result
        );
        assert!(api.received.borrow().is_none());
        assert!(
            run.stderr.contains("every lockfile is excluded"),
            "{}",
            run.stderr
        );
        assert!(!run.stderr.contains("no lockfiles found"), "{}", run.stderr);
    }

    #[test]
    fn an_invalid_exclude_glob_is_a_usage_error_before_any_request() {
        let repo = repository(&[("Cargo.lock", "")]);
        let api = FakeApi::returning(CYCLONEDX);
        let exclude = ["[".to_string()];
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &exclude,
        };

        let run = generate(&request, &api);

        let error = run.result.expect_err("invalid glob");
        assert_eq!(error.kind(), ErrorKind::Usage);
        assert!(error.to_string().contains("--exclude"), "{error}");
        assert!(api.received.borrow().is_none());
    }

    #[test]
    fn include_manifests_uploads_manifest_only_projects_and_names_them() {
        let repo = repository(&[("Cargo.lock", ""), ("legacy/package.json", "{}")]);
        let api = FakeApi::returning(b"SPDXVersion: SPDX-2.3\n");
        let output = repo.path().join("out/bom.spdx");
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::Spdx,
            output: Output::File(output.clone()),
            include_manifests: true,
            exclude: &[],
        };
        fs::create_dir_all(output.parent().expect("parent")).expect("mkdir");

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Success)),
            "{:?}",
            run.result
        );
        assert!(run.stdout.is_empty(), "{:?}", run.stdout);
        assert_eq!(
            fs::read(&output).expect("output file"),
            b"SPDXVersion: SPDX-2.3\n"
        );
        assert_eq!(api.received_paths(), ["Cargo.lock", "legacy/package.json"]);
        assert_eq!(
            run.stderr,
            format!(
                "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 1 manifest...\nuploaded 1 lockfile and 1 manifest (legacy/package.json)\nsaved {} (22 bytes)\n",
                output.display()
            )
        );
    }

    #[test]
    fn an_empty_inventory_is_a_finding_and_never_calls_the_api() {
        let repo = repository(&[("README.md", ""), ("legacy/package.json", "{}")]);
        let api = FakeApi::returning(CYCLONEDX);
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &[],
        };

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Findings)),
            "{:?}",
            run.result
        );
        assert!(api.received.borrow().is_none());
        assert!(run.stdout.is_empty(), "{:?}", run.stdout);
        assert!(
            run.stderr
                .starts_with("scanning repository...\nno lockfiles found in "),
            "{}",
            run.stderr
        );
        assert!(
            run.stderr.ends_with(
                "1 manifest-only project not uploaded (--lockfiles-only): legacy/package.json\n"
            ),
            "{}",
            run.stderr
        );
    }

    #[test]
    fn api_errors_are_execution_errors_and_write_no_document() {
        let repo = repository(&[("Cargo.lock", "")]);
        let api = FakeApi::failing(|| ApiError::Unexpected {
            status: 502,
            request_id: Some("req".into()),
        });
        let output = repo.path().join("bom.cdx.json");
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::File(output.clone()),
            include_manifests: false,
            exclude: &[],
        };

        let run = generate(&request, &api);

        let error = run.result.expect_err("api failure");
        assert_eq!(error.kind(), ErrorKind::Execution);
        assert!(!output.exists(), "output file must not be created");
        assert!(run.stdout.is_empty(), "{:?}", run.stdout);
        assert_eq!(
            run.stderr,
            "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 0 manifests...\n"
        );
    }

    #[test]
    fn a_failed_write_has_progress_but_no_completion() {
        let repo = repository(&[("Cargo.lock", "")]);
        let api = FakeApi::returning(CYCLONEDX);
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::File(repo.path().join("missing-dir").join("bom.cdx.json")),
            include_manifests: false,
            exclude: &[],
        };

        let run = generate(&request, &api);

        let error = run.result.expect_err("write failure");
        assert_eq!(error.kind(), ErrorKind::Execution);
        assert_eq!(
            run.stderr,
            "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 0 manifests...\n"
        );
    }

    #[test]
    fn oversized_files_fail_before_any_read_or_request() {
        let repo = repository(&[("Cargo.lock", "")]);
        let big = repo.path().join("Cargo.lock");
        let file = fs::File::create(&big).expect("create");
        file.set_len(api::MAX_FILE_BYTES + 1).expect("set_len");
        let api = FakeApi::returning(CYCLONEDX);
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &[],
        };

        let run = generate(&request, &api);

        let error = run.result.expect_err("too large");
        assert_eq!(error.kind(), ErrorKind::Usage);
        assert!(
            error.to_string().contains("Cargo.lock is 5242881 bytes"),
            "{error}"
        );
        assert!(api.received.borrow().is_none());
    }

    #[test]
    fn a_file_that_is_not_utf8_is_a_usage_error() {
        let repo = repository(&[("Cargo.lock", "")]);
        fs::write(repo.path().join("Cargo.lock"), [0xff, 0xfe]).expect("write");
        let api = FakeApi::returning(CYCLONEDX);
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &[],
        };

        let run = generate(&request, &api);

        let error = run.result.expect_err("not utf-8");
        assert_eq!(error.to_string(), "Cargo.lock is not valid UTF-8");
        assert_eq!(error.kind(), super::super::ErrorKind::Usage);
        assert!(api.received.borrow().is_none());
    }

    const CONFIG: &str = "\
version = 1

[lockfiles]
include = [\"Cargo.lock\"]
exclude = [\"examples/**\"]
manifests = [\"legacy/package.json\", \"crates/core/Cargo.toml\"]
";

    #[test]
    fn drift_stops_before_any_request_unless_no_check() {
        let repo = repository(&[
            (
                "githits-scan.toml",
                "version = 1\n[lockfiles]\ninclude = [\"Cargo.lock\"]\n",
            ),
            ("Cargo.lock", ""),
            ("web/yarn.lock", ""),
        ]);
        let api = FakeApi::returning(CYCLONEDX);
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &[],
        };

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Findings)),
            "{:?}",
            run.result
        );
        assert!(api.received.borrow().is_none());
        assert!(run.stdout.is_empty(), "{:?}", run.stdout);
        assert_eq!(
            run.stderr,
            format!(
                "scanning repository...\ninventory drift against {} (run `githits-scan detect --save` to accept the detected inventory, or pass --no-check)\n  unlisted: web/yarn.lock\n",
                repo.path().join("githits-scan.toml").display()
            )
        );

        let run = generate(
            &Request {
                quiet: false,
                no_check: true,
                ..request
            },
            &api,
        );

        assert!(
            matches!(run.result, Ok(Outcome::Success)),
            "{:?}",
            run.result
        );
        assert_eq!(
            api.received_paths(),
            ["Cargo.lock"],
            "unlisted lockfiles are not uploaded"
        );
    }

    #[test]
    fn a_config_selects_included_lockfiles_and_listed_manifests() {
        let repo = repository(&[
            ("githits-scan.toml", CONFIG),
            ("Cargo.lock", ""),
            ("Cargo.toml", ""),
            ("crates/core/Cargo.toml", ""),
            ("examples/demo/Cargo.lock", ""),
            ("examples/demo/package.json", ""),
            ("legacy/package.json", ""),
            ("tools/package.json", ""),
        ]);
        let api = FakeApi::returning(CYCLONEDX);
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::CycloneDx,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &[],
        };

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Success)),
            "{:?}",
            run.result
        );
        assert_eq!(
            api.received_paths(),
            [
                "Cargo.lock",
                "Cargo.toml",
                "crates/core/Cargo.toml",
                "legacy/package.json"
            ]
        );
        assert!(
            run.stderr.starts_with(
                "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 3 manifests...\nuploaded 1 lockfile and 3 manifests (Cargo.toml, crates/core/Cargo.toml, legacy/package.json); 1 manifest-only project not uploaded (tools/package.json; --lockfiles-only)\n"
            ),
            "{}",
            run.stderr
        );
    }

    #[test]
    fn requested_format_is_passed_through() {
        let repo = repository(&[("Cargo.lock", "")]);
        let api = FakeApi::returning(b"GitHits dependency inventory report\n");
        let request = Request {
            quiet: false,
            root: repo.path(),
            config: None,
            no_check: false,
            format: OutputFormat::Text,
            output: Output::Stdout,
            include_manifests: false,
            exclude: &[],
        };

        let run = generate(&request, &api);

        assert!(
            matches!(run.result, Ok(Outcome::Success)),
            "{:?}",
            run.result
        );
        let received = api.received.borrow();
        assert_eq!(
            received.as_ref().map(|(_, format)| *format),
            Some(OutputFormat::Text)
        );
        assert!(
            run.stderr.ends_with("wrote 36 bytes to stdout\n"),
            "{}",
            run.stderr
        );
    }
}
