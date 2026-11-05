# Changelog

All notable `githits-scan` changes are recorded here. Unreleased changes use
independent files under [`changes/`](changes/README.md) and are consolidated
here only during release preparation. Dated, versioned sections are historical
records and change only to correct blatant factual errors.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

0.3.0 is the first public release. The 0.2.0 section below records the
pre-public baseline, not a supported installation target. Historical flags in
that section describe 0.2.0 only; use the README for current commands and the
0.3.0 migration notes when updating pre-public automation.

## [0.3.0] - 2026-11-05

### Added

- **Offline audit investigation** - Save an analysis with
  `audit --save-analysis` and replay it with `--from-analysis` without a token
  or network access. Saved evidence supports investigation without another job.
- **Dependency audits** - Audit vulnerabilities, deprecated releases, outdated
  and duplicate versions, and manifest/lockfile disagreements. Human reports
  include service-supplied fix alternatives and explicit coverage gaps; any
  finding or incomplete check exits 1. JSON retains the consumed evidence.
- **License evidence reports** - Add `license report`, lossless experimental API
  JSON, and offline saved-report replay. Reported licenses, publisher context,
  source observations, and coverage gaps remain distinct from policy verdicts.
- **Go, vcpkg, and Zig** - Recognize `go.mod`, `vcpkg.json`, and `build.zig.zon`
  as manifest-only inputs. Go modules remain separate from Go dep locks, and
  vcpkg manifests remain separate from Conan locks.
- **Consistent report destinations and quiet mode** - All commands accept
  `-o/--output` and `-q/--quiet`, including saved-report replay. Quiet
  suppresses routine progress and success notes while preserving reports,
  findings, warnings, and errors.

### Changed

- **Breaking changes and migration** - Update automation written for the
  pre-public 0.2.0 CLI before using 0.3.0.

  #### Exit codes

  Exit 0 means success; 1 means findings, incomplete checks, drift, or nothing
  selected; 2 means caller action is required; 3 means an execution failure.
  Rejected credentials/access, missing selected inputs, invalid UTF-8 upload
  paths/content, upload limits, and deterministic API input/format rejections
  exit 2. HTTP 408/429, network, I/O, service, and protocol failures exit 3.
  Update scripts that treated all API failures as retryable execution errors.

  #### Detection JSON and default selection

  `detect --json` is schema 2. Replace `include_manifests` with the inverse
  `lockfiles_only` boolean, and accept the new `unsupported` and `test_paths`
  arrays. Manifest-only projects are included by default; replace the removed
  `--include-manifests` flag with no flag, or use `--lockfiles-only` to omit
  unconfigured manifest-only projects. Review `detect` and run `detect --save`
  to accept intended inventory changes. Missing explicit `--config` files now
  fail with exit 2, except that `detect --config FILE --save` creates a missing
  file from the same commented template as plain `detect --save`.
- **Compact license reports** - Online `license report --json` uses experimental
  schema 2 with typed input paths and focused evidence summaries. Offline replay
  accepts schemas 1 and 2 with exact original JSON bytes. Human details show
  supplied evidence gaps.
- **Fixture selection** - Exclude directories named `fixtures`, `__fixtures__`,
  `testdata`, `test-data`, or `test_data` at any depth, ignoring ASCII
  case. Explicit configuration entries can select real projects in those
  directories. Ordinary test/evaluation directories remain eligible and are
  annotated for review; invocation excludes still take precedence.
- **Stricter license checks** - Evaluate nested components, require explicit
  SPDX policy expressions and package-wide exceptions, and report unresolved
  projects as findings (exit 1). Malformed CycloneDX structures are usage errors
  (exit 2); offline documents are limited to 16 MiB. Human reports escape
  terminal controls and bound previews; JSON retains full evidence.
- **Owning manifest pairs** - Pair locks only with their cataloged owners.
  Uncombined and nested manifests remain visible for review. A
  `packages.lock.json` beside several `.csproj` files is ambiguous and is not
  uploaded; review affected configuration with `detect --save`.
- **Public documentation** - Add verified upload/privacy details,
  troubleshooting, uninstall instructions, CI setup, and contributor guidance.
  Label 0.2.0 as pre-public history; 0.3.0 is the first public release.
- **Build requirements** - Require Rust 1.99 or newer; development and CI pin
  Rust 1.99.1. Prebuilt binaries do not require Rust.
- **Workspace evidence** - Upload eligible declared Cargo and supported positive
  npm workspace member manifests under selected locks, including with
  `--lockfiles-only`. Exclusions and the 256-file upload limit still apply.
  Other nested manifests require explicit configuration; directory proximity
  alone does not prove dependency coverage.

### Fixed

- **Detect privacy documentation** - Clarify that the local upload preview reads
  selected package-file contents and expands eligible Cargo/npm workspace
  members without contacting the API.
- **Actionable input failures** - Distinguish missing configuration from missing
  license policy, identify unsupported formats, and explain upload-limit and
  account-access remedies. Limit connection establishment to 15 seconds.
- **Actionable CLI guidance** - Create explicit new config paths from the
  commented template with `detect --save`. Improve audit explanations, license
  evidence details, unsupported-format warnings, API-origin/proxy failures,
  quiet help, and common option ordering. Configuration-write failures exit 3.
- **Accurate scan selection** - Prune explicitly excluded directory subtrees
  before reading them and honor owning-manifest exclusions. `detect` previews
  the bounded Cargo/npm upload selection, preserving inventory with exit 2/3
  when preparation is blocked. Reports distinguish selected/excluded counts and
  summarize selected test-looking paths. Real projects under `truth` remain
  eligible by default.

### Security

- **TLS handshake fixes** - Update rustls to 0.23.46 for RUSTSEC-2026-0346,
  RUSTSEC-2026-0347, RUSTSEC-2026-0348, and RUSTSEC-2026-0349.
- **TLS trust fixes** - Update rustls-webpki and webpki-root-certs to reject
  distrusted certificate authorities (RUSTSEC-2026-0382 and RUSTSEC-2026-0383).

## [0.2.0] - 2026-10-12

_Pre-public baseline._

### Added

- **Repository inventory** - `githits-scan detect` finds lockfiles, companion and
  nested manifests, and manifest-only projects without credentials or network
  access. `--json` emits a versioned inventory; the then-current
  `--include-manifests` flag opted into manifest-only projects (removed in 0.3.0).
- **Configuration and drift checks** - `githits-scan.toml` records lockfile and
  manifest selection and license policy. Inventory drift exits 1 for detect,
  SBOM generation and repository-backed license checks before upload, unless
  `--no-check` is used. `detect --save` preserves unrelated configuration and
  comments; unknown keys and unsupported versions are usage errors.
- **SBOM generation** - `githits-scan sbom generate` produces CycloneDX, SPDX, or
  text through the GitHits API and writes the complete document to stdout or
  `--output`. Upload limits are checked before file reads. Credentials come only
  from `GITHITS_API_TOKEN`; origin overrides require HTTPS except for loopback.
- **License policy** - `githits-scan license check` evaluates SPDX expressions and
  package exceptions against the configured allow list, using a generated SBOM
  or an existing `--sbom FILE`. `--json` produces a versioned report; violations
  exit 1; missing or invalid policies and malformed documents exit 2.
- **Invocation exclusions** - Repeatable `--exclude` globs override configuration
  inclusion for detect, SBOM generation, and repository-backed license checking.
  `detect --save` records the patterns; `--exclude` conflicts with `--sbom`.
- **Bun text lockfiles** - Detect and upload `bun.lock` with its same-directory
  `package.json` by default; binary `bun.lockb` remains excluded. Existing
  inventories report newly detected Bun files as drift: review and save with
  `detect --save`, or exclude them.
- **Verified distribution** - Five native GitHub archives cover Linux x86_64 and
  ARM64, macOS Intel and Apple Silicon, and Windows x86_64, with SHA256SUMS.
  Release publication follows exact-commit CI, live API tests, extracted-binary
  checks, and asset verification. Crates.io publication remains deferred.

### Changed

- **Asynchronous scans** - SBOM generation and repository-backed license reports
  now use lockfile jobs, authenticated event streaming and stream recovery.
  Human stderr reports scanning, uploads, job stages, reconnection and download
  with actual counts and actionable failures. Completion is reported only after
  writing the document; document bytes and exit codes are unchanged. JSON
  license reports suppress progress. Library callers of `SbomApi::generate` must
  supply a `ProgressEvent` callback returning `std::io::Result<()>`.

### Security

- **TLS handshake validation** - Rustls 0.23.45 fixes RUSTSEC-2026-0285, which
  allowed TLS 1.3 handshake messages across encryption-level boundaries.
