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

## [0.5.0] - 2026-11-11

### Changed

- **Breaking: native lifecycle audits** - Audits request report v3 automatically
  and preserve native deprecation, withdrawal, retained warnings, source
  observations and affected paths. Native findings and genuine unknown checks
  require attention; lifecycle collection limits and not-applicable checks do not
  fail alone. Unsupported returned versions fail without output or resubmission.
- **Audit format migration** - Audit/explanation JSON and saved analyses advance
  to format 2. JSON consumers must adopt native `lifecycle` evidence in place of
  the removed coarse `deprecated` list. Older reports and saved archives are no
  longer read. Keep the recorded writer's reader for old saved analyses: 0.4.0
  reads archive format 1, while 0.5.0 reads format 2; neither automatically migrates
  the other's archive. Rollback to 0.4.0 restores the prior Git warnings and exits.
- **Informational Git coverage** - Expected Git registry, graph and source-binding
  limits are coverage notes instead of actionable warnings. Factual incompleteness
  remains, but these limits do not independently cause audit exit 1. Audit JSON
  adds `actionable_incomplete` and `issues[].actionable`; saved explanations add
  `audit_actionable_incomplete`. Mixed, unfamiliar and inconsistent evidence still
  requires attention. Dependency-comparison human and Markdown reports show
  these limits as coverage notes instead of generic partial cautions. Raw
  dependency-diff JSON remains unchanged.
- **Clearer audit output** - Human reports omit empty totals, group package
  warnings plainly, explain missing transitive dependencies and simplify fix
  guidance. Complete displayed advisory sets are summarized without repeating
  identifiers; partial fixes and requirement conflicts remain explicit.
- **Recover from short rate limits** - Retry HTTP 429 up to five times across each
  scan, honoring Retry-After within five minutes of total waiting. Every retry is
  reported on stderr, including quiet/JSON mode. Missing, invalid or over-budget
  delays still fail promptly; accepted analyses are never resubmitted.

### Fixed

- **Include Bun workspace evidence** - Declared workspace member manifests now
  accompany `bun.lock` across upload commands and detect previews, including
  lockfiles-only scans. This expands default upload selection; existing exclusions
  and upload limits still apply.
- **Complete comparison Markdown** - Include every returned release note and
  retain entries missing a summary. Terminal output keeps its compact selection;
  service omissions remain explicit.
- **Explain dependency comparisons clearly** - Human and Markdown reports explain
  incomplete dependency information, file problems and upgrade-review failures in
  plain language, with useful context and supported next steps. Repeated
  limitations are grouped without hiding known risks; ordinary accents and emoji
  remain readable. Internal codes and diagnostic counters stay in unchanged JSON.
- **Missing diff inputs** - Human and Markdown reports name the required file when
  the service explains that an input was not supplied.

## [0.4.0] - 2026-11-09

### Added

- **Experimental dependency diff** - Compare Git revisions or the working tree
  through one paired analysis. Human and Markdown reports show source-local
  direct/transitive changes, ownership, scoped advisories and direct upgrade
  evidence; JSON preserves the service report. Git and a token are required,
  including for identical/empty inputs. One analysis costs twice the audit weight;
  the complete pair shares 256 files and an 8 MB multipart limit. Configuration
  is ignored; use explicit exclusions. Exit 0 is informational, including for
  partial or unknown evidence, and is not a policy pass.
- **Diff JSON and Markdown from one analysis** - Use `diff --output-json diff.json
  --output-markdown diff.md` to save exact JSON and Scan-rendered Markdown from
  the same report, or either named output alone. `-` selects stdout for at most
  one destination. Named outputs conflict with `--format` and `-o/--output`;
  existing single-output invocations are unchanged.
- **Reviewed policy exceptions** - License checks accept exact named Git-source
  exceptions with optional full revisions. Advisory ignores retain findings and
  reasons in text, JSON and saved replay without causing failure themselves;
  other audit categories and evidence gaps remain strict.
- **Explain remediation changes** - Audit recommendations show the service's
  checked effects when available, with request evidence in saved explanations
  and JSON. Older reports remain usable and unknown future reasons survive replay.
- **Homebrew distribution** - Install with `brew install githits-com/tap/githits-scan`.
  Bottles cover macOS 15 ARM64 and Linux x86_64/ARM64; Intel macOS builds from
  source. Tagged releases open formula updates for tap bottle publication.

### Changed

- **Policy compatibility and migration** - License-exception reasons must now
  be nonblank. Fill in blank reasons before upgrading. Before returning to an
  older binary, remove `[[audit.ignore]]` and Git-source exception entries from
  configuration; older saved-analysis readers may omit ignores and return
  stricter results. Audit and license-check JSON additions retain schema 1.
  Rust callers must migrate `config::Exception` from a struct to its `Package`
  or `Git` variant, access applied selectors/reasons through
  `license::Applied::exception`, and supply the new `config::Config::audit`,
  `license::Violation::source` and `api::Problem::side` fields when constructing
  those values. Update exhaustive matches for new command-error and API-code
  variants.
- **License coverage warnings** - License checks warn on stderr for zero evaluated
  components and incomplete resolution; offline SBOMs also warn when inventory
  completeness evidence is absent. Warnings remain visible with quiet and JSON
  modes, without changing verdicts or exit codes.
- **Compact license group rows** - Human license check/report output combines
  equivalent default/develop occurrences while preserving differing evidence,
  per-occurrence details, policy results and JSON inventory.
- **Installation guidance** - Homebrew is the recommended macOS/Linux install;
  crates.io is the primary Cargo installation method. Prebuilt binaries and
  checkout installs remain supported.
- **Automated release procedure** - Add a maintainer release skill, full
  previous-tag range review and explicit approval gates. The first automated
  release follows the manually published 0.3.0. Protected crates.io dispatches
  use the approved release tag, and Homebrew handoff requires environment approval.

### Fixed

- **Clarify remediation choices** - Audit output separates advisory-reported fix
  versions from recommendations, explains conflicts and unresolved findings,
  and shows override coverage and verification limits. Joint changes show
  retained request context without guessing why the service chose a change.
- **Identify blocked dependencies** - Remediation blockers show the requested
  dependency name when supplied and preserve `dependency_name` in JSON and saved
  analyses. Older reports retain their blocker structure; provider-bound
  requirements use a readable label.
- **Detect configuration migration guidance** - Correct the 0.3.0 changelog:
  `detect --config FILE --save` creates a missing file from the commented template;
  other commands reject missing explicit configurations with exit 2.

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
