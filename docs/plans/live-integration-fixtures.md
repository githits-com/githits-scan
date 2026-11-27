# Live integration fixtures for release qualification

## Outcome

Contributors can run the real Scan binary against one named fixture or the
complete corpus with one command. The runner fetches pinned public package
files automatically and verifies their hashes. Every cataloged lockfile format
and ecosystem exercises SBOM generation, audit and license reporting. The
merged release commit runs the full corpus before tagging. Ordinary PR CI
continues to use network-free tests.

The corpus should catch regressions in Scan and in the deployed API. Pinned
inputs make a lost locked package or input association a regression. The audit
also has to detect a known historical vulnerability and produce a usable
recommendation, while allowing newer eligible versions to change that
recommendation. Maintainers can review and refresh one baseline or all of them.

## Current state and evidence

- [The catalog](../../src/catalog.rs) has 16 ecosystem IDs, 23 exact lockfile
  names, and a legacy Gradle path pattern. The same `yarn.lock` name covers
  classic and Berry. Go modules, vcpkg and Zig also need manifest-only cases.
  [The catalog guide](../implementation/package-file-catalog.md) distinguishes
  automatic companions, uncombined inputs and native workspace evidence.
- [The ignored live tests](../../tests/live.rs) make five submissions for
  npm/Cargo workspace SBOM, Bun SBOM, manifest-only resolution, npm audit and
  npm licenses. The audit checks a qualified minimist upgrade within the
  fixture's patched range. License replay, workspace attribution and format
  handling have distinct assertions worth retaining. PR tests already cover API errors and replay
  without contacting the service.
- [Release](../../.github/workflows/release.yml) runs the ignored cases on both
  manual rehearsals and tags. It checks out the resolved SHA, uses the existing
  repository secret and makes the live job a dependency of publication. The
  [release procedure](../implementation/release-process.md#rehearsal-and-release-gates)
  already requires green rehearsal evidence on the exact merged SHA before
  tagging.
- The [public OpenAPI contract](https://api.githits.dev/v1/openapi.json) puts
  ordinary analysis jobs in a shared submission bucket and charges one monthly
  analysis unit per successful SBOM or audit job. `license report` submits its
  own SBOM job and reads the license report result, so this suite needs three
  jobs per fixture exercising all three online commands. The public defaults
  are 10 submissions per personal principal or 120 per organization per 60
  seconds, with runtime overrides. Verify the actual release principal's
  allowance before the first full run.
- The public synchronous SBOM reference calls `go.sum` unsupported, and the
  asynchronous operation points to that route for general input support.
  Scan's [Go upload contract](../implementation/sbom-api-contract.md#go-module-parts)
  sends checksum and workspace evidence. The current smoke case stages only
  `go.mod`. The real job endpoint accepted the pinned Cobra `go.mod` and
  `go.sum` pair and returned CycloneDX containing the declared pflag
  `v1.0.9` dependency. Include this input in the pilot to keep verifying
  admission. Qualify checksum attribution and workspace behavior separately
  when completing the corpus.
- The [pilot fixture definitions](../../tests/fixtures/live/fixtures.json)
  record independent input facts, full public commits and content digests.
  The runner exercises locked Cargo input, Go module and checksum evidence,
  and the historical minimist remediation control.

## Design

### Runner and fixtures

Use a contributor script based on Python's standard library alongside the
existing Python release tooling in `scripts/`. It can download by exact URL,
verify SHA-256, stage files, call the binary and compare JSON without adding
shipped dependencies or extending Scan. The existing Rust live tests continue
to own their specialized assertions. Extending the Rust release helper would
add process, JSON and HTTP or Git dependencies to a tool that currently owns
release metadata. A nextest case per fixture would require separate selection
and refresh orchestration and would let test scheduling determine submission
concurrency.

Store JSON fixture descriptions and separate, readable JSON baselines under
`tests/fixtures/live/`. Each description owns the fixture ID, upstream release
label and full commit SHA, exact relative file list, hashes, expected upload
paths, enabled checks and independently checked assertions with their sources.
Allow small committed inputs for purpose-built historical or rare formats when
they provide coverage unavailable from a practical upstream release. Record the
source or generator version and the reason. Download individual pinned files
and stage them in a disposable root with their original relative paths. Keep
upstream configs, hooks and unrelated files out of the root.

Use `detect --json` with the same selection flags and fixture-owned config as
the live commands to verify `upload_paths` before submitting. Build Scan once
per invocation unless an explicit tested binary is supplied. Pass arguments
as a subprocess vector. Run the actual CLI for each online command, one at a
time. The runner owns fixture verification and projection of results. Scan
continues to own discovery, pairing, report decoding, transport and retries.

### What gates release

| Surface | Authored requirements | Baseline changes that fail `check` | Observations shown on a passing check |
| --- | --- | --- | --- |
| Discovery | Exact selected paths and fixture-specific companion or workspace behavior. Compare before submissions | Paths are authored expectations | — |
| SBOM | Valid CycloneDX, expected inventory mode and supplied path evidence, independently checked occurrence witnesses | Locked occurrence identities, versions, multiplicity, relevant relationships and attribution. Manifest-only declarations, version-independent occurrence identities and resolution coverage | Unpinned resolved versions and relationships tied to them |
| Audit | Valid CLI report, exit consistent with findings and actionable gaps, accounted-for dependencies and required fixture findings. For the remediation control, require a whole alternative for the affected copy with known advisory IDs and the applicable service checks | Dependency count on locked input, coverage status and actionable gap categories with affected input paths | Current advisory and lifecycle findings, latest versions, qualified target versions and report-consistent changes between Scan exits 0 and 1 |
| License report | Valid report, expected scoped occurrences and provenance, with license evidence where independently checked | Identities and paths for locked or pinned occurrences, declared versus observed license IDs or expressions, applicability, and resolution and evidence coverage states for those occurrences | Enrichment links and package facts that change solely with an unpinned resolution |
| License policy | For fd, apply a fixture-owned deny-all policy using `license check --sbom`. Require exit 1 and a `not_allowed` finding for a known locked witness with a parseable SPDX expression | — | Other evidence-backed policy findings on the same input |

A lost authored fact or stable baseline change exits 1. Refresh may record a
baseline change after all authored assertions pass. A new coverage gap needs
review even when a command produces its normal report. A passing check with
observational changes exits 0 and prints those changes. Validate command
exit and report facts together before comparing them to a baseline.

Snapshot domain facts and stable relative paths. Resolve document-local
references before comparison, preserve repeated occurrences and keep nullable
or missing evidence distinct where meaningful. Sort only collections whose
order has no contract value. Keep the exact proposed targets, relevant advisory
changes and mutable resolved versions in the comparison so maintainers see what
changed. Omit generated IDs, timestamps and tool build fields from baselines.
Report fixture ID, command and the differing facts. Do not infer an inventory
from audit counts or a clean result from an empty or unsupported assessment.

Use current API recommendations. Patch/minor limits would change the product's
available advice and could exclude the only relevant fix. They would still
allow newer candidates within the selected range. Capturing or replaying
results is useful for deterministic presentation tests. Release qualification
also requires fresh backend results so changes in the deployed service are
observable. Keep current supported evidence and upgrade qualification intact.

### Final coverage and delivery

Cover all exact lockfile rules, legacy Gradle and both Yarn formats. Add native
syntax revisions where documented or qualified as distinct parser paths, plus
representative Cargo, npm and Bun membership and Go checksum/workspace
behavior. Cover Go modules, vcpkg and Zig as manifest-only inputs. Exercise
other manifest-only paths where their behavior adds a distinct qualified case.
Select small projects with known direct and transitive dependencies, useful
license evidence and intentional source/coverage cases. Each coverage claim
must identify a fixture and an assertion tied to the applicable input. When
the API cannot assess a check on a covered format, assert only the specific
qualified limitation and show it in the matrix. A surprise admission failure,
empty response or new coverage gap requires investigation.

In phase 2, enable an offline coverage check beside the catalog's existing
exhaustive tests.
Reuse `lockfile_names()`, `classify` and `Ecosystem::ALL` for the comparison
against declared fixture paths and commands. Check the legacy pattern and the
two Yarn variants explicitly with their fixture evidence. The Python runner
owns the fixture schema. The Rust coverage test reads only the declared input
paths, ecosystems and commands. The catalog owns input recognition. Adding
another cataloged format requires adding coverage in the same change.
The tracked descriptions, baselines and authored files ship with the source
crate's tests. Measure their tracked size before closing phase 2 and stage
downloaded bytes only in temporary directories.

Run the full corpus in the existing merged-SHA rehearsal when
`release_candidate=true`.
Keep the current smoke gate on tag pushes. This preserves the existing
publication dependency and runs the larger spend once before tagging. Running
the full corpus again on the tag would double the spend and allow newly changed
registry data to interrupt publication after the tag already exists. Exact-SHA
rehearsal remains the required maintainer step before tagging. A full failure
blocks release approval and a valid refresh follows ordinary review and a
fresh rehearsal of the resulting release SHA.

### Safety, cost and compatibility

- Local live commands accept an exported matching `GITHITS_API_TOKEN` or
  acquire it privately via the signed-in GitHits CLI, defaulting to production.
  Use the existing production login selection and require the matching token
  when supplying a different origin. CI injects its existing secret in the live
  step and fails closed if absent. Pass the token only to Scan's online child
  processes. Strip it from builds, downloads and offline commands. Capture
  output and check both streams before printing, parsing or writing derived
  reports. If the credential occurs, withhold the output and stop. Keep raw
  reports, job identifiers and credentials out of baselines and CI artifacts.
- Derive fetch URLs from allowlisted public HTTPS hosts and full commit pins.
  Reject redirects, invalid relative paths, symlinks for local inputs and
  mismatched bytes. Stage only verified regular files. No project code or
  package-manager hooks run. Fetch failures identify the pinned source and
  fail without an automatic retry. Scan's existing same-origin HTTP and
  bounded 429 policy owns API recovery. The runner never resubmits a job.
- The two fd inputs total 29,230 bytes and the two Cobra inputs total 1,278
  bytes. The pilot runs seven analysis jobs. The planned matrix is about
  36 cases and 108 submissions, plus five existing release smoke submissions.
  The public personal rate of ten submissions per minute can stretch a full
  run to about eleven minutes. Use measured timing and the actual allowance
  for the credential that runs the release gate.
  Size and budget the actual corpus from its inventory and job count before
  enabling the full gate. Preflight verifies all selected inputs before any
  API call. Stage only selected files on disk and handle one capped Scan
  response at a time. Scan enforces 256 files per job, 5,242,880 bytes per
  file, 8,000,000 bytes for multipart and 16,777,216 bytes per response.
  Allow for quota shared with other traffic. Use the existing CI principal
  and serial flow. Measure elapsed time and budget from a full run before
  setting the release job timeout.
- There are no shipped CLI flags, exit code, library signature, configuration
  or output changes. Harness changes need no release fragment. The rollback is
  to revert the full rehearsal step and retain the preexisting live smoke job,
  fixtures and PR gates. Document the contributor procedure in
  `docs/implementation/live-integration-fixtures.md` and link it from the
  testing and release guides. Keep run links and measurements on the PR.

## Implementation phases

### 1. Run and refresh the pilot from one command

The runner checks and refreshes the pinned fd, Cobra and minimist fixtures
individually or together. These cases qualify recorded inventory, Go
supplement admission, license evidence and audit remediation. Ordinary CI
runs the offline runner tests. The
[live fixture procedure](../implementation/live-integration-fixtures.md)
owns the commands, baseline semantics and credential handling.

### 2. Complete and qualify the corpus

**Outcome.** Every cataloged ecosystem, lockfile format and required workflow
variation has a discoverable fixture, a checked baseline and explicit evidence
for each online command.

**Dependencies.** The pilot runner and baseline contract are available on
`main`. The corpus needs public HTTPS downloads and an authorized production
credential for the qualification run.

**Verified inputs and assumptions.** Prefer small real artifacts from public
projects or upstream test suites. Commit snapshots reproduce the parser input
even when the source checkout has no release tag. The project fixture root may
be a nested directory within its pinned checkout, with input paths relative to
that root. Locked witnesses and source provenance come from inspecting the exact
input bytes. Local authored files cover format filenames or workspace layouts
that are unavailable in a practical upstream fixture.

| Coverage | Origin and cases |
| --- | --- |
| Cargo and npm | Keep fd and the minimist control. Run all three online commands on both and add representative native workspace membership cases |
| JavaScript lock dialects | Pin npm shrinkwrap from OSV-Scalibr and text Bun, two Yarn formats and pnpm lockfile revisions from small qualified fixtures |
| Python lock dialects | Pin uv, Poetry, PDM and Pipenv files from Syft and Trivy, including a supplied owning manifest where the source has one |
| Swift and legacy Go | Pin Swift `Package.resolved` v1 and v2 from Trivy and OSV-Scanner. Pin `Gopkg.lock` from the archived Go dep project's own repository |
| Gradle | Pin the unified and legacy layouts from Syft and the Gradle samples. Use small purpose-built buildscript and settings locks if upstream fixtures are impractical |
| Other recorded formats | Pin NuGet, Dart, Composer, Mix, both Bundler names, Rebar and Conan from public samples. The Conan 2 lock must identify real ConanCenter packages, so audit and license results exercise actual package evidence |
| Manifest resolution and workspaces | Keep Cobra. Add a Go workspace carrying module checksum evidence, plus existing local vcpkg and Zig manifest examples |

The Swift v1, archived Go dep and legacy Gradle candidates were admitted in
production as recorded inventories. Their known dependencies included
`Quick 7.0.0`, `github.com/pkg/errors v0.8.0` and
`org.springframework:spring-core 5.0.5.RELEASE` respectively. Swift and
Gradle produced audit reports with positive dependency counts and explicit
coverage gaps. The Go dep audit returned exit 1, zero assessed dependencies
and actionable dependency-information and exclusion issues. The fixture must
preserve that limitation and require the independently pinned SBOM and license
inventory witnesses. An empty audit without the qualifying gap would fail.

1. Extend fixture definition loading in `scripts/live_fixtures.py` to allow
   optional pinned project subdirectories, retaining the default root for the
   pilot inputs. Validate the source directory as a safe POSIX relative path.
   A verified release label is optional for a commit-only fixture. Extend the
   audit expectations in `scripts/live_fixture_reports.py` to accept a
   declared empty manifest list for lock-only cases, and an explicit zero
   dependency expectation only with a named actionable coverage issue. Verify
   its check, status and affected files when the producer supplies them. An
   empty audit without the required issue fails. Add offline cases for both
  outcomes and for the source-directory preflight. Acquire the current CLI
  token before each online command to cover long runs across expiration.
2. Register cases in `tests/fixtures/live/fixtures.json` and document input
   provenance in the fixture guide. Keep lock-only cases independent, with
   an exact empty audit manifest list when the CLI emits no manifest paths.
   Each case runs SBOM, audit and license report. Every locked case has a
   versioned witness tied to its input path. Manifest-only cases require
   declared dependencies and scoped resolution evidence. Record independently
   qualified audit coverage gaps using the expected status and exit. A fixture
   opting into zero assessed dependencies must name a required actionable gap.
3. Add the offline coverage check beside the catalog tests. Derive named
   families and ecosystem IDs from the catalog. Classify declared fixture
   paths to validate their ecosystem and presence of all three online checks.
   Require the legacy Gradle shape and distinct classic/Berry witness cases.
   Each distinct syntax revision enrolled in the matrix carries a fixture
   and explicit witness for that revision.
4. Validate all staged input paths before making submissions. Run a production
   refresh for the complete matrix and review the generated baselines. Verify
   a complete check plus a representative single-fixture run with exact counts.
   Record list, check, byte size, elapsed time and jobs on the PR. Measure the
   candidate rehearsal's cost and runtime from the resulting matrix.
   The pilot fd baseline is already approximately 0.5 MB. Keep individual
   fixtures and the source crate size within repository limits.

**Unknowns.** Remaining fixture-specific service output shapes and qualified
limitations, final pinned byte count and runtime. Resolve while enrolling
each case. A material producer support gap goes to the maintainer with the
exact fixture, outcome and impact. No product decision is needed to start
with the already qualified input families.

| Scenario | Acceptance |
| --- | --- |
| Catalog matrix | An offline assertion has a qualifying fixture for each named lockfile and ecosystem, legacy Gradle, both Yarn variants and the required workspace cases. A missing family or missing check fails CI |
| Source and selection | Each selected case stages hash-verified files, checks exact upload paths and sends only the selected files. An invalid nested source path is rejected before download |
| Commands and baseline | All and single-fixture modes run SBOM, audit and license report as declared. Locked version and attribution differences fail check. Stable public source pins and all reviewed baselines are committed |
| Coverage limits | Qualified audit gaps retain exit, affected inputs where supplied, and coverage status. An empty or structurally invalid result cannot pass as a qualified limitation |
| Release readiness | The maintainer can see exact production job count, runtime and fixture size. PR CI runs catalog and tooling evidence offline |

### 3. Gate the exact release rehearsal

**Outcome.** The complete corpus runs in the existing pre-tag rehearsal for the
exact merged SHA. Release evidence reports fixture coverage, material failures
and mutable data differences. PR workflows remain network-free for these cases.

**Dependencies.** Qualified complete corpus, working release credential and
verified analysis allowance for the measured corpus and existing smoke checks.
**Verified workflow.** The live job checks out the SHA from release
verification and builds a release-profile Scan binary for the existing
ignored tests. The repository has a configured release secret. Reuse that
job and binary. Run the fixture check only on a manual dispatch with
`release_candidate=true`. Its ordinary nonzero exit blocks the rehearsal.

**Unknowns.** The rate, monthly allocation and timing for the actual release
credential are verified at rehearsal. Use the offline job count from
`scripts/live_fixtures.py list` plus the existing smoke submissions to size
the run before dispatch. A check on an unmerged worktree with a local token
does not validate that credential or the workflow's exact-SHA checkout.

**Acceptance.** Validate workflow syntax and gate selection in the code PR.
Before tagging, a manual release-candidate run on the exact merged SHA
finishes the live smoke and full corpus checks successfully. Attach the
workflow result to the release PR and transfer the finished gate's contract
to the release procedure.

## Completion

Confirm all and single-fixture checks, both refresh scopes and a passing
exact-SHA production rehearsal. Keep the completed matrix and operating
procedure in the implementation and release guides, and the evidence on the
relevant PR. After final implementation review, transfer any remaining durable
decisions and delete this plan using the repository's final-push rule.
