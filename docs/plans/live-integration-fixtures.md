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
  fixture's patched range. License replay, workspace attribution and format handling have distinct
  assertions worth retaining. PR tests already cover API errors and replay
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
- [fd v10.2.0](https://github.com/sharkdp/fd/tree/b19136871310b01500b4f09eadd7387b8476be47)
  supplies a small public Cargo pilot. The exact two files were fetched and
  parsed during planning. Its non-workspace manifest declares
  `fd-find 10.2.0` and `MIT OR Apache-2.0`. The lock records 114 entries
  including the project, `clap 4.5.16` and `regex 1.10.6`. That establishes
  input facts. The production job outputs still need qualification.

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
  bytes. The pilot runs seven analysis jobs. The full lower bound is
  28 fixture cases and 84 jobs before additional
  format/workspace variants and up to five existing release smoke submissions.
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

**Outcome.** A contributor can run all three commands on a pinned Cargo
project and a pinned Go module with checksum evidence, and exercise a known
npm audit remediation case. Each fixture has a reviewed baseline.

**Assumptions and dependencies.** Python 3, Cargo or an explicit Scan binary,
public fixture downloads, and a matching authorized API credential are
available for live runs. Python 3 already runs in the CI toolchain. Existing
Scan CLI options and the contract above suffice. There are no open product
decisions for the pilot. Its measured production output is verification
evidence required before merging the increment.

| Fixture | Inputs and evidence | Checks |
| --- | --- | --- |
| `cargo-fd` | fd v10.2.0 at `b19136871310b01500b4f09eadd7387b8476be47`. `Cargo.toml` SHA-256 `de934f7081bbf86223d6cdea7c0b9456ae48f5c6ce4545854293d4ff3d47f66c`. `Cargo.lock` SHA-256 `dbe6158dbf001a489a53617a531d11dbee22daed2529f87790547ee65d1018d4` | Exact selected pair. Recorded CycloneDX with known locked dependency witnesses. Native audit report with dependency accounting and qualified coverage. License report with fd's project declaration and dependency attribution. Offline license policy on the generated SBOM |
| `go-cobra` | [Cobra v1.10.1](https://github.com/spf13/cobra/tree/7da941c3547e93b8c9f70bbd3befca79c6335388) at `7da941c3547e93b8c9f70bbd3befca79c6335388`. `go.mod` SHA-256 `a501ef186772adafdaabb7aa78623b691890e87accd0715674e69949da6b586e`. `go.sum` SHA-256 `47ddb5ec5a98cda2ef8dbebd40eea3af7bc7cc17894a886e149fdfff71592358` | Exact selected pair and successful job admission. Manifest-resolved SBOM with a versioned pflag occurrence and its expected manifest evidence. Audit coverage and license provenance tied to the selected input. Record changes to the selected dependency versions |
| `npm-minimist-remediation` | The [package and lock](../../tests/fixtures/audit/live-minimist) fix installed minimist at `0.0.8` with manifest range `>=0.0.8 <0.3.0`. The [historical advisory](https://github.com/advisories/GHSA-vh95-rmgr-6w4m) and [later advisory](https://github.com/advisories/GHSA-xvch-5gv4-984h) put the patched stable target in `>=0.2.4 <0.3.0` within this requirement | Require one complete upgrade proposal covering both advisory IDs for the affected copy. Check the stable target against the fixture's patched range and the service's release availability, advisory and requirement checks from the same alternative. Record native resolution qualification and proposed version as observations |

1. Add `scripts/live_fixtures.py` and its network-free tests. Set the existing
   Python unittest discovery step in `ci.yml` to `-p 'test_*.py'`. Expose `list`,
   `check [--fixture ID]` and `refresh [--fixture ID]`. Default selection is
   all fixtures, and `--binary PATH` skips the one-time locked debug build.
   Print selected fixture IDs, check count and planned submissions before live
   work. Acquire credentials after preflight and before the first online child.
2. Register the three fixtures and drive `detect --json`, `sbom generate`
   with CycloneDX, `audit --json`, `license report --json` and the offline
   policy check in the declared cases. Match structured output and command exit
   together. In audit, 0 and 1 are completed reports, and 1 represents findings
   or actionable gaps. The minimist fixture requires exit 1. Change the minimist
   smoke case's exact target pin to the same semantic expectation for the
   required alternative and retain its native audit envelope checks.
3. Separate authored fixture assertions from generated baseline facts.
   `check` reads baselines and never writes them. `refresh` prints the diff
   and writes only selected baselines after all selected commands and required
   assertions pass. Replace each file atomically. Require a valid baseline for
   `check`, and allow `refresh` to create one for a new fixture. Review
   input and baseline diffs before committing. A refresh cannot change pins,
   expected paths or authored assertions.
4. Run the focused Python tests and the changed exact minimist live case, then
   refresh and check the pilot fixtures on production. Record realized job
   counts, run time, projected baseline size and coverage. Compare a
   representative output diff for a moved audit target and a lost locked
   dependency, then document the runner commands and review procedure.

| Scenario | Acceptance |
| --- | --- |
| List, known fixture and all | List works offline. One known ID runs its declared checks. All runs exactly the three pilot fixtures and seven online submissions. Invalid arguments, an unknown ID, an empty inventory or invalid fixture metadata exits 2 before live work |
| Input or credential failure | Missing input, bad hash, redirect or unavailable credential exits 3 before any submissions. Unexpected selected upload paths exit 1 before any submissions. A secret-echo test uses a fake token and verifies the harness exits 3 and withholds the output and baseline |
| Regression or execution error | Removing a locked witness, losing a required audit check or losing required license evidence exits 1. Malformed output or unexpected Scan execution/configuration failure exits 3. A failed selected case leaves existing baselines untouched. Tests cover key ordering and repeated occurrences |
| Mutable audit results | Two results with different qualified targets for the same audit positive control pass with harness exit 0. The comparison names the changed target. Lost required advisory evidence, a new coverage gap or failed qualification yields harness exit 1 |
| Baseline maintenance | Unchanged check leaves the working tree untouched. Check with changed stable evidence exits 1 and prints the actionable diff. Refresh-one updates only its chosen baseline. Refresh-all updates all selected drift with stable formatting and preserves fixture definitions |
| Production qualification | fd returns the recorded versions and expected path and license evidence. Cobra's pinned pair passes all three checks with coverage represented explicitly. The npm control exercises a qualified remediation and passes the changed ignored test with exactly one test executed. The phase report includes the commands and actual counts |

### 2. Complete and qualify the corpus

**Outcome.** Every cataloged ecosystem, lockfile format and required workflow
variation has a discoverable fixture, a checked baseline and explicit evidence
for each online command.

**Dependencies.** Pilot runner, baseline contract and production qualification.
**Assumptions.** A suitable pinned public source or reproducible small lockfile
can be found for each format. Existing authored workspace and manifest-only
cases can seed coverage where their assertions remain unique.
**Unknowns.** Exact upstream pins and native parser revisions, actual API
coverage for every combination, total fixture size and the full job count.
Resolve them while selecting and qualifying the corpus. Before closing this
phase, reconcile any catalog/service mismatch with the service contract and
bring material support gaps to the maintainer. Add implementation detail once
the pilot evidence fixes the runner contract.

### 3. Gate the exact release rehearsal

**Outcome.** The complete corpus runs in the existing pre-tag rehearsal for the
exact merged SHA. Release evidence reports fixture coverage, material failures
and mutable data differences. PR workflows remain network-free for these cases.

**Dependencies.** Qualified complete corpus, working release credential and
verified analysis allowance for the measured corpus and existing smoke checks.
**Assumptions.** The existing workflow and secret suffice.
**Unknowns.** Actual available rate, monthly allocation and end-to-end runtime
on the release runner. Verify them before enabling the gate and bring any
required allowance change to the maintainer. Add the workflow and operational
details once the corpus size and cost are measured.

## Completion

Confirm all and single-fixture checks, both refresh scopes and a passing
exact-SHA production rehearsal. Keep the completed matrix and operating
procedure in the implementation and release guides, and the evidence on the
relevant PR. After final implementation review, transfer any remaining durable
decisions and delete this plan using the repository's final-push rule.
