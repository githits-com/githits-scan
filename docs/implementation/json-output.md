# Command JSON contracts

`--json` selects report data on stdout or `-o/--output FILE`; `-` means stdout.
Reports are emitted for exit 0/1. Detect also preserves its inventory report when
local upload preparation fails (exit 2/3, null `upload_paths` and `upload_error`).
Errors are text on stderr. `--quiet` and
`--details` do not remove JSON evidence. Files overwrite an existing destination,
including when it is also a replay input: choose a separate output to retain it.
Additive fields keep a schema version; removing or renaming fields increments it.
Consumers should ignore unfamiliar additive fields. Human text is presentation.

## Detect (schema 2)

- `schema_version`: 2; `root`: the supplied scan root string.
- `lockfiles_only`: true when `--lockfiles-only` was selected. Schema 1 used
  the inverse boolean `include_manifests`; that field is removed in schema 2.
- `lockfiles`: `{path, ecosystem, bytes, manifests: [{path, bytes, status?}]}` entries.
- `nested`, `uncombined`: `{path, ecosystem, bytes, lockfile}` entries;
  path proximity does not establish workspace membership or actual upload.
- `ambiguous`: `{path, ecosystem, bytes, manifests: [path]}` entries.
- `manifest_only`: `{path, ecosystem, bytes}` entries.
- `unsupported`: `{path, hint}` entries, sorted by path, filtered by exclusions;
  these files are not read or uploaded. Diagnostic paths replace non-UTF-8 characters for display and never select uploads. Hints are explanatory text.
- `upload_paths`: sorted exact locally prepared upload paths, including admitted workspace members; null when preparation fails, with an additive `upload_error` description. Preparation is offline and bounded by the same API limits as uploads; drift can still block submission.
- `excluded_directory_patterns`: configured/invocation patterns ending in `/**`; matching subtrees are not inspected except to preserve explicit file inclusions. These are patterns, not measured omitted file counts.
- `test_paths`: sorted, deduplicated selected package paths (non-excluded candidates when preparation is blocked) under fixture or
  test-looking directories, for selection review; annotations do not select uploads.
- `status` is present on evidence entries when configuration, invocation or default
  fixture exclusions require an evaluation: `included`, `excluded`, `unlisted` (see configuration).
- Optional `config` names the configuration file; `drift` contains `unlisted`
  and `missing` path arrays when a configuration was loaded.
- Optional `saved` for `--save`: `{created, changed, added: [path], removed: [path]}`.

Evidence paths use forward slashes relative to the root. Ecosystem identifiers
come from the catalog. Arrays retain discovery's deterministic path order.

## License check (schema 1)

`schema_version`, numeric `components` and `local_packages`, optional
`completeness` (service inventory code, independent of license coverage), plus:

- `violations`: `{bom_ref, name, version, purl, expression, reason, source?}`.
  Optional `source: {git, rev?}` retains safe, unambiguous recorded Git identity. Version,
  PURL and expression may be null. Reasons are the policy evaluator's identifiers
  (`no_license`, `non_spdx_name`, `unparsable_expression`, `not_allowed`).
- `exceptions_applied`: `{purl, reason, components: [package label]}` or
  `{name, git, rev?, reason, components: [package label]}`. These are exceptions,
  never fabricated license declarations.
- `unresolved_projects`: `{path, status, reasons: [code]}`.

These are policy results, not a replay input or a license inventory. See
[license check](license-check.md) for evaluator semantics.

## Audit and saved explanations (schema 2)

Native audit JSON has `schema_version: 2`, `incomplete`, `actionable_incomplete`, optional saved `analysis`
provenance, required `summary` and `lifecycle`, and useful common groups:
`vulnerabilities`, `outdated`, `duplicates`, `manifest_lock_mismatches`, `issues`,
`manifests`, `limitations` and optional `remediation`. Empty optional groups are
omitted. There is no coarse `deprecated` or manifest-resolution inventory field.
Summary separates `lifecycle` events and `retained_lifecycle_warnings` from
vulnerabilities. Source manifests and common issue paths are sorted and unique.

The canonical `lifecycle` subtree contains native events, distinct source
observations with exact affected coordinates/paths, retained registry warnings,
all four coverage facets, unknown rows and content-safety disclosure. Required
nullable source/affected facts stay null; native strings stay open. Empty findings
or collection limits do not establish a checked-safe result. Unknown/unverified
outcomes set `incomplete`; ordinary collection limits alone do not. Expected Git
source limits retain `incomplete: true` but do not set `actionable_incomplete`.
Each issue has an `actionable` boolean; original status, explanation and
attribution remain present. Mixed causes produce separate attention classes.
Independent findings can still require exit 1 with `actionable_incomplete: false`.
Older schema-2 readers can ignore these additive fields; consumers lacking them
must not guess that a partial report is informational. See
[audit interpretation](audit.md#wire-and-interpretation-boundaries).

Advisory ignores remain exact-ID. Findings retain `ignored: true` and their reason;
summary vulnerability totals stay raw, with optional ignored counts. The archive
stores an explicit nonempty policy when supplied and replay applies it without
reading repository configuration.

Saved explanation JSON has `schema_version: 2`, `kind: audit_explanation`,
`analysis`, selected `problems`, `sources`, `issues`, `audit_incomplete`,
`audit_actionable_incomplete`, `audit_issues`, `audit_lifecycle` and optional `remediation`. Focused advisory
algorithms remain source-local; native audit evidence and the whole-audit outcome
are preserved. A saved analysis is a separate format with
`format: githits-scan-analysis`, archive schema 2 and producer report 3. Old
archive/report versions are rejected; no migration or rescan is automatic.

### Reasons for remediation changes

Both audit and `audit_explanation` schema 2 use the same optional
`remediation.recommendations[].changes[].reasons` array. Absence stays omitted;
order and multiple effects are preserved. Known entries are:

```json
[
  {"code":"advisory_remediation","findings":[{"package":"npm:demo@1.0.0","advisory":"GHSA-example","files":["package-lock.json"]}]},
  {"code":"enables_dependency_target","dependency":{"registry":"npm","name":"demo","version":"1.1.1"},"path":"package-lock.json","original_requests":[{"owner":{"name":"parent","version":"2.0.0"},"owner_role":"third_party","dependency_name":"alias","path":"package-lock.json","kind":"dependency","requested_requirement":"<1.1","requirement_status":"recorded","basis":"lockfile"}],"replacement_requests":[{"owner":{"name":"parent","version":"2.1.0"},"owner_role":"third_party","dependency_name":"alias","path":"package-lock.json","kind":"dependency","requested_requirement":"^1.1.0","requirement_status":"recorded","basis":"exact_parent"}]},
  {"code":"removes_dependency_route","dependency":{"registry":"npm","name":"demo","version":"1.0.0"},"path":"package-lock.json","original_requests":[]},
  {"code":"unavailable"},
  {"code":"future_code"}
]
```

The dependency is a canonical coordinate; request `dependency_name` preserves
an authored alias/capability and is omitted when absent. Owner version and
requested requirement retain their nullable slots. Advisory findings use the
existing package/advisory/files shape. No report-local finding, occurrence or
declaration indices, or opaque request context, appear here. Unknown codes retain
the code only; their opaque evidence is preserved solely in saved analyses for
future replay. Causes describe checked effects with represented scope, not
unique necessity or successful native installation. Examples are synthetic.

## License report and SBOM documents

`license report --json` emits the exact experimental public API report, preserving
unknown additive evidence and source ordering. Online reports use API-owned
schema version 2; saved reports accept versions 1 and 2 without migration or reconstruction. Schema 2 retains every occurrence and
original identity, typed input paths, licenses versus observed licenses, substantive
publisher/source evidence, coverage and resolution gaps. Generic adjacency, digests
and duplicate property bookkeeping are omitted;
see [license report](license-report.md). It is the input to `--from-report`.

`sbom generate` returns the requested document unchanged: CycloneDX 1.7 JSON,
SPDX 2.3 tag-value, or service text. It has no Scan JSON wrapper or `--json` flag.
`license check --sbom` accepts CycloneDX JSON, not the other report formats.

## Experimental diff service report

`diff --format json` or `diff --output-json PATH` writes the exact service result
bytes. `--output-json diff.json --output-markdown diff.md` writes both exact JSON
and Scan-rendered Markdown from one paired analysis. Named destinations imply the
format, conflict with explicit `--format`/`--output`, and emit only requested
documents. Either named destination can be `-` for stdout, but not both. JSON is
written first; a later Markdown write failure exits 3 and retains completed JSON.
See [diff output destinations](dependency-diff.md#output-destinations) for preflight,
partial-write and path-alias rules.

The JSON result has no Scan
wrapper or reconstruction. The versioned report uses `kind: diff` and includes
`accepted_request`, generated time, snapshots, source-local `changes`,
`declaration_changes`, `advisories`, `direct_reviews`, coverage, summary and notices.
Git revision labels and local selection notices are not added to JSON; the latter
are stderr diagnostics.

Snapshots preserve accepted-file digests, canonical declarations/bindings, occurrence
multiplicity and recorded/effective ownership. Changes retain source-local versions,
directness and versions retained elsewhere. Null targets mean absent or unqualified
evidence, not an invented old version. Advisory coordinate and exposure scopes remain
separate, as do review security and changelog qualifications.

Producer explanation fields remain unchanged in JSON: occurrence
`directness_reasons`/`directness_proof_ids`, root proof `id`/`reasons`, binding
`reasons`, coverage `reachability_id` and review `failure`. Human/Markdown follow
these explicit same-side references and explain supplied causes in plain language,
keeping codes, IDs and diagnostic counts in JSON; they do not add
derived explanations to JSON. Older schema-v1 reports may omit these additive
fields. Present fields still validate against the supported display structure,
and malformed known fields produce a protocol error before any output.

`outcome` and independent section statuses describe evidence. Partial, unavailable,
unrequested and unfamiliar statuses never mean pass/safe or zero findings. Additive
fields and positive future schemas remain byte-preserved for pipelines; this binary's
human/Markdown renderer explicitly declines unsupported structures. This replaces the
earlier experimental Scan-owned schema; see [dependency diff](dependency-diff.md).

## Audit presentation (schema 1)

`audit --presentation-json` emits `kind: "audit_presentation"`,
`schema_version: 1`, `audit` and `remediation`. It supports online audit and
`--from-analysis` offline replay, stdout or `--output FILE`. It conflicts with
`--json` and `--explain`; focused explanations keep their existing interface.
`--quiet` and `--details` do not change the exported content. Progress follows
JSON output rules. This is an additive output choice; existing audit fact JSON,
saved analyses and byte-exact diff exports retain their contracts. Online export
and `--save-analysis` use the same completed job; replay requires no credentials,
repository discovery, token acquisition or network.

`audit` is the complete existing schema-2 fact report, including incompleteness,
actionability, ignores, lifecycle evidence and optional saved provenance. These
facts and the process exit code remain authoritative for policy. Presentation
strings must never be parsed for gating, safety or machine classification.

`remediation` contains `messages`, `recommendations` and `limits` arrays. Scan's
audit command presentation layer computes the explanations once for native text,
focused human explanations and this export. It has the curated facts and displayed
problem context; API types remain service evidence, and consumers own their layout.
The first version exports **audit remediation explanations**, not prose for every
audit section or any diff presentation. Other findings remain available in `audit`.

Each recommendation is one independent alternative, in the same order as the fact
report. It contains:

| Field | Meaning |
| --- | --- |
| `recommendation_index` | Zero-based position in this document's `audit.remediation.recommendations` |
| `subject` | Existing subject coordinate; never a new opaque plan ID |
| `findings`, `addressed_findings`, `remaining_findings` | Existing `{package, advisory, files}` fact identities, unchanged |
| `compact_summary` | Nonempty single-line plain text for this alternative. Added after Scan 0.6.0 within schema 1 |
| `details_recommended` | Boolean presentation cue to link to this alternative's full blocks when a reader needs more context |
| `heading` | Shared qualified heading for joint changes; null for a single change whose summary carries its qualification, or when no changes were supplied |
| `outcome` | Plain-language separate outcome, or null when the heading suffices |
| `changes` | Ordered changes that belong together within this alternative |
| `files` | Shared change paths that need display beyond the finding context |
| `context` | Recorded-request explanations when checked effects do not already explain them |
| `impact` | Addressed and unresolved impact, including explicit absence of reported benefit for partial candidates |
| `constraints` | Objects grouped by explanation, with a `summary` and sorted unique request contexts in `details`; required project edits stay distinct from actual requirement conflicts |
| `checks`, `limitations` | Material check qualifications, per-plan limitations and search-retention gaps |
| `search_explanations` | Whole-search obstacle objects with `search_detail_index`, `summary`, and `details`; each index addresses the matching fact record’s `search_details` array |

Each change has `change_index` (zero-based within the matching fact record),
`summary`, `details`, `files` and `reasons`. Each reason has `summary` and
`evidence` (supporting request explanations). Detailed reason evidence is always
exported when available. Ordinary native output can suppress redundant advisory
reasons and supporting request inventories. Use the full blocks alongside
compact text for change reasons and their supporting evidence. Missing or
unfamiliar reason detail is qualified explicitly in the detailed export.

Indices are document-local links, stable only within this complete report. They
are not backend identifiers or identities across analyses. Coordinates, advisory
IDs and full file sets retain their existing meaning; no synthetic globally
stable plan ID is inferred. Keep the enclosing `audit` with its presentation.
Display a recommendation's findings with its blocks: “listed advisory” refers to
its referenced finding context. Native grouping/focused selection can display a
different advisory context; the same builder adjusts redundant impact and file
wording to that context. A consumer may use the fact identities to link to advisory
metadata in `audit.vulnerabilities`.

Use `compact_summary` directly beside the finding identities that associate the
alternative with the row. It names the exact changes and the advisories a
supported upgrade addresses, even when the row covers more advisories than this
alternative. Joint changes share one summary. Keep independent alternatives
separate. The summary leads with the version changes and target warnings,
then highlights the main issue affecting the proposed change. Concrete
dependency conflicts take priority. A release or requirement check gap can
explain why a proposed change is uncertain. If the report only lacks an
application method, the summary states that gap directly.
`Bump` uses the same qualification as a supported upgrade in native output.
When that upgrade supplies a shared path that Scan recognizes as a lockfile,
the summary names it even if the detailed blocks omit it as repeated context.
This describes the recorded scope of the upgrade.
Proposals with remaining advisories name them so readers can see the limits of
applying the change. The detailed impact block retains any reported potential
benefit for a candidate. Target warnings stay with their respective versions.
A record without a change explains the outcome and includes a reported obstacle
when available.
When the selected change includes checked additions, the summary can name one
registry-selected root and points to the full dependency checks through
`details_recommended`. A candidate with no applicable change can surface a
specific addition problem, such as an affecting advisory or the exact release
whose dependencies could not be checked.

Use `details_recommended` to decide whether to show a link such as **Details**
beside the summary. Scan sets it for unclear candidates, no-change outcomes
and upgrades with qualifications such as open advisories, target warnings or
coordination issues. A routine supported upgrade and a single named project
constraint edit with a recorded current range and otherwise supported upgrade
evidence have it set to false. A clear edit names the advisories the upgrade
addresses after the edit. The flag is presentation guidance.
Limits confined to searching for other alternatives stay in the full blocks
and leave a supported upgrade's flag false.
Continue to use audit facts and the exit code for policy. The consumer owns
the link and its target.

Use the full blocks for supporting requests, checked-effect evidence and detailed
upgrade searches. Display report-wide `messages` and `limits` once with the
guidance. Scan provides a single line without a fixed byte budget. Consumers own
layout, escaping and links, including where to put longer qualified alternatives
when space is limited. Keep the qualifications with the proposed changes.
For schema-1 output from Scan 0.6.0, feature-detect the absent fields and use the
full explanation blocks if supporting that release. Existing saved analyses
produce the field when replayed with a binary that supports it.

When planning is absent with vulnerabilities, `messages` says guidance is
unavailable; absent planning without vulnerabilities has empty arrays. Unverified
recommendations export an explicit verification message, no recommendations or
limits, with the authoritative reason retained among audit issues. Present but
empty planning qualifies the absence of recommendations unless completed with no
vulnerabilities. Shared supplied limits remain in `limits`, even when a clean
native report omits its empty guidance section. No recommendations never means no
fix exists. Unknown statuses do not imply completed checks. Empty explanation
arrays mean no additional blocks to display, not an all-clear determination.

### Plain text and consumer responsibilities

Scan produces plain text without adding ANSI styling, HTML or Markdown. It escapes
control characters for display (for example a newline becomes the literal `\n`)
and preserves ordinary punctuation such as `<`, `&`, pipes and backticks. JSON
encoding remains normal JSON escaping; decode it once. Fact values and path arrays
retain fact identity rather than display escaping. Consumers must escape all
values for their own output context: Markdown tables, GitHub HTML, URLs, shell
commands or terminal output. Do not parse terminal output, split prose into
meaning, or turn these strings into executable commands.

After adoption, a consumer can remove its duplicate candidate
qualification, blocker/reason phrase mapping, compact plan semantic selection,
partial-impact wording and explanation-meaning tests. Scan owns those cases.
Retain consumer tests for schema support, associations, missing evidence, inclusion
of the complete qualified block, independent alternatives, GitHub layout/links,
escaping/truncation, configured policy, authoritative facts and exit behavior.
Release availability and downstream adoption are separate steps.

The Rust command API selects `audit::Request.format: audit::Format` instead of
`json: bool`. Offline callers select `ReplayRequest.mode` as
`ReplayMode::Report(Format)` or `ReplayMode::Explain { package, json }`; focused
presentation export is unrepresentable. Archives and configuration need no
migration. Omit the new CLI flag or use the previous binary to return to previous
output behavior without losing saved evidence.

Constraint explanations appear once per plan, with the affected package owners,
requirements and paths beneath them. Conflicts are direction-neutral: an existing
package can exclude a proposed version, or a proposed version can require a
different locked dependency. Unattributed `other_target_versions` stay in the fact
report rather than becoming ambiguous version advice. A per-plan limitation is
omitted from presentation when its exact explanation already appears in that
plan's constraints; audit-wide planning limits retain their broader scope.
Repeated displayed limitation sentences appear once within each scope, in first
appearance order, while all original reason codes remain in the fact report.

Advisory lists show the subject's IDs first, followed by external package groups
(`package — IDs`) in package order. Each `(partly)` qualifier stays attached to its
advisory, and repeated file occurrences do not repeat the same label. Every public
advisory ID remains available. Native guidance wraps at spaces to 100 Unicode
scalar characters including indentation, with four extra spaces on continuation
lines; indivisible identifiers remain whole even when longer. JSON strings retain
unwrapped plain text for the consumer's own layout.


### Whole-search evidence

The added fact fields have these JSON types. Optional means omitted for older
reports, not explicit null.

| Field | JSON type |
| --- | --- |
| `remediation.recommendations[].search_detail_status` | Optional non-null string |
| `remediation.recommendations[].search_details` | Optional non-null array of detail objects, selected by string `kind` |
| `remediation.limits.omitted_search_details` | Optional nonnegative integer (`u64`) |
| `remediation.recommendations[].search_explanations` in presentation schema 1 | Array of objects with nonnegative integer `search_detail_index`, string `summary`, and array of strings `details` |

The optional fact fields `remediation.recommendations[].search_detail_status` and
`search_details` are preserved together. Both remain absent for older immutable
reports. `retained` with an empty array means no recorded obstacle under the
producer's selection policy; it certifies neither exhaustive search, applicability,
native resolution nor safety. `not_retained` requires an empty array: the entire
collection was omitted. An unfamiliar retention status remains explicit.
Optional `remediation.limits.omitted_search_details` counts omitted entries across
recommendations, including omitted recommendations and losing alternatives.

Known detail kinds are `unavailable` (operation, nonempty reasons, witness),
`stopped` (stage, reason, witness), and `added_dependency` (candidate and source
witness, branch evidence). Stopped details require a nullable coordinate
slot and budget scope; `used` and positive `allowed` occur together when supplied.
Known local/shared budget scope stays in fact JSON without a routine human note.
Counts retain producer units in fact JSON; human explanations do not guess units
or invent deadline counts. A known kind with malformed consumed fields is a
protocol error. Unfamiliar operation/stage/reason vocabulary stays informational.
An unfamiliar kind retains only its kind in curated facts and saved analyses;
Scan does not interpret or export its arbitrary payload.

Scan retains a typed witness subset needed for explanations: package and candidate
coordinates; source paths and dependency endpoints; authored requests; request
participation, capture and recorded conditions; effective requirement comparisons;
coverage and acquisition causes; declaration/observation requirements; and Maven
requirement policy diagnostics. Unused occurrence references, scope internals,
markers, policy origins, exclusions and arbitrary additive fields are ignored.
The adopted service schema is `AuditRemediationSearchDetail`. The
[public OpenAPI contract](https://api.githits.dev/v1/openapi.json) documents promoted
API schemas. Availability in development does not establish production promotion.

Search details can describe losing alternatives. They never alter selected-action
checks, candidate qualification, policy, incompleteness or exit codes. Equal reason
codes do not establish equal scope: a search detail cannot suppress a selected-plan
limitation. Captured conditions are literal evidence, never inferred activation.

### Added-dependency branch evidence

When supplied, `remediation.recommendations[].changes[].added_dependencies`
is an array of checked branches attached to the change that introduced the
requests. A whole-search detail of kind `added_dependency` carries the same
branch object in `added_dependency` and retains the candidate coordinate and
source in its `witness`. Older reports can omit both forms.

Each branch keeps the registry and canonical name, authored name and requirement
with its capture status, dependency scope, selection basis and nullable selected
version. The `coordinates` array retains advisory status and IDs for each exact
selected version. The `issues` array retains the operation, reason and supplied
evidence, including failed coordinates or requests, HTTP status, conflicting
requirements and versions, and Cargo feature or Python extra activation inputs.
Scan preserves these facts in schema-2 output and saved analysis. Presentation
JSON supplies the same readable explanations as native audit output in the owning
change's `details` and the matching `search_explanations` entry.
`registry_resolution` describes the supplied registry branch. The project
installer may select different copies or apply different policy.
Authored dependency names remain separate from requesting owners and canonical targets.
Search explanations are computed by the shared presentation owner, without another
backend job. A missing/uninterpretable reason is stated explicitly rather than
invented. Search-retention and legacy-absence notes without a detail index live in
`limitations`; global omission notes live in `limits`.

These fields are additive within fact schema 2 and presentation schema 1; saved
analysis format 2 and producer report version 3 stay supported. No new CLI flag or
migration is required. Older Scan versions ignore new evidence; new Scan versions
can replay archives without the fields, but cannot reconstruct discarded search evidence.
