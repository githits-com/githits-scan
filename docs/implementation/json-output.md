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
| `heading` | Qualified concise heading, or null when no changes were supplied |
| `outcome` | Plain-language separate outcome, or null when the heading suffices |
| `changes` | Ordered changes that belong together within this alternative |
| `files` | Shared change paths that need display beyond the finding context |
| `context` | Recorded-request explanations when checked effects do not already explain them |
| `impact` | Addressed and unresolved impact, including explicit absence of reported benefit for partial candidates |
| `constraints` | Objects grouped by explanation, with a `summary` and sorted unique request contexts in `details`; required project edits stay distinct from actual requirement conflicts |
| `checks`, `limitations` | Material check qualifications and per-plan limitations |

Each change has `change_index` (zero-based within the matching fact record),
`summary`, `details`, `files` and `reasons`. Each reason has `summary` and
`evidence` (supporting request explanations). Detailed reason evidence is always
exported when available; native compact output can suppress redundant advisory
reasons and request inventories. All explanation selection and wording still come
from the same model. Missing or unfamiliar reason detail is qualified explicitly
in the detailed export; it never becomes an invented checked benefit.

Indices are document-local links, stable only within this complete report. They
are not backend identifiers or identities across analyses. Coordinates, advisory
IDs and full file sets retain their existing meaning; no synthetic globally
stable plan ID is inferred. Keep the enclosing `audit` with its presentation.
Display a recommendation's findings with its blocks: “listed advisory” refers to
its referenced finding context. Native grouping/focused selection can display a
different advisory context; the same builder adjusts redundant impact and file
wording to that context. A consumer may use the fact identities to link to advisory
metadata in `audit.vulnerabilities`.

For a table, show the qualified `heading` together with every `changes[].summary`.
Place checked reasons, `impact`, constraints and limitations in the same row or its
associated details. A project requirement by itself is context for applying a
change, not a substitute for the candidate's changed package/version. Keep joint
changes together, and keep alternative records separate. A removed route does not
prove every advisory occurrence closes. `Suggested fix` describes the supplied
checks, not successful native installation or a verified build. Partial/unresolved
prerelease proposals remain candidates even if some findings are addressed;
complete supported proposals retain their explicit prerelease warning.

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

Explanation strings contain no ANSI styling, HTML or Markdown. Scan escapes
control characters for display (for example a newline becomes the literal `\n`)
and preserves ordinary punctuation such as `<`, `&`, pipes and backticks. JSON
encoding remains normal JSON escaping; decode it once. Fact values and path arrays
retain fact identity rather than display escaping. Consumers must escape all
values for their own output context: Markdown tables, GitHub HTML, URLs, shell
commands or terminal output. Do not parse terminal output, split prose into
meaning, or turn these strings into executable commands.

After adoption, a consumer such as scan-action can remove its duplicate candidate
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

Advisory lists show the subject's IDs first, followed by external package groups
(`package — IDs`) in package order. Each `(partly)` qualifier stays attached to its
advisory, and repeated file occurrences do not repeat the same label. Every public
advisory ID remains available. Native guidance wraps at spaces to 100 Unicode
scalar characters including indentation, with two extra spaces on continuation
lines; indivisible identifiers remain whole even when longer. JSON strings retain
unwrapped plain text for the consumer's own layout.
