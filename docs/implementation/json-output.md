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

## Audit and saved explanations (schema 1)

Audit has `schema_version`, `incomplete`, optional `analysis` provenance,
optional `summary`, and nonempty finding/evidence groups: `vulnerabilities`,
`deprecated`, `outdated`, `duplicates`, `manifest_lock_mismatches`, `issues`,
`manifests`, `resolved_from_manifests`, `limitations`, plus `remediation` when
available. Empty optional groups are omitted. Source paths and manifests are
unique and sorted. Summary is absent for unknown producer versions. Vulnerability findings may carry
`ignored: true` and `ignore: {id, reason}`; unmatched findings omit both fields.
`summary.vulnerabilities` remains the raw total; optional
`summary.ignored_vulnerabilities` counts ignored rows when nonzero. The same
annotations appear on saved explanation `problems`. Archive schema 1 may contain
optional `audit_policy: {ignore: [{id, reason}]}`; replay validates and reapplies
it, while archives without it have no ignores.

`audit --from-analysis --explain ... --json` has `kind: audit_explanation`,
`analysis`, selected `problems`, `sources`, `issues`, `audit_incomplete`,
`audit_issues`, and optional `remediation`. Its issues concern the selected
explanation; audit issues retain whole-report gaps. Detailed nested evidence
contracts live in [audit](audit.md). A saved analysis archive is a separate
format (`format: githits-scan-analysis`), not compact audit JSON.

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

## Experimental diff (schema 1)

`diff --format json` emits `schema_version: 1`, `base`/`head` (resolved commit IDs
or `working-tree`), `comparison_scope`, `analysis_performed`, `incomplete`,
`notices`, and ordered `changes`. This is informational data, not a policy result.

Each change has nullable `registry`, `name`, `kind`, nullable `base`/`head` package
facts, `base_scope`/`head_scope` (direct, transitive, unknown, or null for an absent
side), `vulnerabilities`, `upgrade_reviews`, and `review_gaps`. Package facts retain
version/path sets, per-manifest exact `direct` versions, `direct_unknown` sources
and `scope_unknown`. Direct facts take precedence over unknown transitive scope.
`kind` is added, removed, upgraded, downgraded, changed, or scope_changed.

`vulnerabilities` has `assessed`, nullable fixed/introduced/unchanged advisory sets,
and `base_observed`/`head_observed` sets. Null means unknown, not zero. Repository
version unions and source-local direct comparison are described in
[dependency diff](dependency-diff.md); this does not detect every per-project
transitive exposure change. Upgrade reviews retain selected producer facts,
including unknown qualifications, nullable security lists and changelog links.
They do not replace the scan deltas. Human and Markdown formatting are presentation.
