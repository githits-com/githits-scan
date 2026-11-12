# Experimental dependency diff

`githits-scan diff [PATH] --base REF [--head REF]` compares literal Git revisions;
without `--head` it reads actual working-tree bytes. PATH must be the Git root.
For a PR, explicitly choose the merge-base:

```sh
githits-scan diff --base "$(git merge-base origin/main HEAD)" --head HEAD
githits-scan diff --base HEAD --format json -o dependency-diff.json
githits-scan diff --base HEAD~1 --head HEAD --format markdown
```

The command is experimental and informational. Exit 0 means a report was produced,
including partial or unfamiliar evidence; it is never a policy pass. Local input,
configuration and admission errors use 2; execution/output failures use 3. Git and
`GITHITS_API_TOKEN` are required, including identical or empty selected inputs.
The service can assess unchanged dependencies against current evidence.

## Output destinations

The original `--format human|json|markdown` selects one representation (default
`human`); `-o/--output PATH` selects its file, with stdout when omitted or `-`.
To select destinations by format instead:

```sh
githits-scan diff --base HEAD~1 --head HEAD --output-json diff.json --output-markdown diff.md
githits-scan diff --base HEAD --output-json - --output-markdown diff.md
githits-scan diff --base HEAD --output-json diff.json --output-markdown -
```

`--output-json PATH` and `--output-markdown PATH` may be used together or individually.
Each implies its representation; repeated `--format` flags are not needed or accepted.
Named outputs emit only requested documents, with no implicit human report on stdout.
They conflict with explicitly supplied `--format` (even `human`) and `-o/--output`.
`-` means stdout for either flag, but at most one destination may use it. Empty
paths, mixed flag styles and two stdout destinations are usage errors (exit 2).
Paths are relative to the process working directory, not the scanned repository.

Both representations consume the same returned report: no second submission,
audit or review. JSON preserves the producer bytes exactly, including when a
future schema cannot be interpreted; Markdown then contains the existing explicit
unsupported-schema/unassessed notice. Partial, unavailable and unknown evidence
keeps its qualifications. Exit 0 remains informational, never safe/passed.

When both outputs are requested, preflight checks run before snapshot reads,
credentials or charged submission. File destinations must be distinct: existing
canonical aliases (including symlinks), equal canonical-parent/filename paths for
new files, and Unix hard-link aliases fail with exit 2. Missing parents,
directories, dangling symlinks and destination inspection failures use the usual
output error (exit 3). No files are opened or truncated by preflight. Hard-link
identity is not checked on non-Unix systems. Destinations are checked again after
JSON is written: case aliases between previously absent files may only become
resolvable then. Such a conflict exits 2 after analysis, retaining JSON without
opening Markdown. Keep redirected stdout separate from
the other destination: Scan cannot identify shell redirection or prevent concurrent
path replacement. These checks cannot guarantee subsequent write success.

After successful analysis/validation, files overwrite their destinations using the
shared buffered writer. With two outputs, JSON is written first, then Markdown;
flag order does not affect this. Each completed file write produces a `saved`
diagnostic unless `--quiet`. Service/invalid-report errors leave destinations
untouched. Any write/flush failure exits 3, stops remaining writes and never
resubmits. Earlier completed output remains; a failing file can be partially written.
There is no transaction or rollback across destinations. Avoid automatically
rerunning a charged analysis to recover a local output error. There is no saved-JSON
replay command. Omitting the named flags restores the original single-output
contract; existing report files need no migration.

## Inputs and ownership

`repository.rs` enumerates immutable commit trees or tracked/nonignored untracked
working-tree files. It never mutates the index/checkout, follows symlinks, executes
package managers, or fetches missing objects. Git children receive no API token,
disable fsmonitor/replacement objects/transports/lazy fetch, and suppress raw
diagnostics. Missing objects need an explicit fetch outside Scan. Sparse/unmerged
working trees require an explicit committed head or resolution first.
Working-tree bytes can differ from committed blobs through line-ending conversion.

The catalog owns recognition. Discovery pairs metadata and the existing bounded
upload selector includes owning companions and Cargo/npm/Bun workspace manifests through
an injected snapshot reader. Hidden/installed paths and default fixture exclusions
are omitted. Tracked ignored files remain tracked; Git ignores exclude untracked
files. `--exclude` applies to both sides. Diff deliberately ignores
`githits-scan.toml`; its presence and other selection limitations are diagnostics on
stderr, including with `--quiet`, without altering returned JSON.

By default, manifest-only projects are selected and `unlocked_manifests=resolve`.
`--lockfiles-only` excludes those projects, retains lock companions/workspace
evidence and requests `recorded_only`. Groups are `all`; both advisories and direct
reviews are requested. Scan sends explicit supplied/empty side states. It never
silently removes a selected file that the service rejects, including marker-only
manifests. Parser errors retain the rejected side, path and status.

## Comparison and presentation

The service owns canonical package/declaration identity, alias resolution, source
ownership, directness, version pairing, advisory assessments and upgrade enrichment.
Scan does not infer them from SBOM properties or recompute a repository version union.
All selected recorded sources remain visible, including auxiliary locks. Ownership
qualifies a recorded transition rather than proving an effective workspace upgrade.
Only proven recorded direct old/new transitions are eligible for upgrade review;
transitive changes remain visible without client review requests. Additions,
removals, ambiguity and mismatches retain actual eligibility reasons and nullable
targets. Backend review batching has no first-30 total cap.

Human and Markdown output groups changes by file, preserves before/after versions
and versions retained in other files, and shows a short description of known direct
or indirect usage. Declaration-only edits remain visible. Secondary workspace locks
are identified as such; a change in one does not establish a workspace upgrade.

Reports explain problems in plain language, with the affected package or file and
a next step only when supported by the returned information. Internal IDs, reason
codes, diagnostic counters and status tuples stay in JSON. An inability to determine
something must say what could not be determined and why. If the service supplies no
usable explanation, Scan says that explicitly and suggests manual review rather
than inventing a cause, a fix, a retry or a new analysis. Routine all-clear security
rows and empty advisory changes are omitted; material limitations remain visible.
Repeated inconclusive project-wide advisory results are grouped by their supplied
scope, revision and reason. Independent missing-inventory, unfinished-assessment
and unidentified-package limitations all remain visible. Known affected-before/after
facts remain visible. Grouped security limitations include a shared manual-check
next step. When
a project result shares the explicit finding ID of a changed-version result, the
scope qualification attaches to that result instead of repeating the advisory ID;
unmatched positive project results stay separate. A local fix never implies that
the project-wide result is clear.
An incomplete security-check section remains visible even when it returns no
findings, including the supplied reason and any unsupported-package limitation.

Changed-version advisory results and results across supplied project files remain
distinct: a package update can remove an advisory from one file while the project
files remain affected. Incomplete file and security information qualifies its own
revision and scope. The comparison uses today's advisory information, not knowledge
at commit time; a reported fix does not establish runtime reachability or
exploitability. Known service notices become these plain caveats; other supplied
qualifications remain visible once. JSON retains every notice and the complete
source, resolution-unit and project scopes.

Security information and release-note completeness are separate. Release-note
warnings identify possible compatibility changes and migration work, without
presenting them as a complete migration checklist. Human output shows the first three returned entries and every flagged entry,
with a plain notice when more are available in JSON. Markdown includes every
returned entry in producer order, without shortening supplied text. Entries with
no summary retain their version (or an explicit missing-version label) and explain
that the release-note summary was not supplied, in both formats. Producer
truncation and incomplete-coverage warnings remain explicit; neither format can
recover entries the service omitted. Links use only validated credential-free HTTP(S) addresses
supplied by the service; Scan never invents a full-history URL.

Markdown escapes untrusted formatting/mentions and terminal text escapes control
characters. The shared string escaper preserves combining accents and standard
text/emoji presentation selectors after a literal base. Leading extenders and
extenders after an escaped control remain escaped; bidi, ZWJ and tag controls remain
escaped. Identifier text is not stripped or normalized, and JSON is untouched.
Unsupported report and review formats receive a plain explanation of
why Scan cannot display them. Required report and section fields still validate
before output, including machine metadata that human output omits. JSON preserves
original result bytes, including whitespace, additive fields, nullable targets and
unfamiliar vocabulary. No Git-label wrapper or client notices are added.
See [JSON output](json-output.md#experimental-diff-service-report).

### Explaining missing evidence

The producer owns causal explanations because it owns binding, reachability and
review decisions. Scan translates known supplied reasons into plain language and
presents their associated file and dependency context; it does not
attribute a nearby coverage gap to a package whose dependency type is unknown.
For a resolution gap with `reason:required_input_not_supplied`, human/Markdown
name both the source `path` and the missing `required_path` when supplied. Other
gaps can omit that field; Scan does not guess a required file. File problems have
their own section. Identical known file-problem rows in both snapshots are combined
by full projected equality within the same family; different requirements, paths,
reasons and report-wide scope stay distinct. Reachability references remain
side-specific. Advice names the unread file and the workspace/exclusion selection
rules; it does not promise that file existence alone fixes unsupported selection,
and there is no manual include flag.

The [public OpenAPI](https://api.githits.dev/v1/openapi.json) defines the identity
associations below. The table also includes supported producer details within
the schema's open coverage/review objects, for consumers of the unchanged JSON:

| Evidence | Exact association and explanation |
| --- | --- |
| Changed package | `before_ids` and `after_ids` refer to occurrences in the base and head snapshots respectively; IDs must not be compared across sides. |
| Ineligible direct review | Each declaration change's `binding_transitions` carries `source_key`, side binding statuses, nullable targets and `review_eligibility.reason`. Its declaration IDs identify the authored dependency and manifest. |
| Missing or failed eligible review | A deduplicated `direct_reviews.data` row retains package/from/to, `source_keys`, `declaration_change_ids`, status and reason. Coverage counts alone do not explain an individual missing review. |
| Partial returned review | Returned `data.unknown_details` carries section/code/message; changelog coverage remains separate from direct security evidence. |
| Incomplete comparison | Side-specific resolution gaps retain source paths, reasons and any required input path. Advisory delta reasons qualify their own scope and side. |

For an unknown changed dependency type, Scan joins `before_ids` to base
occurrences and `after_ids` to head occurrences. It presents the occurrence's
`directness_reasons` and follows its explicit `directness_proof_ids` to
`reachability[].id` in that same snapshot. It never compares IDs across sides or
attaches causes by matching names, paths or neighboring workspace gaps. Individually
known occurrences inside an aggregate unknown change need no explanation;
additions/removals do not qualify their absent side as a failed assessment.

Cause codes and native dependency-information reasons are translated at the command
renderer, their natural presentation owner; Scan does not recompute dependency
semantics. Associated paths and dependency names give useful context. When
`declaration_id` is present, `dependency_name` identifies the declaration blocking
the result, which can differ from the changed package. Otherwise it names the
affected dependency. Equal full causes and shared proofs are deduplicated within
each change/side. Identical visible reasons before and after are combined; within
a file group, a reason appears once with exactly the affected package names.
Different files, blockers and reasons remain distinct.

Snapshot binding `reasons` join through the enclosing declaration change's same-side
declaration ID and exact `source_key`, independently of eligibility vocabulary.
A joined cause replaces the duplicate explanation of its binding status; distinct
status limitations and legacy reasons without a matching cause remain visible.
Declaration labels prefer the head's `after_id`, then the base's `before_id`, looking
up each only in its own snapshot. Missing identity is explained rather than guessed
from a package name. Legacy ineligibility reasons still receive plain explanations
even without the additive cause fields; mismatched listed versions are never
presented as usable review baselines.

Review failures distinguish a package review failure from failure to prepare the
combined report. The latter does not prove an individual review failed. Known
service errors receive plain descriptions; other supplied messages remain useful
context without raw codes or scopes. Reviews retain declaring-file context through
`declaration_change_ids`, even without an occurrence change. Interpretable partial
review details still display beside a failure.

`deadline` means the review was not completed in time; `evidence_unavailable`
means the required information was unavailable. `result_size_limit` means assessed detail was
omitted for size, not that the review was unassessed. Legacy `review_failed` rows without detail
explicitly say the service supplied no explanation. No missing review or security
conclusion implies safety, and no output recommends a charged rerun.

Incomplete snapshot coverage summaries follow `reachability_id` to their own
side's proof causes. Report-level coverage has no snapshot side and never resolves
IDs through either snapshot. Older schema-v1 reports can omit the additive cause
fields; an unknown with no associated cause remains explicitly unexplained, and
unavailable proof detail stays qualified. No missing evidence implies safety.

## HTTP, limits and cost

One accepted `POST /v1/experimental/dependency-diffs` sends a text `request` JSON part plus
literal repeated `base_files[]` and `head_files[]` with relative filenames/original
UTF-8 bytes. Required controls are closed; no query kind/format, refs, URLs,
completeness receipts or enforcement rules are submitted. The returned shared
job links drive SSE and the result read: ordinarily three requests. No separate
SBOM, audit or upgrade-review request is made. Redirects, transport-error retries,
polling and old comparison fallbacks are disabled. Explicit HTTP 429 refusals
receive bounded Retry-After recovery. Existing established-stream
reconnection behavior is shared with other commands.

The complete pair is limited to 256 files, 5,242,880 bytes per file, 1,024 UTF-8
bytes per path and 8,000,000 full multipart bytes including framing, inclusive.
Duplicate paths within a side are rejected; the same path across sides is valid.
Two individually valid uploads can exceed the pair limit. Validation precedes
credential acquisition; do not chunk, silently prune or increase bounds. Successful
responses are capped at 16,777,216 bytes. Path/security/transport rules remain owned
by [the shared API boundary](sbom-api-contract.md).

One admission is weighted as two audits (currently 200 daily units at policy
defaults). Runtime quotas can vary. Reads and stream reconnects do not resubmit.
A completed partial result remains a report; admission or required core failure
produces an error and no document. Service HTTP 429 refusals share the [bounded Retry-After recovery](sbom-api-contract.md#rate-limit-recovery) across paired submission, progress and result requests; final problem errors preserve Retry-After.

## Prototype migration

This replaces the earlier experimental local schema and four-analysis composition.
Consumers should read the producer's versioned `kind=diff` report and its independent
section statuses/coverage. Identical inputs now require a real charged analysis.
Flags and informational exits remain stable. There is no persisted repository data
migration; an earlier binary can be restored, with its documented semantic limitations.
Future configurable scan composition and enforcement are outside this command.

## Expected Git coverage notes

Human and Markdown output separate exact expected Git source limitations into
Coverage notes, preserving partial/unknown producer facts. JSON remains the
original bytes. A neutral partial headline requires exhaustive expected-only
causes on each affected source and exposure, fully checked eligible registry
coordinates, complete upgrade reviews, and consistent revision
labels. Aggregate causes never explain a different owner's deficit. Missing or
empty cause lists, unknown status/reasons, provider failures, incomplete review
counts and independent file/assessment failures retain caution. A derived
`source_scope_incomplete` explanation is informational only with its own scoped
expected-only proof. Non-registry exclusions require complete inventory unless an
explicit expected Git graph limitation also explains inventory loss. Coverage
notes group each cause with its affected files; aggregate-only
causes without file attribution remain explicit. Known affected advisories and
changes remain visible.

## Non-registry exclusions and downstream consumers

`non_registry_source` in `coverage.excluded_dependencies` (snapshot or report)
identifies a package excluded from public registry checks, not a failed lookup.
Human and Markdown output keep its name, recorded version and all file paths
under **Coverage notes**, without requiring manual review on that basis alone.
This reason does not establish that a package is local, safe, or licensed.
The same string in source gaps, resolution gaps, mismatches, arbitrary assessment
reasons or reachability causes does not qualify those failures as expected.

The existing producer contract supplies the required distinction: the exclusion
family identifies ineligible packages; advisory coverage supplies exhaustive
causes and eligible coordinate/check counts; each exposure supplies its own
inventory and assessment status. No additional upstream field is required for
this classification. Unknown reasons remain actionable. JSON remains the exact
producer bytes, including partial statuses and every exclusion; Scan adds no
attention fields to diff JSON.

For `scan-action` and other JSON consumers:

- **Audit:** use Scan's `actionable_incomplete` and per-issue `actionable` fields
  for coverage attention. `incomplete` alone includes normal coverage exclusions.
  Findings remain independent: an advisory still requires attention when
  `actionable_incomplete` is false. Saved explanations use
  `audit_actionable_incomplete` and `audit_issues[].actionable`.
- **Diff exclusion rows:** only the exclusion family admits `non_registry_source`
  alongside the three exact expected Git reasons above. Every reason in a row
  must be recognized; empty, missing and mixed unknown causes retain caution.
  Source and resolution rows continue to admit only the expected Git reasons;
  any mismatch remains actionable.
- **Diff advisory aggregate:** a neutral partial result needs a complete or partial
  advisory section with no failure reason, present equal `checked` and
  `coordinates`, zero `unknown` and `unsupported`, and a nonempty exhaustive list
  of expected Git or non-registry exclusion reasons.
- **Each exposure and revision:** non-registry reasons qualify assessment only
  with `inventory: complete`, `assessment: complete` or `partial`, equal `checked`
  and `coordinates`, and a nonempty expected-only reason list. A partial inventory
  still needs Git-only proof or an explicit `git_dependency_graph_unavailable`
  cause alongside expected-only exclusions; non-registry exclusions alone cannot
  explain graph loss.
  Complete exposure sides with no causes require zero unqualified occurrences.
  Both revision sides must be present.
- **Derived advisory limits:** only `source_scope_incomplete` can inherit an
  expected limitation from its own qualified exposure side. Every transition
  needs exactly one matching change; derived transition limitations additionally
  need exactly one matching source exposure. Transitions without limitation
  reasons do not require the source-exposure join. An unexplained unknown or
  indeterminate result, `coordinate_assessment_incomplete`, or another reason
  remains cautionary. Actual affected advisories remain visible.
- **Other sections:** retain the existing checks for complete upgrade reviews and
  matching eligible/completed/returned counts, zero omitted/unavailable/not-assessed
  reviews, revision labels, unexplained partial snapshots, and owner-scoped
  reachability proof. Aggregate reasons cannot explain a different source's gap.

For example, an excluded `workspace-helper` at `0.1.0` in `Cargo.lock`, with
`reason: non_registry_source`, is a coverage note. If its exposure has complete
inventory and two eligible coordinates both checked, `assessment: partial` with
`reasons: [non_registry_source]` is also expected. Changing inventory to `partial`,
adding `dependency_list_unavailable`, leaving a required `member/Cargo.toml`
uncaptured, or failing one eligible check retains caution. A separate
`tools/Cargo.lock` dependency-information gap stays actionable even if the main
lockfile contains an expected exclusion.

Consumers need no migration of stored reports. Audit-only exclusions now return
exit 0 when no independent findings or inconsistencies exist; `incomplete` stays
true. Diff exit behavior is unchanged (the command reports producer facts rather
than enforcing them). Restore an earlier binary to restore earlier presentation
and audit attention behavior; saved producer evidence remains readable.
