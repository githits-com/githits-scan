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
upload selector includes owning companions and Cargo/npm workspace manifests through
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
presenting them as a complete migration checklist. The compact view shows the first
three returned entries and every flagged entry, with a plain notice when more are
available in JSON. Links use only validated credential-free HTTP(S) addresses
supplied by the service; Scan never invents a full-history URL.

Markdown escapes untrusted formatting/mentions and terminal text escapes control
characters. Unsupported report and review formats receive a plain explanation of
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
gaps can omit that field; Scan does not guess a required file. Because Scan selects
companions automatically, advice checks that the file exists in that revision and
is not excluded; there is no manual include flag.

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

A deadline means the review was not completed in time; unavailable required
information is a separate cause. `result_size_limit` means assessed detail was
omitted for size, not that the review was unassessed. Legacy failures without detail
explicitly say the service supplied no explanation. No missing review or security
conclusion implies safety, and no output recommends a charged rerun.

Incomplete snapshot coverage summaries follow `reachability_id` to their own
side's proof causes. Report-level coverage has no snapshot side and never resolves
IDs through either snapshot. Older schema-v1 reports can omit the additive cause
fields; an unknown with no associated cause remains explicitly unexplained, and
unavailable proof detail stays qualified. No missing evidence implies safety.

## HTTP, limits and cost

One `POST /v1/experimental/dependency-diffs` sends a text `request` JSON part plus
literal repeated `base_files[]` and `head_files[]` with relative filenames/original
UTF-8 bytes. Required controls are closed; no query kind/format, refs, URLs,
completeness receipts or enforcement rules are submitted. The returned shared
job links drive SSE and the result read: ordinarily three requests. No separate
SBOM, audit or upgrade-review request is made. Redirects, submission/result retries,
polling and old comparison fallbacks are disabled. Existing established-stream
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
produces an error and no document. Service 429 responses preserve Retry-After.

## Prototype migration

This replaces the earlier experimental local schema and four-analysis composition.
Consumers should read the producer's versioned `kind=diff` report and its independent
section statuses/coverage. Identical inputs now require a real charged analysis.
Flags and informational exits remain stable. There is no persisted repository data
migration; an earlier binary can be restored, with its documented semantic limitations.
Future configurable scan composition and enforcement are outside this command.
