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

Human/Markdown output groups changes by source and preserves before/after versions
and retained-elsewhere notes. Declaration-only edits remain visible. Human/Markdown show changed-coordinate and recorded repository-union advisory
deltas, including non-affecting coordinate rows. Empty delta arrays are labelled
without inferring a clean assessment; coverage qualifications still apply. The
complete source, resolution-unit and project scopes remain in JSON.
Incomplete scope qualifications are still shown. A local fix can coexist with an affected repository union.
The comparison uses current shared advisory evidence, not knowledge at commit time;
a reported fix is not proof of runtime reachability or exploitability.

Assessment gaps, partial source inventory, exclusions, unknown ownership, unrequested
sections and failed enrichment remain distinct. Completed coordinate evidence can
survive unrelated source gaps. Security assessments and changelog truncation are
separate: returned headlines/signals are attention evidence, not an exhaustive
migration checklist. Links are validated credential-free HTTP(S) URLs supplied by
the service and labelled as changelog entries, never invented full-history URLs.
The compact view shows the first three returned entries and every entry carrying
producer signals, with an explicit additional-entry count; JSON retains all entries.

Markdown escapes untrusted formatting/mentions and terminal text escapes control
characters. Human/Markdown explicitly decline unsupported future report structures.
Review detail is an open service object: unfamiliar detail stays in JSON and is
labelled uninterpreted in human output, without blocking export. The pinned report
and section structure still validates before output.
JSON preserves original result bytes, including whitespace, additive fields, nullable
targets and unfamiliar vocabulary. No Git-label wrapper or client notices are added.
See [JSON output](json-output.md#experimental-diff-service-report).

### Explaining missing evidence

The producer owns causal explanations because it owns binding, reachability and
review decisions. Scan presents supplied reasons and associated files; it does not
attribute a nearby coverage gap to a package whose dependency type is unknown.
For a resolution gap with `reason:required_input_not_supplied`, human/Markdown
name both the source `path` and the missing `required_path` when supplied. Other
gaps can omit that field; Scan does not guess a required file.

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

The current directness contract returns strings on changes and occurrences, with
exposure/reachability qualifications elsewhere, but no per-occurrence causal
reason. Existing IDs permit exact joins; they do not explain why a proof failed.
An unknown dependency type must not be described as direct, transitive or safe by
inferring from unrelated bindings or source gaps. Additions/removals have no
occurrence on one side; that absence is not a failed assessment.

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
