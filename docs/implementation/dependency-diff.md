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
