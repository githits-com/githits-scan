# Experimental dependency diff

`githits-scan diff [PATH] --base REF [--head REF]` compares literal Git revisions;
without `--head` it reads actual working-tree bytes. PATH must be the repository
root. For a PR, explicitly choose its merge-base:

```sh
githits-scan diff --base "$(git merge-base origin/main HEAD)" --head HEAD
githits-scan diff --base HEAD --format json -o dependency-diff.json
githits-scan diff --base HEAD~1 --head HEAD --format markdown
```

The command is experimental and informational. Exit 0 means a report was produced,
including partial results; inspect `incomplete`, per-row assessments and notices
before using it to enforce a policy. Input/configuration errors use 2; failures
preventing the inventory comparison and output failures use 3.

## Inputs and ownership

`repository.rs` enumerates immutable commit trees or tracked/nonignored untracked
working-tree files. It never changes the index or checkout, follows symlinks,
executes package managers, or fetches missing objects. Git subprocesses receive no
`GITHITS_API_TOKEN`, disable fsmonitor and transports, and suppress raw diagnostics.
Missing partial-clone objects require an explicit fetch outside Scan. Sparse or
unmerged working trees require an explicit committed head or resolution first.
Working-tree reads preserve actual bytes, so checkout line-ending conversions can
make otherwise unchanged files differ from committed blobs.

The catalog alone recognizes package evidence. Discovery pairs the metadata through
its normal pure rules; upload preparation uses the existing bounded selection and
Cargo/npm workspace expansion with an injected snapshot reader. Hidden and
installed-dependency paths are omitted. Tracked-but-ignored files remain tracked;
Git ignores exclude untracked working-tree files. Default fixture exclusions and
`--exclude` apply to both sides. `--lockfiles-only` skips manifest-only resolution.
This command ignores `githits-scan.toml` and reports its presence as a notice; use
explicit flags. Unsupported, ambiguous and unselected evidence remains a notice,
including when selected inputs are identical. Deliberate exclusions are omitted.

## Comparison and evidence

The full CycloneDX inventory supplies dependency versions. Compact audit findings
supply advisory identities; the remediation trace is finding-focused and cannot
replace a complete inventory. License-report DTOs lack the complete registry and
adjacency evidence required here. Missing registry/version evidence stays unknown.
The current producer's extensible `githits:registry` property supplies registry
identity; missing properties and unmatched audit coordinates qualify the result.

Changes aggregate version sets across the repository by registry/name. Row scope
describes changed versions; an unchanged direct version does not label a changed
transitive version direct. Mixed subsets remain explicit. A transitive
version already present elsewhere is not a new repository-wide version when added
to another project. This is not a per-project exposure diff. Stable numeric X.Y.Z
transitions are ordered locally; unfamiliar version schemes remain `changed`.

Directness comes from registry declarations joined to declaration agreement by
source path, package name and matched versions. Ambiguous joins, aliases without
an exact identity, empty matched-version lists and missing scope evidence remain
unknown. Direct membership is compared independently, so a promotion to direct at
the same version is visible. Per-manifest direct transitions are paired before
identical transitions are deduplicated. Only a unique old/new direct pair is sent
to upgrade review; transitive changes never cause a review request.

Audit advisory sets span all reported versions of each package. Fixed means absent
from the head set, introduced means absent from the base set, and unchanged means
present in both. If a reported coordinate's vulnerability assessment is unavailable or unverified,
these three sets are null, and observed findings remain separately available.
`assessed` concerns the reported versions: source/declaration gaps still qualify
the overall report without erasing completed coordinate checks. A partial report
is not a clean vulnerability assessment of the whole repository.

Markdown text escapes formatting and URL syntax and breaks `@`/`#` tokens
with a zero-width separator, because GitHub applies those filters after decoding
entities. Terminal text and JSON remain exact. Validated producer changelog URLs
are intentionally formatted as links.

## HTTP and cost

Nonidentical nonempty inputs use base SBOM, head SBOM, base audit, head audit, in
that order. Empty sides skip their calls. Identical selected uploads make no calls
and explicitly state that vulnerabilities were not assessed. API upload/response
limits, authentication, redirect prohibition and retry policy remain shared.

At documented default policy, four analyses cost 400 weighted daily units, plus
upgrade-review requests. The personal short-rate limit is two analysis submissions
per minute, and the organization/project default is five; runtime policy can vary.
Audit failure stops further audits and retains the inventory diff with unavailable
security evidence. Upgrade failures retain scan results; a 429 stops later review
batches. There are no sleeps or retries.

`POST /v1/package-upgrade-reviews?fields=security.direct,changelog` accepts up to
30 transitions per batch. Returned direct security evidence stays separate from
repository audit deltas. Unknown qualifications and nullable/truncated changelog
evidence are retained; links come only from returned `html_url` values. No URL is
constructed for an index route. Direct additions have no previous direct version,
which this endpoint requires, so the report records an API gap. Unsupported review
registries and ambiguous version pairs also remain explicit gaps.

See the [public OpenAPI](https://api.githits.dev/v1/openapi.json) for current fields
and policy defaults. [JSON output](json-output.md#experimental-diff-schema-1)
describes the report representation.
