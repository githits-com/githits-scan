# Audit consumer

`githits-scan audit [PATH]` submits the selected files as one combined asynchronous
analysis. The backend owns parsing, advisory applicability and metadata assessment;
Scan owns evidence interpretation, output and exit policy. It does not infer
reachability from manifest associations or execute one job per file pair.

## Command contract

The inventory/configuration/exclusion rules match `sbom generate`, including
manifest-only resolution by default. `--lockfiles-only` skips it. Reports name the
unique manifest paths selected for upload in `manifests` (`Manifests:` in human
output). Deliberately omitted files are not listed: results describe the selected
scope, not every file discovered in the repository.

Default human output shows vulnerability problems, qualified fix alternatives,
manifest/lock disagreements and all evidence gaps. Deprecated, outdated and
duplicate findings contribute their totals; `--details` expands their complete
human lists with recorded origins and paths. A hint appears only when such
maintenance findings exist. The audit-only switch applies to live and saved
ordinary reports and to human output files. JSON is always complete and accepts
the switch without changing facts; focused explanation remains scoped to its
selected component. Library callers supply `details` on `Request` and
`ReplayRequest` (`false` for compact output). `--quiet` does not change result visibility.

Both human and JSON output use one command-owned result view. It contains summary
counts, security/maintenance findings, native declaration/lock disagreements,
deduplicated input-file paths and grouped issues
for unresolved dependencies, excluded package checks and incomplete assessments.
There is no full occurrence, native-ID, declaration, subject or parser-statistics
inventory dump. Missing optional severity or source metadata is omitted; a missing
lockfile path on a manifest-resolved package does not mean the package is missing.
For v1 reports, returned manifest-resolution evidence is still named once
(`resolved_from_manifests` in JSON). V2 omits that producer metadata, so the optional
field is absent rather than inferred from directory layout or missing lockfiles.
The upload plan is the canonical manifest-name source for both versions.

JSON is a Scan-owned `schema_version: 1` contract. Empty finding categories and
optional fields are omitted. `incomplete` describes coverage gaps or inconsistent
consumed evidence, independently of whether findings exist. Future API versions produce a
compact incomplete issue without interpreting known-version counts or forwarding
opaque fields. Producer report IDs, timestamps, unknown additional fields and raw
evidence are not emitted.

Vulnerability JSON retains the legacy `severity` string and adds independently
optional `severity_score` (number) and `severity_type` (the supplied source string).
The legacy string keeps its original spelling and is absent without a score.
Source-only evidence remains available in `severity_type`; missing values are
omitted rather than inferred. These additive fields use the existing schema 1,
including explanation `problems`; nested remediation finding identities stay
unchanged. Saved analyses already retain the producer facts and need no migration.

Human reports use one severity formatter across vulnerability lists, mitigation
cards and explanations: known CVSS sources show `CVSS 7.4`, label-origin or
unspecified sources show `severity 6`, and unknown sources show their escaped
identifier alongside the score. A score of zero is retained; a missing score adds
no annotation. Scores use their existing numeric display (`7.0` becomes `7`),
without ranking, rescaling or assuming that a label-origin score is CVSS.

`-o/--output FILE` saves the selected representation; `-` means stdout. Human files are
plain text. Progress goes to stderr; JSON suppresses live progress. Writing to stdout
has no completion message. Saving a file confirms its path after a successful write.
`-q/--quiet` suppresses progress and file-save messages; report content, failures,
actionable warnings and blocked-scan diagnostics are unchanged.
Admission/transport/structural decoding failures leave an existing output file
untouched; output I/O failures can leave partial writes. Strings are escaped for
terminal output; color never carries meaning.

| Exit | Audit meaning |
| --- | --- |
| 0 | No unignored finding in any category, and the selected evidence is fully checked |
| 1 | Any unignored vulnerability, deprecated release, outdated version, duplicate group, manifest/lock disagreement, evidence gap, unverified accounting or future unassessed report version; also preflight drift/empty selection |
| 2 | Usage/configuration/credentials/access/upload-limit or caller-action API error; missing/invalid saved input or explanation selector |
| 3 | Transport, rate limit, service/problem execution, structural report decoding or output error |

Outdated, duplicate or manifest/lock disagreement findings alone cause exit 1.
This is an attention gate across unignored findings and evidence gaps.

## Local advisory policy

`[[audit.ignore]]` in `githits-scan.toml` accepts `id` and mandatory nonblank
`reason`. IDs match only the exact case-sensitive reported advisory ID, not an
alias. Duplicate IDs, whitespace in IDs, unknown keys and blank reasons are
configuration errors (exit 2). Expiry is not supported.

Raw producer evidence is assessed before local policy. Ignored vulnerabilities
remain in the same JSON `vulnerabilities` array with `ignored: true` and
`ignore: {id, reason}`; unmatched findings omit those fields. Summary
`vulnerabilities` keeps the raw total and optional `ignored_vulnerabilities`
counts ignored rows when nonzero. Human output always includes an
`Ignored vulnerabilities` section with reasons, even when mitigation groups
also cover the finding. Producer mitigation evidence remains visible and may
include ignored advisories; it is not a local enforcement verdict. Saved human
explanations also mark ignored problems with the reason.

When all vulnerabilities are ignored, all other finding categories are empty,
and evidence is complete, exit is 0 and the headline is
`No unignored audit findings in checked dependencies`. The human summary retains
the total and ignored count. Ignored advisories with incomplete evidence still
produce `Audit results` and exit 1; other findings produce `Audit findings` and
exit 1. Ignores never suppress coverage or accounting errors.

There is no category-specific `--fail-on` or configuration equivalent. Audit is
an attention gate across vulnerabilities, maintenance, input disagreements and
evidence gaps. Consumers requiring a different gate can compute it from full
JSON, including `incomplete`, `issues` and ignored annotations; handle exits 2/3
as errors rather than policy findings. No additional flag is needed for that
workflow.

## Saved analysis and component investigation

`audit --save-analysis FILE` adds an explicit, new analysis file to the ordinary
one-job audit. It does not replace the compact stdout report. Known existing
files, directories and symlinks fail with usage exit 2 before discovery/upload;
write-time `create_new` also prevents overwriting a path created during the job.
Live token/client setup is unchanged. The archive is encoded and written before
the report; save errors return 3 without a report or false saved message. I/O
failure can leave a newly created partial archive. Successful saves announce the
path on stderr unless `--quiet`.

`audit --from-analysis FILE` re-renders the saved facts. It bypasses credentials,
HTTP client construction, discovery and configuration. Neither file mode accepts
`-`. Replay accepts `-o/--output FILE`, including explanations. Offline mode rejects PATH and scan-selection flags rather than
silently ignoring them. Human output identifies the recorded timestamp; offline
compact JSON adds `analysis` provenance. Replay uses the current Scan assessment
of stored facts, not a stored verdict or a fresh check. The archive also stores
its explicit local `audit_policy` when nonempty, separate from unchanged producer
facts. Replay validates and reapplies that policy without reading configuration.
Older archives default to no ignores. This is additive archive schema 1; older
Scan readers may omit the policy and return the stricter exit 1.

`--explain REGISTRY:NAME@VERSION` requires offline mode and exactly matches a
vulnerability coordinate. Human output shows the problem, its immediate recorded
requesters, then whole fix alternatives using the same guidance/check renderer as
the compact report. Further recorded requests follow the fixes. Joint changes are
not split and alternatives are not combined. An
unmatched selector is usage exit 2. Inspection preserves the entire saved audit's
0/1 outcome, including unrelated findings/gaps. Explanation JSON has its own
`schema_version: 1`, `kind: audit_explanation`, provenance, selected problems,
source-grouped nodes/relations, remediation and explicit detail/audit issues.

Detailed recommendations also expose `occurrence_scope`: subject references,
per-change references in the same order as the complete change list, and
remaining references. Each set links consumer-local `{source, node}` labels to
`source.id` and `source.nodes[].id`. A null remaining/per-change set means not
supplied; it is distinct from an explicitly empty set. References outside the
selected trace are counted, not silently presented as an empty scope. Unknown
recommendation detail status leaves copy scope unavailable. Partial/multiple-copy
human explanations identify the affected and remaining labeled copies. Ordinary
compact reports omit this inspection-only field.

The pure audit layer owns the archive format and evidence selection; command
handlers own explicit file I/O and presentation. The API DTOs retain the service
facts. The command's compact change serializer excludes archive-only occurrence
references, so ordinary live JSON remains unchanged.

Human guidance deduplicates identical rendered blocker blocks within each
alternative; distinct target details remain separate and JSON preserves every
original blocker, including its opaque context. Inspection omits a request path
only when it exactly equals the section's source path. Manifest paths that differ
from that source remain visible. Missing requirement values remain explicit;
unrecognized requirement-status values are escaped without interpreting them as
planner check states.

Human inspection groups requests within one source and target occurrence by exact
requirement/status, path/basis, owner role, request kind and relation kind/basis.
The vulnerable dependency is named once above its request section; each line
shows a requested range followed by comma-separated requesters. A single source
already shown by `Found in` uses a plain `Requested by:` heading; multiple sources
keep explicit source paths on their request sections. Further requests
name each target once as a heading above its range rows. Recorded lockfile ranges
from the section source use the bare range; manifest declarations, other paths,
unknown bases and missing requirements retain their explicit context. Every
request item is preserved, including identical repeats. Multiple selected copies
use `Copy nX` headings; other repeated coordinates retain source-local copy
labels. Exact coordinate/path selection, carried internally by the pure audit
layer, identifies immediate targets; the renderer never infers identity from a
formatted package label. Independent request-owner facts remain visible unless
name and version exactly equal the requester occurrence.

Parenthesized qualifiers distinguish otherwise identical visible evidence variants. Further
requests are ordered by shortest recorded distance from the selected copies,
then the target's first relation and the group's first relation/request. This is
finite ordering over the recorded graph, not root-to-leaf path expansion or
native activation. Cycle notes precede guidance. Non-ancestry observations remain
separate after further requests, retaining unknown endpoints and request owners.
Each selected copy without immediate requests is named explicitly before fixes,
even when other copies have requesters. Absence refers to recorded ancestry;
non-ancestry observations may still contain request evidence. Unavailable detail
stays explicit too.

Requester lists wrap between complete items at a soft 100 Unicode scalar values
of escaped text, with continuation indentation two spaces beyond the range row.
A long prefix or item stays intact; no evidence is truncated.
Whole-audit evidence gaps become one reported-count sentence pointing to replay
without `--explain`; the count is the number of `audit_issues` entries, not
rendered lines. It does not imply those gaps
are unrelated. Explanation JSON and full replay retain every gap. Shared fix
search limits explicitly apply to the whole audit. These layout rules do not
change ordinary reports, archive/JSON schemas, flags or exit status.

The archive is a JSON object with `format: githits-scan-analysis`, archive
`schema_version: 1`, `writer_version`, `producer_report` and `selected_manifests`.
The producer report is the consumed typed v2 projection with its generation
timestamp, finding/coverage facts and retained mitigation/trace detail. It is a
subset, not the original service JSON. Producer schema, archive schema and writing
Scan versions are distinct. Optional keys preserve absence; required nullable
facts remain null. V2 without remediation is saveable; v1/future producer schemas
are not saveable in this format. Ordinary live interpretation is unchanged.

Loading and encoding are capped at 16,777,216 bytes; reads stop at cap+1. Archive
overhead can make a near-cap service result unsaveable, which returns an error
rather than truncating. Malformed/oversized archives, including malformed inner
producer reports and missing selected files return usage exit 2; other open/read I/O errors return 3. Unknown
archive versions return 2 without a rescan. Archive schema 1 freezes its required
projection; later additions must be optional/unavailable when absent. An authored
schema-1 fixture protects compatibility. Across Scan releases, presentation and
interpretation can evolve; the source evidence is not refreshed.

Only consumed fields are saved. Unknown properties, native IDs, endpoint subject
strings and opaque relation/request contexts are ignored. Missing-target requests
retain only typed condition fields used by the command view. Existing blocker
`context` remains an opaque open JSON object for established compact replay
parity; its nested keys are not filtered or printed as human context. Credentials,
API/job URLs, uploaded contents and local absolute scan roots are not added.
Source paths inside the document are display-only and never opened or executed.
The explicit artifact can still contain sensitive package names and relative
project paths.

When trace status is retained, a selected finding/path seeds every matching
coordinate/path occurrence, independently of whether a recommendation exists.
The reverse closure follows only relations with `disposition: standard_dependency`
within one source. Distinct copies retain identity. Known incoming observations
and `kind: feature_activation` observations originating in that closure are shown
separately, with their endpoints retained but marked outside ancestry when
appropriate. Shared nodes and cycles are represented once rather than expanding
all possible paths. Explanation IDs are consumer-local labels; internal archive
refs address retained occurrence arrays and are never user selectors.

Null endpoints, invalid refs/source associations, incomplete/unknown coverage and
unfamiliar statuses stay explicit. A retained trace with no matching occurrence
is distinct from an absent/not-retained trace. Omitted detail cannot be recovered
from the archive. Native feature/platform conditions inside opaque context are
not expanded or inferred as activation, and original parent requests do not
constrain a proposed replacement parent. Existing findings, checks and omission
limits remain authoritative; the client does not perform new upgrade reasoning.

## Mitigation recommendations

Optional v2 `remediation` is consumed as proposals about the existing findings,
not a change to installed dependencies. The service owns release/advisory/request
checks and joint action reasoning; Scan never matches ranges or solves a graph.
One record's changes stay together. JSON and archives preserve producer order.
Human output groups records by exact subject coordinate in first-appearance order,
keeping the original relative order of alternatives within each group. Records
remain independent without inferred exclusivity or compatibility. Conflict
and coordination warnings remain attached to their records and exact targets.

Human output inserts a problem-then-guidance section between vulnerabilities and
maintenance findings. Each exact vulnerable component's problem appears once,
with advisory IDs and aliases, supplied severity/summary and source files,
followed by all of its independent alternatives numbered within the group.
The subject appears before related components within its problem block.
Joint findings refer to other components explicitly; a component without its
own subject group is described before the first alternative involving it. Advisory context comes directly from the exact referenced
finding during view projection, with render-only fields skipped by JSON; there is
no second package-name join. One view helper formats human severity for v1, v2 and
recommendation context. Covered vulnerabilities appear in these cards rather than also in the earlier
inventory. Membership uses validated original finding
indices, not coordinate matching; uncovered findings and reports without usable
remediation keep the original vulnerability section. Supplied advisory fix hints
stay attached to their advisory in the card. JSON retains the complete
vulnerability inventory and advisory hints.

The guidance names exact from/target versions, requesting blockers and material
warnings. `Suggested fix` and imperative upgrade wording require observed target
availability, non-affecting advisory checks, matched requirements, an addressed
vulnerability and recognized planning/check evidence. Both use one predicate that
also requires every change to be a recognized upgrade. Weaker facts, missing
addressed evidence, overrides and future strategies retain neutral
candidate wording; partial candidate groups keep their partial qualifier. Joint action sets stay together; partial results distinguish addressed
and remaining findings. The complete proposed case avoids repeating advisory IDs only when the record's
own findings equal the displayed finding context (coordinate, advisory and full
file set). Subset and joint scopes keep explicit addressed/remaining references.
The shared guidance renderer derives file sets from that borrowed context and
from the record itself. Common change paths are omitted only when they equal
both file sets; otherwise change paths stay explicit. Ordinary audit and focused
explanation use this same comparison, so grouping never broadens a fix's scope. Blockers use
owner, supplied dependency name, requirement, path and readable reasons; role/kind/basis/recorded-status
bookkeeping stays in JSON. An override signals departure from a represented
requirement, not proof of a valid package-manager override or build. Unknown
outcomes, strategies and check values remain visible neutral candidate evidence.

Blockers may supply an optional `dependency_name`, the dependency identity requested
by the owner. Human output renders `express@5.1.0 requires cookie ^0.7.1` when
that name and range are supplied. With a name but no range, it keeps the name and
explicit requirement status, such as `express@5.1.0 requires cookie (requirement
not recorded)`. The name is escaped like other untrusted text. Older reports
without the field keep their existing human blocker structure. Scan never infers this
identity from the owner, recommendation target or opaque context. Compact JSON,
explanation JSON and saved analyses retain `dependency_name` when supplied and
omit it when absent. A supplied value must be a string; null and other types are
protocol errors, matching other optional non-null service facts.
The known `provider_requirement` status reads as “bound to a provider package”;
the raw status stays in JSON. This readable label also applies to unnamed blockers.
The limitation `new_dependency_not_checked` is rendered as “a new dependency was
not checked”; JSON retains the code and the original coverage facts.

Routine unknown catalog freshness, unchecked native resolution, unknown release
withdrawal and unassessed parent search are JSON evidence, not a human checklist.
Trace retention and omitted graph/detail counts also remain in JSON. Human output
keeps omitted recommendation counts, actionable planning limits and warnings about
the target or requirements. Target-check warnings require an actual proposed
change; a scoped no-upgrade result does not print checks for an absent target.
It adds no generic follow-up instructions.
`withdrawal` describes release yanking/retraction, not advisory
withdrawal. The service excludes withdrawn advisories and known withdrawn release
targets before mitigation planning; Scan does not reclassify advisory eligibility.

Scan JSON schema 1 adds optional `remediation`: status, recommendations,
trace_status and the useful omission limits/reasons. Records retain subject,
outcome, changes, blockers, every independent check, resolved findings,
addressed_findings, remaining_findings, limitations, detail_status and an optional
search_domain. Finding references become package/advisory/files; no report-local
indices, trace inventories, declaration refs or search counters are exported.
Selected change/check/blocker DTOs serialize the exact same facts for the command;
their explicit field lists exclude ignored producer data. This avoids parallel
definitions of identical facts while keeping the whole wire report private.

Blocker context is structurally retained as the contract's open JSON object,
including future keys; key order/whitespace are not preserved. Human output uses
the blocker's named owner, optional dependency name, requirement, path and reason fields rather than dumping
this object. Neither context nor returned paths are opened or executed.
Optional change flags preserve absence separately from false.

Consumed structures/types are strict, with open string vocabularies. A malformed
consumed type is a protocol error (exit 3) and leaves an existing output file
unchanged. Pure interpretation checks only consumed finding-index bounds and the
required search-domain prerequisite for a negative; it does not impose a disjoint
or exhaustive partition on the producer's finding lists. A contradiction suppresses
the whole optional action section and adds one report-unverified issue, setting
incomplete true and exit 1 while preserving original findings. JSON remediation
is omitted and the issue alone explains why; no unavailable-planning note prints.

Producer absence means planning was not assessed/retained; JSON omits remediation
and vulnerable human reports say so once. Finding-free old reports gain no banner.
Optional planning failure/limits alone do not change base completeness or exits.
Proposed actions never clear original findings. A no-upgrade-path conclusion is
restricted to its supplied represented-request and observed-release domain;
unfamiliar scope values produce no negative human conclusion. Missing/omitted
recommendations are never evidence that no mitigation exists. Native resolution,
build success, API compatibility and runtime applicability remain unproved.

Ordinary compact presentation uses trace status and omission facts without a graph
dump. Saved analysis retains the consumed graph for the separate offline
inspection described above; replay and inspection make no API call.

## Wire and interpretation boundaries

`api::AuditApi` is injectable independently of `SbomApi`. `HttpSbomApi` implements
both using one internal operation selector and one submit/events/result path.
Audit requests `kind=audit&format=json` in the query, leaving multipart files and
canonical upload-size estimation unchanged. Result media is `application/json`.
One accepted job is never resubmitted for an events/result failure. Current full
snapshots replace progress even when revisions are equal; reconnect starts with
latest state, not replay history. Known terminal states close consumption.

`assessing` displays measured assessment counters; zero is distinct from unavailable.
Unfamiliar phases display a generic stage, and unfamiliar failure codes use a static
safe diagnostic. Unfamiliar job states stop with a protocol error because their
terminal semantics are unknown. Each read has the established timeout; there is no
global reconnect count, new polling fallback or result retry.

`api::audit::Report` decodes disjoint v1/v2 payloads using a crate-private body
enum. Required consumed fields and nullable slots are checked; objects cannot be
positional arrays. Additional fields and response strings remain open. Versions 3+
are identified without retaining their payload and produce unsupported/incomplete
exit 1. Invalid/zero versions and malformed known reports are execution errors. V1
remains supported for existing API origins and production rollout compatibility;
retiring it requires a separate explicit compatibility decision.

For v1, pure interpretation checks occurrence/reference attribution and coverage
accounting and recomputes summary counts and duplicate-version groups from eligible
occurrences. The candidate/outcome partitions must account for eligible coordinates;
exclusions, sources and resolutions must reconcile. Manifest/structural owners are
valid but manifest source rows are not mandatory. Unknown resolutions remain gaps.

V2 has no input or occurrence inventory. Scan checks the three coverage partitions
against `summary.dependencies`, recomputes finding/group/gap counts from available
rows, and verifies distinct duplicate versions/groups and origin path coherence.
Each version path must have a recorded parent or explicit absence; unattributed
requirements intentionally select no target and may name a separate manifest path.
Input path order is normalized; repeated/empty path evidence is unverified.
Qualified advisory rows (`affected` or `non_affecting`) do not have to equal
`unknown_count`; all qualified rows remain visible gaps. Unsupported and
not-collected partitions are legitimate incomplete outcomes, not accounting errors.

V2 cannot independently prove that an unreported coordinate or duplicate group is
absent: it deliberately contains no inventory to reconstruct. Reported coordinates
provide only a lower bound. Coverage and findings reflect producer-owned assessment,
not globally fresh advisory truth or observed installations. Scan never fabricates
v1 entries to recover stronger-looking checks, assesses advisories or solves constraints.
Findings and gaps may coexist for one coordinate.

Semantic discrepancies are rendered as a **report unverified** issue, return 1 and
retain the findings with a focused consistency issue. Structural decoding alone
cannot establish a clean scan. Parser completeness is open source applicability, not
a universal `complete` token: package inventory and relationship detail are
different facts. Scan consumes backend source coverage instead of duplicating
parser-family rules. Human headlines lead with findings or neutral `Audit results`
for gap-only reports. Excluded packages appear once under **Packages not checked**,
with their reason and files, separately from **Incomplete checks**. A non-registry
source is ineligible for registry matching, not a failed package lookup. The wire
reason does not distinguish local workspace packages from every other non-registry
source, so Scan does not label them all local. Exclusions still set JSON
`incomplete` and exit 1; this display change does not silently weaken the
coverage/exit policy.

Pure assessment owns incomplete coverage separately from findings; the presentation
view consumes that decision for both formats. Proven first-party projects are
backend-owned project evidence; Scan adds no generic LOCAL/path/Git exemption and
still treats actual excluded groups as gaps. Standard producer caveats live in
help/documentation, not a repetitive footer. Producer notice inventories are not
forwarded; actionable gaps come from the structured assessment and resolution
fields.

Duplicate version rows name their files and, for v2, requesting origins with
literal recorded version/tag requirements. JSON adds compact `origins` rows under
each version (`file`, optional requester/requirement/attribution basis, open
status). Requesters are names with a version suffix only when recorded. Missing parent, not-recorded,
withheld and ambiguous requirements retain their explicit status; unfamiliar
statuses remain visible. Human output recognizes `parent_release_declared` as
published parent-package metadata. Its requesting package and range are useful;
the source alone is normal enrichment, so no generic provenance banner is printed.
Specific missing or uncertain information remains visible. The internal token is
retained in JSON and omitted from each human row.
Metadata supplements requirements absent from uploaded evidence; this does not
prove activation or historical selection. `parent_release_compatible` renders as
`possible requester: requests@2.32.3 (requires <4,>=2)`: the published requirement
fits this source-local version, but no incoming edge is observed. Several versions
may match, and explicit `parent_not_recorded` evidence remains beside possibilities.
`recorded` and exact-edge `parent_release_declared` keep ordinary requester wording.

Compact JSON origins retain the producer's optional open `attribution_basis`.
Known values are `lockfile_recorded` (native target), `manifest_lock_agreement`
(current uploaded declaration agreement), and `published_requirement_compatibility`
(a static published-version possibility). These values may appear on observed as
well as possible origins; they do not promise historical solver choices. Missing
or null basis is omitted, and unfamiliar basis text is retained. This useful field
is additive in Scan schema 1; declaration-context inventories remain excluded.

A file shared by every version, origin and unattributed requirement is named once
on the group; mixed and inconsistent paths retain precise per-version/request
attribution. Repeated identical useful origins are deduplicated.

Group-level `unattributed_requirements` retain requester, file, optional requirement,
requirement status and target status. They select no version and are never joined
by name. Human output labels these 'Declarations without a recorded dependency
link'; it does not repeat an untargeted status on every row. Explicit absence and
unfamiliar target states remain separately labelled. The coverage reason for an
untargeted request uses 'dependency requirement without a recorded link' in both
representations. No candidate is filtered or assigned locally. New producer
reports omit release-only unlinked declarations; retained older reports may still
include them. Uploaded/native gaps remain visible in either case. V1 still emits its no-origin limitation
once; v2 drops that obsolete line.
Multiple versions and overlapping ranges do not establish conflicts, satisfaction
or reachability. Native missing-input diagnostics and automatic Cargo/npm member
evidence follow the [workspace evidence boundary](#workspace-evidence-boundary).

Source fixed-version proposals and verified remedies are labelled separately.
Verified remedies describe selected advisory evidence for one exact coordinate;
neither field guarantees global safety/freshness, installed-build coverage or
compatibility with caller constraints. Latest versions are metadata evidence.

## Validation and limits

Deterministic trait, pure, loopback and real-binary tests use authored synthetic
fixtures plus the public OpenAPI example. They verify each finding category, clean
and gap-only outcomes, semantic discrepancies, v1/v2/future versions, compact JSON
allow-listing, duplicate origins and unattributed requirements, streams/files,
progress/reconnect/terminal behavior, failures and result limits. Existing
SBOM/license regression cases protect shared preparation and transport.

Live checks require an environment-matched `GITHITS_API_TOKEN`. Scan never
acquires credentials itself. A test launcher may capture
`npx -y githits@latest auth token` privately and provide its stdout only through
the Scan child process environment; no token goes in arguments, logs or files.
The token must come from the CLI login environment that matches the origin in
`GITHITS_API_URL` (production by default); the CLI's `GITHITS_ENV` selects its login
namespace and does not configure Scan's origin. Disable shell tracing and fail
closed on unsuccessful/empty token acquisition. See [README authentication](../../README.md#authentication-and-environment)
for shell examples. The ignored audit live test fails if selected without a token.
Loopback tests verify consumer interpretation, not deployed service behavior.
Live qualification must be scoped to the exact inputs and claims being checked;
a small fixture does not establish large-workspace capacity or complete coverage
for an ecosystem. See [audit qualification](audit-qualification.md).

Limits stay in the API boundary: 256 files, 5,242,880 bytes per file,
8,000,000 encoded upload bytes, 1,024-byte paths and 16,777,216 result bytes.
Upload selection/read/normalization and authenticated transport remain single paths;
no cache, queue, lock, execution mode or dependency is added.

## Actionable input gaps and file lists

V2 resolution diagnostics may supply `required_path`, a safe request-relative
required manifest path. The API decoder accepts an optional string and rejects
wrong types. Compact issues retain sorted unique `required_files` only when
present. Neither interpretation nor rendering opens those paths or resubmits a
job. Missing/null fields remain absent; unknown reasons stay visible.

A file-level (name-null) resolution diagnostic whose exact reason already appears
in that path's source gap joins the same source issue, retaining the source's full
reason set and every required path. Package-specific and unmatched diagnostics
stay separate. This removes repeated descriptions without weakening completeness
assessment or discarding mixed source gaps. Known input/requirement/capability
reasons get plain wording; no unknown package or installed-state inference is made.

Both output formats describe incomplete dependency groups, unsupported manifest/lock
comparisons, unavailable advisory affected-version ranges, unavailable dependency
lists and unresolved dependencies in plain language. Missing advisory ranges keep
their package, advisory and source-file context. Equivalent unresolved-dependency
reasons appear once; unknown future reasons remain visible. These translations
do not change summary counts, coverage assessment or exit status.

Unresolved activation is described as dependency activation that could not be
determined; incomplete dependency lists stay explicit. A version the service
cannot evaluate is not labelled an invalid lockfile: branch versions can be
valid package-manager input while remaining outside an assessment's support.

The supported-input remedy is to check discovery/ignore/exclude rules and list
available manifests in `[lockfiles].manifests` in `githits-scan.toml`. Human output
prints this shared remedy once per issue section. Per-path selection-state explanations require actual selection evidence; Cargo
member selection follows the shared upload boundary described below.
If a producer omits the optional required path, Scan keeps the generic incomplete
reason and never fabricates a filename.

Human manifest, manifest-resolution and required-file lists stay inline when the
whole escaped line, including label and indentation, has at most 100 characters.
Longer lists show a count and each full path on its own line. JSON retains all
paths. `UNUSABLE_MANIFEST` advises `--exclude <glob>` for unrelated projects or
fixing relevant inputs; paired manifests follow selection of their lockfile.
See [qualification procedures](audit-qualification.md) for the evidence needed
before claiming ecosystem or runtime support.


`unmet_dependency` identifies a missing non-optional native target;
`unresolved_dependency` identifies incomplete requirement resolution. Both use
neutral unresolved-dependency wording, and equivalent visible text is combined
without changing the underlying coverage facts.

## Workspace evidence boundary

The service owns native membership, activation, lock ownership and applicability
proof. Scan's selection layer owns bounded discovery and explicit configuration;
it must not infer membership from a package name, `publish = false`, or missing
registry source. An unproved Git/path dependency remains an explicit gap. Shared
workspace locks must not be replaced by fictional member-local locks.

Automatic Cargo evidence follows [discovery's member selection contract](discovery.md#cargo-member-evidence).
Supported npm evidence follows [its bounded declaration contract](discovery.md#npm-member-evidence).
Other native families still require a qualified admission contract that associates
members with their owning locks without independently resolving unrelated projects.
Missing-input diagnostics name only producer-supplied paths; ignored/missing/excluded
causality requires actual selection-state evidence. Explicit `[lockfiles].manifests`
remains available for additional intended inputs.

### Native input diagnostics

Optional `unknowns.resolution` request fields retain the missing target (`name`),
`requester` name/version, `requested_requirement`, `requirement_status`, native
`kind` and `requester_scope`. Only `unmet_dependency` proves a missing required
native target; absence is not inferred from a peer/optional kind. Requirement
status is `recorded`, `not_recorded` or `withheld`; unknown future values stay
neutral. No range is inferred when unavailable. A requester-bearing unmet row
attaches to a source gap on the same raw path and matching raw reason, preserving
distinct requester/range/condition rows without repeating the file-level issue.

The command view and archive consume only known native condition fields:
`marker`, `requires_python`, `marker_unavailable`, `requested_extras`,
`dependency_group`, `bundler_source_pinned`, `bun_bundled`, and
`paket_restriction` (`syntax`, `expression`). Coverage/target-status telemetry and
unknown context keys are not persisted. Conditions remain facts, not proof that
a dependency is active on the current machine.

### Declaration and lock disagreements

Optional `findings.manifest_lock_mismatches` retain source `path`,
`declaration_path`, dependency `name`, declared requirement/status, locked versions,
recorded requirements, declared/recorded scopes and reason. The reasons
`locked_version_does_not_satisfy_request`, `recorded_requirement_differs` and
`recorded_dependency_scope_differs` are distinct; unknown reasons stay explicit.
The renderer supplies purpose-specific reconciliation guidance, not a local range
comparison or an unconditional upgrade instruction. Opaque producer remediation
text is not consumed.

These findings alone produce attention exit 1, consistent with other findings.
The optional `summary.manifest_lock_mismatches` count is checked against the list;
a disagreement marks the report unverified/incomplete, not a decoding failure.
Empty attribution paths or a recorded null/empty requirement also mark consumed
new rows unverified. Older reports/archives omitting all additions remain valid.
JSON additions preserve the command and archive schema versions. Replay retains
the findings; vulnerability explanation still selects a component from the full
analysis without hiding its overall outcome.

Scan does not yet request native dependency groups. Group defaults and reconciled
coverage remain separate product work; there is no universal production group.

## Extension boundaries

New output formats and CI integrations must consume the same curated result,
escape untrusted text, preserve gaps and exit semantics, and avoid invented file
line numbers. An HTML report should work without a server or remote assets.
The attention gate covers all unignored findings and gaps. Advisory ignores
have exact-ID, repository-wide scope with mandatory reasons and no expiry;
aliases and package/path constraints are not selectors. Any future category or
severity policy must define missing severity, malicious evidence and incomplete
checks explicitly, and cannot erase unrelated gaps. Saved-report comparisons require stable finding identities,
source scope and coverage comparison: absence from incomplete evidence cannot
prove resolution or attribute a change to a pull request. Migration explanations
need qualified release/source evidence and a bounded cost model; an advisory fix
version alone does not prove API compatibility.

Scan's useful distinction is joint security and maintenance guidance with
inspectable evidence limits. No comparative accuracy, coverage or speed claim is
established by the presence of license checks, offline replay or remediation.

## Public schema publication

Publishing optional remediation and related response types is a service-owned
follow-up, deferred until the schema stabilizes. Scan consumes the
qualified additive projection; this does not establish that generated clients can
discover it. Before a contract-dependent increment, verify public admission and
response schemas against the behavior it needs. User-facing schema publication
is not replaced by speculative client defaults.

An unmatched saved-analysis `--explain` selector reports up to five unique
vulnerable coordinates from that report, ranking exact names and substrings
before spelling distance with deterministic coordinate ties. Suggestions never
select a component automatically; matching still requires the exact coordinate.
