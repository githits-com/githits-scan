# Audit consumer

`githits-scan audit [PATH]` submits the selected files as one combined asynchronous
analysis, explicitly requesting native report version 3. There is no report-version
flag. The backend owns parsing, advisory applicability and metadata assessment;
Scan owns evidence interpretation, output and exit policy. It does not infer
reachability from manifest associations or execute one job per file pair.

## Command contract

The inventory/configuration/exclusion rules match `sbom generate`, including
manifest-only resolution by default. `--lockfiles-only` skips it. Reports name the
unique manifest paths selected for upload in `manifests` (`Manifests:` in human
output). Deliberately omitted files are not listed: results describe the selected
scope, not every file discovered in the repository.

Human output omits empty finding totals and uses plain package-warning and fix-guidance
headings. Default human output shows vulnerability problems, qualified fix alternatives,
manifest/lock disagreements, native lifecycle warnings and genuine evidence gaps.
Each lifecycle event has a compact package/native-kind/scope line and its distinct
publisher reasons. `--details` expands every source observation, source version,
metadata observation time, replacement advice and affected coordinate/file list;
it also expands outdated/duplicate lists and collection limits. JSON always keeps
those facts. `--quiet` changes progress/messages, not result visibility.

Human and JSON output use one command-owned view. JSON separates native
events and retained registry warnings from advisory counts. The human overview
shows nonempty finding categories and combines native events and retained registry
warnings as package warnings; the detailed rows preserve their distinct meaning.
The `lifecycle` subtree
retains findings, distinct attributed observations, retained warnings, four
coverage facets, unknown outcomes and content-safety disclosure. It has no coarse
`deprecated` list or occurrence/manifest-resolution inventory. The upload plan
remains the canonical manifest-name source. Paths locate selected evidence and
never establish package reachability.

Audit and saved-explanation JSON use Scan schema 2. Empty optional common groups
are omitted; `summary` and native lifecycle evidence are present. `incomplete`
means factual coverage gaps or inconsistent consumed evidence, independently of
positive findings. Only producer schema 3 is supported. Returned older/newer
versions fail with exit 3, request ID and an explanation before writing output;
Scan never converts them or resubmits the completed job. Unknown additive fields
are ignored; native vocabulary remains open and retains unfamiliar values in JSON.

Vulnerability JSON has the `severity` display string and independently optional
numeric `severity_score` and source `severity_type`. Missing values are omitted
rather than inferred. Advisory/remediation identities and exact-ID ignores keep
their meaning; lifecycle events never become vulnerability counts or verified
upgrade advice.

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
| 0 | No unignored finding or actionable gap; expected Git limits and lifecycle collection limits can remain |
| 1 | Any unignored vulnerability, native lifecycle event, retained registry warning, outdated version, duplicate group, manifest/lock disagreement, actionable evidence gap or unverified accounting; also preflight drift/empty selection |
| 2 | Usage/configuration/credentials/access/upload-limit or caller-action API error; missing/invalid saved input or explanation selector |
| 3 | Transport, rate limit, service/problem execution, malformed/unsupported returned report or output error |

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
and no actionable evidence gaps remain, exit is 0 and the headline is
`No unignored audit findings in available evidence`. The human summary retains
the total and ignored count. Ignored advisories with actionable incomplete evidence still
produce `Audit results` and exit 1; other findings produce `Audit findings` and
exit 1. Ignores never suppress coverage or accounting errors.

There is no category-specific `--fail-on` or configuration equivalent. Audit is
an attention gate across vulnerabilities, maintenance, input disagreements and
evidence gaps. Consumers requiring a different gate can compute it from full
JSON, including `actionable_incomplete`, `issues[].actionable` and ignored annotations; handle exits 2/3
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
When the current archive omits policy, no advisory ignores apply. Old archive
formats are rejected rather than migrated or reinterpreted.

`--explain REGISTRY:NAME@VERSION` requires offline mode and exactly matches a
vulnerability coordinate. Human output shows the problem, its immediate recorded
requesters, then whole fix alternatives using the same guidance/check renderer as
the compact report. Further recorded requests follow the fixes. Joint changes are
not split and alternatives are not combined. An
unmatched selector is usage exit 2. Inspection preserves the entire saved audit's
0/1 outcome, including unrelated findings/gaps. Explanation JSON has its own
`schema_version: 2`, `kind: audit_explanation`, provenance, selected problems,
source-grouped nodes/relations, remediation, explicit detail/audit issues and
`audit_lifecycle` for the whole saved audit. Native warnings remain visible in
human explanations without changing advisory reference or requester algorithms.

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
`schema_version: 2`, `writer_version`, `producer_report` and `selected_manifests`.
Its producer report is the consumed typed native schema-3 data, including native
observations/coverage, generation timestamp and optional mitigation/trace detail.
It is not the original service JSON. Producer, archive and writing Scan versions
are independent. Required nullable facts stay null; optional fields stay absent.
Native reports without remediation remain saveable.

Reads and bounded encoding are capped at 16,777,216 bytes. Archive overhead can
make a near-cap service result unsaveable; the encoder errors rather than
truncating. Malformed/oversized archives or unsupported archive/producer versions
return usage exit 2, with no network request or conversion. Other open/read I/O
errors return 3. Use the recorded older writer to inspect an old analysis offline;
a new audit is a separate intentional paid operation, never an automatic fallback.
Across supported Scan releases, interpretation may evolve but stored evidence is
not refreshed.

Only consumed fields are saved, except opaque evidence for unknown change-reason
codes retained for forward replay (see checked reasons below). Other unknown
properties, native IDs, endpoint subject
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

## Fix guidance

Optional native `remediation` is consumed as proposals about the existing findings,
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
no second package-name join. One view helper formats human severity for ordinary reports and
recommendation context. Covered vulnerabilities appear in these cards rather than also in the earlier
inventory. Membership uses validated original finding
indices, not coordinate matching; uncovered findings and reports without usable
remediation keep the original vulnerability section. Supplied advisory fix hints
stay attached to their advisory in the card as `advisory-reported fix versions`;
this is advisory evidence, distinct from an applicable recommendation. JSON retains the complete
vulnerability inventory and advisory hints.

The guidance names exact from/target versions, requesting blockers and material
warnings. `Suggested fix` and imperative upgrade wording require observed target
availability, non-affecting advisory checks, matched requirements, an addressed
vulnerability and recognized planning/check evidence. Both use one predicate that
also requires every change to be a recognized upgrade. Weaker facts, missing
addressed evidence, overrides and future strategies retain neutral
candidate wording; partial candidate groups keep their partial qualifier. Joint action sets stay together; partial results distinguish addressed
and remaining findings. A supported complete proposed fix avoids repeating advisory IDs only when the
record's own findings equal the displayed finding context (coordinate, advisory
and full file set). Weak candidates, including overrides, retain their supplied
`would address` findings even when those cover the full displayed set. Human
`still unresolved` lines keep remaining advisory/package identities visible, including scoped
no-upgrade results with no candidate. A package/advisory present in both impact
lists gets an item-level `(partly)` suffix in both; other advisories are unmarked.
This describes the supplied overlap without inventing copy counts. A partial
record with no addressed references says `would address: none reported`. Subset and joint scopes keep explicit addressed/remaining references.
The shared guidance renderer derives file sets from that borrowed context and
from the record itself. Common change paths are omitted only when they equal
both file sets; otherwise change paths stay explicit. Ordinary audit and focused
explanation use this same comparison, so grouping never broadens a fix's scope. Blockers use
owner, supplied dependency name, requirement, path and readable reasons; role/kind/basis/recorded-status
bookkeeping stays in JSON. Exclusion reasons use `requirement conflict` without
a redundant exclusion suffix; other and unknown reasons use neutral `constraint`
plus the supplied readable/escaped reason. This does not turn an unevaluated
selector or a deliberate override into a blocked verdict. An override signals
departure from a represented requirement, not proof of a valid package-manager
override or build. Unknown
outcomes, strategies and check values remain visible neutral candidate evidence.

Blockers may supply an optional `dependency_name`, the dependency identity requested
by the owner. Human output renders `express@5.1.0 requires cookie ^0.7.1` when
that name and range are supplied. With a name but no range, it keeps the name and
explicit requirement status, such as `express@5.1.0 requires cookie (requirement
not recorded)`. The name is escaped like other untrusted text. When the optional field is absent,
human blockers show the owner and supplied requirement without an inferred dependency name. Scan never infers this
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
An explicit override candidate is the exception: when native resolution is the
supplied `not_checked` state, one `override not verified` note states that
package-manager support and build were not checked. Unknown future check values
retain their own neutral display and do not trigger that assertion.
Trace retention and omitted graph/detail counts also remain in JSON. Human output
keeps omitted recommendation counts, actionable planning limits and warnings about
the target or requirements. Target-check warnings require an actual proposed
change; a scoped no-upgrade result does not print checks for an absent target.
It adds no generic follow-up instructions.
A scoped negative is separated from source metadata by a blank line and reads
`No upgrade path found among releases known to the service, under the dependency requirements considered.` The
search scope stays explicit; it does not establish that no fix exists.

Joint actions can show `recorded request for TARGET: REQUIREMENT; owner OWNER
[request path]` immediately after changes and their file locations, unless the
checked reasons described below supersede this context. The pure audit trace
selector owns this context and reuses explanation source/reference
validation. Both trace and recommendation detail must be retained; both relation
endpoints must be exact occurrence references of changes whose typed coordinates
match their from versions. Only standard dependency relations with a recorded,
non-null request are selected. The explicitly supplied request owner remains
separate from graph endpoints, since they can differ. Identical display facts
deduplicate in producer order; distinct request paths retain separate lines.
Missing/unknown detail or unverifiable identity supplies no optional context;
normal findings and actions keep their existing behavior. This is neither a
package-name join nor range evaluation, target inference, or a causal explanation
for a selected parent upgrade. The same context appears in ordinary and focused
saved explanations; it does not add JSON or saved-report fields. Availability of the optional context depends on supplied retained evidence.

### Checked reasons beside changes

Optional `changes[].reasons` carries service-owned checked effects. Human output
attaches each effect directly to its change: acceptance of a dependency target
that the current requested range excludes, removal of a represented route, or
addressed advisories. These are not proofs of unique necessity, global range widening,
removal of every installed copy, or native resolver/build success. Strategy,
blockers, advisory coverage and verification checks retain their own meanings.

Ordinary output shows a concise `why` line. A single-change advisory explanation
is omitted when its finding identities equal the record's addressed findings,
which are already explained by the problem and impact lines. Joint changes keep
per-change attribution. The displayed source path is omitted only when the same
single path belongs to that change and is already displayed by `Found in`,
`Change in` or its `files` line. Identical reason text
within a change is shown once; distinct paths remain separate.

`--explain` also shows original and replacement requests, keeping their explicit
owners, authored dependency names or capabilities, requirements, statuses and
source paths. Request owners need not equal changed packages or graph endpoints.
Empty original-request lists on route removal add no fabricated request. A
reason's canonical dependency target never replaces an authored alias.

Absent reasons retain earlier output. `unavailable` and unfamiliar codes add no
ordinary explanation; inspection says `reason unavailable` or identifies an
escaped unrecognized code. Trace omission does not erase the service's inline
boundary evidence: it still describes a represented route at its source, never
all matching copies. Existing record-wide request context is suppressed only
when every change has a substantive known reason and at least one reason describes
a checked dependency boundary (target acceptance or route removal). Advisory-only,
mixed or unavailable reason coverage keeps that factual context without attempting
identity joins: advisory effects do not explain requests between changed packages.

The API decodes consumed known reason fields strictly and ignores unused known
occurrence references, declaration references and request context. Existing
type-only array handling remains: empty arrays are tolerated, although current
producer schemas require some arrays to be nonempty. An invalid consumed advisory
finding reference follows the existing unverified-remediation rule. Compact and
explanation JSON resolve finding references to package/advisory/files identities
and expose no raw reason indices; see [JSON contracts](json-output.md).

Saved analyses retain the consumed known subset. Unknown reason codes are the
explicit open-evidence exception: their opaque evidence is retained in the saved
wire projection so a future reader can recognize it. That evidence is neither
interpreted nor emitted in compact/explanation JSON or human output. Unknown
fields on known reasons remain ignored. The optional reasons field may be absent.

The service's `change_reason_deadline` and `change_reason_membership_limit` limits
read as time or requirement-check limits reached while checking change reasons.
Some explanations can be unavailable while selected recommendations and their
independent checks remain intact; Scan does not turn a proof limit into a failed
recommendation or a new exit condition.

`withdrawal` describes release yanking/retraction, not advisory
withdrawal. The service excludes withdrawn advisories and known withdrawn release
targets before mitigation planning; Scan does not reclassify advisory eligibility.

Scan JSON schema 2 includes optional `remediation`: status, recommendations,
trace_status and the useful omission limits/reasons. Records retain subject,
outcome, changes, blockers, every independent check, resolved findings,
addressed_findings, remaining_findings, limitations, detail_status and an optional
search_domain. Finding references become package/advisory/files; no report-local
indices, trace inventories, declaration refs or search counters are exported.
Selected change/check/blocker projections retain their typed facts for the command;
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
and vulnerable human reports say so once. Finding-free reports gain no banner.
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
Audit requests `kind=audit&format=json&report_version=3` in the query, leaving multipart files and
canonical upload-size estimation unchanged. Result media is `application/json`.
One accepted job is never resubmitted for an events/result failure. Current full
snapshots replace progress even when revisions are equal; reconnect starts with
latest state, not replay history. Known terminal states close consumption.

`assessing` displays measured assessment counters; zero is distinct from unavailable.
Unfamiliar phases display a generic stage, and unfamiliar failure codes use a static
safe diagnostic. Unfamiliar job states stop with a protocol error because their
terminal semantics are unknown. Each read has the established timeout; there is no
global reconnect count or new polling fallback. Explicit HTTP 429 refusals at any
request share the [bounded rate-limit policy](sbom-api-contract.md#rate-limit-recovery).

`api::audit::Report` decodes only native producer schema 3. Required consumed
fields and required-nullable slots are checked; objects cannot be positional
arrays. Unsupported versions are typed execution failures carrying the result
request ID. Older service results can occur during rollback; share the request ID
with support rather than submitting another analysis. A newer returned format may
need a newer Scan release for future audits. No opaque document is emitted as a
clean or partly understood audit.

Pure interpretation checks common advisory/outdated coverage, summary/group/gap
counts, duplicate origins and native lifecycle evidence. The compact report has
no full input/occurrence inventory to reconstruct: reported exact coordinates
provide only a lower bound on `summary.dependencies`. Unattributed requirements
select no target and can name a separate manifest path. Qualified advisory rows
can remain meaningful gaps even when they are not counted as unknown advisories.

Native event identity is registry/name/category/kind/scope/source/affected-version.
Each event retains all distinct source-version/time/reason/reason-code/replacement
observations and their exact affected coordinates with nonempty unique selected
paths. Known package scope has a null affected version; release/file scope has a
version. Source authority and accepted selected-version spellings can differ, so
Scan does not equate them or canonicalize package identities locally. A source
observation time is acquisition evidence, not a status-change time or freshness
promise. Replacement advice is labelled as the publisher's, never a verified fix.

Each of deprecation, withdrawal, registry archival and repository archival
partitions eligible candidates into checked, unknown, not-collected and NA.
Candidate totals, overflow-safe partitions, per-facet unknown rows, event and
retained-warning totals, reference coherence and the combined incomplete-check
count are reconciled. Incomplete checks sum advisory unknown/unsupported counts,
outdated metadata-gap rows and native unknown rows. No local registry capability
rules override those outcomes. A positive may coexist with an unknown, notably
partial PyPI file withdrawal; findings are not required to be checked negatives.

An ambiguous retained NuGet warning appears once with its supplied reason and
native uncertainty. Hex retirement, yanking, retraction, unlisting, package
abandonment/discontinuation and Go module deprecation keep their native meaning.
A package-wide finding is not relabelled a deprecated selected release. Native
counts do not alter advisory counts or the service's upgrade-selection authority.
Remediation's current `deprecated_target` flag remains producer-supplied evidence,
independent of the removed coarse audit list.

Lifecycle not-collected and NA outcomes are collection limits, not findings or
incomplete checks. JSON carries all four facets; `--details` shows supplied
counts/registries. Help/docs describe routine capability limits instead of
repeating archival/NA notices on every ordinary audit. Both archival facets are
currently not collected; Scan acquires no registry/repository status. PyPI
native deprecation NA does not assert a negative withdrawal check. Genuine unknown
and failed observations stay visible and incomplete. Outdated not-collected and
advisory unsupported outcomes retain their separate gap behavior. Only native
lifecycle facets define not-applicable coverage; outdated metadata has checked,
unknown and not-collected outcomes.

Empty findings and zero candidates
never establish health. Headlines describe available evidence, not universally
checked safety. Coverage reflects the service's accepted observations, not global
freshness or an observed installation. Scan neither assesses advisories nor
solves dependency constraints.

Semantic discrepancies are rendered as a **report unverified** issue, return 1 and
retain the findings with a focused consistency issue. Structural decoding alone
cannot establish a clean scan. Parser completeness is open source applicability, not
a universal `complete` token: package inventory and relationship detail are
different facts. Scan consumes backend source coverage instead of duplicating
parser-family rules. Human headlines lead with findings or neutral `Audit results`
for actionable-gap-only reports. Actionable exclusions appear once under **Packages not checked**,
with their reason and files, separately from **Incomplete checks**. A non-registry
source is ineligible for registry matching, not a failed package lookup. The wire
reason does not distinguish local workspace packages from every other non-registry
source, so Scan does not label them all local. Exclusions retain JSON `incomplete` as a factual qualification. Pure
assessment owns `actionable_incomplete` separately from findings, and the shared
view retains both decisions in human output, JSON and saved explanations.

Only the exact producer reasons `git_registry_checks_not_supported`,
`git_dependency_graph_unavailable` and `git_source_binding_unavailable` identify
expected Git limits. These appear as concise **Coverage notes**, including in
quiet reports, and do not independently cause attention or exit 1. Each compact
issue has `actionable: false` for these reasons. Explicit `non_registry_source`
rows in `unknowns.excluded_dependencies` are also informational; that same
reason in source, resolution, vulnerability or metadata gaps remains actionable.
Other causes have `actionable: true`. Mixed source
reason lists split into informational and actionable subsets before grouping;
resolution diagnostics cannot borrow the other class's message. Missing/empty or
unfamiliar causes, actual source contradictions (`recorded_git_source_differs`),
unsupported generic sources, missing files and lookup failures remain actionable.
All rows still participate in count and attribution validation; an inconsistent
report is actionable even when its named causes are expected limits.
Non-registry exclusions appear in **Coverage notes** with package/version and
files, without a manual-review instruction. They mean registry checks do not
apply, not that the package is local, safe, or fully assessed. The producer
reason does not establish license eligibility or license policy compliance.

`incomplete: true, actionable_incomplete: false` does not imply exit 0: independent
advisory, native lifecycle, maintenance or disagreement findings still cause exit
1. Expected-only limits with no independent findings exit 0 while retaining their
factual incomplete status. Unavailable Git bindings remain unknown; no Git source
is treated as a checked registry release or an empty dependency graph. Standard
producer caveats stay in help/docs; these result-specific coverage notes are always
visible. Producer notice inventories are not forwarded. Saved archive schema 2
retains the producer report unchanged and replay applies the same interpretation.


Duplicate version rows name their files and requesting origins with
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
is included in Scan schema 2; declaration-context inventories remain excluded.

A file shared by every version, origin and unattributed requirement is named once
on the group; mixed and inconsistent paths retain precise per-version/request
attribution. Repeated identical useful origins are deduplicated.

Group-level `unattributed_requirements` retain requester, file, optional requirement,
requirement status and target status. They select no version and are never joined
by name. Human output labels these 'Declarations without a recorded dependency
link'; it does not repeat an untargeted status on every row. Explicit absence and
unfamiliar target states remain separately labelled. The coverage reason for an
untargeted request uses 'dependency requirement without a recorded link' in both
representations. No candidate is filtered or assigned locally. The producer omits release-only unlinked declarations. Uploaded/native gaps remain visible. No requesting origin or requirement is inferred when the service did not record it.
Multiple versions and overlapping ranges do not establish conflicts, satisfaction
or reachability. Native missing-input diagnostics and automatic Cargo/npm/Bun member
evidence follow the [workspace evidence boundary](#workspace-evidence-boundary).

Source fixed-version proposals and verified remedies are labelled separately.
Verified remedies describe selected advisory evidence for one exact coordinate;
neither field guarantees global safety/freshness, installed-build coverage or
compatibility with caller constraints. Latest versions are metadata evidence.

## Validation and limits

Deterministic trait, pure, loopback and real-binary tests use authored synthetic
fixtures, including `tests/fixtures/audit/native-findings.json`. They verify each finding category, clean
and gap-only outcomes, semantic discrepancies, native and unsupported versions, compact JSON
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

Native resolution diagnostics may supply `required_path`, a safe request-relative
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

Human manifest and required-file lists stay inline when the
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
Supported npm/Bun evidence follows [its bounded declaration contract](discovery.md#javascript-workspace-member-evidence).
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
new rows unverified. These optional evidence fields may be absent in native v3 reports.
Audit/explanation JSON use schema 2; saved analysis uses format 2 with producer report 3. Replay retains
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

Native audit v3 and lifecycle response schemas are published in the public
OpenAPI. Remediation recommendation/blocker definitions remain partial stubs,
and some qualified mismatch/remediation extensions are not fully described there.
Do not infer generated-client discovery from an outer type's presence. Before a
contract-dependent change, verify the actual emitted fields and public schema at
their owning boundaries; keep this qualification distinct from runtime support.

An unmatched saved-analysis `--explain` selector reports up to five unique
vulnerable coordinates from that report, ranking exact names and substrings
before spelling distance with deterministic coordinate ties. Suggestions never
select a component automatically; matching still requires the exact coordinate.
