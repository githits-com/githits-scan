# Native lifecycle audit adoption

## Outcome and scope

Status: implementation in progress. One implementation PR makes ordinary Scan
audits request the qualified public native lifecycle report, interpret its native
findings and coverage, and preserve those facts in human/JSON output and offline
analysis. The next release has minor impact with an explicit breaking-change note.

Juha's decisions supersede the readiness backlog: no report-version flag, request
v3 by default, use the best native logic, and remove v1/v2 support completely.
There is no compatibility adapter, legacy deprecation projection, or old archive
reader. The existing attention rule applies to native events, retained warnings,
genuine unknown checks and other findings/gaps. Lifecycle facet collection limits
alone do not fail; outdated not-collected evidence retains its gap behavior.
No product decisions remain open.

This changes Scan only. Action, other lanes, backend/gateway code, archival
acquisition, quarantine, manual paid analyses, merge/release/deploy and new
dependencies/infrastructure are excluded. The draft PR and its normal CI are
authorized. Implementation is expected to remain one focused PR; stop and reduce
scope with Juha if verified implementation changes exceed roughly 1.5–2k lines
excluding tests/docs or require additional mechanisms.

## Verified contract and assumptions

The public OpenAPI at <https://api.githits.dev/v1/openapi.json> describes audit-only
query/multipart `report_version=3`, returned-version dispatch and native audit v3.
The gateway admits and forwards the control; its production schema matches the
supplied deployment/smoke evidence. Detailed qualification is in the temporary
[readiness receipt](../reports/2026-11-11-lifecycle-v3-readiness.md).

V3 replaces coarse deprecation summary/findings/coverage and deprecation metadata-gap rows
with `lifecycle { findings, retained_warnings, coverage, unknowns, content_safety }`.
Events group category/kind/scope/source/affected-version identity, then retain
distinct source-version/time/reason/reason-code/replacement observations with
exact affected coordinates and selected paths. Package events have a null affected
version; the authority version is never substituted for it. Responses and native
vocabulary are open. Both archive facets remain not-collected.

Lifecycle coverage partitions candidates into checked/unknown/not-collected/NA;
only unknown rows contribute lifecycle incomplete checks. Summary incomplete
checks also include advisory unknown/unsupported counts and outdated gaps.
Native and retained warning counts are independent of advisory counts. Outdated
metadata coverage has checked, unknown and not-collected outcomes only;
applicability belongs to native lifecycle facets.

The consistency checks are limited to the qualified public fields and verified
producer grouping; they do not independently classify a registry:

| Invariant | Contract/evidence and failure behavior |
| --- | --- |
| Four facet candidate counts equal eligible dependency count; checked + unknown + not-collected + NA equals candidates without overflow | `AuditLifecycleCoverageFacet` describes a complete partition over eligible exact coordinates; a mismatch is unverified/incomplete. |
| Known-facet unknown counts match distinct coordinate/check rows; registry lists are unique and nonempty exactly when their collection-limit count is nonzero | Public coverage/unknown descriptions and the qualified pure producer projection emit one row per selected coordinate/check and actual registry lists. Preserve unfamiliar check/status strings; do not assign a new check to a known facet. |
| Native/retained summary counts equal their lists; total incomplete checks equals advisory unknown + unsupported + outdated gap rows + native unknown rows | `AuditSummaryV3` and `AuditLifecycleUnknown` explicitly define these independent counts. |
| Event keys and source-observation keys are distinct; an observation has attributed references with distinct coordinates and nonempty unique paths | Public event/observation/reference descriptions plus verified producer grouping by the documented keys; an incoherence is unverified, not a decoding failure. |
| Known package scope has null affected version; known release/files scope has a supplied affected version; exact affected references participate in the common dependency-count lower bound | Public finding/reference descriptions and the qualified producer distinguish package events from release/file events and exact selected coordinates. Missing or repeated paths stay unverified. |

Non-invariants: a native positive can coexist with an unknown for the same
coordinate (including partial PyPI file evidence); findings need not be bounded
by checked positives. An unfamiliar category maps to no known coverage facet.
Do not equate the event's/source authority's version with selected-reference
versions: accepted aliases/spellings and package authority can differ. Preserve
native identities and exact selected identities without client normalization or
unqualified raw-name/version equality checks.

A v3 request can return v2 during rollback or an older worker. With legacy support
explicitly removed, Scan must reject that returned version clearly; never coerce
or resubmit an accepted job. Future versions are also unassessed and rejected
without interpreting or emitting opaque fields. This is an execution error (3)
online, or invalid/unsupported input (2) for a saved analysis. The online error
names the returned and required versions, explains that the completed result
cannot be read, and preserves the result request ID. For an older returned
version, explain that the service returned an older format and direct the user
to share the ID with support. For a newer version, say a newer Scan reader may
be needed for future audits and retain the support ID. The completed bytes were
not saved, so do not suggest offline replay or retrying a paid job.
Old archive errors name the unsupported format and writer, with guidance to use
that writer's reader; no automatic migration or new analysis is suggested.

Assumptions resolved: service owns classification, selected attribution, event
grouping and collection limits; Scan owns consistency, display and attention.
Existing advisory ignores remain exact-ID and affect only advisory attention.
No new acquisition, registry policy or local reclassification is needed. A lower
v3 incomplete count does not establish better evidence than an older report.

## Architecture and ownership

The sole known report type lives in `src/api/audit/`; the response decoder accepts
schema 3 only. Keep `Report::from_bytes`; delete the now-constant `Report::version`,
`Body` version variants and version-specific consumer branching. A native DTO module
reuses current common vulnerability, duplicate, outdated, diagnostics and
remediation rows, including optional manifest/lock mismatches and their optional
summary count, and native condition fields. These qualified additive findings
remain count-checked and independently attention-worthy even where public schema
publication lags the emitted extensions. Preserve remediation's producer-supplied
`deprecated_target` condition with its unchanged v3 meaning; it is a current
target flag, not the removed coarse audit projection, and does not authorize
client reclassification of selection/upgrade eligibility. `wire.rs` keeps only shared scalar/object/coverage helpers;
delete its unused v1 inventories. Native lifecycle DTOs belong beside the report
because strict consumed fields, required nullable slots and open strings are wire
facts. Exact-coordinate versions stay required; package events have a separate
nullable affected version. No generic report trait or common-version adapter is
needed now that legacy support is out of scope.

`src/api/http.rs` adds `report_version=3` to audit submission only. The API trait,
command Request and CLI need no selector/signature widening. Existing upload,
progress, result retrieval and bounded 429 recovery stay canonical.

`src/audit.rs` exposes the single compact-report assessment in its private
`assessment` module, reusing the current
compact algorithms for attribution, common counts, advisory policy and
remediation consistency. A cohesive lifecycle helper owns event identity,
observation/affected-reference consistency and facet accounting. Combine native
affected coordinates with common coordinates for the existing dependency-count
lower bound; do not derive a full inventory. Duplicate or inconsistent consumed
evidence marks the result incomplete/unverified rather than silently safe.

The command-owned view remains shared between human and JSON. It has native
lifecycle evidence and event/retained-warning totals, without deprecated or v1
manifest-resolution fields. JSON allow-lists consumed typed native fields,
preserving scope, every observation, paths, nullable evidence and open tokens.
Human output shows affected packages, native meaning, source-qualified
observations, paths and useful limitations. Ordinary output gives each native
event one compact package/kind/scope line with its distinct supplied reasons;
do not expand every source observation or affected path there. This makes the
warning useful without burying security/remediation in repetitive metadata.
`--details` expands the complete source observations, versions/times, replacement
advice and affected paths, alongside the existing outdated/duplicate lists.
Translate known check reasons and scope; unfamiliar labels get neutral wording
without inventing meaning or dumping internal codes. Missing reasons are explicit.
Collection limits are limitations, not positive issues. No checked-safe assertion
comes from empty findings or zero candidates.

JSON always carries all four lifecycle facets. Ordinary output does not repeat
permanent not-collected or NA facet inventories (including the always-uncollected
archival checks). Describe those capability limits in help/docs and show their
selected counts/registries in `--details`. Real unknown/failure rows are always
visible. Headlines say "available evidence", not "fully checked", so normal
collection limits do not become either findings or a safety assertion.

Audit and explanation JSON become schema 2. Saved analysis becomes format schema
2 containing only producer schema 3; reject old archives, do not migrate them.
`src/audit/saved.rs` owns bounded framing and actual producer provenance. Replay
and vulnerable-component explanation reuse the sole assessment/view and unchanged
advisory/remediation algorithms. Reusing archive schema 1 was considered but is
unnecessary after Juha removed retention and would obscure the breaking contract.

## Implementation increment

Status: implementation in progress; verification and review remain. Dependencies: qualified public v3 contract
and Juha's explicit breaking-change direction, both satisfied. Unknowns: none.

1. Replace legacy report/assessment/view paths with the sole native model; update
   transport to request v3 and reject unsupported returned versions with a typed,
   safe error carrying the result request ID. Preserve structural failures and
   existing output-file protection. Remove the old types and version-named paths.
2. Implement native consistency, attention, display and schema-2 persistence;
   keep advisory remediation/explanation behavior on the same canonical report.
3. Convert reusable authored audit fixtures/builders and their meaningful tests
   to new `tests/fixtures/audit/native-findings.json`; add the normal
   `audit_native_fixture_decodes_current_contract` decoder test and repoint
   the file-output benchmark from its v1 fixture to these same native bytes.
   Update `tests/fixtures/audit/README.md` to describe only current fixtures.
   Delete obsolete v1/v2 acceptance/compatibility fixtures
   and tests, not unrelated behavior tests. Retain only small explicit rejection
   cases for unsupported versions/archives. Include `tests/live.rs` and
   `tests/file_output_bench.rs`: migrate ignored audit checks/fixtures so release
   rehearsal is not left on the removed schemas. The live adapter must allow
   truthful native unknowns while still rejecting unverified accounting; do not
   retain an unconditional completeness assertion unsupported by native evidence.
   No service fixture/source is copied into the repository.
4. Verify representative real-binary output and the case matrix below. Update
   `src/cli.rs` audit long help and `--details` help, its existing binary help
   regression, README, the exit table and procedures in `docs/implementation/audit.md`,
   `json-output.md`, `command-model.md` and any affected owning docs. Explicitly
   enumerate all exit changes: native withdrawal/package events now draw attention;
   lifecycle collection limits alone do not fail and exit 0 does not mean fully
   checked; unsupported returned report versions are execution error 3 rather
   than attention 1. Preserve the independent outdated/advisory/input gap rules.
   Add a minor-impact breaking fragment with these changes, JSON/archive schema 2
   and the no-resubmission/old-archive migration notes. Remove the superseded
   unreleased `pypi-deprecation-applicability.fixed.md` fragment; the new native
   entry absorbs truthful PyPI applicability and replaces its legacy behavior.
   Review and deliver a draft PR.
   Correct public-schema-publication prose in `docs/implementation/audit.md`
   precisely: native v3/lifecycle schemas
   are published; remediation recommendation/blocker schemas remain partial stubs
   and mismatch/additional remediation fields remain qualified but undescribed.

Keep policy, native consistency, rendering and model changes with the coordinator.
One delegated test implementor will receive these independent mechanical test slices,
serially after the needed interfaces are stable, with uncommitted checkpoints:

- `tests/api_audit.rs`: one new `audit_native_requires_version_three_without_resubmitting`
  case proves audit query opt-in, unsupported returned v2, its result request ID,
  older-result support guidance without a retry/replay suggestion, and one POST. Exact
  filter `test(audit_native_requires_version_three_without_resubmitting)`; 1 pass.
- A new real-binary native lifecycle test module: one
  `audit_native_collection_limits_are_not_failures` case proves a report with
  only not-collected/NA facets returns 0 and has explanatory limitations without
  positive findings/incomplete issues. Assert that all facets survive in JSON,
  routine archival/NA notices are absent in ordinary output, and `--details`
  explains the actual limits. Exact matching filter; 1 pass.
- In that module, one `audit_native_save_replay_preserves_observations` case
  proves schema-2 save/offline replay retains distinct observations, exact source
  and affected versions/paths and the overall outcome. Exact matching filter;
  1 pass. No extra platforms, containers or CI infrastructure are authorized.

Each brief will enumerate its exact allowed files, expected assertions and command
after tracing stable helper interfaces. The coordinator will not build/test while
the test implementor runs. A fresh conformance pre-flight, internal review and one external reviewer per
round follow the governing skills. Plan review closes before a fresh code reviewer
session begins; reviewers are read-only and run no builds/tests.

## Acceptance matrix

| Case | Required result and verification |
| --- | --- |
| Ordinary audit submission | Query explicitly requests v3, with one accepted job and unchanged selected uploads/authentication/stream behavior; transport and binary tests. |
| Returned versions 1, 2 or 4+ | Error names returned/required versions and result request ID, with older-format support guidance or newer-reader guidance for future audits, never a replay/retry suggestion. No raw fields, output overwrite or resubmission; decoder/loopback/binary cases. |
| Native release positives | npm deprecation, Hex retirement, crates yank, NuGet unlisting/deprecation, Go/Pub retraction stay distinct and return 1; minimal fixture mutations and reader-facing binary assertions. |
| Package positives | Go deprecation, Packagist abandonment and Pub discontinuation retain null affected version, all selected coordinates/paths and independent source version; observations never collapse by selected version. |
| PyPI withdrawal and deprecation NA | Release and partial/file yanks retain native scope; a positive can coexist with unknown whole-release evidence. NA alone is neither incomplete nor checked-negative. |
| Retained ambiguous NuGet | One unclassified warning plus supplied uncertainty, exit 1; no coarse deprecation append or invented native kind. |
| Checked negative, unsupported/NA, zero candidates | No positive finding; collection limits are explained and do not fail alone; zero candidates makes no health claim. |
| Unknown/failure or future native vocabulary | Supplied facts remain in JSON and human explanations remain neutral/actionable; real unknown rows make the audit incomplete and exit 1. |
| Bad partitions, summaries, repeated event/observation identities or affected attribution | Incomplete/unverified, never clean; checked-add overflow and exact-boundary unit cases. |
| Advisory ignores, outdated/duplicate/input gaps and remediation | Existing independent semantics and joint recommendation/explanation behavior survive; migrated authored regressions. |
| Save, offline replay and explanation | Format/JSON schema 2, producer 3, complete native facts and whole-report outcome; replay needs no token/discovery/network; old archive schema/producer rejected. |
| Untrusted/missing publisher text | Escaped human output, meaningful no-reason explanation, replacement labelled publisher advice, content filtering disclosed; no internal codes or telemetry as prose. |

## Cross-cutting constraints and delivery

No new security concerns: token input remains injected `GITHITS_API_TOKEN`, never
printed/persisted; only selected catalogued files with validated relative paths
leave the machine. No new network work or redirect/retry path is introduced.
One audit POST plus established events/result retrieval remains the request model.
Limits stay at their owners: 256 files, 5,242,880 bytes/file, 8,000,000 upload bytes,
1,024-byte paths and 16,777,216 response/archive bytes. Typed native data and
rendering stay bounded by that response limit. No optimization claim or benchmark.

Local tests are targeted and sequential. The smallest slice filters above prove
their individual criteria; coordinator coverage uses `test(audit_)` plus affected
fixture-consumer filters (`test(npm_workspace)`, `test(config_policy)`, rate-limit
and relevant license/discovery cases only where changed). Confirm nonzero counts.
CI owns the full workspace/platform gates; pre-commit hooks stay enabled.

For independent zero-quota producer evidence, wrap the already qualified upstream
authored v3 fixture as a schema-2 analysis in `/tmp` and replay through the debug
binary. Verify native meaning, affected paths and absence of unverified
accounting; keep that fixture outside the public repository. This complements
authored regressions and upstream deployment evidence; it does not claim a real
paid audit execution. Manual paid/live audit remains explicitly prohibited, so
that ignored test is migrated but not run here. The benchmark must use exactly
the same `native-findings.json` bytes that the non-ignored
`audit_native_fixture_decodes_current_contract` decoder test consumes. Execute
that exact filter with 1 pass; no performance run is needed because no performance
claim or output-I/O optimization is being made.

Rollback uses the previous binary against default v2. Old/new saved formats are
not interchangeable: retain an old binary for old analyses, or create a new v3
analysis intentionally. Scan never automatically pays for a replacement analysis.
Document that break, JSON schema 2 and archive schema 2 in the owning docs and
minor fragment; no flag, fallback, conversion or deprecated shim remains.

Keep this plan through clean implementation review. Then move the settled contract
to owning docs, delete the plan and obsolete readiness receipts, and search source,
tests/docs for stale audit version paths, fixtures and compatibility claims.
Put test/review/CI evidence on the draft PR. No merge/release/deploy is authorized.
Create/keep `BACKLOG.md` containing only this real open item: a later explicit Action
handoff must consume audit/explanation JSON 2 and native lifecycle facts before
its pinned Scan version is advanced. It must avoid duplicate warnings and
preserve native scope, limits and the attention contract. Do not modify/contact
Action here. This is separate open work, not a legacy compatibility path.
