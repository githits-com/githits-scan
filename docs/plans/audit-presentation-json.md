# Shared audit remediation presentation

Status: READY. One implementation increment; no open product decisions.

## Problem and outcome

Consumers currently reproduce Scan's remediation meaning from fact JSON. A parent
candidate that removes one route can consequently become an unconditional manifest
bump instruction. Scan will compute remediation explanations once and expose those
same explanations as structured plain text beside its unchanged audit facts.

## Verified state and assumptions

- Branch and origin/main both start at d67894711b209940f90efecf9be969add0aa30b2.
- audit::write_result selects curated view JSON or render::write. Offline replay
  projects the same View, with saved provenance and policy, without HTTP or tokens.
- render/remediation.rs owns supported-fix selection, changed-package wording,
  impact, constraints, checks and limits; reasons.rs owns checked benefits.
  problems.rs groups alternatives and establishes displayed advisory context.
- Records have no durable plan ID. Existing identities are subject coordinates,
  package/advisory/files finding identities, and ordered changes. Presentation links
  use document-local recommendation/change positions into the included fact report,
  plus existing identities; they are not producer IDs or cross-analysis identities.
- Focused saved explanations reuse guidance with selected problem context and
  expanded reason evidence. They must continue using the shared computation.
- Diff JSON is exact service bytes. It will remain untouched.
- No new API schema assumptions, service calls, dependencies or infrastructure.

## Architecture and explicit interface

The audit command presentation layer owns explanations because it has curated facts
and displayed problem context. API DTOs cannot own client wording; putting the
model in the Action perpetuates duplicate semantic interpretation. A small
command-local presentation module supplies remediation-specific records, not a
UI/document framework. The text renderer owns indentation, problem grouping,
file wrapping, palette and layout only.

Add `audit --presentation-json`, mutually exclusive with `--json` and `--explain`.
It supports ordinary online audit, `--save-analysis`, `--from-analysis`, `--output`,
`--quiet`, `--details` (structured content remains complete). Default text and
existing --json stay unchanged. A public audit Format enum (Text, Json,
PresentationJson) replaces Request.json. ReplayRequest uses ReplayMode::Report(Format)
or ReplayMode::Explain { package, json }, making focused presentation export
unrepresentable for library callers too. These are explicit public library API
changes; the PR and fragment will record them. CLI behavior remains additive.

Output envelope: schema_version 1, kind audit_presentation, audit (the unchanged
schema-2 curated fact report), remediation (messages, recommendations, limits).
Each recommendation has recommendation_index into audit.remediation.recommendations,
subject, findings/ addressed_findings/remaining_findings using existing identities,
heading, optional outcome explanation (null only when the heading suffices; plain-language sentences
replace raw indeterminate/proposed/partial labels when changes are absent;
indeterminate with no displayed constraints/limitations explicitly says no further
reason was supplied),
changes (change_index, summary, details, files, reasons with summary/evidence),
files, context, impact, constraints with summary/details,
checks, limitations. Arrays of plain text are independent readable blocks in
producer order; changes stay together within one independent alternative.
Each change carries its own identity through the matching fact record. Concise
summary is the qualified heading plus change summaries, never a manifest blocker
alone. Detailed blocks preserve checked benefit, no addressed findings, remaining
advisories, project edits versus real exclusions, and limitations. No strings are
policy/gating input. Material unknown/missing evidence stays explicit.

One pure plan builder owns semantic selection, impact compression, change-file
selection and phrasing. Context moves from render/problems to presentation/context.
Native passes the displayed grouped/selected context; export passes Context::record,
the union of the record’s referenced findings. Any “listed advisory” phrase refers
to that record’s findings, which consumers must display with the explanation.
Reason detail preserves compact/focused behavior; export includes detailed reason
evidence from the same builder. A context comparison owner test covers this.
Both native rendering and presentation serialization consume that model. Section
status and limits are computed there too. No terminal text is captured or parsed.
The builder uses existing control-character escaping for safe single-line plain
text; it emits no ANSI, Markdown or HTML. Consumers still escape for their output
context. Fact identities retain exact fact values.

### Block mapping and unavailable evidence

| Existing guidance | Model field |
| --- | --- |
| Qualified title / separate outcome | heading / outcome |
| Changed package + versions / warnings | changes[].summary / details |
| Checked benefit / detailed requests | changes[].reasons[].summary / evidence |
| Change in/files | files / changes[].files, selected by builder |
| Recorded requests | context |
| Addressed + unresolved advisories | impact |
| Project edits / exclusions / other targets | constraints[].summary / details |
| Override verification, checks, parent search | checks |
| Per-plan limitations / shared search limits | limitations / remediation.limits |

Present planning exports its status message (if needed), recommendations and limits.
Present empty planning exports no-recommendations qualification unless completed
with no vulnerabilities, which exports empty messages/recommendations. Supplied
shared limits remain exported even when native section visibility suppresses them. Unavailable with vulnerabilities
exports “Fix guidance is unavailable in this report.” and empty recommendations/limits;
without vulnerabilities it exports empty arrays. Unverified exports an explicit
message that recommendation evidence could not be verified, with no recommendations
or limits; the fact report retains its authoritative issue. Native retains its
existing section visibility for Unverified (the issue already explains it). No
consumer State interpretation is needed to display the exported messages.

## Scope, alternatives and non-goals

Single PR: shared audit remediation explanations, online/offline presentation JSON,
existing focused-human integration, tests, durable contract and fragment.
Diff presentation, other audit sections' prose, Action adoption and release are
outside this increment. The complete audit facts in the envelope preserve other
findings and incompleteness without claiming a complete human report abstraction.
No downstream changes, private examples, live/paid analysis or last-mile actions.
Adding explanation fields to audit --json would blur its existing contract and
cannot generalize to exact diff bytes; a separate explicit output avoids that.
A generic renderer framework would add mechanism without a verified use case.

## Increment — shared explanations and explicit export (READY after review)

Expected outcome: native audit and offline replay retain truthful guidance, and a
consumer can build a table/report from the same explanations without reproducing
candidate, blocker or reason semantics. Dependencies: reviewed plan and existing
curated View. Assumptions: verified above. Unknowns/product decisions: none.

1. Extract remediation-specific model/builder and reason computation from renderer;
   retain grouping/wrapping in renderer; context-sensitive semantic compression lives
   in the builder only.
2. Make project requirement wording change-scoped: applying this change
   requires updating the project requirement/preference; cover both project_request_change
   and project_preference_change, and preserve third-party exclusions. Partial/unresolved plans with a prerelease
   flag on either the record checks or a change remain candidates, even when
   some findings are addressed; they never become a confirmed prerelease fix.
   Exact supported predicate: existing known planning/checks + outcome proposed/partial,
   nonempty addressed findings, observed availability, non-affecting advisories, matched
   requirements, all upgrade strategies, AND NOT ((partial OR nonempty remaining findings)
   AND (checks.prerelease_target OR any change.prerelease_target == true)).
   Complete proposed prereleases with no remaining findings retain prior supported
   wording and an explicit prerelease warning; no new prohibition is inferred.
3. Add Format and CLI selection, presentation envelope serialization, and replay
   wiring through the same completed View. Progress follows existing JSON rules.
4. Move representative semantic assertions to owner tests using small existing
   synthetic fixtures, with a new authored example-parent/example-leaf partial
   route-removal case. Keep CLI tests for structural association, preservation,
   offline behavior, flag conflicts, output errors and escaping; do not duplicate
   phrase inventories across output formats.
5. Document schema/escaping/consumer handoff in docs/implementation/json-output.md,
   README usage, a minor-impact added fragment for the flag/library migration and
   a changed fragment for native qualification/wording. Review representative native and
   JSON examples side by side. Complete internal then Claude review and delivery.

### Case matrix and acceptance

| Case | Required result | Proof |
| --- | --- | --- |
| Supported upgrade | Suggested fix, actual changed dependency, preserved impact | Owner tests and existing renderer regressions |
| Partial parent, no addressed advisory | Candidate, parent/version, checked route benefit, none reported, unresolved advisory together; no unconditional bump | New owner regression; side-by-side example |
| Project required edit/preference / third-party exclusion | Change-scoped edit / true requirement conflict remain distinct | Owner test |
| Partial prerelease with some addressed and some remaining | Candidate even with otherwise supported checks; record/change flags both qualify | Owner regression |
| Complete proposed prerelease / proposed prerelease with remaining findings | Complete supported proposal stays suggested with warning; unresolved proposed stays candidate | Owner regression |
| Partial overlap / joint changes / alternatives | Keep partly qualifier, joint changes, independent alternatives; never combine | Existing grouping/UX regressions plus model association |
| Unknown checks/outcomes, missing/unverified planning | No supported-fix or no-fix inference; explicit material limitation | Owner and existing regression cases |
| Online export plus archive | One audit call, structured output and archive, same exit | Fake API/CLI test |
| Offline export | No token/network, same model, stored policy/provenance preserved | CLI replay test |
| Existing --json / diff | Unchanged fact serialization / exact bytes | Existing targeted preservation tests |
| Conflicting flags / malformed saved input / output failure | Usage 2 or execution 3 as established, no success output | CLI tests |
| Untrusted text | No ANSI/control leakage; JSON valid and layout escaping remains consumer-owned | Owner escaping and CLI structure tests |

## Cross-cutting constraints and completion

Security: existing env boundary alone reads the token; no new upload/file reads,
credentials, retained private data or logs. Existing path/API limits remain in
api/upload; output is derived only from bounded completed evidence. Online request
count is unchanged (one submission); replay is zero requests. New memory is
proportional to displayed explanations; no benchmark/optimization claim.
Compatibility: additive CLI/schema, no migration of archives or facts. Existing
callers of public Rust audit request structs select Format instead of json bool.
Rollback: omit new flag or use the prior binary; archives and config are unchanged.
Errors reuse existing JSON I/O/error handling and exit semantics.

Verification: targeted nextest filters for the model, audit remediation/reasons,
CLI/replay and diff byte preservation, with nonzero counts; one cargo command at
a time. CI owns broad/platform checks. No live tests. Reviewers are read-only.
Review findings use agent-feedback; one external reviewer per round, at most three
implementation rounds. Commit/push/draft PR and inspect CI without skipping jobs.
Before final push, after clean review, transfer durable contract and handoff to
implementation docs, remove this completed plan, and check stale references.
Consumer handoff names semantic tests Action can remove and layout, escaping,
policy, fact completeness and exit tests it must retain. No further product
work is deferred by this PR; diff remains a separate explicitly excluded scope.
