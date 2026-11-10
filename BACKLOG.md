# Open work

## Adopt native lifecycle evidence after the audit report contract exists

Scan cannot yet distinguish native deprecation from withdrawal in audit results.
The service exposes this distinction on package inspection, but its audit reports
still supply only the legacy `findings.deprecated` coordinate/reason projection.
This is a producer prerequisite, not a ready implementation increment. Qualification
and compatibility evidence are in the [readiness receipt](docs/reports/2026-11-10-lifecycle-report-readiness.md).

### Required producer boundary

The service owns native classification and bounded shared metadata preparation;
its report projection must reuse that authority for selected dependencies. Scan
owns decoding, evidence consistency, presentation and exit policy. Classification
in Scan would discard source authority; per-dependency inspection requests would
create a separate acquisition path and are excluded.

Before implementing, qualify the producer-owned, actually emitted audit report
contract that supplies all of the following. These are semantic requirements,
not proposed HTTP field names or a new schema:

- Native findings with registry/name identity, category, kind, scope, nullable
  affected version, source, source version and observation time where retained.
  A package-wide affected version is absent; the observed authority's version
  must not be substituted for it. Selected coordinates and input paths must be
  attributable without implying reachability or expanding the selected scope.
- Independent deprecation, withdrawal, registry archival and repository archival
  outcomes, with supplied failure/missing-evidence reasons. Checked negatives,
  unavailable native observations, unsupported collection and not-applicable
  checks must remain distinct; empty findings do not prove checked coverage.
- Optional native reason, reason codes and publisher replacement advice, with
  the service's content-safety treatment. Advice is not a verified upgrade.
- Retained ambiguous legacy warnings and a rule relating native findings to
  legacy deprecation rows, so one event renders once without parsing old prose.
- Defined summary/coverage accounting, scope-aware event identity, and the
  compatibility boundary for omission in older immutable reports. The producer
  must explicitly choose additive v2 support or a new report version; Scan must
  not guess. Neither lifecycle counts nor retained warnings are advisory counts.

The HTTP API forwards new producer fields even when OpenAPI does not describe
them. Schema omission alone is therefore not a Scan adoption blocker; the missing
audit preparation/report projection is the prerequisite. Public API updates
belong to the separately assigned API work. Its schema should also describe the
existing `not_applicable_count` and `not_applicable_registries` coverage fields,
which the fetched OpenAPI omits even though the producer and Scan support them.
Retain that compatibility while qualifying any lifecycle addition.

Current submissions produce report version 2; retained version 1 remains readable.
Scan JSON is independently version 1, and saved-analysis format 1 embeds a typed
version-2 producer report. A producer version change therefore needs an explicit
decode/save/replay compatibility decision. Optional additions must preserve old
absence rather than synthesize checked outcomes. Archival is currently uncollected
in the inspection assessment; collection and any future archive kinds remain
service prerequisites. Quarantine is excluded.

### Receiving paths once that prerequisite is met

| Owner | Existing path and required follow-up |
| --- | --- |
| Version dispatch and transport | `src/api/http.rs` (`AuditApi::audit`) sends the combined job result to `src/api/audit.rs` (`Report::from_bytes`, `Body`); retain v1/v2 handling, structural errors and uninterpreted future versions. `src/api/audit/wire.rs` and `src/api/audit/v2.rs` own typed consumed fields. `Coordinate.version` is required today and cannot represent package-wide affected scope by itself. Additional fields are discarded, including on save. |
| Pure assessment | `src/audit.rs` and `src/audit/v2.rs`; reconcile consumed attribution, summary and coverage against the qualified producer contract. Keep native event counts separate from vulnerabilities and legacy deprecation. |
| Shared command view | `src/commands/audit/view.rs` and `src/commands/audit/view/v2.rs`; project scope, source qualifications, useful reasons and retained warnings once for both human output and JSON. Existing maintenance rows contain an exact coordinate and reason only. |
| Human presentation | `src/commands/audit/render.rs`; show meaningful native warnings and limitations without relabelling package/file events as deprecated releases. Respect compact/detail behavior, escape publisher text and avoid a clean headline when warnings exist. |
| Offline persistence | `src/audit/saved.rs`, `src/commands/audit/saved.rs`; preserve consumed lifecycle facts and old absence through bounded save/replay, using the same assessment and view as online output. |
| Command policy | `src/commands/audit.rs` (`project`); keep exit selection owned by pure assessment. Adding a visible lifecycle warning must not silently add a default failure gate. |

Existing legacy findings and genuine metadata/advisory/source failures retain
their current attention behavior. In particular, existing `not_collected`
metadata gaps currently cause exit 1. Do not erase that behavior or route every
new unsupported lifecycle check through the existing metadata-gap computation:
that would introduce a new default failure policy. New lifecycle unsupported/NA
outcomes are neither positive issues nor checked-safe assertions. Unknown native
evidence remains disclosed, and existing failure policy remains intact.

### Acceptance cases for the later consumer increment

Use minimal authored rows against the qualified report, preserving existing
immutable fixtures. These are required assertions, not evidence of shipped support.

| Evidence case | Required consumer outcome |
| --- | --- |
| npm native release deprecation plus legacy warning | One warning with reason and input paths; legacy attention behavior retained. |
| npm observed negative | No positive warning; only an explicit checked outcome establishes the negative. |
| Hex retirement, including an older known positive | Native retirement remains retirement; no prose-based reclassification or duplicate warning. |
| PyPI release yank with deprecation NA | Withdrawal remains distinct from deprecation; NA is disclosed without an incomplete check or checked-negative claim. |
| PyPI mixed or partly missing file flags | File withdrawal remains file-scoped; a positive can coexist with unknown whole-release evidence. No invented file list or whole-release yank. |
| crates yank with legacy deprecation positive | One yank warning; advisory counts, old deprecation support and remediation semantics remain intact. |
| Go package deprecation with legacy false | Warning is visible with no affected release; source version is authority evidence, even when different from a selected version. |
| Go retraction, NuGet unlisting/deprecation, Packagist abandonment, Pub discontinuation/retraction | Preserve each supplied kind and package/release scope, reasons and optional replacement advice; do not create an upgrade recommendation. |
| Ambiguous retained NuGet warning | One unclassified warning plus native uncertainty; invent no native kind and append no coarse warning again. |
| Checked negative, UNKNOWN/missing native capture, NOT_COLLECTED, NA, and zero candidates | Distinct evidence outcomes; no positive issue or safe claim inferred from unsupported/absent data. Existing actual failures stay actionable. |
| Package event affects multiple selected versions/files | One source-qualified event with supplied affected scope and attribution; no duplicate event per selected version or unrelated project leakage. |
| Registry archival versus repository archival | Independent checks; currently uncollected adds no archival finding. Future positives need a qualified producer source and kind before adoption. |
| Immutable v1/v2 and saved format-1 reports lacking additions | Original findings, gaps, legacy absence and exit status retained; no retrospective reclassification. |
| New lifecycle evidence plus existing findings or gaps | No changed default failure gate, advisory count, advisory-ignore behavior or suppression of existing gaps; warning-only additions do not independently change the exit code. |
| Malformed consumed fields, inconsistent counts/attribution, unfamiliar values or future report version | Typed structural failures or existing incomplete/unassessed handling as appropriate; no false clean result or opaque data forwarding. |
| Save then offline replay; hostile/absent publisher prose | Same retained facts and overall outcome, no credential/discovery/network access on replay, escaped human text, no diagnostic jargon in prose. |

Target existing decoder and assessment tests, real-binary cases in
`tests/cli/audit_applicability.rs`, `audit.rs`, `audit_v2.rs` and `audit_saved.rs`,
and `tests/fixtures/audit/README.md`. Add only the smallest fixture cases that
prove new semantics. Exact test filters and nonzero counts belong to the later
implementation evidence. No live paid scan is needed to invent fixture coverage.

### Delivery and remaining decisions

Requalify the actual producer schema, immutable-report compatibility and scope
accounting before creating an implementation plan. No new CLI flag, public Rust
signature, schema version or runtime dependency is chosen by this investigation.
No new infrastructure, local registry fetching, automatic resubmission or
default scan gate is authorized. Any future default gate requires a separate
product decision; warning-only adoption is the current scope.

Security and performance remain at existing boundaries: token input only through
`GITHITS_API_TOKEN`, never output; only selected catalogued files with validated
relative paths leave the machine. No extra dependency request is permitted.
Existing limits remain 256 files, 5,242,880 bytes/file, 8,000,000 upload bytes,
1,024-byte paths and 16,777,216 response/archive bytes. Redirect/retry policy is
unchanged. This is no optimization and needs no benchmark.

At implementation, update `docs/implementation/audit.md` and
`docs/implementation/json-output.md` with the settled contract, add the required
user-visible change fragment, and preserve old binary/configuration usability.
Rollback must revert consumer projection without invalidating retained reports;
settle saved-format compatibility before choosing any version migration.

After the shared Scan JSON/view contract is concrete, a separate explicit Action
handoff must adopt native warnings, scopes, retained warnings and limitations
without double counting or changing default failure policy. This backlog grants
no Action changes or coordination. Remove this item after reviewed consumer
adoption transfers the durable contract to the owning implementation docs.
