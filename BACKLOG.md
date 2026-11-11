# Open work

## Adopt audit v3 after public version forwarding is available

The service now provides opt-in audit v3 with native lifecycle evidence, verified
in development. Scan cannot request it through its public experimental endpoint:
the current gateway rejects the required `report_version` control in both query
and multipart input. Public request admission/forwarding is the remaining external
prerequisite. Scan adoption has not shipped. Current evidence is in the
[readiness receipt](docs/reports/2026-11-11-lifecycle-v3-readiness.md).

### Qualified producer contract and remaining admission boundary

The service owns native classification and bounded shared metadata preparation;
its report projection must reuse that authority for selected dependencies. Scan
owns decoding, evidence consistency, presentation and exit policy. Classification
in Scan would discard source authority; per-dependency inspection requests would
create a separate acquisition path and are excluded.

The qualified service contract accepts `report_version=3` for audit jobs through
query or multipart; multipart wins. Omission or `2` keeps v2. Other values and
non-audit uses are rejected before admission. Scan uses
`/v1/experimental/lockfile-jobs`; service admission alone does not qualify that
route. The separately assigned API work owns admission/forwarding and public
schema adoption. Response passthrough does not admit a new request control.
OpenAPI omission alone remains insufficient evidence of a runtime failure.

Audit v3 has a canonical `lifecycle` subtree with `findings`, `retained_warnings`,
`coverage`, `unknowns` and `content_safety`. It replaces `findings.deprecated`,
`summary.deprecated`, `coverage.deprecation` and deprecation rows in
`unknowns.metadata`; it is not an optional addition to v2.

- Findings group native events by registry/name/category/kind/scope/source/affected
  version. Package-wide events have `version: null`. Each event's `observations`
  retain distinct nullable source version, observation time, reason and replacement,
  reason codes, and `affected` exact coordinates with selected paths. Authority
  version and selected version remain independent; paths do not prove reachability.
- `retained_warnings` carry ambiguous legacy NuGet evidence once with
  `legacy_unclassified`, coordinate, paths and reason. Do not reconstruct or append
  the removed coarse deprecation row.
- Four coverage facets partition deprecation, withdrawal, registry archival and
  repository archival into checked/unknown/not-collected/not-applicable outcomes.
  Lifecycle `unknowns` contain only unknown rows, distinguishing `lookup_failed`,
  `metadata_unavailable` and `native_evidence_unavailable`. Each contributes one
  incomplete check. Not-collected and not-applicable remain collection limits.
- `summary.lifecycle` counts native events;
  `summary.retained_lifecycle_warnings` counts retained rows. Neither is an advisory
  count. `summary.incomplete_checks` sums vulnerability unknown/unsupported counts,
  outdated metadata gap rows and lifecycle unknown rows. Lower v3 counts than v2
  do not prove improved evidence. `content_safety.filtered` qualifies publisher
  text; replacement advice is not a verified upgrade.

Dispatch on the returned version: a v3 request may return v2 during rollout or
rollback. Never resubmit an accepted job to obtain v3. Immutable v1/v2 reports
retain their meanings. Scan JSON is independently version 1; saved format 1
currently embeds only a typed v2 report. Decide decode/save/replay compatibility
in the consumer implementation plan, including old archives and the returned v2
case. Do not widen exact `Coordinate.version` to represent package events.
Both archival facets remain uncollected; collection and future archive kinds
remain service work. Quarantine is excluded.

### Receiving paths once that prerequisite is met

| Owner | Existing path and required follow-up |
| --- | --- |
| Version dispatch and transport | `src/api/http.rs` (`submit`, `AuditApi::audit`) currently sends only kind/format; request version 3 for audit only after public admission is qualified. `src/api/audit.rs` (`Report::from_bytes`, `Body`) currently treats 3 as future/unassessed. Add explicit v3 dispatch while retaining v1/v2 and future handling. `src/api/audit/wire.rs` and `src/api/audit/v2.rs` own existing typed fields; additional fields are discarded, including on save. |
| Pure assessment | `src/audit.rs` and `src/audit/v2.rs`; reconcile consumed attribution, summary and coverage against the qualified producer contract. Keep native event counts separate from vulnerabilities and legacy deprecation. |
| Shared command view | `src/commands/audit/view.rs` and `src/commands/audit/view/v2.rs`; project scope, source qualifications, useful reasons and retained warnings once for both human output and JSON. Existing maintenance rows contain an exact coordinate and reason only. |
| Human presentation | `src/commands/audit/render.rs`; show meaningful native warnings and limitations without relabelling package/file events as deprecated releases. Respect compact/detail behavior, escape publisher text and avoid a clean headline when warnings exist. |
| Offline persistence | `src/audit/saved.rs`, `src/commands/audit/saved.rs`; preserve consumed lifecycle facts and old absence through bounded save/replay, using the same assessment and view as online output. |
| Command policy | `src/commands/audit.rs` (`project`); keep exit selection owned by pure assessment. Adding a visible lifecycle warning must not silently add a default failure gate. |

Existing v1/v2 findings and genuine metadata/advisory/source failures retain their
current attention behavior. In particular, old `not_collected` metadata gaps
currently cause exit 1. V3 intentionally changes lifecycle coverage accounting:
do not route its collection limits through the old metadata-gap computation or
reinterpret retained reports. New lifecycle unsupported/NA outcomes are neither
positive issues nor checked-safe assertions. Native unknown rows remain explicit
and incomplete. Do not introduce a new default lifecycle failure gate; confirm
the positive-warning policy when preparing the implementation plan rather than
reconstructing coarse compatibility facts from native kinds.

### Acceptance cases for the later consumer increment

Use minimal authored rows against the qualified report, preserving existing
immutable fixtures. These are required assertions, not evidence of shipped support.

| Evidence case | Required consumer outcome |
| --- | --- |
| npm native release deprecation in v3; legacy warning in retained v2 | One warning with reason and input paths per report; no invented coarse v3 row, retained v2 attention behavior preserved. |
| npm observed negative | No positive warning; only an explicit checked outcome establishes the negative. |
| Hex retirement, including an older known positive | Native retirement remains retirement; no prose-based reclassification or duplicate warning. |
| PyPI release yank with deprecation NA | Withdrawal remains distinct from deprecation; NA is disclosed without an incomplete check or checked-negative claim. |
| PyPI mixed or partly missing file flags | File withdrawal remains file-scoped; a positive can coexist with unknown whole-release evidence. No invented file list or whole-release yank. |
| crates native yank in v3; legacy deprecation positive in retained v2 | One warning through each version's canonical path; advisory counts, retained report behavior and remediation semantics remain intact. |
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
| Version-3 request returns version 2; accepted result is incomplete or failed | Decode the actual returned version; never resubmit or retry as a different report version. Existing bounded 429 recovery is unchanged. |

Target existing decoder and assessment tests, real-binary cases in
`tests/cli/audit_applicability.rs`, `audit.rs`, `audit_v2.rs` and `audit_saved.rs`,
and `tests/fixtures/audit/README.md`. Add only the smallest fixture cases that
prove new semantics. Exact test filters and nonzero counts belong to the later
implementation evidence. No live paid scan is needed to invent fixture coverage.
Existing future-version decoder/binary regressions explicitly use version 3;
move their future case beyond the supported version when v3 is implemented.

### Delivery and remaining decisions

Requalify public version admission/forwarding and the actual producer contract
before creating the consumer implementation plan. No new CLI flag, public Rust
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
