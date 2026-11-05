# SBOM API Contract (Client View)

## Purpose

This document records what `githits-scan` relies on from the GitHits public API's SBOM operation and the client-side rules that follow from it. It is a summary for implementers of the API boundary; the authoritative contract is the public documentation and OpenAPI document listed under References. When they disagree with this page, the public contract wins and this page must be corrected.

## Background

The API is pre-production: the `/v1` contract is not yet frozen and the SBOM operation lives under `/v1/experimental`, which means its route may move under a documented migration policy. The client therefore keeps every contract fact in one module (`src/api/`) so a change is a one-place edit, and it treats response documents as extensible rather than closed.

## The Operation

| Item | Value |
| --- | --- |
| Submit | `POST /v1/experimental/lockfile-jobs?kind=sbom&format=cyclonedx\|spdx\|text` |
| Production origin | `https://api.githits.dev` |
| Authentication | `Authorization: Bearer <token>`; anonymous requests are rejected with 401 |
| Request content type | `multipart/form-data`; let the HTTP library set the boundary |
| Query parameters | `kind=sbom`, `format=cyclonedx\|spdx\|text` |
| Acceptance | HTTP 202 JSON: queued UUID, expiry and canonical relative status/events/result URLs |
| Progress | `GET {events_url}`: HTTP 200 `text/event-stream`, full snapshot events |
| Result | `GET {result_url}` after success: HTTP 200 document bytes |
| Errors | `application/problem+json` (RFC 9457) with a stable `code` |

### Multipart body

- Repeat the literal field name `files[]` once per file.
- Each part carries raw UTF-8 file bytes (not base64) and a `filename` equal to the file's repository-relative path with forward slashes, for example `app/package.json`.
- `kind=sbom` is required in the query or a non-file part; optional `format` may also be a part, and body fields take precedence. Unknown fields, missing filenames, duplicate fields and invalid values are a 400. Scan sends kind and format in the query.

### Upload limits

| Limit | Value | Where the client enforces it |
| --- | --- | --- |
| Files per request | 1 to 256 | Upload-set validation, from the discovery inventory, before any file is read |
| Bytes per file | 5,242,880 | Upload-set validation, from the metadata size in the inventory, before the file is read |
| Whole multipart body including framing | 8,000,000 | Estimated from file bytes plus per-part overhead before sending |
| Filename length | 1,024 UTF-8 bytes | Path validation |
| Filename shape | Relative; no empty, `.`, or `..` segments; no backslashes; no control characters | Path validation; paths are normalized to `/` at the discovery boundary |
| Upload deadline | 30 seconds | Finite submission allowance is 210 seconds |

The per-part overhead for the body estimate is the multipart framing the HTTP library emits: boundary line, `Content-Disposition` header with the filename, `Content-Type` header, and blank lines. The client computes a conservative estimate and rejects an upload whose estimate exceeds the limit, so a 413 from the service indicates a bug in the estimate rather than expected behavior.

### Supported families

Cargo, npm, pnpm, Yarn classic and Berry, uv, Poetry, PDM, Pipenv, Swift, Gradle, NuGet, Dart, Composer, Mix, Bundler, Rebar, Conan, and Go dep. Recognition is by filename and contents; renaming a file does not add support. The exact filenames the client uploads are in `package-file-catalog.md`.

Text `bun.lock` is also cataloged and covered by an ignored production API
fixture test. See [Bun qualification](package-file-catalog.md#bun-text-qualification)
for its verification procedure and limits.
Binary `bun.lockb` is excluded from this UTF-8 upload contract.

The public API gives non-exhaustive manifest examples; acceptance also depends
on their contents. Go `go.mod`, vcpkg `vcpkg.json`, and Zig `build.zig.zon` are
cataloged as manifest-only ecosystems from the service's documented resolution
support; see `package-file-catalog.md`.

Lockfiles may be uploaded alone. A compatible lockfile in the same directory as a manifest supplies recorded versions for that manifest. The public OpenAPI states that a nested manifest does not automatically inherit an ancestor lockfile. Workspace association through native membership evidence belongs to backend parsing, not Scan's directory-containment heuristic; preserve relative paths exactly. An uploaded manifest not associated with recorded lock evidence can be resolved by the service from its declared constraints. Manifest-only inputs are selected unless the run is `--lockfiles-only` or configuration omits them; eligible Cargo and supported npm members are selected automatically, including under `--lockfiles-only`, under the [Cargo](discovery.md#cargo-member-evidence) and [npm](discovery.md#npm-member-evidence) evidence contracts; other nested manifests require explicit configuration. The upload summary reports selected files, not backend resolution mode.

### Output formats

| `format` | Response `Content-Type` | Contents | Suggested file name |
| --- | --- | --- | --- |
| `cyclonedx` (default) | `application/vnd.cyclonedx+json` | CycloneDX 1.7 JSON | `bom.cdx.json` |
| `spdx` | `text/spdx` | SPDX 2.3 tag-value (not JSON) | `bom.spdx` |
| `text` | `text/plain` | Human-readable inventory report | `bom.txt` |

Result media may include `; charset=utf-8`; another charset or media type is rejected. Gateway owns format-specific document validation; scan preserves exact bytes. All outputs are UTF-8 and at most 16,777,216 bytes. The client reads the body with that cap and treats a longer body as an error.

### Interpreting a document

The CycloneDX schema is an extensible subset: additional standard fields may appear at any level, so the client never deserializes into a closed struct. If the client inspects the document at all (for example to print a summary), it does so through `serde_json::Value` and looks up document properties by name, never by position:

| `githits:completeness` value | Meaning |
| --- | --- |
| `resolved_manifest_inventory` | Inventory from manifest dependency resolution |
| `partial_manifest_inventory` | Resolution incomplete; the component list can be empty |
| `recorded_lockfile_inventory` | Inventory recorded in uploaded lockfiles |
| `mixed_dependency_inventory` | Lockfile records plus separately resolved manifests |

A missing version, PURL, or license means unavailable evidence, not a default value. Component names are not unique; `bom-ref` is the identity.

## Errors

Every error is a problem document. Branch on `code`, never on `detail`. The `instance` field equals the `X-Request-ID` response header; include it in every user-facing error so support can trace the request.

| Status | `code` | User-facing action |
| --- | --- | --- |
| 400 | `VALIDATION_ERROR` | Client bug or unsupported path; report with request ID |
| 401 | `AUTHENTICATION_REQUIRED` | Set `GITHITS_API_TOKEN` to a valid token |
| 403 | `FORBIDDEN`, `ACCOUNT_INACTIVE`, `TERMS_ACCEPTANCE_REQUIRED`, `FEATURE_FLAG_REQUIRED` | Resolve account access or accept terms; `terms_url` and `acceptance_url` may be present |
| 408 | `UPLOAD_TIMEOUT` | Upload could not finish in 30 seconds; check connectivity or reduce upload |
| 413 | `INPUT_TOO_LARGE` | Client-side limit check missed a case; report |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Client bug; report |
| 422 | `UNUSABLE_MANIFEST` | The `files[]` array lists each rejected path with `unsupported`, `invalid_utf8`, or `unparsed`; show them and exit |
| 422 | `NO_MANIFEST_EVIDENCE` | Uploaded files contained no usable package evidence |
| 422 | `UNREPRESENTABLE_SPDX` | Rerun with `--format cyclonedx` |
| 422 | `SBOM_OUTPUT_TOO_LARGE` | Document exceeded the output limit; scan a smaller tree |
| 404 | `ANALYSIS_NOT_FOUND` | Missing, expired or another owner's job; no recovery |
| 409 | `ANALYSIS_PENDING`, `ANALYSIS_FAILED` | Result unavailable; failed may include allowlisted `failure_code` |
| 503 | `ANALYSIS_UNAVAILABLE` | Admission unavailable; retry manually |
| 429 | `RATE_LIMITED` | Show `Retry-After` when present (decimal digits use an `s` seconds suffix; other values unchanged) and exit; never sleep and retry |
| 500 | none (empty body, no request ID) | Service could not create request identity; retry later manually |
| 502 | `UPSTREAM_ERROR` | Service failure; retry later manually |
| 503 | `SBOM_UNAVAILABLE`, `UPSTREAM_UNAVAILABLE` | Service unavailable; retry later manually |
| 504 | `TIMEOUT` | Generation exceeded the service deadline; a retry repeats the work |

The `UNUSABLE_MANIFEST` problem carries per-file diagnostics:

```json
{ "code": "UNUSABLE_MANIFEST", "status": 422, "instance": "...",
  "files": [ { "path": "app/manifest.txt", "status": "unsupported" } ] }
```

## Client Rules

These follow directly from the contract and are non-negotiable for the API boundary.

- **Submit once.** No submission/result retry, status polling, sync fallback or Last-Event-ID replay. Established event-stream EOF/read loss reopens to obtain the latest snapshot; every opening must deliver a valid first snapshot. Opening transport/HTTP errors, empty streams and malformed data stop immediately. There is no delay or retry counter. A server repeatedly closing after one snapshot can consume admission until 429; no fleet burst has been qualified.
- **No redirects.** A redirect could forward the bearer token to another host. The HTTP client disables redirect following; a 3xx is an error.
- **Explicit transport budgets.** Both clients limit connection establishment to 15 seconds, independently of their read allowances. Finite submission/result headers and individual reads retain 210 seconds. Events use 60 seconds for headers and each read, above the 30-second opening budget and 15-second keepalive. There is no whole-job timeout. See [Transport budgets](#transport-budgets).
- **Limits before bytes.** Every upload limit is checked locally before the request is built, with an error that names the limit and the offending files.
- **Bounded reads.** Success bodies are read with a 16,777,216-byte cap; error bodies with a small cap (64 KiB) before JSON parsing.
- **Output only on success.** The `--output` file is written only after a 200 with the full body; a problem document never lands in the SBOM file.
- **Attribution headers.** `User-Agent: githits-scan/<version>`, `X-GitHits-Client-Name: githits-scan`, and `X-GitHits-Client-Version: <version>`. Values are trimmed printable ASCII within the documented byte limits (80 bytes for name and version).
- **Token hygiene.** The token is read from `GITHITS_API_TOKEN`, held in a type without `Debug` output, sent only in the `Authorization` header, and never logged, echoed, or included in error messages.
- **HTTPS only.** `GITHITS_API_URL` must use `https`, except for exact loopback hosts (`localhost`, `127.0.0.1`, `[::1]`) to allow local mocks.

## Snapshots and ownership

`jobs.rs` owns wire validation; `sse.rs` owns incremental framing; `http.rs` owns
submit/events/result orchestration. Commands receive a fallible `ProgressEvent` callback
and own display. `Snapshot(Progress)` retains validated replacement measurements;
`Reconnecting` announces an established-stream reopening, and `Downloading`
announces result retrieval after success. These are client transitions, not
invented server phases. A callback error stops before the next opening/result GET. The existing `HttpSbomApi` is migrated without a second synchronous
path. No new runtime dependency, signal handler or reader task is introduced.

Acceptance JSON is capped at 65,536 bytes. Accepted IDs must be UUID-shaped. All authored links must exactly equal the canonical
relative path for that ID before resolving against the validated origin. Absolute,
foreign-origin, alternate-job or query-bearing links never receive credentials.
Each request constructs fresh authentication from the constructor's validated token.
Scan cannot refresh an expired bearer held in its process environment.

A full snapshot requires matching ID, `kind=sbom`, selected format, canonical result
link, revision matching its SSE ID, state, attempt, phase, counts, expiry and required
nullable error. Revisions are nondecreasing; equal revisions replace the full snapshot.
Known counters are optional unsigned integers; null/absent differs from measured zero.
Unknown additive fields/counters are ignored. Unfamiliar phases display a generic
stage; unfamiliar failure codes use a static safe diagnostic. Unknown states stop
because their terminal semantics cannot be inferred. The failure allowlist is `resolution_timeout`,
`resolution_failed`, `output_too_large`, `unrepresentable_spdx`, `parser_contract_changed`,
`execution_failed`, `execution_record_unavailable`, `invalid_response`, `no_manifest_evidence`.
Raw malformed JSON, phases or failure messages are never included in diagnostics.

Frames have a 65,536-byte framing budget, including comments, ignored events and
field delimiters. CR reserves its optional LF before dispatch, so standalone CR uses
one extra budget byte per delimiter; the authored service stream uses LF. LF, CRLF, CR, multiline data and split UTF-8 are decoded incrementally.
Incomplete frames at EOF are discarded. Success/failure immediately drops the stream,
without waiting for EOF. Callback failure also releases it; no job cancellation is sent.
OS interruption terminates the process normally. Result bytes reach stdout/files only
after complete media-checked, capped download. Existing output files survive API failures.

## Transport budgets

Both clients use `CONNECT_TIMEOUT` (15 seconds) for connection establishment, including TLS, independently of response read budgets.

One API wrapper owns two blocking clients with common TLS, disabled redirects/retries
and attribution policy: finite requests use `REQUEST_TIMEOUT` (210 seconds), events
use `STREAM_TIMEOUT` (60 seconds). Locked reqwest 0.13.5 client-level timeout bounds
send through headers and then each `Response::read` independently. It is not a whole
response lifetime. Do not set `RequestBuilder::timeout`: the async transport underneath
turns that into a total response-body deadline. Two clients imply two existing reqwest
runtime threads per invocation. Recheck these semantics when upgrading reqwest.

A stream may last ten minutes and reopen normally. Stream lifetime exceeding the read
allowance is tested with a callback held by an event, then a fresh terminal frame;
actual server-observed EOF proves terminal/callback stream release. Tests shorten the
production constructor allowances to one second, without sleep-driven pacing.

## Remaining gaps

A release requires production availability of the lockfile-job routes; the
maintainer live-test release gate checks it before tagging. Successful work lasting
over 120 seconds and a check that one token cannot read another owner's job are not
yet qualified. One scan opens one progress stream at a time.

## References

| Reference | Content |
| --- | --- |
| https://docs.githits.com/api-reference/v1/experimental/generate-an-sbom-from-uploaded-files | Operation reference: limits, formats, error table, examples |
| https://api.githits.dev/v1/openapi.json | OpenAPI 3.1 document; public, no credentials required |
| https://docs.githits.com/api/errors | Problem document shape and retry guidance |
| https://docs.githits.com/api/authentication | Token creation at `https://app.githits.com/settings/tokens` |
| https://docs.githits.com/api/versioning | `/v1` namespace, experimental route policy, contract status |
| https://docs.githits.com/changelog/overview | Where route or contract changes are announced |

## Migration verification

Phase 3 implementation passed `scripts/check.sh` on 2026-10-11: formatting,
warning-denied Clippy, 193 deterministic tests (two credential-dependent live tests
explicitly skipped), doctests, warning-denied rustdoc and cargo-deny. Transport and
binary cases cover the policies above. The implementation review's second round was
clean.

The wire parser owns state/error consistency and emits a validated control outcome
carrying the allowlisted failure code. The transport does not repeat that validation.
The pre-release trait migrated with the client; no unused synchronous library shim
was retained. Binary compatibility is pinned by exact output/exit tests.

## Shared audit transport

Audit uses the same upload/job limits, security, progress framing and result path
with `kind=audit&format=json` and `application/json` result media. It adds the
`assessing` phase and optional assessment counters. Phases/failure codes are open:
unfamiliar phases get generic progress and unfamiliar failures get a static safe
code/action. Unknown job states stop rather than infer terminal semantics.
`SbomApi` and its output formats remain unchanged; `AuditApi` selects a different
operation through one internal transport. Report version/coverage consumer rules
are in [audit.md](audit.md). Source preparation is shared by the command layer.

## Licenses result view

`LicensesApi` reuses the CycloneDX job flow and canonical-link validation, then
reads `/v1/experimental/license-reports/{id}` instead of the ordinary result. It expects
JSON and recognizes `INCOMPATIBLE_ANALYSIS` (409) and `LICENSE_REPORT_TOO_LARGE`
(422) without resubmitting. See [license reports](license-report.md) for report
version, presentation, saved replay and informational exit semantics.

## Account access diagnostics

`FEATURE_FLAG_REQUIRED`, `TERMS_ACCEPTANCE_REQUIRED`, and `ACCOUNT_INACTIVE`
are caller-action errors (exit 2), following the API error classification. The client always
supplies an action at `https://app.githits.com`: request feature access, accept
the terms, or contact support to reactivate the account. Optional service URLs
are still shown, but the action works when they are absent. These failures
produce no result document; the account restriction must be resolved before
retrying.
