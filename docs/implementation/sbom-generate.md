# `sbom generate`

## Purpose

This document records how `githits-scan sbom generate` turns the discovery inventory into one job through `POST /v1/experimental/lockfile-jobs` and what it guarantees about the result. The contract facts it relies on are in `sbom-api-contract.md`; the code is `src/commands/sbom.rs` (generation/output), `src/commands/upload.rs` (shared preparation), `src/api/` (the boundary), and `src/env.rs` (token and origin).

## Flow

1. `env::from_source` resolves `GITHITS_API_TOKEN` and `GITHITS_API_URL` through an injected source; the CLI passes `std::env::var_os`. A missing token, a token that cannot travel in a header, an origin that is not exactly `scheme://host[:port]`, or a non-HTTPS non-loopback origin is a usage error (exit 2) before anything else runs, so a pipeline learns about a misconfiguration in milliseconds. Origin errors never echo the value, which could carry userinfo or a query; only the scheme and host of an insecure origin are shown.
2. `discover::scan` produces the inventory. The plan is every lockfile plus its owning manifest (deduplicated across lockfiles that share one), plus every manifest-only project unless the run is `--lockfiles-only`. Nested and uncombined manifests require explicit configuration except for eligible declared Cargo/npm workspace members added during shared upload preparation. Ambiguous lockfiles are never selected; each unacknowledged ambiguous lockfile prints a warning on stderr first. An empty plan is a finding (exit 1) that names `detect` and, when `--lockfiles-only` left manifest-only projects out, names them; no request is made.
3. `api::upload::check_plan` validates count, per-file size, estimated body size, and filename rules from the inventory's metadata. Nothing has been read yet, so a tree with a 40 MB lockfile fails without I/O. Limit failures are usage errors (exit 2): the invocation cannot succeed as given and the caller must narrow `PATH`.
4. `discover::read_file` reads each accepted file as UTF-8 with the per-file limit as a hard bound on the read. A file that is not UTF-8 fails here rather than as a `422 UNUSABLE_MANIFEST` after an upload; a file that grew past the limit since the scan fails as a usage error like any other limit violation.
5. `UploadSet::try_new` runs the same validation on actual contents. The type is the only thing the HTTP client accepts, so a request within limits is guaranteed by construction.
6. `SbomApi::generate` submits once, consumes validated current snapshots and retrieves the result only after success. Commands flush plain human stage lines to stderr, in terminals and CI. Resolving shows manifest counts; enrichment shows package metadata counts and nonzero fetch failures. Partial counts say “processed” or “known”; null/omitted is distinct from measured zero. Totals may grow and are never an overall percentage or ETA. Attempts above one remain visible. Cache/fetch telemetry stays in snapshots rather than repeating in the human output. See [the API contract](sbom-api-contract.md) for recovery, framing, authentication and transport budgets.
7. The document is written unchanged to stdout or `--output`, only after the whole body arrived. The stderr summary then reports how many lockfiles and manifests were uploaded (manifest-only projects count as manifests), names the sorted unique uploaded manifest paths and every manifest-only project that was skipped, gives the `githits:completeness` value for CycloneDX output, and says where the bytes went. Upload selection does not establish whether the backend used a shared workspace lock or resolved declared constraints; the summary makes no resolution claim.

Human output starts with “scanning repository...” before discovery, “preparing upload...”
before file reads, and the selected file counts before submission. The API emits
`ProgressEvent::Reconnecting` before a fresh event opening and `Downloading` before
the result GET. The latter renders “SBOM ready; downloading...”: remote success is
not command completion. The “saved” or “wrote” completion message appears only after destination I/O
succeeds; later download/write failures cannot show a completion claim. Progress
writer failures stop before the corresponding next operation. `license check --json`
suppresses every progress message, retaining its existing upload summary.

## Decisions That Differ From the Original Plan

- `Retry-After` is kept as the raw header string. Nonempty decimal digits are displayed with an `s` suffix for seconds (`30s`); dates and opaque values keep their original display. The client never sleeps on it or parses a bounded integer, and never retries submission or result retrieval.
- One `ApiError::Problem` variant carries the parsed problem with a `Code` enum, instead of one error variant per documented code. The rendering and caller action are keyed by `Code`, which is the stable contract; per-variant errors would duplicate that enum.
- `discover::read_file` is bounded by the API's per-file limit even though the plan was validated from metadata first, because a package manager can rewrite a lockfile between the scan and the read. Reads never allocate more than the limit plus one byte per file.
- `reqwest`'s own protocol-level retry is disabled explicitly with `retry::never()`; the multipart body cannot be replayed anyway, but the guarantee should not depend on that.

## Multipart Details

- Each file is a `files[]` part with `Content-Type: application/octet-stream` and `filename` equal to the forward-slash relative path. `reqwest` is configured with no-op percent-encoding so non-ASCII paths reach the service as raw UTF-8; the default path-segment encoding would have renamed `résumé/Cargo.lock` to `r%C3%A9sum%C3%A9/Cargo.lock` inside the document.
- Because the `filename` attribute is quote-delimited, the upload set rejects a path containing `"` as a client rule in addition to the service's documented rules (relative, no empty, `.` or `..` segments, no backslashes, no control characters, at most 1,024 bytes).
- The body estimate mirrors `reqwest`'s framing exactly (67-byte boundary, the two part headers, line breaks, closing boundary) and `tests/api_http.rs` asserts it equals the real `Content-Length`. If a `reqwest` upgrade changes the framing, that test fails before a 413 can surprise a user.

## Errors

Every API problem renders as one message with the stable code, HTTP status, the service's `detail`, the request id for support, any rejected files with their status, the `Retry-After` value when present, the terms or acceptance URL when present, and the documented caller action (`Code::action`). Unknown codes and file statuses are preserved verbatim so a newer service still yields a readable message. A status without a parsable problem document (a redirect, the documented empty 500, a proxy page) reports the status and request id. Caller-action API failures (including authentication/access and deterministic input/format/size failures) exit 2; transport, service, protocol, rate-limit and internally missing/pending job failures exit 3. Unknown/raw 4xx statuses exit 2 except 408 and 429; other statuses exit 3. A parsed 401 says the supplied token was rejected rather than echoing the server's missing-credential message; submission and result are never retried; only an established event stream reconnects. Terminal job failures show an allowlisted failure code, request ID when available, and an authored next step; malformed protocol diagnostics use static safe descriptions.

The token is held in `env::Token`, whose `Debug` output is redacted, and is read only by the HTTP client when it sets the `Authorization` header. Environment and transport errors are checked in tests to not contain it.

## Testing

- `src/commands/sbom.rs` tests the orchestration with a recording fake `SbomApi`: which paths are uploaded, the summary, that nothing is written on failure, and that limit and UTF-8 failures never reach the API.
- `src/api/http/tests.rs` pins finite 210-second and events 60-second allowances. Shortened constructor budgets and event-held streams prove typed header/body timeouts, established read-timeout recovery versus initial failure, lifetime beyond the read allowance, and server-observed terminal/callback release. See [Transport budgets](sbom-api-contract.md#transport-budgets).
- `tests/api_http.rs` runs the real client against loopback servers (`tests/support/`): request shape, every response class, redirect refusal, and the response-size boundary at exactly 16,777,216 bytes and one more.
- `tests/api_jobs.rs` tests full snapshots, media, bounds, authenticated recovery and failed openings.
- `tests/cli.rs` runs the binary with `Command::env` for the token and origin: usage errors without echoing the token, the finding path without a request, and end-to-end success and failure against the mock server.
- `tests/live.rs` contains ignored tests against the real API; they fail closed without a token.

## Key Reference Files

| File | Demonstrates |
| --- | --- |
| `src/api/mod.rs` | Limits, `OutputFormat`, `Document::completeness`, the `SbomApi` trait, `ApiError` rendering |
| `src/api/upload.rs` | One validation path for plans and contents; the body estimate |
| `src/api/problem.rs` | Problem parsing with every documented code and caller action |
| `src/api/http.rs` | The one place that builds requests and interprets statuses |
| `src/api/jobs.rs`, `src/api/sse.rs` | Validated full snapshots, canonical links and bounded incremental frames |
| `src/commands/progress.rs` | Flushed actual stage/count progress without estimated percentages |
| `src/env.rs` | Token hygiene and origin validation through an injected source |
| `src/commands/sbom.rs` | Plan, output-only-on-success, summary |

## Quiet output

`-q/--quiet` suppresses scanning/upload/job progress and successful upload,
complete-inventory and destination messages. The SBOM bytes, output file, upload selection
and exit codes are unchanged. Errors, actionable warnings and blocked-scan
diagnostics (such as inventory drift or no selected files) remain on stderr.
A CycloneDX `partial_manifest_inventory` still prints one warning: dependency
resolution is incomplete and the SBOM may have no components. The document and
existing success exit code are preserved. Quiet mode therefore still reads the
completeness property; it is actionable status, not only a success summary.
This switch belongs to `sbom generate` and `audit`; it does not change license output.
