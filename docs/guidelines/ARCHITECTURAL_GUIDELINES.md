# Architectural Guidelines

> **Intent**: Provide a lightweight checklist for design docs and task planning so new work arrives with deterministic tests, predictable performance, and clean boundaries.

## Core Principles

- **Deterministic testability**: Every feature must be testable with unit tests, predictable state, and mocked dependencies. The external API is mocked at a trait boundary; filesystem tests use isolated temporary repositories.
- **Pure-first design**: Model business logic as pure functions. The catalog (`src/catalog.rs`) is the canonical example: it answers "is this path package evidence?" from data alone. Push filesystem walking, network, and output writing to thin edges.
- **Documented separation**: `src/main.rs` and `src/cli.rs` orchestrate; library modules compute.
- **Dependency injection**: Command handlers receive the relevant API as a trait object; tests pass a recording fake.
- **Performance by construction**: The API caps an upload at 256 files, 5,242,880 bytes per file, and 8,000,000 bytes per body. Design around those numbers: read only cataloged files, stop early when a limit is exceeded, and never buffer the whole repository.
- **Observability + safety**: Plan diagnostics and error surfaces alongside each feature. Failures surface as typed errors the CLI renders with stable exit codes; include the API request ID when the response carried one, without exposing credentials.
- **Clear ownership**: Put each concept at the boundary that has the data and authority to own it; keep one canonical implementation path.
- **Root-cause simplicity**: Solve the verified failure at its origin. Do not add fallback or recovery machinery for hypothetical states.
- **Type-driven safety**: Prefer enums over strings (`Ecosystem`, `Role`, output format, problem codes) and newtypes over primitives (a validated repository-relative path is not a `String`).
- **Explicit toolchain**: `rust-toolchain.toml` pins 1.99.1 and `Cargo.toml` sets `edition = "2024"` and `rust-version`. Upgrade the toolchain deliberately, in its own change, with the CI, release and publish `toolchain` inputs.

## Deterministic Testability

### 1. Service/State Isolation

Wrap HTTP behind `SbomApi`, `AuditApi` or `LicensesApi`. Production implementations wrap the real client; test fakes return deterministic data and record uploads. Pass dependencies rather than using globals or static mutable state.

### 2. Pure Helpers

Pass data in and return results. Keep functions small (under 30 lines typically), without hidden state; document intent. The catalog, license policy evaluator, and audit interpreter are pure examples.

### 3. Deterministic Inputs

Inject the environment source and output streams. Use explicit per-test repository roots and mock API responses; never rely on global environment or current directory changes.

## Pure Function Helpers & Layering

### Conversion Modules

`src/api/` parses untrusted service responses; `src/env.rs` resolves token/origin values; `src/config.rs` owns the configuration schema (unknown keys are errors) and format-preserving save. Convert raw inputs into validated types at their boundary, without duplicating interpretation in renderers.

### Type Definitions

Use enums (`Ecosystem`, `Role`, `OutputFormat`, error kinds) and validated newtypes for domain values. Do not introduce parameter structs solely to evade an argument-count lint; each struct must represent a cohesive concept with a natural owner.

### Service/Boundary Layer

Discovery owns repository reads; the API owns HTTP. Command handlers orchestrate and render, and the CLI maps outcomes to exit codes. Shared helpers stay with the concept they compute.

### Ownership and API Boundaries

| Concept | Owner | Why this level |
| --- | --- | --- |
| Which files are lockfiles or manifests, and their ecosystem | `src/catalog.rs` | Pure data derived from the API's documented families; nothing else may know file names |
| Repository walking, `.gitignore`, hidden and installed-dependency directories, lockfile-manifest pairing | `src/discover.rs` | Owns the filesystem boundary and produces the inventory every command starts from |
| Orchestration and rendering per command, `Outcome` and `ErrorKind` | `src/commands/` | Knows the user-facing shape of each command; never prints to process streams directly |
| Upload limits, path validation, multipart framing, headers, problem parsing | `src/api/` | These are the service's contract; the client mirrors them once |
| Output format, `--output` handling, exit codes | `src/cli.rs` and command handlers | The command-line contract is a compatibility boundary |
| Configuration schema, drift evaluation, format-preserving save | `src/config.rs` | Computes inventory evaluation once for consumers and owns the persisted configuration |
| License policy | `src/license.rs` | Pure SPDX evaluation over a CycloneDX document; the command only chooses the source and renders |
| Informational license reports | `src/api/licenses.rs`, `src/commands/license/report.rs` | API validates the public wire contract and retains bytes; the command presents separate evidence without policy interpretation |
| Audit interpretation and saved-analysis format | `src/audit/` | Pure projection of service evidence, attribution, and bounded versioned encoding/decoding |
| Local Git snapshots | `src/repository.rs` | Owns immutable enumeration and bounded reads; reuses discovery pairing and command upload selection |
| Dependency comparison | The service; `src/api/diff` and `src/commands/diff` consume it | Canonical source-local meaning/enrichment stays service-owned; Scan validates paired uploads, retains exact JSON and renders facts |
| Styling | `src/style.rs` | Pure palette supplied by command layer; never decides terminal capabilities |
| Token and API origin resolution | `src/env.rs` | Reads `GITHITS_API_TOKEN` and `GITHITS_API_URL` through an injected source so parsing is testable without mutating the process environment |

Before adding or moving a module, helper, field, or abstraction, state who naturally owns the concept and why that layer has the required data and authority. If threading a value through several unrelated layers feels awkward, stop and check whether ownership is misplaced before applying the local fix.

- Keep one canonical path for normalization, validation, identity, and policy decisions. The API limits are constants in the API boundary and are enforced there, by the upload set, against the sizes discovery reports; discovery never redefines or checks them.
- Make required state required. Optional fields are appropriate only when absence is a real domain state.
- Prefer types and signatures that make invalid states unrepresentable: an upload set that has passed validation is a distinct type from a list of candidate paths.
- Do not introduce queues, locks, caches, counters, feature flags, or new recovery paths without a verified need and maintainer agreement.

### Dependencies and Runtime Environment

Adding an operating-system command, native library, or new runtime dependency requires maintainer agreement. The ordinary scan path never shells out to Git or a package manager; use in-process libraries (`ignore` for the walk, `reqwest` for HTTP). Experimental `diff` is the explicit Git exception: `src/repository.rs` enumerates local snapshots and reads bounded cataloged blobs without mutation, remote fetching, fsmonitor helpers or the API token in child environments. Git is required for that command only.

- The binary runs on developer machines and CI runners for Linux, macOS, and Windows. Paths are converted to forward-slash repository-relative form at the discovery boundary; nothing downstream sees platform separators.
- Declare approved runtime dependencies in the shipped artifact and exercise it on supported platforms; availability on a development host does not prove a downloaded binary can use it. Local temporary files are bounded scratch unless an explicit file format defines persistence.
- For upgrades of HTTP, walking, serialization, compression, or other critical dependencies, inspect changed defaults and all affected call sites with production-shaped data and I/O. Compilation and small fixtures alone are insufficient.

### Dependency Injection via Traits

Define traits at the consuming boundary when test substitution is required. Keep the trait as narrow as the consumer's needs; do not mirror the whole HTTP client.

```rust
pub trait SbomApi {
    fn generate(
        &self, upload: UploadSet, format: OutputFormat,
        progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
    ) -> Result<Document, ApiError>;
}
```

Implementations:

- Production: `reqwest` blocking client with rustls, redirects and reqwest automatic retries disabled, explicit finite/event transport budgets, and authored bounded HTTP 429 recovery.
- Test: records the upload set it received and returns a fixed document or a fixed problem.

The token is provided to the production implementation at construction time and is never part of the trait, a log line, or a `Debug` impl.

### Boundary Modules

Within `src/api/`, `upload.rs` owns filename and size validation, `problem.rs` owns problem parsing, `jobs.rs` owns snapshots and canonical links, `sse.rs` owns incremental framing, `licenses.rs` owns license-report decoding, and `http.rs` owns submission/stream/result orchestration; `http/retry.rs` owns the shared invocation budget and Retry-After interpretation.

External services (file system, network) must be wrapped in modules with deterministic contracts.

- Parse untrusted data into validated domain types at the boundary. Apply byte, item-count, and path-length limits before expensive work. The API response is bounded to 16,777,216 bytes; read it with a cap, never with an unbounded `bytes()`.
- Persisted and wire formats use explicit versions, widths, units, and compatibility rules. Validate invariants before writing and after reading; `src/audit/saved.rs` owns the saved-analysis envelope.
- The SBOM response schema is an extensible subset of CycloneDX 1.7: preserve or ignore unfamiliar fields, never deserialize into a closed struct.
- Select consequential dependency features explicitly (`reqwest` with `default-features = false` and `rustls`). Never rely on a transitive dependency to activate a required feature or add a dependency before code uses it.

## Designing for Test Harnesses

### Layering

```
CLI Command (src/cli.rs) -> Command handler -> discover / catalog / api
        |                        |                    |
        |                        |                    +-- Filesystem and network boundaries, mockable via traits
        |                        +-- Orchestration: build upload set, call API, write output
        +-- Argument parsing, exit code mapping only
```

Never reach from `src/main.rs` or `src/cli.rs` directly into the filesystem walker or the HTTP client.

### Test Helpers

Use repository builders from `tests/support/` and recording API fakes beside command-handler tests (for example `FakeApi` in `src/commands/sbom.rs`); override the response or error for the behavior under test. Keep pure modules concrete rather than adding one-implementation traits.

## Greenfield Lint Profile

The workspace root `Cargo.toml` owns the lint policy through `[workspace.lints]`, and the package opts in with `[lints] workspace = true`. Every future member must do the same. `clippy.toml` sets the thresholds:

```toml
too-many-lines-threshold = 100
too-many-arguments-threshold = 7
excessive-nesting-threshold = 3
allow-expect-in-tests = true
allow-unwrap-in-tests = true
```

The test exceptions apply only to test functions and `#[cfg(test)]` code. Prefer `expect()` with failure context where it makes a test easier to diagnose.

`unsafe_code = "forbid"` is the default. If unsafe code ever becomes a verified requirement, review that decision explicitly and change it to `deny` with `unsafe_op_in_unsafe_fn`, `undocumented_unsafe_blocks`, and one justified operation per block still enforced.

`clippy::doc_markdown` flags product names in prose; add legitimate identifiers to `doc-valid-idents` in `clippy.toml` rather than backticking a brand name.

### Function Shape Enforcement

The workspace denies `too_many_lines`, `too_many_arguments`, and `excessive_nesting`. The 100-line and 7-argument ceilings are tripwires, not design targets; do not raise them or add blanket allowances. Item-scoped `#[expect(..., reason = "...")]` is the only maintained-code exception; remove it when no longer needed. Prefer a boundary correction over mechanical extraction or arbitrary parameter bags. Nesting includes item/module structure: inspect the boundary rather than flattening sound modules. Do not use Clippy's `cognitive_complexity` as a quality metric.

### Rust Code Style

- Document every public item with `///`, including errors and non-obvious invariants. Use `#[must_use]` when discarding a result would likely be a bug; keep visibility no wider than consumers require.
- Use `thiserror` at library boundaries; `anyhow` is reserved for application-level context in `src/main.rs`. No `unwrap()` or `expect()` in non-test code.
- Prefer iterators when clearer; use loops for stateful control flow. Borrow inputs that are not retained, own data at storage/transfer boundaries, and justify clones without creating unnecessary lifetime complexity.
- Use builders for genuinely optional or validated construction and literals for simple configuration; use `impl Trait` only to intentionally hide a concrete return type.
- Library modules return data; only the command layer prints. Use `std::process::ExitCode`, never `std::process::exit` in library code. Exit codes are fixed: 0 success, 1 findings, 2 usage/configuration error, 3 execution error; see [Command model](../implementation/command-model.md).

## Performance & Reliability

### Cost Modeling

During planning, estimate:

- One job submission per `sbom generate` run, followed by events and result requests. Resubmission recomputes and consumes quota; no idempotency key exists.
- File reads: only cataloged files, each at most 5,242,880 bytes. Reject an oversized file before reading the next one.
- Memory: the upload set (at most 8,000,000 bytes) plus the response (at most 16,777,216 bytes) is the ceiling.
- Directory walk: `ignore` parallel walking is unnecessary; a single-threaded walk that skips hidden and ignored entries is fast enough and deterministic. Benchmark before changing that.

### Backpressure & Retries

- Never retry submission or result. Only established event-stream loss reopens for the latest snapshot; failed openings stop. Surface `Retry-After` from a 429 and exit.
- One request at a time. If a repository exceeds the upload limits, fail with a precise message about which limit and which files; do not split into multiple documents without an explicit design.

### Error Handling

- Use `Result<T, E>` for expected failure and untrusted input.
- Define error enums with `thiserror`; preserve the API's stable `code`, `status`, `instance` (request ID), and per-file `files[]` diagnostics as typed data.
- Log errors at the CLI boundary, not deep in call stacks.
- Panic only for documented internal invariants whose violation could publish an invalid document.

### Async and Concurrency

The client uses blocking HTTP and one request at a time. If a verified requirement adds concurrency, bound fan-out and channel capacity and define overload behavior. Every task must have an owner that joins, cancels, or supervises it; do not detach work whose result matters. Never hold synchronous lock guards across `.await`. Define cancellation around side effects so it leaves valid state or reaches an explicit commit boundary.

### Observability

- Diagnostics go to stderr; documents go to stdout or the `--output` file, never mixed.
- Every API failure message includes the request ID when the response carried one.
- The token is never printed, not even partially.
- Plan progress events and diagnostic context at command/API boundaries; use existing injected streams and callbacks. Do not add service telemetry or a logging dependency without a verified CLI need.

## Clean Separation of Concerns

- Boundary modules own data access and expose stable contracts.
- Pure modules own interpretation and policy; command handlers own orchestration and rendering.
- Entry points parse arguments, construct dependencies, dispatch, and map exit codes.
- Shared helpers stay focused on one owned concept. See [Ownership and API Boundaries](#ownership-and-api-boundaries) and [src/lib.rs](../../src/lib.rs).

## Planning Checklist

When drafting a plan or proposal, explicitly answer:

### 1. Testability

- Which parts are pure functions? Which need mocked dependencies?
- What interfaces need to be defined for dependency injection?
- Which binary-level scenarios belong in `tests/cli.rs`?

### 2. Dependency Injection

- What boundaries need fake implementations?
- How are dependencies passed into the code path?

### 3. Error Handling

- What errors can occur (local validation, each documented API code, I/O)?
- How are they surfaced to users, with which exit code?
- Are error messages helpful and free of credentials?

### 4. Performance

- Expected file reads and request size?
- Where is each API limit enforced, and is it enforced exactly once?

### 5. Separation

- Which modules are touched? Are we reusing existing helpers or creating new ones?
- Does the change affect the command-line contract?
- Who owns each new concept, and is there exactly one path that computes or validates it?
- Does any new optional field or widened signature represent a verified state or need?

### 6. Documentation

- Which `docs/implementation/` document records the decision?
- Does `README.md` or the `changes/` fragment need an update?

## Key Contract References

| Reference | Use it for |
| --- | --- |
| [SBOM API contract](../implementation/sbom-api-contract.md) | Canonical client rules, limits, errors, stream handling, and token safety |
| [Public OpenAPI](https://api.githits.dev/v1/openapi.json) | Authoritative public API schema |
| [SBOM endpoint](https://docs.githits.com/api-reference/v1/experimental/generate-an-sbom-from-uploaded-files) | Upload contract |
| [API errors](https://docs.githits.com/api/errors) | Problem documents, codes, and `Retry-After` |
| [Authentication](https://docs.githits.com/api/authentication) | Bearer-token format |
| [Repository foundation](../implementation/repository-foundation.md) | Toolchain, lint, CI, licensing, and provenance decisions |

<!-- conventions: v2.0.2 -->
