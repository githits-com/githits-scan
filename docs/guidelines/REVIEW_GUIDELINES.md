# Code Review Guidelines

## Purpose

This checklist helps reviewers evaluate code changes consistently. Each criterion includes what "good" looks like and common issues to watch for.

Review documentation and small metadata changes inline. Scale independent
review to the changed behavior; changes to concurrency, security, data integrity, or performance
need the corresponding code and test evidence. Reviewers are read-only and ask
the author for missing verification.

Use one independent reviewer per round. Fix accepted findings and repeat code
review until a clean round; minor wording-only findings can be closed by applying
them. Do not re-raise a rejected finding without new evidence.

Before labeling a finding high or blocking, state the worst realistic outcome, its concrete trigger and likelihood, and the cost of the smallest fix. Normal operation and documented inputs count as triggers; unusual timing with bounded, self-healing impact does not by itself justify a blocking label. Name any new infrastructure the fix requires; the maintainer decides whether it is justified.

## Architecture

**Criterion**: Architecture is sound and follows our guidelines.

Judge direction before line-level findings: does the change advance the end goal, fix the root cause, and rest on settled structure? Report a direction problem first with evidence and the cost of a more direct route, or state that the direction is sound. Changes to the project goal or unresolved architecture need maintainer agreement. Reassess on later rounds only if the approach changes. A simpler route to the same scoped goal is an ordinary finding: adopt it and update the plan, or explain any rejection to the maintainer.

**What good looks like**:
- Pure functions for business logic, I/O at the discovery and API boundaries
- `src/main.rs` and `src/cli.rs` orchestrate; they never walk directories or build HTTP requests
- The SBOM API is reached only through its trait
- Each concept has one clear owner and one canonical computation or validation path (API limits live in the API boundary only; file names live in the catalog only)
- The change fixes the verified root cause without speculative fallback or recovery machinery

**Watch for**:
- Entry points doing business logic instead of orchestrating
- A second place that knows lockfile names or upload limits
- Untestable code without dependency injection points
- Static mutable state that prevents test isolation
- A local patch spreading through several layers because the owning boundary is wrong

**Reference**: [Architectural Guidelines](./ARCHITECTURAL_GUIDELINES.md)

---

## Implementation Clarity

**Criterion**: Implementation is easy to understand.

**What good looks like**:
- Functions do one thing (single responsibility)
- Clear naming that reveals intent
- Early returns, `let-else`, and `?` over nested conditionals
- Complex logic extracted into well-named helpers with narrow inputs

**Watch for**:
- Deep nesting (more than 2 levels); see [Nesting Refactoring](./NESTING_REFACTORING.md)
- Long functions (the 100-line lint ceiling is a tripwire; 30 lines usually indicates a needed extraction)
- Cryptic variable names or magic numbers (limits are named constants with their source documented)
- Comments explaining "what" instead of "why"

---

## Code Organization

**Criterion**: Code is in correct modules without unnecessary duplication.

**What good looks like**:
- Related functions grouped in focused modules
- Shared logic extracted to helper modules, not copy-pasted
- Module names reflect their responsibility

**Watch for**:
- Similar code in multiple places
- "Utils" modules growing unbounded
- Business logic in `src/main.rs` or `src/cli.rs`

---

## CLI Design

The command line is a compatibility boundary. Rendering is scan's UI: command handlers receive pre-computed data and injected streams; `src/style.rs` supplies styling without reinterpreting domain facts.

**What good looks like**:
- `clap` derive macros with help text on every argument
- Helpful error messages with suggestions
- Stable exit codes: 0 success, 1 findings (drift, violations, nothing found), 2 usage or configuration error, 3 execution error; documented additions only through a plan
- Documents on stdout or `--output`; diagnostics on stderr; never mixed
- Color never carries meaning; `NO_COLOR` respected

**Watch for**:
- Missing help text on arguments
- Inconsistent flag naming with existing commands
- Hard-coded paths or origins instead of configurable options
- Accidental output or exit-code changes without a compatibility test and a `changes/` fragment

---

## Type Safety

**Criterion**: Types are properly defined and as narrow as possible.

**What good looks like**:
- Enums for known variants (`Ecosystem`, `Role`, output format, problem codes) instead of strings
- Newtypes for domain values that must not be mixed (a validated repository-relative path, a request ID)
- `Option<T>` used correctly for optional values; `Result<T, E>` for fallible operations
- Visibility no wider than the actual consumers require

**Watch for**:
- `unwrap()` or `expect()` in non-test code (scan forbids both)
- Missing error context on `?` propagation
- Primitive obsession (raw `String` for a path that has been validated, raw `u16` for a status the code has already classified)
- Boolean flags or optional fields that admit invalid state combinations
- `#[must_use]` omitted where discarding a return value would likely be a bug
- Public items introduced only to make tests or internal callers convenient

---

## API Boundaries & Signatures

**Criterion**: New and changed boundaries are as narrow and unambiguous as possible.

**What good looks like**:
- Required state is represented by required fields
- Optional values correspond to real domain states (a problem document's `files[]` is present only for `UNUSABLE_MANIFEST`)
- Types and signatures make invalid states unrepresentable
- The command-line contract grows only when end-to-end evidence requires the new shape

**Watch for**:
- Optional or nullable fields added "just in case"
- Two helpers that do the same thing with slightly different rules
- One path validating a value while a sibling path trusts it
- Command-line changes tested only at an internal helper layer, not in `tests/cli.rs`

---

## Performance

**Criterion**: Solution has good performance without unnecessary overhead.

**What good looks like**:
- `&str` and `&Path` parameters where ownership is not needed
- Iterators instead of collecting then iterating
- Reads bounded by the API limits; files are read once
- Response bodies read with a byte cap
- Optimization claims backed by comparable release-mode before/after measurements

**Watch for**:
- Unnecessary `.clone()` calls
- Reading files the catalog did not select
- Buffering more than the documented limits
- Blocking work on an async executor, or a synchronous lock guard held across `.await`
- Unbounded parallelism or a thread pool introduced without a measured need
- Spawned tasks without an owner, join/cancel path, or surfaced failure; cancellation that leaves side effects inconsistent
- Caches, queues, locks, counters, or feature flags added without measured need and maintainer agreement
- Performance conclusions based only on noisy wall-clock measurements

---

## Error Handling

**Criterion**: Errors are handled properly with good context.

**What good looks like**:
- `thiserror` enums at library boundaries; sources preserved
- The API's stable `code`, `status`, `instance`, and `files[]` preserved as typed data
- User-facing messages that say what went wrong and what to do (the documented "caller action" for each code)
- The output file is never written on failure
- Cleanup happens in error paths

**Watch for**:
- Swallowing errors silently
- Matching on `detail` text instead of the stable `code`
- Retrying submission/result automatically; established stream reconnection only retrieves the latest snapshot
- Logging the same error at several layers
- Any code path that could print the token

---

## Dependencies & Runtime Environment

**Criterion**: Dependency changes are deliberate and minimal.

**What good looks like**:
- `default-features = false` with an explicit feature list for `reqwest`
- New dependencies added in the change that first uses them, with `deny.toml` updated for any new license
- Upgrades of serialization, HTTP, or walking crates reviewed for changed defaults at every call site and exercised with production-shaped data/I/O
- Approved runtime dependencies present and exercised in the shipped artifact on supported platforms; development-host availability is insufficient

**Watch for**:
- Required behavior activated only by transitive feature unification
- A dependency used directly but omitted from `Cargo.toml`
- Dependency-only diffs justified only by compilation
- A new operating-system command or shell-out
- Silent fallback when a required runtime dependency is missing
- Temporary local files treated as durable or shared cache state without a design

---

## Test Coverage

**Criterion**: Good test coverage with passing tests.

**What good looks like**:
- Happy path and every documented error path covered
- Boundary values tested exactly, and one past the boundary
- Fake API implementation for command-handler tests
- Tests verify behavior, not implementation details
- Missing fixtures, baselines, prerequisites, or expected test matches fail closed
- Concurrent tests use events and bounded waits and assert that all owned tasks finish and surface failures

**Watch for**:
- Tests that only cover the happy path
- Tests depending on the network, the current directory, or process environment
- Sleeps, polling, retries, or loosened assertions masking nondeterminism
- New verification infrastructure when an existing fixture can answer the question

**Reference**: [Testing Guide](./TESTING.md)

---

## Documentation

**Criterion**: Documentation explains what and why.

**What good looks like**:
- Documentation on all public items
- Comments on non-obvious logic explaining intent
- `docs/implementation/` updated when decision criteria change
- A `changes/` fragment for every user-visible change

**Watch for**:
- Missing documentation on public functions/types
- Comments restating what code already shows
- Stale docs or stale references after renames
- Deleted plans whose durable decisions were not transferred, or whose inbound references remain
- Plans containing history, status/state logs, evidence, delivery recaps, or acceptance criteria beyond the next one or two increments; see [Keeping Plans Compact](PLANNING_GUIDELINES.md#keeping-plans-compact)

**Reference**: [Documentation Guidelines](./DOCUMENTATION_GUIDELINES.md)

---

## Security

**Criterion**: No security vulnerabilities introduced.

**What good looks like**:
- Token read only from `GITHITS_API_TOKEN`; never a command-line flag, never logged, never in `Debug` output
- `GITHITS_API_URL` must be HTTPS except for loopback hosts
- Repository-relative paths validated before upload (no `..`, no absolute paths, no backslashes, no control characters)
- Uploaded content limited to cataloged files; nothing else leaves the machine
- Response bodies bounded before parsing

**Watch for**:
- Secrets in code, fixtures, examples, or logs
- Following redirects (must be disabled; a redirect could leak the bearer token)
- Reading files outside the scanned root through symlinks without an explicit decision
- Exposing internal error details that include file contents

---

## Cleanliness

**Criterion**: Only relevant changes, no warnings.

**What good looks like**:
- Commits focused on the task at hand
- Zero Clippy warnings under the workspace profile
- Unused variables and imports removed

**Watch for**:
- Debug code left in (`println!`, `dbg!`)
- Commented-out code or TODOs without context and an active owning plan
- `#[allow(...)]` where a reasoned, self-expiring `#[expect(...)]` works
- A lint threshold raised or disabled to make a change pass
- A genuine unsafe requirement introduced without explicit review of the current forbid policy, a narrow safe boundary, and exact invariants documented per operation
- A workspace member missing `[lints] workspace = true`

---

## Build & Lint

**Criterion**: Code builds and passes all checks.

- [ ] The PR's CI is green (reviewers do not run the gate locally)
- [ ] No new Clippy warnings
- [ ] Code is formatted with `cargo fmt`
- [ ] `cargo deny check` passes after any dependency change

---

## Commit Quality

**Criterion**: Commits are well-structured.

- [ ] Commit message is descriptive with context
- [ ] Changes are logically grouped
- [ ] No unrelated changes mixed in

<!-- conventions: v2.0.2 -->
