# Testing Guide

## Purpose

This document provides the testing patterns and conventions for `githits-scan`. All contributors should understand these patterns to write effective, isolated tests.

## Quick Reference

- **Test Runner**: `cargo nextest run --locked --workspace --all-targets --all-features` (full suite in CI)
- **Philosophy**: Test behavior, not implementation
- **Isolation**: Every test must be independent; every filesystem test uses `tempfile`
- **Network**: Default tests are network-free. The SBOM and audit APIs have traits; tests use fakes. Live tests require explicit opt-in.

## Testing Philosophy

- **Test behavior, not implementation**: Focus on inputs and outputs
- **Use dependency injection**: Mock the API at its trait boundary
- **Enable isolation**: Each test should be independent
- **Keep tests fast**: No network, no fixed paths, no sleeps
- **If it is not tested, it is likely broken**
- **Fail closed**: Missing fixtures, baselines, prerequisites, or expected test matches are failures unless the test is explicitly opted out with a reason

### What to Test

- Catalog classification for every documented file name, including exclusions and case sensitivity
- Discovery on synthetic repositories: nested projects, `.gitignore`, hidden directories, installed-dependency directories, files over the size limit, more than 256 files
- Upload-set validation against every API limit, at the exact boundary value and one past it
- Problem-document parsing for every documented `code`, including the `files[]` array of `UNUSABLE_MANIFEST`
- Command handler behavior with a fake API: success writes the document unchanged, failure never writes the output file
- Binary-level contract: exit codes, stdout and stderr separation, `--help`, `--version`

### What NOT to Test

- `clap` itself (one `Command::debug_assert()` test is enough)
- `reqwest` internals
- The service's parsing behavior; the tool never parses lockfiles

## Test Quality Guidelines

High-quality tests catch real bugs without slowing down development. The goal is maximum bug-catching value per test, not maximum test count.

### Keep Tests Fast

- Tests run in parallel under nextest, one process per test. Never depend on the current directory or process environment.
- Test pure functions without filesystem or I/O when possible (`catalog::classify` takes a path, not a file).
- Use shared fixture builders for synthetic repositories instead of repeating `fs::write` calls.

### Test Organization Rules

- Split test files exceeding 1000 lines.
- Keep individual tests under 50 lines; extract helpers for setup.
- Group tests by user-visible behavior, not by internal function name.
- Parameterize similar tests with a table (see `recognizes_every_cataloged_lockfile_family` in `src/catalog.rs`).

### Assertions Must Be Meaningful

Every assertion must fail if the behavior breaks. Avoid:

- Truthy-only checks (`assert!(result.is_ok())` without inspecting the value)
- Tautological assertions that can never fail
- Asserting on fake setup rather than on behavior

### Verification Scope

Run the smallest local test that exercises the changed behavior. CI owns the macOS and Windows matrix; do not duplicate it locally, but a change that touches path handling must be reasoned about for Windows separators and confirmed in CI before completion.

Verification infrastructure must be proportional to the decision it gates. For "did behavior change?" questions, extend an existing fixture before designing a new proof system.

For performance work, benchmark the exact code path before changing it and repeat the same benchmark afterwards, in release mode. Prefer deterministic work evidence (files read, bytes buffered) over wall-clock timing.

## Test Organization

```
src/
├── lib.rs            # Library root
├── catalog.rs        # #[cfg(test)] mod tests at the bottom of each module
tests/
├── cli.rs            # Runs the real binary via CARGO_BIN_EXE_githits-scan
├── fixtures/         # Byte-exact inputs when a file expresses behavior better than code
```

### Unit Tests

- Live in `#[cfg(test)] mod tests` at the bottom of the module they test
- Test individual functions and modules in isolation
- No filesystem unless the module's job is the filesystem; then `tempfile`

### Integration Tests

- `tests/cli.rs` spawns the built binary and asserts on exit status, stdout, and stderr
- Use a child process with `Command::env`, `env_remove`, or `env_clear` to test how `GITHITS_API_TOKEN` and `GITHITS_API_URL` are read; never `std::env::set_var` in the test process

## Dependency Injection for Testing

The consumer of an external boundary owns the trait because it knows the smallest contract it needs.

1. **Define interface**: `SbomApi` with one method, `generate`.
2. **Create production implementation** wrapping `reqwest`.
3. **Create fake implementation** that records the received upload set and returns a configured `Result`.
4. **Inject** the fake in tests and the production implementation in `src/cli.rs`.

Use a trait only where production and test implementations genuinely differ. The catalog and the upload-set validator are pure and need no trait.

## Test Isolation

- Each test must be independent and not affect other tests
- Use `tempfile::tempdir()` for every synthetic repository; it is removed automatically
- Never rely on test execution order
- Do not read or mutate process-wide state (environment, current directory)
- Synchronize concurrent tests with channels, barriers, notifications, or a paused test clock and bounded waits; never use sleeps or polling to decide readiness. Assert task completion and inner results instead of discarding child outcomes.

### Environment Variable Isolation

Rust 2024 marks `std::env::set_var` and `remove_var` unsafe, and this crate forbids unsafe code. Put configuration parsing behind an injected source (a function or trait that yields variable values) and test the precedence rules as pure logic. Test the real process boundary in `tests/cli.rs` with `Command::env`.

## Fixture-Based Testing

Use fixtures under `tests/fixtures/<feature>/` when files express behavior more clearly than inline values, for example a captured CycloneDX document or a problem response.

- Fail if an expected fixture is missing; never treat an empty discovery result as success.
- Provide an exact invocation for one fixture and a command for its family; confirm matched counts. Normal tests compare expected output, never regenerate it; use an explicit reviewable regeneration command.
- Keep fixtures byte-exact when a test asserts on bytes; exclude them from `end-of-file-fixer` in `.pre-commit-config.yaml` if needed.
- Fixtures must not contain a real token, request ID from a real account, or any private repository content.

## Concurrency and Randomized Tests

Coordinate with events; bounded waits only fail a stuck test. For concurrent pipelines, cover cancellation, producer/consumer failure, saturation, and shutdown; assert task termination and that failures reach the owner. Randomized tests use a deterministic seed, report it on failure, and check an independent oracle or invariant. Add them only when the state space warrants them, alongside named regression cases.

## Best Practices

### 1. Use Fixture Builders

Create a shared helper that writes a synthetic repository layout into a `tempdir` from a list of relative paths, so discovery tests read as a list of files plus an expected upload set.

### 2. Test One Thing Per Test

Each test verifies a single behavior. Multiple unrelated assertions in one test make failures harder to diagnose.

### 3. Use Descriptive Test Names

- Good: `rejects_upload_when_a_single_file_exceeds_the_byte_limit`
- Bad: `test_limits`

### 4. Arrange-Act-Assert Pattern

Structure tests with clear setup, execution, and verification phases.

## Running Tests

```bash
# Run one test by exact name
cargo nextest run --locked --all-targets --all-features -E 'test(=catalog::tests::recognizes_every_cataloged_manifest)'

# Run a module's tests
cargo nextest run --locked --all-targets --all-features catalog::

# Run one test with output visible
cargo nextest run --locked --all-targets --all-features --no-capture -E 'test(=catalog::tests::recognizes_every_cataloged_manifest)'
```

After using a filter, confirm the runner executed the expected number of tests. A successful command that matched zero tests is not evidence.

Tests that need a real token are marked `#[ignore = "requires GITHITS_API_TOKEN and network access"]` and run with `--run-ignored ignored-only` and an exact filter. Ordinary PR CI excludes them; the exact-commit release rehearsal runs all ignored live tests as a separate gate (see [Release process](../implementation/release-process.md#rehearsal-and-release-gates)).

## Local Validation Policy

Use targeted local checks during development. CI runs the full workspace and
platform matrix on every PR; open the PR early to use that feedback.

- Run focused checks after each edit. Use `scripts/check.sh` for a complete local
  gate when requested or when diagnosing a CI failure; avoid repeating the full
  suite without a specific question.
- Use debug builds for functional CLI and live API checks. Build `--release` only when behavior depends on optimization; state why first.
- Run at most one cargo command at a time in a worktree.
- Reviewers are read-only: no builds or tests; name a required run in findings.
- Every required check must run somewhere before completion. Report a blocked check; narrower evidence does not replace it. Evidence CI cannot produce (ignored live tests and authorized live API checks) still runs with an exact filter and verified count.

## Quality Gates

CI (`.github/workflows/ci.yml`) is the merge gate. `scripts/check.sh` runs
the same workspace checks locally:

```bash
cargo xtask release audit
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo nextest run --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-features --doc
RUSTDOCFLAGS="-Dwarnings" cargo doc --locked --workspace --all-features --no-deps
cargo deny check
cargo package --locked -p githits-scan --allow-dirty
```

CI runs them on Linux, plus `cargo test` on macOS and Windows, cargo-deny, gitleaks, actionlint, and zizmor. Every third-party action is SHA-pinned; keep it that way.

Before committing, the pre-commit hooks run fmt, Clippy, rustdoc, cargo-deny (on dependency changes), and the hygiene checks; run the targeted tests for the areas you touched. A commit is not evidence that the full suite passes; the PR's CI is.

## Validation Commands

The canonical full command list is in [Quality Gates](#quality-gates); use the focused commands in [Running Tests](#running-tests) for local work.

CI runs all of them on every PR; use focused checks during development as
described in [Local Validation Policy](#local-validation-policy). There are no mutually exclusive features; `--all-features` is always correct. The manifest requires Rust 1.99 and CI pins 1.99.1; there is no separate MSRV matrix. Use Miri, sanitizers, or model checking only for a relevant verified requirement, with a pinned command and target; unsafe code remains forbidden.

## Diagnosing Flaky Tests

A flake is a probability. Reproduce it at the smallest suspected boundary with varied seeds, ordering, or concurrency, including known collision partners. After a fix, repeat that focused reproducer; CI supplies the broad signal. Investigate before distinguishing shared-state races from host-load failures. Never make a flaky test pass by adding sleeps, retries, larger timeouts, weaker assertions, or skipped hooks. Fix the ownership or synchronization defect. If the root cause is still unknown, report that plainly.

## Coverage Goals

- All public functions have tests
- Error paths are tested, including every documented API problem code
- Boundary values are tested exactly (256 files, 5,242,880 bytes, 8,000,000 bytes, 1,024-byte paths)

### Priority Tiers

| Priority | What to Test | Test Type |
|----------|-------------|-----------|
| High (must test) | Catalog, upload-set validation, problem parsing, credential handling | Unit tests |
| High | Command handler with fake API: output written only on success | Unit tests |
| Medium | Discovery on synthetic repositories | Unit tests with `tempfile` |
| Medium | Exit codes, stdout/stderr separation, environment boundary | `tests/cli.rs` |
| Lower | Live request against the real API | Ignored test, manual |

## Common Pitfalls

- Fixed paths instead of `tempdir()`
- Mutating process environment inside the multithreaded test process
- Testing implementation details instead of observable behavior
- Asserting on a document's exact bytes when the service is allowed to add fields
- Successful filtered commands that execute zero tests
- Timer-based synchronization or retries that hide an unknown race

<!-- conventions: v2.0.2 -->
