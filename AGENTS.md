# githits-scan Agent Instructions

Open-source Rust command-line tool that scans a repository for lockfiles and generates an SBOM with the GitHits public API.

This is a public showcase of the GitHits API. Its purpose is to be useful on its own and to demonstrate good client behavior. We optimize for long-term maintainability, a stable command-line contract, deterministic tests, and correct handling of credentials and API limits. Small scope is not an excuse for lower quality.

This document contains the most important instructions that need to be kept always in context.

## General

- Use very concise output and neutral tone.
- If unclear about anything or stuck, stop and ask for clarification.
- Don't jump into coding; plan and assess the impact first.
- Never expose credentials in source, examples, fixtures, logs, process arguments, or tool output. The API token comes only from `GITHITS_API_TOKEN`. If a request would expose a token, stop and explain the risk.
- For authorized live verification, reuse a signed-in GitHits CLI with `npx -y githits@latest auth token`. Capture stdout privately in memory and pass it only as the Scan child process's `GITHITS_API_TOKEN`; never print/persist the token, place it in arguments, or enable shell tracing. Fail closed on failed/empty acquisition. Use the production origin unless told otherwise, and acquire the token from the CLI login environment that matches the origin in `GITHITS_API_URL`; the CLI environment selector does not configure Scan's origin. Scan itself must not invoke credential commands. See README Authentication.
- Irreversible or outward-facing actions require explicit user approval for that exact step. Approval to prepare or review work does not authorize merging, publishing to crates.io, releasing, tagging, or posting on third-party projects.
- Never copy proprietary GitHits code into this public repository, and never name non-public projects, hosts, environments, or internal identifiers in files, commits, or pull requests here; describe the behavior as the service's.
- This is the only agent instruction file; do not create alternate files or symlinks.
- Read more detailed documentation when needed; `docs/implementation/` holds the durable decisions.
- Remember your MCP tools and use them when needed.
- Fix minor in-scope findings immediately. Defer only work that genuinely requires a larger effort, explain why, and record it in the active plan or durable documentation.

### Quality Standards

- Do not cut corners. This tool handles credentials and uploads user files; correctness at every layer matters.
- Performance matters. The tool must stay fast on large monorepos: stream file reads, bound memory by the API limits, and never read files the catalog does not recognize.
- Do not dismiss issues as "pre-existing" to avoid addressing them. If you notice potential improvements while working, report them.
- Strive for excellence, not mediocrity.
- Prefer the smallest design that meets verified requirements. Do not add fallbacks, guards, retries, caches, queues, locks, or other infrastructure for states that have not been shown to occur.
- Fix production issues at their root cause. If a local fix keeps spreading across layers or adding machinery, stop and verify whether ownership is misplaced; say plainly when the clean fix requires a boundary change.
- New projects start with the strict workspace lint profile in `Cargo.toml` and `clippy.toml`. Do not raise thresholds or add crate-level allowances to make a change pass.
- `unsafe_code` is forbidden. Revisit that decision explicitly if a verified requirement ever needs it.

### Assumptions

- Be conscious about assumptions. Document them explicitly in plans and code comments.
- Always verify assumptions via codebase exploration, the public OpenAPI contract (`https://api.githits.dev/v1/openapi.json`), or by asking the user.
- Resolve assumptions before implementation. Defensive code is not a substitute for verifying that a state can occur.

## Architecture

Philosophy: "Create architecture that is performant and easy to test"

- `src/main.rs` parses arguments and returns the process exit code; `src/cli.rs` owns the CLI contract and dispatch. Command handlers orchestrate and render through injected streams, returning typed outcomes/errors.
- Keep catalog, configuration evaluation, license policy, and audit interpretation pure; isolate filesystem and HTTP boundaries. Only the catalog knows package filenames; only `src/api/` constructs requests, interprets status codes, and defines upload/response limits.
- Put each concept at its natural owner, with one canonical computation/validation path and narrow types/signatures. Optional fields and widened APIs need a concrete use case and end-to-end evidence.
- Inject the API through traits; keep modules focused and helpers cohesive. The token and origin come through the injected environment source; token `Debug` is redacted and only the HTTP client exposes it for authentication.

See [Architectural Guidelines](docs/guidelines/ARCHITECTURAL_GUIDELINES.md) for the module map, Rust patterns, and planning checklist; [SBOM API contract](docs/implementation/sbom-api-contract.md) owns the client-side HTTP rules. Durable feature decisions live in `docs/implementation/`.

## Rust

- Use Rust 1.99.1 and edition 2024 (`rust-toolchain.toml`, `Cargo.toml`).
- Document every public item (`///`) and every non-obvious invariant. Do not narrate obvious private code.
- Return `Result<T, E>` for untrusted input and expected operating failures. Use `thiserror` for the library's typed errors at public boundaries; use `anyhow` only in `src/main.rs` if application-level context is needed.
- No `unwrap()` or `expect()` in non-test code. Propagate with `?` and add context.
- Panic only for a documented internal invariant whose violation means continuing could publish an invalid document. Never for malformed input, missing files, or network failures.
- Prefer enums and newtypes over stringly typed domain APIs (`Ecosystem`, `Role`, output format, error codes).
- Keep nesting to two levels; use early returns, `let-else`, and `?`. See `docs/guidelines/NESTING_REFACTORING.md`.
- Use item-scoped `#[expect(..., reason = "...")]` for genuine exceptions; never `#[allow]`.
- Select dependency features explicitly (`default-features = false` where the crate's defaults pull in more than needed). Do not add a dependency before code uses it.
- Use `std::process::ExitCode` for exit codes; never call `std::process::exit` from library code. The scheme is fixed: 0 success, 1 findings, 2 usage or configuration error, 3 execution error (`src/cli.rs` constants; rationale in `docs/implementation/command-model.md`).
- Print user-facing output through the command layer only; library modules return data. Human-readable diagnostics go to stderr, documents go to stdout or the `--output` file.

## Testing and Quality Gates

Philosophy: "If it is not tested, it is likely broken"

- Local validation is targeted-only; CI owns the full workspace and platform matrix. Run broader checks only when the user asks or to diagnose a specific CI failure.
- Run the smallest matching command, such as `cargo nextest run --locked --all-features -E 'test(<name>)'`, and confirm the executed count. Zero matches fail closed.
- Run at most one cargo command at a time in a worktree. Use debug builds for functional and live checks; justify release builds when optimization affects the behavior.
- Mock the API through `SbomApi` or `AuditApi`; network-free tests use `tempfile` for filesystem state and child processes for environment tests. Never mutate the multithreaded test process's environment.
- Test behavior, errors, and exact boundaries. CLI contract changes need `tests/cli.rs` coverage. Synchronize with events and bounded waits, never sleeps or polling.
- Review agents are read-only: no builds or tests. Required evidence that CI does not produce still runs before completion; ignored live tests use an exact filter and verified count.
- Verification infrastructure must be proportional to the decision it gates. A commit is not full-suite evidence; the PR's CI is the gate.

See [Testing](docs/guidelines/TESTING.md) for isolation, live verification, local restrictions, the full gate commands, and pre-commit policy. Never soften a gate or unpin a third-party action.

## Development Workflow (Docs-driven)

- Proposals → Plans → Implementation → Completion. Read [Planning Guidelines](docs/guidelines/PLANNING_GUIDELINES.md) first; use agent planning mode for a single PR and `docs/plans/` for multi-PR coordination.
- Plans hold current scope, verified assumptions, decisions, open work, and only the next one or two increments in detail. Replace finished work with a short outcome and owning-doc link; never append execution, review, rollout, status, or state histories. Delivery and verification go in the PR description; evidence without a PR uses a small linked receipt.
- Keep active open work in the plan. After clean implementation review, transfer durable decisions to the owning implementation/guideline docs; delete the completed plan and search for stale references. Follow [Plan Lifecycle](docs/guidelines/PLANNING_GUIDELINES.md#plan-lifecycle), including the final-push rule.
- On a reused branch, verify its merge base and ahead/behind state against `main` before interpreting failures or opening/updating a PR. Rebase only with explicit user authorization.
- Cross-agent handoffs restate the original objective and acceptance criteria separately from incidental findings or detours.
- Use test-driven development whenever possible. Document what and why; update the owning docs when rationale, patterns, or decision criteria change. Check stale references after renames or deletions.
- Every user-visible change adds a fragment under `changes/` (see `changes/README.md`); release notes come from reviewed fragments.

## Commit & PR Guidelines

- Use the repository-local [`githits-scan-release` skill](.agents/skills/githits-scan-release/SKILL.md)
  for release preparation, release-readiness reviews, and approved release execution.
- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`) with a descriptive title and a body explaining context; no single-line messages.
- Follow [Review Guidelines](docs/guidelines/REVIEW_GUIDELINES.md). Do not amend or rebase unless specifically asked.
- Keep PR titles descriptive and label PRs `feature`, `bug`, `documentation`, `maintenance`, or `skip-changelog`.
- Release, tag, publish, and merge approvals are separate exact-step decisions. See [Release process](docs/implementation/release-process.md) for CLI release gates; [Planning Guidelines](docs/guidelines/PLANNING_GUIDELINES.md#breaking-changes) requires rollback strategies for risky changes.

<!-- conventions: v2.0.2 -->
