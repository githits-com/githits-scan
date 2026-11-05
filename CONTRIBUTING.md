# Contributing

`githits-scan` handles credentials and uploads package files. Contributions
should preserve tested behavior, clear client boundaries, and a stable
command-line contract. Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- Open an issue for anything beyond a small fix so the approach can be agreed
  first. The command surface, exit codes, and JSON shapes are compatibility
  boundaries; changes to them need a design note.
- Read `AGENTS.md` (the working conventions) and the relevant document under
  `docs/implementation/` (the durable decisions).

## Development

Requirements: the Rust toolchain pinned in `rust-toolchain.toml` (installed
automatically by `rustup`), `cargo-nextest`, and `cargo-deny`.

```bash
scripts/check.sh          # release audit, format, Clippy, tests, docs, package, cargo-deny
scripts/check.sh --fast   # same without cargo-deny
```

CI runs the same commands on Linux, plus `cargo test` on macOS and Windows,
cargo-deny, gitleaks, actionlint, and zizmor. Every third-party action is
SHA-pinned; keep it that way.

The `#[ignore]` tests in `tests/live.rs` reach the real API. Supply a token in
`GITHITS_API_TOKEN` and run them deliberately:

```bash
cargo nextest run --locked --workspace --all-targets --all-features --run-ignored ignored-only -E 'binary(live)'
```

To run them against another origin you have access to, set
`GITHITS_API_URL=<origin>` and use a token issued for that origin.

When a script acquires a token with `npx -y githits@latest auth token`,
capture it privately: fail closed on an empty or failed acquisition, never print or
persist it, and pass it only in the child process environment.

The `license_report_uses_deployed_api_and_saved_report_offline` check accepts the
same supplied token as the release live gate. For local runs without that
variable, its harness uses a signed-in GitHits CLI and an explicitly selected
environment, captures the token privately and passes it only to the Scan child,
then replays without a token. The exact local invocation is in the
[license-report verification procedure](docs/implementation/license-report.md#exit-contract-and-verification).

For a focused test run, use an exact nextest filter and confirm it executed:

```bash
cargo nextest run --locked --all-features -E 'test(=catalog::tests::recognizes_every_cataloged_lockfile_family)'
```

Avoid full-suite runs after every small edit; CI supplies the platform matrix.
Run at most one Cargo command at a time in a checkout.

## Making a change

- Every behavior has a test. Filesystem tests use `tempfile`; the API is
  mocked at the `SbomApi`, `AuditApi`, or `LicensesApi` traits, or the loopback
  server in `tests/support/`.
- The workspace lint profile is strict on purpose. Do not raise thresholds or
  add crate-level allowances; use an item-scoped `#[expect(..., reason)]` for a
  genuine exception.
- No `unwrap()` or `expect()` outside tests; errors are typed and carry
  context.
- Every user-visible change adds a fragment under `changes/` (see
  `changes/README.md`). Command-line contract changes also add a test in
  `tests/cli.rs`.
- Keep `docs/implementation/` current when the "why" changes.

## Pull requests

- Use Conventional Commits with a body that explains the why.
- Label the PR `feature`, `bug`, `documentation`, `maintenance`, or
  `skip-changelog`; labels are for triage; release notes come from reviewed changelog fragments.
- CI must be green. Reviews focus on the criteria in
  `docs/guidelines/REVIEW_GUIDELINES.md`.

## Licensing

By contributing you agree that your contributions are licensed under the
Apache-2.0 license that covers the project.
