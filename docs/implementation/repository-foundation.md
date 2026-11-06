# Repository Foundation

## Purpose

This document records the decisions behind the repository scaffold so future changes to tooling, layout, or policy start from the reasons rather than rediscovering them.

## Background

`githits-scan` is an Apache-2.0 Rust client for the public GitHits API.
Its tooling keeps the distributed CLI, reusable library, and maintainer release
operations separate while enforcing the same lint and test policy.

## Decisions

### Crate shape

The application package is the workspace root, alongside the unpublished `xtask` maintainer tool (`members = [".", "xtask"]`). The lint policy lives under `[workspace.lints]` and the package opts in with `[lints] workspace = true`, so a future member (for example a separately published API client crate) inherits the same floor without restructuring.

The package builds a library (`githits_scan`) and a binary (`githits-scan`). `src/main.rs` only parses arguments and returns an exit code; everything else is library code that tests reach without spawning a process. Binary-level contract tests in `tests/cli.rs` use `CARGO_BIN_EXE_githits-scan`.

### Toolchain and edition

Rust 1.99.1 pinned in `rust-toolchain.toml` with `edition = "2024"` and `rust-version = "1.99"`. The workflows select the same toolchain. The manifest requires Rust 1.99; CI tests the pinned 1.99.1 patch, with no separate MSRV matrix. Rust upgrades change the toolchain file, `Cargo.toml`, and the CI, release and publish `toolchain` inputs together. Refresh the installer action SHA independently when needed.

### Lint profile

The workspace lint profile includes `missing_docs`, `unreachable_pub`, `unsafe_code = "forbid"`, Clippy `all`, `pedantic`, and `nursery` as warnings under `RUSTFLAGS=-Dwarnings`, and denials for `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro`, `too_many_lines`, `too_many_arguments`, `excessive_nesting`, and `allow_attributes`. Thresholds are in `clippy.toml` (100 lines, 7 arguments, nesting 3). Product and format names that appear in prose are listed in `doc-valid-idents` so `doc_markdown` does not force backticks around brand names.

`missing_errors_doc` and `missing_panics_doc` are not relaxed. Every fallible public function documents its errors; this crate is a library that people will read to learn the API.

### Dependencies

Dependencies belong in the manifest only when used. HTTP uses `reqwest` with
explicit features and no default features. Domain errors use `thiserror`;
filesystem tests use `tempfile`. The current declarations are in `Cargo.toml`.

`deny.toml` owns allowed dependency licenses and advisory/source checks.
Add a license only when a locked dependency needs it and record the reason.

### Release profile

`lto = true`, `codegen-units = 1`, `strip = true`. The binary is small and compile time is not a concern; a single optimized profile is simpler than separate `dist` and `release` profiles.

### Quality gate

`scripts/check.sh` runs format check, strict Clippy, nextest, doctests, rustdoc with `-Dwarnings`, release metadata audit, source-package verification, and `cargo deny check`. Lint/test/doc commands cover the whole workspace. CI (`.github/workflows/ci.yml`) runs the same on Linux, `cargo test` on macOS and Windows because the tool ships to developer machines, `cargo-deny`, gitleaks over history, and actionlint plus zizmor for workflow hygiene. Every third-party action is SHA-pinned and every downloaded tool is SHA-256 verified. Dependabot updates Cargo and Actions weekly with a seven-day cooldown.

Pin `dtolnay/rust-toolchain` to a commit in its `master` history and select Rust
with `toolchain: 1.99.1`. Its generated version branches are rewritten; pins
from those branches can lose reachable history and fail the online workflow
audit. The [upstream pinning guidance](https://github.com/dtolnay/rust-toolchain#choice-of-full-length-commit-sha)
requires `master` history so commits remain available.
Upstream adds a `master` commit for every Rust release, and zizmor's
`ref-version-mismatch` audit then fails because the `# master` comment no longer
names the pinned commit. Re-pin to the new `master` head after checking that
the upstream delta leaves `action.yml` unchanged, or review the change when it
does not.

`.pre-commit-config.yaml` runs format, Clippy, rustdoc, cargo-deny on dependency
changes, and hygiene hooks. Tests and doctests run in CI rather than on every
commit; contributors run focused tests during development.

### Changelog

`CHANGELOG.md` is consolidated only at release time from fragments under `changes/`, one file per user-visible change with an explicit impact level. This avoids merge conflicts between parallel branches and keeps release notes reviewable. User-visible distribution changes also get a `none` fragment; purely internal changes need no fragment. The unpublished xtask validates and consolidates fragments; see `release-process.md`.

### Licensing

The code is distributed under Apache-2.0; see `LICENSE`. New fixtures must be
authored or have suitable public provenance and must contain no credentials or
private repository content.

Crates.io publication is a separate maintainer operation; see
[release process](release-process.md#cratesio-publication).

## Key Reference Files

| File | Demonstrates |
| --- | --- |
| `Cargo.toml` | Workspace lint inheritance and release profile |
| `clippy.toml` | Greenfield thresholds and `doc-valid-idents` |
| `deny.toml` | Dependency policy |
| `.github/workflows/ci.yml` | Pinned, verified CI gate |
| `scripts/check.sh` | The complete local quality gate |
| `src/catalog.rs` | The house style: pure data, exhaustive tests, documented public items |
