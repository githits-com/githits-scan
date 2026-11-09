//! Library behind the `githits-scan` command-line tool.
//!
//! The binary in `src/main.rs` is a thin entry point; every behavior lives here so
//! it can be tested through public boundaries without spawning a process.
//!
//! This library is not a supported API. Its items may change in any release,
//! including patch releases; the stable interface is the command line (arguments,
//! exit codes, and JSON output) documented in the README.
//!
//! Module ownership:
//!
//! - [`catalog`] owns the knowledge of which repository files are package
//!   evidence (lockfiles and the manifests that own them) and which package
//!   family each belongs to. It is pure data and has no I/O.
//! - [`api`] owns the lockfile-job and paired dependency-diff submission contracts:
//!   upload limits and filename rules, problem documents, and HTTP requests.
//!   Nothing else constructs requests or interprets status codes.
//!   [`api::licenses`] validates license reports and retains their original JSON;
//!   [`commands::license::report`] selects their source and renders evidence.
//! - [`mod@env`] owns resolving the token and origin from the process
//!   environment through an injected source.
//! - [`license`] owns license policy evaluation over a CycloneDX document:
//!   SPDX expressions against the allow list and per-package exceptions. Pure.
//! - The pure audit interpreter owns attribution/coverage accounting and count/group
//!   recomputation over producer evidence; it never assesses advisories or upgrades.
//! - [`discover`] owns walking a directory tree, applying ignore rules, and
//!   pairing lockfiles with the manifests that own them. It is the only
//!   module that reads the filesystem during a scan.
//! - [`repository`] supplies immutable local Git inputs for experimental diff; it
//!   reuses discovery pairing and bounded command upload selection.
//! - Dependency diff consumes source-local comparison and upgrade evidence from the service.
//! - [`commands`] owns orchestration and rendering for each command; handlers
//!   write to injected streams and report typed outcomes and errors.
//! - [`style`] owns terminal styling; renderers receive a palette and never
//!   decide whether color is appropriate.
//! - [`cli`] owns the command-line contract: argument names, help text, exit
//!   codes, and the mapping from parsed arguments to command handlers.

pub mod api;
#[expect(
    clippy::redundant_pub_crate,
    reason = "explicit crate-only interpretation visibility satisfies unreachable_pub without exporting consumer internals"
)]
mod audit;
pub mod catalog;
pub mod cli;
pub mod commands;
pub mod config;
pub mod discover;
pub mod env;
pub mod license;
pub mod repository;
pub mod style;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
