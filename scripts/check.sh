#!/usr/bin/env bash
# Runs the complete local quality gate. CI runs the same commands; keep them in
# sync with .github/workflows/ci.yml and AGENTS.md.
#
# Usage: scripts/check.sh [--fast]
#   --fast  Skip cargo-deny (network access to the advisory database).

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

fast=false
if [[ "${1:-}" == "--fast" ]]; then
  fast=true
fi

run() {
  echo "==> $*"
  "$@"
}

run cargo xtask release audit
run cargo fmt --all --check
run cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
run cargo nextest run --locked --workspace --all-targets --all-features
run cargo test --locked --workspace --all-features --doc
RUSTDOCFLAGS="-Dwarnings" run cargo doc --locked --workspace --all-features --no-deps
if ! $fast; then
  run cargo deny check
fi

# Package the working tree being reviewed; CI packages a clean checkout.
run cargo package --locked -p githits-scan --allow-dirty

echo "==> all checks passed"
