#!/usr/bin/env bash
# Prepares a new Orca worktree for local development.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ -n "${ORCA_ROOT_PATH:-}" && -d "$ORCA_ROOT_PATH" ]]; then
  MAIN_DIR="$ORCA_ROOT_PATH"
else
  MAIN_DIR=$(git worktree list --porcelain | awk '
    /^worktree / { path = substr($0, 10) }
    $0 == "branch refs/heads/main" { print path; exit }
  ')
fi

if [[ -z "$MAIN_DIR" ]]; then
  echo "orca-setup: no main worktree found" >&2
  exit 1
fi

build_directory() {
  cargo metadata --format-version 1 --no-deps 2>/dev/null | python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
print(metadata.get("build_directory") or metadata["target_directory"])
'
}

# Copy-on-write clone only (APFS clonefile on macOS, reflinks on Linux); a
# full copy of a large build directory would cost more than rebuilding.
clone_tree() {
  cp -cR "$1/." "$2/" 2>/dev/null || cp -R --reflink=always "$1/." "$2/" 2>/dev/null
}

SOURCE_BUILD=$(cd "$MAIN_DIR" && build_directory)
DESTINATION_BUILD=$(build_directory)
DESTINATION_CACHE_ENTRY=$(find "$DESTINATION_BUILD" \
  -mindepth 1 \
  -maxdepth 1 \
  ! -name '.rustc_info.json' \
  ! -name '.rustdoc_fingerprint.json' \
  ! -name 'CACHEDIR.TAG' \
  -print \
  -quit 2>/dev/null || true)

if [[ "$SOURCE_BUILD" == "$DESTINATION_BUILD" ]]; then
  echo "orca-setup: build cache already belongs to this worktree"
elif [[ -n "$DESTINATION_CACHE_ENTRY" ]]; then
  echo "orca-setup: worktree build cache already initialized"
elif [[ -d "$SOURCE_BUILD" ]] && mkdir -p "$DESTINATION_BUILD" && clone_tree "$SOURCE_BUILD" "$DESTINATION_BUILD"; then
  echo "orca-setup: cloned build cache from $SOURCE_BUILD"
else
  # The destination held no cache entries before the attempt, so a partial
  # clone is discarded rather than left as a broken cache.
  [[ -d "$DESTINATION_BUILD" ]] && rm -rf "${DESTINATION_BUILD:?}"/*
  echo "orca-setup: no copy-on-write build cache available; starting empty"
fi

if [[ "$PROJECT_ROOT" != "$MAIN_DIR" && -f "$MAIN_DIR/.env.local" ]]; then
  install -m 600 "$MAIN_DIR/.env.local" .env.local
  echo "orca-setup: copied local environment configuration"
else
  echo "orca-setup: no local environment configuration to copy"
fi

PRE_COMMIT_HOOK=$(git rev-parse --git-path hooks/pre-commit)

if [[ -x "$PRE_COMMIT_HOOK" ]] && grep -q 'pre_commit' "$PRE_COMMIT_HOOK"; then
  echo "orca-setup: pre-commit hook already installed"
elif git config --get core.hooksPath >/dev/null; then
  echo "orca-setup: core.hooksPath is set but has no pre-commit hook" >&2
  exit 1
elif command -v pre-commit >/dev/null 2>&1; then
  pre-commit install
  echo "orca-setup: pre-commit hook installed"
else
  echo "orca-setup: pre-commit is not installed; hook was not installed" >&2
fi

echo "orca-setup: worktree ready"
