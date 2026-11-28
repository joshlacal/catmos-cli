#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
fixture_dir=$(mktemp -d)
trap 'rm -rf "$fixture_dir"' EXIT
fixture_manifest="$fixture_dir/Cargo.toml"
cp "$repo_root/Cargo.toml" "$fixture_manifest"

rewrite_fixture() {
  local temporary_manifest="$fixture_dir/Cargo.toml.tmp"
  sed "$@" "$fixture_manifest" > "$temporary_manifest"
  mv "$temporary_manifest" "$fixture_manifest"
}

rewrite_fixture \
  -e 's#path = "../catbird-mls"#path = "../.codex-workspaces/security-w1-catbird-mls-resolved-context"#' \
  -e 's#path = "../Petrel/rust/petrel"#path = "../.codex-workspaces/parked-petrel"#'

run_expect_failure() {
  local output status
  set +e
  output=$(bash "$repo_root/scripts/check-canonical-sibling-deps.sh" --manifest "$fixture_manifest" 2>&1)
  status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    printf 'expected guard failure, but command succeeded:\n%s\n' "$output" >&2
    exit 1
  fi
}

run_expect_success() {
  local output status
  set +e
  output=$(bash "$repo_root/scripts/check-canonical-sibling-deps.sh" --manifest "$fixture_manifest" 2>&1)
  status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    printf 'expected guard success, but command failed (status %s):\n%s\n' "$status" "$output" >&2
    exit 1
  fi
}

run_expect_failure

rewrite_fixture 's#path = "../\.codex-workspaces/security-w1-catbird-mls-resolved-context"#path = "../catbird-mls"#'
run_expect_failure

rewrite_fixture 's#path = "../\.codex-workspaces/parked-petrel"#path = "../Petrel/rust/petrel"#'
run_expect_success

printf 'canonical sibling dependency guard test passed\n'
