#!/usr/bin/env bash
set -euo pipefail

# No path overrides are accepted: production provenance comes only from this
# tracked checkout and the sibling Cargo resolves from its own manifest.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
sibling_root="$repo_root/../catbird-mls"
manifest="$repo_root/scripts/canonical-sibling-provenance.env"

if [[ $# -ne 0 ]]; then
  printf 'usage: %s\n' "$0" >&2
  exit 2
fi

[[ -f "$repo_root/Cargo.toml" ]] || { printf 'Cargo.toml not found: %s\n' "$repo_root/Cargo.toml" >&2; exit 1; }
[[ -f "$manifest" ]] || { printf 'provenance manifest not found: %s\n' "$manifest" >&2; exit 1; }
[[ -f "$repo_root/Cargo.lock" ]] || { printf 'tracked Cargo.lock not found: %s\n' "$repo_root/Cargo.lock" >&2; exit 1; }
[[ -d "$sibling_root" ]] || { printf 'catbird-mls sibling not found: %s\n' "$sibling_root" >&2; exit 1; }

manifest_value() {
  local key=$1 value
  value=$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$manifest")
  [[ -n "$value" ]] || { printf 'missing provenance value: %s\n' "$key" >&2; exit 1; }
  printf '%s' "$value"
}

expected_commit=$(manifest_value CATBIRD_MLS_COMMIT)
expected_child=$(manifest_value CATBIRD_MLS_CHILD)
expected_tree=$(manifest_value CATBIRD_MLS_TREE)
expected_lock=$(manifest_value CATMOS_CLI_LOCK_SHA256)

actual_lock=$(shasum -a 256 "$repo_root/Cargo.lock" | awk '{print $1}')
if [[ "$actual_lock" != "$expected_lock" ]]; then
  printf 'Cargo.lock provenance mismatch: expected %s, got %s\n' "$expected_lock" "$actual_lock" >&2
  exit 1
fi

metadata=$(mktemp)
metadata_error=$(mktemp)
trap 'rm -f "$metadata" "$metadata_error"' EXIT
if ! CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo metadata \
  --manifest-path "$repo_root/Cargo.toml" --format-version 1 --locked > "$metadata" 2>"$metadata_error"; then
  printf 'locked Cargo metadata failed; refusing unverified sibling provenance\n' >&2
  cat "$metadata_error" >&2
  exit 1
fi
resolved_mls_manifest=$(jq -er '[.packages[] | select(.name == "catbird_mls") | .manifest_path] | if length == 1 then .[0] else error("expected one catbird_mls package") end' "$metadata")
expected_mls_manifest=$(cd "$sibling_root" && pwd)/Cargo.toml
if [[ "$resolved_mls_manifest" != "$expected_mls_manifest" ]]; then
  printf 'Cargo resolved catbird_mls outside checked sibling\nexpected: %s\nactual:   %s\n' \
    "$expected_mls_manifest" "$resolved_mls_manifest" >&2
  exit 1
fi

status_output=$(cd "$sibling_root" && jj st)
if ! grep -Fq 'The working copy has no changes.' <<<"$status_output"; then
  printf 'catbird-mls sibling is dirty or conflicted: %s\n%s\n' "$sibling_root" "$status_output" >&2
  exit 1
fi

actual_child=$(cd "$sibling_root" && jj log -r '@' --no-graph -T 'commit_id')
actual_parent=$(cd "$sibling_root" && jj log -r '@-' --no-graph -T 'commit_id')
actual_tree=$(cd "$sibling_root" && jj debug object commit "$actual_child" | awk '/TreeId\(/ { getline; gsub(/[",[:space:]]/, ""); print; exit }')

if [[ "$actual_child" != "$expected_child" || "$actual_parent" != "$expected_commit" || "$actual_tree" != "$expected_tree" ]]; then
  printf 'catbird-mls provenance mismatch\nexpected child: %s\nactual child:   %s\nexpected parent: %s\nactual parent:   %s\nexpected tree:   %s\nactual tree:     %s\n' \
    "$expected_child" "$actual_child" "$expected_commit" "$actual_parent" "$expected_tree" "$actual_tree" >&2
  exit 1
fi

printf 'exact Cargo-resolved catbird-mls and lock provenance verified: manifest=%s child=%s parent=%s tree=%s lock=%s\n' \
  "$resolved_mls_manifest" "$actual_child" "$actual_parent" "$actual_tree" "$actual_lock"
