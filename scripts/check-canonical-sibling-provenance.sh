#!/usr/bin/env bash
set -euo pipefail

# No path overrides are accepted: production provenance comes only from this
# tracked checkout and the siblings Cargo resolves from its own manifest.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$repo_root/scripts/canonical-sibling-provenance.env"

if [[ $# -ne 0 ]]; then
  printf 'usage: %s\n' "$0" >&2
  exit 2
fi

[[ -f "$repo_root/Cargo.toml" ]] || { printf 'Cargo.toml not found: %s\n' "$repo_root/Cargo.toml" >&2; exit 1; }
[[ -f "$manifest" ]] || { printf 'provenance manifest not found: %s\n' "$manifest" >&2; exit 1; }
[[ -f "$repo_root/Cargo.lock" ]] || { printf 'tracked Cargo.lock not found: %s\n' "$repo_root/Cargo.lock" >&2; exit 1; }

manifest_value() {
  local key=$1 value
  value=$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$manifest")
  [[ -n "$value" ]] || { printf 'missing provenance value: %s\n' "$key" >&2; exit 1; }
  printf '%s' "$value"
}
manifest_value_optional() {
  local key=$1 fallback=$2 value
  value=$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$manifest")
  if [[ -n "$value" ]]; then printf '%s' "$value"; else printf '%s' "$fallback"; fi
}

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

if jq -e 'any(.packages[].name; test("^jacquard(-|$)") or . == "catbird-atproto")' "$metadata" >/dev/null; then
  printf 'CLI dependency graph still includes Jacquard or its generated types\n' >&2
  exit 1
fi

tree_of() {
  local root=$1 rev=$2 id
  id=$(cd "$root" && jj --ignore-working-copy log -r "$rev" --no-graph -T 'commit_id')
  (cd "$root" && jj --ignore-working-copy debug object commit "$id") |
    awk '!found && /TreeId\(/ { getline; gsub(/[",[:space:]]/, ""); print; found=1 }'
}

# verify_sibling <label> <dir-key> <default-dir> <commit-key> <package>...
# The sibling's working copy must be an empty change whose parent is the
# recorded commit, and Cargo must resolve every named package inside it. The
# empty working-copy commit id is not pinned because jj rewrites it whenever
# the sibling is snapshotted; its parent commit and tree are stable.
verified=()
last_tree=
verify_sibling() {
  local label=$1 dir_key=$2 default_dir=$3 commit_key=$4
  shift 4
  local rel root expected_commit status_output actual_parent parent_tree child_tree pkg resolved
  rel=$(manifest_value_optional "$dir_key" "$default_dir")
  root="$repo_root/$rel"
  [[ -d "$root" ]] || { printf '%s sibling not found: %s\n' "$label" "$root" >&2; exit 1; }
  root=$(cd "$root" && pwd)
  expected_commit=$(manifest_value "$commit_key")
  if [[ ! "$expected_commit" =~ ^[0-9a-f]{40}$ ]]; then
    printf '%s: %s is not a 40-character commit id: %s\n' "$label" "$commit_key" "$expected_commit" >&2
    exit 1
  fi

  for pkg in "$@"; do
    resolved=$(jq -er --arg n "$pkg" \
      '[.packages[] | select(.name == $n) | .manifest_path] | if length == 1 then .[0] else error("expected exactly one package named " + $n) end' \
      "$metadata")
    if [[ "$resolved" != "$root"/* ]]; then
      printf 'Cargo resolved %s outside checked %s sibling\nexpected under: %s\nactual:         %s\n' \
        "$pkg" "$label" "$root" "$resolved" >&2
      exit 1
    fi
  done

  status_output=$(cd "$root" && jj st)
  if ! grep -Fq 'The working copy has no changes.' <<<"$status_output"; then
    printf '%s sibling is dirty or conflicted: %s\n%s\n' "$label" "$root" "$status_output" >&2
    exit 1
  fi
  actual_parent=$(cd "$root" && jj --ignore-working-copy log -r '@-' --no-graph -T 'commit_id')
  if [[ "$actual_parent" != "$expected_commit" ]]; then
    printf '%s provenance mismatch\nexpected commit: %s\nactual @-:       %s\n' \
      "$label" "$expected_commit" "$actual_parent" >&2
    exit 1
  fi
  parent_tree=$(tree_of "$root" "$expected_commit")
  child_tree=$(tree_of "$root" '@')
  if [[ -z "$parent_tree" || "$parent_tree" != "$child_tree" ]]; then
    printf '%s working-copy tree %s differs from recorded commit tree %s\n' \
      "$label" "$child_tree" "$parent_tree" >&2
    exit 1
  fi
  verified+=("$label commit=$expected_commit tree=$parent_tree manifest_root=$root")
  last_tree=$parent_tree
}

verify_sibling catbird-mls CATBIRD_MLS_SIBLING_DIR ../catbird-mls CATBIRD_MLS_COMMIT catbird_mls
expected_mls_tree=$(manifest_value CATBIRD_MLS_TREE)
if [[ "$last_tree" != "$expected_mls_tree" ]]; then
  printf 'catbird-mls tree mismatch\nexpected tree: %s\nactual tree:   %s\n' "$expected_mls_tree" "$last_tree" >&2
  exit 1
fi
verify_sibling catbird-atproto CATBIRD_ATPROTO_SIBLING_DIR ../catbird-atproto CATBIRD_ATPROTO_COMMIT \
  atproto-spaces
verify_sibling Petrel PETREL_SIBLING_DIR ../Petrel PETREL_COMMIT petrel petrel-api petrel-core
verify_sibling PetrelCatbird PETREL_CATBIRD_SIBLING_DIR ../PetrelCatbird PETREL_CATBIRD_COMMIT petrel-catbird
verify_sibling labyrinth LABYRINTH_SIBLING_DIR ../labyrinth LABYRINTH_COMMIT labyrinth-protocol

printf 'exact Cargo-resolved sibling and lock provenance verified: lock=%s\n' "$actual_lock"
printf '  %s\n' "${verified[@]}"
