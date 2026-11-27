#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$repo_root/Cargo.toml"

if [[ $# -gt 0 ]]; then
  if [[ $# -ne 2 || $1 != "--manifest" ]]; then
    printf 'usage: %s [--manifest PATH]\n' "$0" >&2
    exit 2
  fi
  manifest=$2
fi

if [[ ! -f "$manifest" ]]; then
  printf 'manifest not found: %s\n' "$manifest" >&2
  exit 1
fi

if grep -Fq '.codex-workspaces' "$manifest"; then
  printf 'parked dependency path rejected in manifest: %s\n' "$manifest" >&2
  exit 1
fi

required_mls_canonical='catbird-mls = { path = "../catbird-mls", package = "catbird_mls", features = ["legacy-orchestrator"] }'
for expected in \
  "$required_mls_canonical" \
  'petrel = { path = "../Petrel/rust/petrel" }' \
  'petrel-core = { path = "../Petrel/rust/petrel-core" }' \
  'petrel-api = { path = "../Petrel/rust/petrel-api", features = ["com_atproto"] }' \
  'petrel-catbird = { path = "../PetrelCatbird/rust/petrel-catbird" }'; do
  if ! grep -Fqx "$expected" "$manifest"; then
    printf 'canonical dependency missing: %s\n' "$expected" >&2
    exit 1
  fi
done

printf 'canonical sibling dependency paths verified: %s\n' "$manifest"
