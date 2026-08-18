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

required_mls='catbird-mls = { path = "../catbird-mls", package = "catbird_mls" }'
required_atproto='catbird-atproto = { path = "../catbird-atproto", features = ["streaming"] }'

if ! grep -Fqx "$required_mls" "$manifest"; then
  printf 'canonical catbird-mls dependency missing from manifest: %s\n' "$manifest" >&2
  exit 1
fi

if ! grep -Fqx "$required_atproto" "$manifest"; then
  printf 'canonical catbird-atproto dependency missing from manifest: %s\n' "$manifest" >&2
  exit 1
fi

printf 'canonical sibling dependency paths verified: %s\n' "$manifest"
