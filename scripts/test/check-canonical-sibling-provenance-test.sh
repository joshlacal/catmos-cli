#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
exact_sibling=$(cd "$repo_root/../.codex-workspaces/task1-clean-chat-signed-request" && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/catmos-cli"
rsync -a --exclude target --exclude .jj --exclude .git "$repo_root/" "$fixture/catmos-cli/"
ln -s "$exact_sibling" "$fixture/catbird-mls"
ln -s "$repo_root/../catbird-atproto" "$fixture/catbird-atproto"

checked_sibling=$(cd "$fixture/catbird-mls" && pwd)
(cd "$fixture/catmos-cli" && scripts/check-canonical-sibling-provenance.sh)
metadata=$(cd "$fixture/catmos-cli" && CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo metadata --format-version 1 --locked)
resolved_manifest=$(jq -er '[.packages[] | select(.name == "catbird_mls") | .manifest_path] | if length == 1 then .[0] else error("expected one catbird_mls package") end' <<<"$metadata")
[[ "$resolved_manifest" == "$checked_sibling/Cargo.toml" ]]

if (cd "$fixture/catmos-cli" && scripts/check-canonical-sibling-provenance.sh --sibling "$checked_sibling"); then
  printf 'expected sibling override to fail\n' >&2
  exit 1
fi
if (cd "$fixture/catmos-cli" && scripts/check-canonical-sibling-provenance.sh --manifest /tmp/external-provenance.env); then
  printf 'expected external manifest override to fail\n' >&2
  exit 1
fi

mkdir -p "$fixture/wrong"
rsync -a "$fixture/catmos-cli/" "$fixture/wrong/"
ln -s "$exact_sibling" "$fixture/catbird-mls-alt"
sed 's#path = "../catbird-mls"#path = "../catbird-mls-alt"#' \
  "$fixture/wrong/Cargo.toml" > "$fixture/wrong/Cargo.toml.tmp"
mv "$fixture/wrong/Cargo.toml.tmp" "$fixture/wrong/Cargo.toml"
if (cd "$fixture/wrong" && scripts/check-canonical-sibling-provenance.sh); then
  printf 'expected mismatched Cargo-resolved sibling to fail\n' >&2
  exit 1
fi

printf 'canonical sibling provenance guard test passed\n'
