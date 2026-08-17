#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
exact_sibling=$(cd "$repo_root/../.codex-workspaces/task1-clean-chat-signed-request" && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/scripts"
cp "$repo_root/Cargo.lock" "$fixture/Cargo.lock"
cp "$repo_root/scripts/canonical-sibling-provenance.env" "$fixture/scripts/"
cp "$repo_root/scripts/check-canonical-sibling-provenance.sh" "$fixture/scripts/"
ln -s "$exact_sibling" "$fixture/catbird-mls"

bash "$fixture/scripts/check-canonical-sibling-provenance.sh" \
  --repo-root "$fixture" --sibling "$fixture/catbird-mls"

sed 's/^CATBIRD_MLS_CHILD=.*/CATBIRD_MLS_CHILD=0000000000000000000000000000000000000000000000000000000000000000/' \
  "$fixture/scripts/canonical-sibling-provenance.env" > "$fixture/scripts/wrong.env"
if bash "$fixture/scripts/check-canonical-sibling-provenance.sh" \
  --repo-root "$fixture" --sibling "$fixture/catbird-mls" \
  --manifest "$fixture/scripts/wrong.env"; then
  printf 'expected wrong sibling provenance to fail\n' >&2
  exit 1
fi

sed 's/^CATMOS_CLI_LOCK_SHA256=.*/CATMOS_CLI_LOCK_SHA256=0000000000000000000000000000000000000000000000000000000000000000/' \
  "$fixture/scripts/canonical-sibling-provenance.env" > "$fixture/scripts/wrong-lock.env"
if bash "$fixture/scripts/check-canonical-sibling-provenance.sh" \
  --repo-root "$fixture" --sibling "$fixture/catbird-mls" \
  --manifest "$fixture/scripts/wrong-lock.env"; then
  printf 'expected wrong lock provenance to fail\n' >&2
  exit 1
fi

printf 'canonical sibling provenance guard test passed\n'
