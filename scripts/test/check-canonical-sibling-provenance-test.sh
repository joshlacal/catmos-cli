#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
exact_sibling=$(cd "$repo_root/../catbird-mls" && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/ws/catmos-cli"
rsync -a --exclude target --exclude _trash --exclude .jj --exclude .git "$repo_root/" "$fixture/ws/catmos-cli/"
ln -s "$exact_sibling" "$fixture/ws/catbird-mls"
ln -s "$repo_root/../catbird-atproto" "$fixture/ws/catbird-atproto"
ln -s "$repo_root/../labyrinth" "$fixture/ws/labyrinth"
ln -s "$repo_root/../Petrel" "$fixture/ws/Petrel"
ln -s "$repo_root/../PetrelCatbird" "$fixture/ws/PetrelCatbird"

checked_sibling=$(cd "$fixture/ws/catbird-mls" && pwd)
(cd "$fixture/ws/catmos-cli" && scripts/check-canonical-sibling-provenance.sh)
metadata=$(cd "$fixture/ws/catmos-cli" && CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo metadata --format-version 1 --locked)
resolved_manifest=$(jq -er '[.packages[] | select(.name == "catbird_mls") | .manifest_path] | if length == 1 then .[0] else error("expected one catbird_mls package") end' <<<"$metadata")
[[ "$resolved_manifest" == "$checked_sibling/Cargo.toml" ]]

if (cd "$fixture/ws/catmos-cli" && scripts/check-canonical-sibling-provenance.sh --sibling "$checked_sibling"); then
  printf 'expected sibling override to fail\n' >&2
  exit 1
fi
if (cd "$fixture/ws/catmos-cli" && scripts/check-canonical-sibling-provenance.sh --manifest /tmp/external-provenance.env); then
  printf 'expected external manifest override to fail\n' >&2
  exit 1
fi

mkdir -p "$fixture/ws/wrong"
rsync -a "$fixture/ws/catmos-cli/" "$fixture/ws/wrong/"
ln -s "$exact_sibling" "$fixture/ws/catbird-mls-alt"
sed 's#path = "../catbird-mls"#path = "../catbird-mls-alt"#' \
  "$fixture/ws/wrong/Cargo.toml" > "$fixture/ws/wrong/Cargo.toml.tmp"
mv "$fixture/ws/wrong/Cargo.toml.tmp" "$fixture/ws/wrong/Cargo.toml"
if (cd "$fixture/ws/wrong" && scripts/check-canonical-sibling-provenance.sh); then
  printf 'expected mismatched Cargo-resolved sibling to fail\n' >&2
  exit 1
fi

# Each recorded sibling commit is enforced: a wrong or missing value must fail.
zero_commit=0000000000000000000000000000000000000000
expect_manifest_failure() {
  local name=$1 sed_expr=$2 want=$3 dir="$fixture/ws/$1" err
  mkdir -p "$dir"
  rsync -a "$fixture/ws/catmos-cli/" "$dir/"
  sed "$sed_expr" "$fixture/ws/catmos-cli/scripts/canonical-sibling-provenance.env" \
    > "$dir/scripts/canonical-sibling-provenance.env"
  if cmp -s "$dir/scripts/canonical-sibling-provenance.env" \
    "$fixture/ws/catmos-cli/scripts/canonical-sibling-provenance.env"; then
    printf 'negative case %s did not change the manifest\n' "$name" >&2
    exit 1
  fi
  err="$fixture/$name.err"
  if (cd "$dir" && scripts/check-canonical-sibling-provenance.sh) 2>"$err"; then
    printf 'expected negative case %s to fail\n' "$name" >&2
    exit 1
  fi
  if ! grep -Fq "$want" "$err"; then
    printf 'negative case %s failed for the wrong reason (wanted: %s)\n' "$name" "$want" >&2
    cat "$err" >&2
    exit 1
  fi
}
expect_manifest_failure wrong-mls-commit "s/^CATBIRD_MLS_COMMIT=.*/CATBIRD_MLS_COMMIT=$zero_commit/" \
  "catbird-mls provenance mismatch"
expect_manifest_failure wrong-atproto-commit "s/^CATBIRD_ATPROTO_COMMIT=.*/CATBIRD_ATPROTO_COMMIT=$zero_commit/" \
  "catbird-atproto provenance mismatch"
expect_manifest_failure missing-atproto-commit '/^CATBIRD_ATPROTO_COMMIT=/d' \
  'missing provenance value: CATBIRD_ATPROTO_COMMIT'
expect_manifest_failure wrong-labyrinth-commit "s/^LABYRINTH_COMMIT=.*/LABYRINTH_COMMIT=$zero_commit/" \
  "labyrinth provenance mismatch"
expect_manifest_failure missing-labyrinth-commit '/^LABYRINTH_COMMIT=/d' \
  'missing provenance value: LABYRINTH_COMMIT'

expect_manifest_failure wrong-petrel-commit "s/^PETREL_COMMIT=.*/PETREL_COMMIT=$zero_commit/" \
  "Petrel provenance mismatch"
expect_manifest_failure wrong-overlay-commit "s/^PETREL_CATBIRD_COMMIT=.*/PETREL_CATBIRD_COMMIT=$zero_commit/" \
  "PetrelCatbird provenance mismatch"

# The empty working-copy commit of a sibling is not pinned, so a stale child id
# left in the manifest is ignored rather than breaking on the next jj snapshot.
mkdir -p "$fixture/ws/stale-child"
rsync -a "$fixture/ws/catmos-cli/" "$fixture/ws/stale-child/"
printf 'CATBIRD_MLS_CHILD=%s\n' "$zero_commit" >> "$fixture/ws/stale-child/scripts/canonical-sibling-provenance.env"
(cd "$fixture/ws/stale-child" && scripts/check-canonical-sibling-provenance.sh)

printf 'canonical sibling provenance guard test passed\n'
