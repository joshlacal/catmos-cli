#!/usr/bin/env bash
# Build the fixture-only CLI runtime artifacts from exact, clean, pinned sources
# and record their provenance. Rerunnable: the same private jj workspaces are
# moved to the requested commits on every run.
#
# usage: build-fixture-runtime-artifacts.sh --label NAME \
#          --cli REV --mls REV --atproto REV --ds REV --out DIR [--build-root DIR]
#
# REV is any jj revision in the corresponding shared repository. The script
# never edits shared working copies: it creates (or reuses) workspaces named
# `fixture-build` under --build-root laid out so the path dependencies
# (../catbird-mls, ../catbird-atproto, ../../catbird-mls) resolve inside it.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
build_root="$root/../fixture-build-catmos-cli"
label= cli= mls= atproto= ds= out=
while [[ $# -gt 0 ]]; do
  case $1 in
    --label) label=$2 ;;
    --cli) cli=$2 ;;
    --mls) mls=$2 ;;
    --atproto) atproto=$2 ;;
    --ds) ds=$2 ;;
    --out) out=$2 ;;
    --build-root) build_root=$2 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift 2
done
for v in label cli mls atproto ds out; do
  [[ -n ${!v} ]] || { printf 'missing --%s\n' "$v" >&2; exit 2; }
done
[[ $out = /* && ! -e $out ]] || { printf -- '--out must be a new absolute path\n' >&2; exit 2; }
mkdir -p "$build_root" "$out"
build_root=$(cd "$build_root" && pwd)

# name shared-repo revision
pin() {
  local name=$1 shared="$root/$1" rev=$2 dir="$build_root/$1" commit
  commit=$(jj -R "$shared" log -r "$rev" --no-graph -T commit_id)
  [[ $commit =~ ^[0-9a-f]{40}$ ]] || { printf '%s: %s is not one commit\n' "$name" "$rev" >&2; exit 1; }
  if [[ -d $dir/.jj ]]; then
    jj -R "$dir" new "$commit" >/dev/null 2>&1
  else
    jj -R "$shared" workspace add --name fixture-build --revision "$commit" "$dir" >/dev/null 2>&1
  fi
  grep -Fq 'The working copy has no changes.' <<<"$(jj -R "$dir" st)" \
    || { printf '%s private workspace is not clean\n' "$name" >&2; exit 1; }
  [[ $(jj -R "$dir" log -r '@-' --no-graph -T commit_id) == "$commit" ]] \
    || { printf '%s private workspace is not on %s\n' "$name" "$commit" >&2; exit 1; }
  printf '%s' "$commit"
}
cli_commit=$(pin catmos-cli "$cli")
mls_commit=$(pin catbird-mls "$mls")
atproto_commit=$(pin catbird-atproto "$atproto")
ds_commit=$(pin mls-ds "$ds")

export CMAKE_POLICY_VERSION_MINIMUM=3.5
log="$out/build.log"
(
  set -x
  cargo build --locked --manifest-path "$build_root/mls-ds/server/Cargo.toml" \
    --features test-support --bin encrypted_request_server_fixture
  cargo build --locked --manifest-path "$build_root/catmos-cli/Cargo.toml" \
    -p catmos --features local-runtime-fixture --bin catmos
  cargo build --locked --manifest-path "$build_root/catmos-cli/Cargo.toml" \
    -p catmos-core --features local-runtime-fixture --example seed_local_request_profile
) >"$log" 2>&1
runner=$(cargo test --locked --manifest-path "$build_root/catmos-cli/Cargo.toml" \
  -p catmos-core --features local-runtime-fixture --test shipping_request_runtime \
  --no-run --message-format=json 2>>"$log" \
  | jq -r 'select(.reason=="compiler-artifact" and .target.name=="shipping_request_runtime" and .executable!=null) | .executable')
[[ -x $runner ]] || { printf 'runner executable missing; see %s\n' "$log" >&2; exit 1; }

identifier="blue.catbird.synthetic.clicases.$(uuidgen | tr 'A-Z' 'a-z')"
cp "$build_root/catmos-cli/target/debug/catmos" "$out/catmos"
cp "$build_root/catmos-cli/target/debug/examples/seed_local_request_profile" "$out/seed_local_request_profile"
cp "$runner" "$out/shipping_request_runtime"
cp "$build_root/mls-ds/target/debug/encrypted_request_server_fixture" "$out/encrypted_request_server_fixture"
# The CLI and seeder share one designated requirement so the seeded OS-keychain
# items are readable by the CLI without changing any keychain ACL.
for binary in catmos seed_local_request_profile shipping_request_runtime; do
  codesign --force --sign "Apple Development" --identifier "$identifier" "$out/$binary" >>"$log" 2>&1
done

sha() { shasum -a 256 "$1" | awk '{print $1}'; }
requirement() { codesign -d -r- "$1" 2>&1 | sed -n 's/^designated => //p'; }
jq -n \
  --arg label "$label" --arg identifier "$identifier" \
  --arg cli "$cli_commit" --arg mls "$mls_commit" --arg atproto "$atproto_commit" --arg ds "$ds_commit" \
  --arg cliLock "$(sha "$build_root/catmos-cli/Cargo.lock")" \
  --arg dsLock "$(sha "$build_root/mls-ds/Cargo.lock")" \
  --arg mlsLock "$(sha "$build_root/catbird-mls/Cargo.lock")" \
  --arg rustc "$(rustc --version)" --arg built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg catmos "$out/catmos" --arg catmosSha "$(sha "$out/catmos")" --arg catmosReq "$(requirement "$out/catmos")" \
  --arg seed "$out/seed_local_request_profile" --arg seedSha "$(sha "$out/seed_local_request_profile")" --arg seedReq "$(requirement "$out/seed_local_request_profile")" \
  --arg runner "$out/shipping_request_runtime" --arg runnerSha "$(sha "$out/shipping_request_runtime")" \
  --arg server "$out/encrypted_request_server_fixture" --arg serverSha "$(sha "$out/encrypted_request_server_fixture")" \
  '{fixtureOnly:true, features:["local-runtime-fixture"], sourcePairLabel:$label,
    sources:{"catmos-cli":$cli, "catbird-mls":$mls, "catbird-atproto":$atproto, "mls-ds":$ds},
    cargoLockSha256:{"catmos-cli":$cliLock, "catbird-mls":$mlsLock, "mls-ds":$dsLock},
    toolchain:$rustc, builtAt:$built, signingIdentifier:$identifier, signingIdentity:"Apple Development",
    binaries:[
      {role:"cli", path:$catmos, sha256:$catmosSha, designatedRequirement:$catmosReq},
      {role:"seeder", path:$seed, sha256:$seedSha, designatedRequirement:$seedReq},
      {role:"runner", path:$runner, sha256:$runnerSha},
      {role:"serviceFixture", path:$server, sha256:$serverSha}]}' >"$out/artifact-manifest.json"

python3 "$here/verify-runtime-artifact.py" "$out/artifact-manifest.json" \
  --expect-source "catmos-cli=$cli_commit" --expect-source "catbird-mls=$mls_commit" \
  --expect-source "catbird-atproto=$atproto_commit" --expect-source "mls-ds=$ds_commit" \
  --source-root "$build_root" | tee "$out/verify.log"
if python3 "$here/verify-runtime-artifact.py" "$out/artifact-manifest.json" --production >>"$out/verify.log" 2>&1; then
  printf 'production guard accepted a fixture artifact\n' >&2; exit 1
fi
printf 'production guard rejected fixture artifact (expected)\n' | tee -a "$out/verify.log"
printf '%s\n' "$out/artifact-manifest.json"
