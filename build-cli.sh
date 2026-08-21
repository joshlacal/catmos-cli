#!/bin/bash
# Build the catmos CLI and sign it with the stable Apple Development identity.
#
# Why this exists: a plain `cargo build` leaves the binary ad-hoc signed, and the
# ad-hoc signature changes on every rebuild. macOS keychain ACLs are bound to the
# code signature, so every rebuild would otherwise look like a brand-new app and
# re-prompt for the login keychain password on each stored MLS key.
#
# Always build through this script (or run codesign yourself afterwards).
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

PROFILE="${1:-debug}"
case "$PROFILE" in
  debug)   CARGO_ARGS=() ;;
  release) CARGO_ARGS=(--release) ;;
  *) echo "usage: $0 [debug|release]" >&2; exit 2 ;;
esac

CMAKE_POLICY_VERSION_MINIMUM=3.5 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" \
  cargo build -p catmos ${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"}

BIN="target/$PROFILE/catmos"
codesign -s "Apple Development" -f "$BIN"
codesign -dv "$BIN" 2>&1 | grep -E 'TeamIdentifier|Signature' || true
echo "signed: $BIN"
