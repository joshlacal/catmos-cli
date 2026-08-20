#!/bin/bash
# Auto-sign and run: signs the binary with the stable Apple Development cert before executing.
# Keeps the code signature (and thus keychain item ACLs) identical across rebuilds,
# so macOS stops prompting for the login keychain password on every build.
codesign -s "Apple Development" -f "$1" || echo "warning: codesign failed; keychain prompts may reappear" >&2
exec "$@"
