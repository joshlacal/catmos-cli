#!/usr/bin/env python3
"""Reject local qualification binaries when validating a production artifact."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("manifest", type=Path)
parser.add_argument("--production", action="store_true")
args = parser.parse_args()
manifest = json.loads(args.manifest.read_text())
if args.production and (manifest.get("fixtureOnly") is not False
                        or "local-runtime-fixture" in manifest.get("features", [])):
    raise SystemExit("Rejected: local-runtime-fixture artifacts are not production eligible")
for artifact in manifest["binaries"]:
    with open(artifact["path"], "rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    if digest != artifact["sha256"]:
        raise SystemExit("Rejected: artifact bytes differ from retained manifest")
print("Artifact identity verified")
