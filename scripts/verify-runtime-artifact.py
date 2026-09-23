#!/usr/bin/env python3
"""Verify retained runtime artifact bytes and, optionally, their source pins.

--production rejects local qualification binaries. Each --expect-source
NAME=COMMIT requires the manifest to record exactly that commit; with
--source-root, the named jj workspace there must also be clean and on it.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("manifest", type=Path)
parser.add_argument("--production", action="store_true")
parser.add_argument("--expect-source", action="append", default=[])
parser.add_argument("--source-root", type=Path)
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
for expectation in args.expect_source:
    name, commit = expectation.split("=", 1)
    if manifest.get("sources", {}).get(name) != commit:
        raise SystemExit(f"Rejected: {name} source is not {commit}")
    if args.source_root:
        workspace = args.source_root / name
        run = lambda *a: subprocess.run(["jj", "-R", str(workspace), *a], check=True,
                                        capture_output=True, text=True).stdout
        if "The working copy has no changes." not in run("st"):
            raise SystemExit(f"Rejected: {name} build workspace is dirty")
        if run("log", "-r", "@-", "--no-graph", "-T", "commit_id") != commit:
            raise SystemExit(f"Rejected: {name} build workspace is not on {commit}")
print("Artifact identity verified")
