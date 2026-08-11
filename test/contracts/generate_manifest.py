#!/usr/bin/env python3
"""Generate test/contracts/manifest.json — SHA-256 of every frozen artifact.

Deterministic: paths sorted, no timestamps. Frozen artifact roots:
  docs/protocol.md, docs/state-model.md, docs/installer-contract.md,
  docs/test-strategy.md, docs/error-codes.md,
  api/openapi.yaml,
  internal/protocol/testdata/** (json),
  test/fixtures/compat/**, test/fixtures/installer-contract/** (json).

Usage: python3 test/contracts/generate_manifest.py [repo-root]
"""

import hashlib
import json
import os
import sys

REPO_ROOT = sys.argv[1] if len(sys.argv) > 1 else "."

MANIFEST_PATH = f"{REPO_ROOT}/test/contracts/manifest.json"

VALIDATION_COMMAND = "go test ./test/contracts/... -count=1 -v"

FROZEN_PATHS = [
    "docs/protocol.md",
    "docs/state-model.md",
    "docs/installer-contract.md",
    "docs/test-strategy.md",
    "docs/error-codes.md",
    "api/openapi.yaml",
]

FROZEN_DIRS = [
    "internal/protocol/testdata",
    "test/fixtures/compat",
    "test/fixtures/installer-contract",
    "test/contracts/testdata/state-model",
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_frozen():
    files = []
    for rel in FROZEN_PATHS:
        files.append(rel)
    for d in FROZEN_DIRS:
        for root, _dirs, names in sorted(os.walk(os.path.join(REPO_ROOT, d))):
            for name in sorted(names):
                if name.endswith(".json"):
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, REPO_ROOT)
                    files.append(rel)
    return sorted(set(files))


def main():
    frozen = collect_frozen()
    if not frozen:
        print("no frozen artifacts found", file=sys.stderr)
        return 1
    manifest = {
        "schema": "antinat.contracts/manifest/v1",
        "contract_revision": "v1.0-beta",
        "validation_command": VALIDATION_COMMAND,
        "artifacts": [
            {"path": rel, "sha256": sha256_file(os.path.join(REPO_ROOT, rel))}
            for rel in frozen
        ],
    }
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print(f"wrote {MANIFEST_PATH}: {len(frozen)} artifacts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
