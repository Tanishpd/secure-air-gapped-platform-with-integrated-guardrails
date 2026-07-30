#!/usr/bin/env bash
# 01 — build the offline wheelhouse for the sealed runtime install.
# Downloads the runtime closure as cp311 macosx arm64 wheels into vendor/wheelhouse,
# so the post-seal `pip install --no-index` is reproducible and offline. The real
# arm64 platform tag for torch 2.x / onnxruntime 1.28 is macosx_14_0, NOT macosx_11_0.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="$ROOT/vendor/wheelhouse"
PIP="$ROOT/.venv/bin/pip"
mkdir -p "$DEST"

echo "[01_wheelhouse] downloading runtime closure -> vendor/wheelhouse"
# Resolve the runtime deps from pyproject (the installed runtime venv is the source of truth).
"$PIP" download \
  --dest "$DEST" \
  --python-version 3.11 --implementation cp --abi cp311 \
  --platform macosx_14_0_arm64 --platform macosx_11_0_arm64 --only-binary=:all: \
  -e "$ROOT" >/dev/null 2>&1 || {
    # -e is not downloadable; fall back to freezing the installed runtime set.
    "$ROOT/.venv/bin/pip" freeze | grep -v '^-e ' | grep -iv '^sagp' > "$ROOT/vendor/runtime.frozen.txt"
    "$PIP" download \
      --dest "$DEST" \
      --python-version 3.11 --implementation cp --abi cp311 \
      --platform macosx_14_0_arm64 --platform macosx_11_0_arm64 --only-binary=:all: \
      -r "$ROOT/vendor/runtime.frozen.txt"
  }

n="$(find "$DEST" -name '*.whl' | wc -l | tr -d ' ')"
echo "[01_wheelhouse] $n wheels in $DEST"
echo "[01_wheelhouse] done"
