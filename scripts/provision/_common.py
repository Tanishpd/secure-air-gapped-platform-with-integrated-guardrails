"""Shared helpers for the provisioning scripts (run with .venv-provision).

Stdlib + tomllib only, so these helpers do not depend on the runtime package.
ROOT is the repo root (parent of scripts/); every path is derived from it with
pathlib, so spaces in the repo path are never a problem.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS_LOCK = ROOT / "artifacts.lock"


def load_artifacts() -> dict:
    with ARTIFACTS_LOCK.open("rb") as fh:
        return tomllib.load(fh)


def log(step: str, msg: str) -> None:
    print(f"[{step}] {msg}", flush=True)


def die(step: str, msg: str) -> None:
    print(f"[{step}] FAIL: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def human(n: int) -> str:
    x = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if x < 1024 or unit == "GB":
            return f"{x:.1f} {unit}"
        x /= 1024
    return f"{x:.1f} GB"
