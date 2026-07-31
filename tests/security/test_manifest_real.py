"""The REAL provisioned + signed manifest verifies (complements the fixture-based
tests/unit/test_manifest.py, which covers tamper/unmanifested/quick on tmp trees)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sagp.netguard.manifest import verify

_MANIFEST = Path("models") / "MANIFEST.json"


@pytest.mark.needs_models
def test_real_signed_manifest_full_verifies() -> None:
    if not _MANIFEST.exists():
        pytest.skip("models/MANIFEST.json not provisioned")
    res = verify(Path.cwd(), mode="full")
    assert res.ok, res.problems
    assert res.root_hash and len(res.root_hash) == 64
