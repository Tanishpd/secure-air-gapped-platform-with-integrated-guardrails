"""Guardrails policy loader: real file loads + hashes; bad weights refuse."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sagp.guardrails.policy import load_policy

REPO_POLICY = Path("config/guardrails.yaml")


def test_repo_policy_loads_and_hashes() -> None:
    p = load_policy(REPO_POLICY)
    assert p.version == 1
    assert len(p.sha256) == 64
    assert p.heuristics.weights["DAN_PERSONA"] == 0.90
    assert "DELIMITER_SPOOF" in p.heuristics.block_rules
    assert p.deobfuscate.max_depth == 2


def test_weight_out_of_range_refuses(tmp_path: Path) -> None:
    bad = tmp_path / "g.yaml"
    bad.write_text(
        "version: 1\n"
        "heuristics:\n  weights:\n    X: 1.5\n  block_rules: []\n"
        "deobfuscate:\n  codecs: [hex]\n  max_depth: 2\n  max_bytes: 1024\n"
    )
    with pytest.raises(ValidationError):
        load_policy(bad)


def test_extra_key_forbidden(tmp_path: Path) -> None:
    bad = tmp_path / "g.yaml"
    bad.write_text(
        "version: 1\nsurprise: true\n"
        "heuristics:\n  weights:\n    X: 0.9\n  block_rules: []\n"
        "deobfuscate:\n  codecs: [hex]\n  max_depth: 2\n  max_bytes: 1024\n"
    )
    with pytest.raises(ValidationError):
        load_policy(bad)


def test_sha256_changes_with_content(tmp_path: Path) -> None:
    a = tmp_path / "a.yaml"
    body = (
        "version: 1\n"
        "heuristics:\n  weights:\n    X: 0.9\n  block_rules: []\n"
        "deobfuscate:\n  codecs: [hex]\n  max_depth: 2\n  max_bytes: 1024\n"
    )
    a.write_text(body)
    b = tmp_path / "b.yaml"
    b.write_text(body.replace("0.9", "0.8"))
    assert load_policy(a).sha256 != load_policy(b).sha256
