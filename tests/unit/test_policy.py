"""Guardrails policy loader: real file loads + hashes; bad weights refuse."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sagp.guardrails.policy import load_policy

REPO_POLICY = Path("config/guardrails.yaml")

# A valid injection section so minimal fixtures satisfy the (required) schema and
# fail for the reason under test, not for a missing section.
_INJ = (
    "injection:\n"
    "  labels:\n    positive_aliases: [injection]\n    negative_aliases: [safe]\n"
    "  window:\n    max_length: 512\n    stride: 128\n    max_windows: 16\n    aggregate: max\n"
    "  thresholds:\n    user_prompt: 0.85\n    doc_suspect: 0.70\n"
    "    doc_quarantine: 0.95\n    retrieval: 0.90\n"
)
_DEOBF = "deobfuscate:\n  codecs: [hex]\n  max_depth: 2\n  max_bytes: 1024\n"
_RET = "retrieval:\n  top_k: 6\n  min_score: 0.35\n  strong_score: 0.5\n  max_ctx_chars: 7000\n"


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
        "version: 1\nheuristics:\n  weights:\n    X: 1.5\n  block_rules: []\n"
        + _DEOBF
        + _INJ
        + _RET
    )
    with pytest.raises(ValidationError):
        load_policy(bad)


def test_extra_key_forbidden(tmp_path: Path) -> None:
    bad = tmp_path / "g.yaml"
    bad.write_text(
        "version: 1\nsurprise: true\nheuristics:\n  weights:\n    X: 0.9\n  block_rules: []\n"
        + _DEOBF
        + _INJ
        + _RET
    )
    with pytest.raises(ValidationError):
        load_policy(bad)


def test_injection_threshold_out_of_range_refuses(tmp_path: Path) -> None:
    bad = tmp_path / "g.yaml"
    bad.write_text(
        "version: 1\nheuristics:\n  weights:\n    X: 0.9\n  block_rules: []\n"
        + _DEOBF
        + _INJ.replace("user_prompt: 0.85", "user_prompt: 1.4")
        + _RET
    )
    with pytest.raises(ValidationError):
        load_policy(bad)


def test_sha256_changes_with_content(tmp_path: Path) -> None:
    body = (
        "version: 1\nheuristics:\n  weights:\n    X: 0.9\n  block_rules: []\n"
        + _DEOBF
        + _INJ
        + _RET
    )
    a = tmp_path / "a.yaml"
    a.write_text(body)
    b = tmp_path / "b.yaml"
    b.write_text(body.replace("X: 0.9", "X: 0.8"))
    assert load_policy(a).sha256 != load_policy(b).sha256
