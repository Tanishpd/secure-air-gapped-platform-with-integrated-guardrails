"""Entities policy loader: block/mask/allow tables, thresholds, sha256."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sagp.guardrails.entities import load_entities

REPO = Path("config/entities.yaml")


def test_repo_entities_load() -> None:
    e = load_entities(REPO)
    assert "CREDIT_CARD" in e.block_names
    assert "PERSON" in e.mask_names
    assert "DATE_TIME" in e.allow_names
    assert len(e.sha256) == 64


def test_binary_entities() -> None:
    e = load_entities(REPO)
    assert e.is_binary("CREDIT_CARD")
    assert e.is_binary("EMAIL_ADDRESS")
    assert e.ingress_threshold("CREDIT_CARD") == 0.0  # binary -> accept any Presidio hit
    assert not e.is_binary("PERSON")
    assert e.ingress_threshold("PERSON") == 0.50
    assert e.egress_threshold("PERSON") == 0.35


def test_unknown_entity_uses_defaults() -> None:
    e = load_entities(REPO)
    assert e.ingress_threshold("NOT_REGISTERED") == 0.50
    assert e.egress_threshold("NOT_REGISTERED") == 0.35


def test_bad_threshold_refuses(tmp_path: Path) -> None:
    bad = tmp_path / "e.yaml"
    bad.write_text(
        "version: 1\nblock: []\nmask:\n  - {name: PERSON, ingress: 1.5}\n"
        "allow: []\ndefaults: {ingress: 0.5, egress: 0.35}\n"
    )
    with pytest.raises(ValidationError):
        load_entities(bad)
