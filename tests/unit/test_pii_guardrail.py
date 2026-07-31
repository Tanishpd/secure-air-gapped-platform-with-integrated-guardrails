"""PII guardrail end-to-end against real Presidio + spaCy: mask, block, alias, deadline."""

from __future__ import annotations

import time

import pytest

from sagp.errors import GuardrailUnavailable, PromptRejected
from sagp.guardrails.pii import PiiGuardrail
from sagp.guardrails.vault import PiiVault


def test_masks_person_and_email(pii_guardrail: PiiGuardrail) -> None:
    vault = PiiVault()
    res = pii_guardrail.run_input("Email Alice Smith at alice@example.com please.", vault)
    assert "alice@example.com" not in res.masked_text
    assert "Alice Smith" not in res.masked_text
    assert "<EMAIL_ADDRESS_1>" in res.masked_text
    assert "<PERSON_1>" in res.masked_text
    assert res.entity_types.get("EMAIL_ADDRESS") == 1
    assert res.entity_types.get("PERSON") == 1


def test_credit_card_is_blocked(pii_guardrail: PiiGuardrail) -> None:
    vault = PiiVault()
    with pytest.raises(PromptRejected):
        pii_guardrail.run_input("my card is 4111 1111 1111 1111", vault)


def test_api_key_is_blocked(pii_guardrail: PiiGuardrail) -> None:
    vault = PiiVault()
    with pytest.raises(PromptRejected):
        pii_guardrail.run_input("here is my key AKIA1234567890ABCDEF for access", vault)


def test_person_aliases_share_one_placeholder(pii_guardrail: PiiGuardrail) -> None:
    vault = PiiVault()
    res = pii_guardrail.run_input("Alice Smith joined. Later, Alice approved the request.", vault)
    # Both mentions collapse to a single PERSON placeholder — no <PERSON_2> person.
    assert "<PERSON_1>" in res.masked_text
    assert "<PERSON_2>" not in res.masked_text
    assert res.masked_text.count("<PERSON_1>") == 2


def test_benign_text_unmasked(pii_guardrail: PiiGuardrail) -> None:
    vault = PiiVault()
    res = pii_guardrail.run_input("How many days of parental leave am I entitled to?", vault)
    assert res.masked_text == "How many days of parental leave am I entitled to?"
    assert len(vault) == 0


def test_analyze_deadline_fails_closed() -> None:
    class _SlowAnalyzer:
        def analyze(self, **_kw: object) -> list:
            time.sleep(2.0)
            return []

    from pathlib import Path

    from sagp.guardrails.entities import load_entities

    guard = PiiGuardrail(
        _SlowAnalyzer(),  # type: ignore[arg-type]
        anonymizer=None,  # type: ignore[arg-type]
        entities=load_entities(Path("config/entities.yaml")),
        timeout_ms=100,
    )
    with pytest.raises(GuardrailUnavailable):
        guard.analyze("anything")
