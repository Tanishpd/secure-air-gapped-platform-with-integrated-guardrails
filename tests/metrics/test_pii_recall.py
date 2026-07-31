"""PII recall gate (real Presidio + spaCy over the labelled corpus).

Hard floors (EVALUATION §5): EMAIL_ADDRESS >= 0.98, CREDIT_CARD >= 0.98,
IN_AADHAAR >= 0.95, PERSON >= 0.80. The IN_AADHAAR floor is what caught the M4
bug where the India recognizers were never registered.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sagp.guardrails.evaluate import evaluate_pii
from sagp.guardrails.pii import PiiGuardrail

CORPUS = Path("tests/corpus")
FLOORS = {"EMAIL_ADDRESS": 0.98, "CREDIT_CARD": 0.98, "IN_AADHAAR": 0.95, "PERSON": 0.80}


def _jsonl(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture(scope="module")
def report(pii_guardrail: PiiGuardrail):  # type: ignore[no-untyped-def]
    return evaluate_pii(_jsonl(CORPUS / "pii.jsonl"), pii_guardrail)


@pytest.mark.parametrize("entity,floor", FLOORS.items())
def test_pii_recall_floor(report, entity: str, floor: float) -> None:  # type: ignore[no-untyped-def]
    per_type = report["per_type"]
    assert entity in per_type, f"{entity} has no corpus examples"
    recall = per_type[entity]["recall"]
    assert recall >= floor, f"{entity} recall {recall} < floor {floor}"
