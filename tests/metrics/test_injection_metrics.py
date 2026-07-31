"""Injection metrics gate (real classifier over the corpus).

Hard floors: headline recall >= 0.90; B and F reported separately. Precision and
FPR miss their documented TARGETS (archived classifier + deliberate hard
negatives) — those are gated by regression-from-baseline, and the fact that they
miss is asserted to be RECORDED in known_gaps, so the shortfall can never be
quietly hidden.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sagp.guardrails.evaluate import evaluate_injection
from sagp.guardrails.injection.scanner import InjectionScanner
from sagp.guardrails.policy import load_policy

CORPUS = Path("tests/corpus")
BASELINE = json.loads(Path("docs/metrics/latest.json").read_text(encoding="utf-8"))


def _jsonl(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture(scope="module")
def report(injection_scanner: InjectionScanner):  # type: ignore[no-untyped-def]
    policy = load_policy(Path("config/guardrails.yaml"))
    return evaluate_injection(
        _jsonl(CORPUS / "attacks.jsonl"),
        _jsonl(CORPUS / "benign.jsonl"),
        injection_scanner,
        policy,
    )


def test_headline_recall_floor(report) -> None:  # type: ignore[no-untyped-def]
    assert report.headline_recall >= 0.90, f"headline recall {report.headline_recall} < 0.90"


def test_families_b_and_f_reported_separately(report) -> None:  # type: ignore[no-untyped-def]
    assert report.family_b_recall is not None
    assert report.family_f_recall is not None


def test_no_precision_regression(report) -> None:  # type: ignore[no-untyped-def]
    baseline = BASELINE["injection"]["precision"]
    assert report.precision >= baseline - 0.02, (
        f"precision {report.precision} regressed from {baseline}"
    )


def test_no_fpr_regression(report) -> None:  # type: ignore[no-untyped-def]
    baseline = BASELINE["injection"]["benign_fpr"]
    assert report.benign_fpr <= baseline + 0.02, (
        f"FPR {report.benign_fpr} regressed from {baseline}"
    )


def test_unmet_targets_are_documented() -> None:
    """If precision/FPR miss their target, the gap MUST be recorded (honesty gate)."""
    inj, floors = BASELINE["injection"], BASELINE["floors"]
    gaps = {g["metric"] for g in BASELINE["known_gaps"]}
    if inj["precision"] < floors["injection_precision"]:
        assert "injection_precision" in gaps
    if inj["benign_fpr"] > floors["benign_fpr_ceiling"]:
        assert "benign_fpr" in gaps
