"""Scanner logic with a FakeScorer: thresholds, aggregation, truncation, fail-closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from sagp.errors import GuardrailUnavailable
from sagp.guardrails.injection.scanner import InjectionScanner, WindowScore
from sagp.guardrails.policy import load_policy
from sagp.types import InjectionVerdict


class FakeScorer:
    """Returns a preset score per text; can flag truncation or raise."""

    def __init__(self, scores: dict[str, WindowScore] | None = None, raises: bool = False) -> None:
        self._scores = scores or {}
        self._raises = raises

    def score_max(self, text: str) -> WindowScore:
        if self._raises:
            raise RuntimeError("model exploded")
        return self._scores.get(text, WindowScore(max_score=0.0, n_windows=1, truncated=False))


@pytest.fixture(scope="module")
def policy():  # type: ignore[no-untyped-def]
    return load_policy(Path("config/guardrails.yaml")).injection


def _ws(score: float, truncated: bool = False) -> WindowScore:
    return WindowScore(max_score=score, n_windows=1, truncated=truncated)


def test_high_score_blocks_prompt(policy) -> None:  # type: ignore[no-untyped-def]
    sc = InjectionScanner(FakeScorer({"x": _ws(0.99)}), policy)
    r = sc.scan(["x"], surface="user_prompt")
    assert r.verdict is InjectionVerdict.QUARANTINED
    assert sc.blocks_prompt(r)


def test_low_score_allows_prompt(policy) -> None:  # type: ignore[no-untyped-def]
    sc = InjectionScanner(FakeScorer({"x": _ws(0.10)}), policy)
    r = sc.scan(["x"], surface="user_prompt")
    assert r.verdict is InjectionVerdict.CLEAN
    assert not sc.blocks_prompt(r)


def test_truncated_blocks_regardless_of_score(policy) -> None:  # type: ignore[no-untyped-def]
    sc = InjectionScanner(FakeScorer({"x": _ws(0.01, truncated=True)}), policy)
    r = sc.scan(["x"], surface="user_prompt")
    assert r.truncated
    assert r.verdict is InjectionVerdict.QUARANTINED
    assert sc.blocks_prompt(r)


def test_max_over_surfaces(policy) -> None:  # type: ignore[no-untyped-def]
    sc = InjectionScanner(FakeScorer({"raw": _ws(0.2), "decoded": _ws(0.97)}), policy)
    r = sc.scan(["raw", "decoded"], surface="user_prompt")
    assert r.score == pytest.approx(0.97)
    assert r.verdict is InjectionVerdict.QUARANTINED


def test_heuristic_or_blocks(policy) -> None:  # type: ignore[no-untyped-def]
    sc = InjectionScanner(FakeScorer({"x": _ws(0.02)}), policy)
    r = sc.scan(["x"], surface="user_prompt")
    assert not sc.blocks_prompt(r, heuristic_weight=0.0)
    assert sc.blocks_prompt(r, heuristic_weight=0.90)  # rule fires alone (max, not average)


def test_document_three_way_verdict(policy) -> None:  # type: ignore[no-untyped-def]
    sc = InjectionScanner(FakeScorer({"clean": _ws(0.5), "sus": _ws(0.8), "q": _ws(0.97)}), policy)
    assert sc.scan(["clean"], surface="document").verdict is InjectionVerdict.CLEAN
    assert sc.scan(["sus"], surface="document").verdict is InjectionVerdict.SUSPECT
    assert sc.scan(["q"], surface="document").verdict is InjectionVerdict.QUARANTINED


def test_scorer_failure_is_fail_closed(policy) -> None:  # type: ignore[no-untyped-def]
    sc = InjectionScanner(FakeScorer(raises=True), policy)
    with pytest.raises(GuardrailUnavailable):
        sc.scan(["x"], surface="user_prompt")
