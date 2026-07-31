"""C19 assembled-context re-scan (M12): drop-and-continue + the whole-context gate.

``filter_context`` (C19a) scans each masked retrieved chunk on the retrieval
surface and drops only the flagged ones, so one poisoned chunk does not deny
service to a query that also retrieved good chunks. ``scan_context`` (C19b) then
re-scans the fully assembled string as one unit and records it in ``scanned`` (the
bytes the flagship test asserts on). Driven by a FakeScorer so the thresholds are
deterministic (retrieval threshold = 0.90).
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from sagp.config import Settings
from sagp.guardrails.injection.scanner import InjectionScanner, WindowScore
from sagp.guardrails.pii import PiiGuardrail
from sagp.guardrails.pipeline import InputGuardrail
from sagp.guardrails.policy import load_policy
from sagp.types import Chunk, Hit

# filter_context / scan_context read only self._scanner — pii and settings are
# never touched, so stub them rather than build real ones (a real Settings would
# also couple this unit test to whatever SAGP_ vars leaked into the environment).


class MarkerScorer:
    def __init__(self, scores: dict[str, float]) -> None:
        self._scores = scores

    def score_max(self, text: str) -> WindowScore:
        best = max((v for k, v in self._scores.items() if k in text), default=0.0)
        return WindowScore(max_score=best, n_windows=1, truncated=False)


def _guardrail(scores: dict[str, float]) -> InputGuardrail:
    policy = load_policy(Path("config/guardrails.yaml"))
    scanner = InjectionScanner(MarkerScorer(scores), policy.injection)
    return InputGuardrail(scanner, cast(PiiGuardrail, None), policy, cast(Settings, None))


def _hit(text: str, score: float = 0.6) -> Hit:
    return Hit(chunk=Chunk(doc_sha256="d", index=0, text=text, page=1, source="s"), score=score)


def test_filter_context_drops_only_the_flagged_chunk() -> None:
    g = _guardrail({"ATTACK": 0.97})  # >= retrieval 0.90
    hits = [_hit("clean one"), _hit("ATTACK payload"), _hit("clean two")]
    kept, dropped = g.filter_context(hits)
    assert dropped == 1
    assert [h.chunk.text for h in kept] == ["clean one", "clean two"]


def test_filter_context_all_flagged_returns_empty() -> None:
    g = _guardrail({"ATTACK": 0.97})
    kept, dropped = g.filter_context([_hit("ATTACK a"), _hit("ATTACK b")])
    assert kept == []
    assert dropped == 2


def test_filter_context_keeps_borderline_below_retrieval_threshold() -> None:
    # 0.80 clears doc_suspect but NOT the 0.90 retrieval threshold -> still served.
    g = _guardrail({"BORDER": 0.80})
    kept, dropped = g.filter_context([_hit("BORDER text")])
    assert dropped == 0
    assert len(kept) == 1


def test_scan_context_records_the_assembled_bytes() -> None:
    g = _guardrail({"ATTACK": 0.97})
    scanned: list[str] = []
    assert g.scan_context("a wholly benign assembled context", scanned=scanned) is True
    assert g.scan_context("contains ATTACK spanning chunks", scanned=scanned) is False
    assert scanned == ["a wholly benign assembled context", "contains ATTACK spanning chunks"]
