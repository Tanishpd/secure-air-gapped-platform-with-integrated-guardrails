"""Injection scanner (C6–C7 / I7 / C19): scores surfaces and assigns a verdict.

The scanner is decoupled from the model behind a ``Scorer`` protocol, so the
threshold / aggregation / fail-closed logic is testable with a ``FakeScorer`` and
the real ONNX backend is swapped in at runtime.

Aggregation is ``max`` over windows and over surfaces — an attack in one window
of twelve is an attack; mean would let benign context dilute it (long-context
dilution). ``truncated`` (input needed more than ``max_windows``) blocks on every
surface: "too long to scan" never means allowed. Any scorer error/timeout is
fail-closed → ``GuardrailUnavailable`` (503), never a low score treated as safe.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from sagp.errors import GuardrailUnavailable
from sagp.guardrails.policy import InjectionPolicy
from sagp.types import InjectionVerdict, ScanResult


@dataclass(frozen=True)
class WindowScore:
    max_score: float  # max P(INJECTION) over the text's windows
    n_windows: int
    truncated: bool  # input exceeded max_windows


class Scorer(Protocol):
    def score_max(self, text: str) -> WindowScore: ...


class InjectionScanner:
    def __init__(self, scorer: Scorer, policy: InjectionPolicy) -> None:
        self._scorer = scorer
        self._policy = policy

    def scan(self, surfaces: Sequence[str], *, surface: str = "user_prompt") -> ScanResult:
        """Score every non-empty surface; return the max score + surface verdict."""
        best = 0.0
        truncated = False
        try:
            for s in surfaces:
                if not s:
                    continue
                ws = self._scorer.score_max(s)
                best = max(best, ws.max_score)
                truncated = truncated or ws.truncated
        except GuardrailUnavailable:
            raise
        except Exception as exc:  # any scorer failure is fail-closed
            raise GuardrailUnavailable("injection scorer failed") from exc

        return ScanResult(
            score=best,
            verdict=self._verdict(best, truncated, surface),
            truncated=truncated,
            rule_ids=(),
        )

    def _verdict(self, score: float, truncated: bool, surface: str) -> InjectionVerdict:
        thr = self._policy.thresholds
        if truncated:  # too long to scan == block on every surface
            return InjectionVerdict.QUARANTINED
        if surface == "document":
            if score >= thr["doc_quarantine"]:
                return InjectionVerdict.QUARANTINED
            if score >= thr["doc_suspect"]:
                return InjectionVerdict.SUSPECT
            return InjectionVerdict.CLEAN
        key = "user_prompt" if surface == "user_prompt" else "retrieval"
        return InjectionVerdict.QUARANTINED if score >= thr[key] else InjectionVerdict.CLEAN

    def blocks_prompt(self, result: ScanResult, heuristic_weight: float = 0.0) -> bool:
        """C7 policy: max(classifier, heuristic) >= user_prompt threshold, or truncated."""
        if result.truncated:
            return True
        return max(result.score, heuristic_weight) >= self._policy.thresholds["user_prompt"]
