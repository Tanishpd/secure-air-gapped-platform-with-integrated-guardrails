"""Swap-gate for an injection-classifier replacement — invariant 12, mechanised.

A replacement classifier must **never lower attack recall on any family** — that is
the security property, and it is checked first and hard: any regression is a
``REJECT`` regardless of any false-positive-rate gain. Only once recall is proven
non-regressed does an improvement in the benign-FPR / precision ceiling (the thing
that motivates a swap in the first place) earn a ``RECOMMEND``. A ``RECOMMEND`` means
"worth the next step" — ONNX export + the FP32↔INT8 parity gate + the measured-RSS
budget gate in ``07_gates.py`` — never "deploy now".

This is kept torch-free (it operates on two ``InjectionReport`` summaries) so the
gate itself is unit-tested in CI, separate from the torch bake-off that produces the
reports (``scripts/eval_classifier_candidate.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sagp.guardrails.evaluate import InjectionReport

# Families whose recall a swap must not regress: the headline set (A,C,D,E,G,H,I)
# plus B (jailbreak) and F (indirect), which are reported separately but still
# guarded — a swap that admits jailbreaks or planted payloads is not an improvement.
GATED_FAMILIES: tuple[str, ...] = ("A", "C", "D", "E", "G", "H", "I", "B", "F")

_EPS = 1e-9


@dataclass(frozen=True)
class SwapVerdict:
    verdict: str
    detail: str
    regressions: list[dict[str, object]] = field(default_factory=list)


def _fam_recall(report: InjectionReport, fam: str) -> float | None:
    """Per-family recall, or None if the corpus has no example of that family."""
    return report.per_family.get(fam, {}).get("recall")


def recall_regressions(
    baseline: InjectionReport, candidate: InjectionReport
) -> list[dict[str, object]]:
    """Gated families whose candidate recall fell below baseline — each a swap-killer.

    A family absent from a report is treated as recall 1.0 (nothing to detect, nothing
    missed), so an absent-vs-present pair never manufactures a phantom regression.
    """
    out: list[dict[str, object]] = []
    for fam in GATED_FAMILIES:
        b = _fam_recall(baseline, fam)
        c = _fam_recall(candidate, fam)
        if b is None and c is None:
            continue
        b = 1.0 if b is None else b
        c = 1.0 if c is None else c
        if c < b - _EPS:
            out.append({"family": fam, "baseline": round(b, 4), "candidate": round(c, 4)})
    return out


def swap_verdict(baseline: InjectionReport, candidate: InjectionReport) -> SwapVerdict:
    """Decide whether the candidate is worth advancing toward a swap.

    - ``REJECT_RECALL_REGRESSION``: any gated family lost recall. Hard stop.
    - ``RECOMMEND_PROCEED_TO_EXPORT``: recall held AND benign FPR or precision improved.
    - ``NO_IMPROVEMENT``: recall held but the ceiling did not move — not worth the risk.
    """
    regressions = recall_regressions(baseline, candidate)
    if regressions:
        fams = ", ".join(str(r["family"]) for r in regressions)
        return SwapVerdict(
            "REJECT_RECALL_REGRESSION",
            f"candidate lowers attack recall on families [{fams}] — a swap must never reduce "
            "detection (invariant 12). Rejected regardless of any FPR gain.",
            regressions,
        )
    fpr_better = candidate.benign_fpr < baseline.benign_fpr - _EPS
    prec_better = candidate.precision > baseline.precision + _EPS
    if fpr_better or prec_better:
        deltas = []
        if fpr_better:
            deltas.append(f"benign FPR {baseline.benign_fpr:.3f} -> {candidate.benign_fpr:.3f}")
        if prec_better:
            deltas.append(f"precision {baseline.precision:.3f} -> {candidate.precision:.3f}")
        return SwapVerdict(
            "RECOMMEND_PROCEED_TO_EXPORT",
            "no recall regression AND improves the ceiling (" + "; ".join(deltas) + "). "
            "Next step is NOT deploy: ONNX export + FP32<->INT8 parity + measured-RSS budget "
            "gate (07_gates.py) must pass before this is wired in.",
        )
    return SwapVerdict(
        "NO_IMPROVEMENT",
        "recall held but neither benign FPR nor precision improved over the baseline — "
        "no reason to take on the swap risk.",
    )
