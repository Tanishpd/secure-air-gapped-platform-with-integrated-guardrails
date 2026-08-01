"""The injection-classifier swap-gate (invariant 12): a replacement must never lower
attack recall, and only earns a RECOMMEND if it also improves the FPR/precision ceiling.

Pure logic over two InjectionReports — no torch, no models (the torch bake-off that
produces the reports lives in scripts/eval_classifier_candidate.py).
"""

from __future__ import annotations

from sagp.guardrails.candidate_gate import recall_regressions, swap_verdict
from sagp.guardrails.evaluate import InjectionReport

_ALL_FAMILIES = ("A", "C", "D", "E", "G", "H", "I", "B", "F")


def _report(
    *,
    recalls: dict[str, float] | None = None,
    precision: float = 0.85,
    fpr: float = 0.24,
) -> InjectionReport:
    """A report with every gated family at recall 1.0 unless overridden."""
    per_family = {f: {"recall": 1.0} for f in _ALL_FAMILIES}
    for fam, r in (recalls or {}).items():
        per_family[fam] = {"recall": r}
    return InjectionReport(per_family=per_family, precision=precision, benign_fpr=fpr)


def test_identical_is_no_improvement() -> None:
    base = _report()
    assert swap_verdict(base, _report()).verdict == "NO_IMPROVEMENT"


def test_headline_recall_regression_is_rejected() -> None:
    base = _report()
    cand = _report(recalls={"A": 0.9}, fpr=0.01)  # huge FPR win, but recall dropped
    v = swap_verdict(base, cand)
    assert v.verdict == "REJECT_RECALL_REGRESSION"
    assert any(r["family"] == "A" for r in v.regressions)


def test_jailbreak_family_regression_is_rejected() -> None:
    # B (jailbreak) is reported separately but still guarded — a swap that admits
    # jailbreaks for a lower FPR is not an improvement.
    base = _report()
    cand = _report(recalls={"B": 0.5}, fpr=0.05)
    assert swap_verdict(base, cand).verdict == "REJECT_RECALL_REGRESSION"


def test_indirect_family_regression_is_rejected() -> None:
    base = _report()
    cand = _report(recalls={"F": 0.8}, precision=0.99)
    assert swap_verdict(base, cand).verdict == "REJECT_RECALL_REGRESSION"


def test_recall_held_and_fpr_improved_recommends() -> None:
    base = _report(fpr=0.24)
    cand = _report(fpr=0.08)  # recall held, FPR improved
    v = swap_verdict(base, cand)
    assert v.verdict == "RECOMMEND_PROCEED_TO_EXPORT"
    assert not v.regressions
    assert "deploy" in v.detail.lower()  # states RECOMMEND != deploy


def test_recall_held_and_precision_improved_recommends() -> None:
    base = _report(precision=0.85, fpr=0.24)
    cand = _report(precision=0.95, fpr=0.24)  # only precision moved
    assert swap_verdict(base, cand).verdict == "RECOMMEND_PROCEED_TO_EXPORT"


def test_recall_improved_but_ceiling_worse_is_no_improvement() -> None:
    # A candidate can't buy its way in by raising an already-1.0 family; if the
    # ceiling didn't move, it's not worth the swap risk.
    base = _report(fpr=0.24, precision=0.85)
    cand = _report(fpr=0.30, precision=0.80)  # recall held, FPR + precision worse
    assert swap_verdict(base, cand).verdict == "NO_IMPROVEMENT"


def test_absent_family_is_not_a_phantom_regression() -> None:
    base = _report()
    cand = _report()
    del cand.per_family["F"]  # candidate corpus lacked family F
    assert recall_regressions(base, cand) == []


def test_regressions_lists_every_dropped_family() -> None:
    base = _report()
    cand = _report(recalls={"A": 0.9, "D": 0.5})
    fams = {r["family"] for r in recall_regressions(base, cand)}
    assert fams == {"A", "D"}
