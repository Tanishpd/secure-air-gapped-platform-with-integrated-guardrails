"""Guardrail evaluation: the input-side decision and the corpus metrics (M6).

``decide_injection`` is the C3–C7 input decision (normalize → heuristic block →
deobfuscate → classifier OR heuristic), reused by both the metrics harness and,
later, the pipeline. ``evaluate_injection`` / ``evaluate_pii`` run it over the
labelled corpus and compute the metrics whose floors gate the build.

Per-family recall is reported per family; the headline recall is over families
A, C, D, E, G, H, I only — B (jailbreak, the classifier's documented blind spot)
and F (indirect/document, a different surface) are reported apart and never
averaged in (EVALUATION §4). FPR is benign-blocked / total-benign — NOT
1 − precision.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sagp.guardrails import deobfuscate, heuristics
from sagp.guardrails.injection.scanner import InjectionScanner
from sagp.guardrails.normalize import BLOCKING_FLAGS, has_blocking_flag, normalize
from sagp.guardrails.pii import PiiGuardrail
from sagp.guardrails.policy import GuardrailsPolicy
from sagp.types import InjectionVerdict

HEADLINE_FAMILIES = ("A", "C", "D", "E", "G", "H", "I")


@dataclass(frozen=True)
class InjectionDecision:
    blocked: bool
    stage: str  # normalize_block | heuristic_block | decode_bomb | classifier
    score: float
    verdict: InjectionVerdict
    rule_ids: tuple[str, ...]


def decide_injection(
    text: str,
    *,
    surface: str,
    scanner: InjectionScanner,
    policy: GuardrailsPolicy,
) -> InjectionDecision:
    """The C3–C7 input decision for one text on one surface."""
    art = normalize(text)
    if has_blocking_flag(art):  # C3: tag chars / bidi override
        rules = tuple(sorted(art.flags & BLOCKING_FLAGS))
        return InjectionDecision(True, "normalize_block", 1.0, InjectionVerdict.QUARANTINED, rules)

    heur = heuristics.scan(art.normalized, policy)
    if heur.blocked:  # C4: DELIMITER_SPOOF etc.
        return InjectionDecision(
            True, "heuristic_block", heur.max_weight, InjectionVerdict.QUARANTINED, heur.rule_ids
        )

    deob = deobfuscate.expand(
        art.normalized,
        codecs=policy.deobfuscate.codecs,
        max_depth=policy.deobfuscate.max_depth,
        max_bytes=policy.deobfuscate.max_bytes,
    )
    if deob.truncated:  # C5: decode bomb
        return InjectionDecision(
            True, "decode_bomb", 1.0, InjectionVerdict.QUARANTINED, ("DECODE_BOMB",)
        )

    surfaces = [text, art.normalized, *deob.candidates]
    result = scanner.scan(surfaces, surface=surface)
    if surface == "document":
        blocked = result.verdict is not InjectionVerdict.CLEAN
    else:  # C6–C7: classifier OR heuristic weight
        blocked = scanner.blocks_prompt(result, heuristic_weight=heur.max_weight)
    return InjectionDecision(blocked, "classifier", result.score, result.verdict, heur.rule_ids)


def _family(category: str) -> str:
    return category.split("_", 1)[0]


@dataclass
class InjectionReport:
    per_family: dict[str, dict[str, Any]] = field(default_factory=dict)
    headline_recall: float = 0.0
    family_b_recall: float | None = None
    family_f_recall: float | None = None
    precision: float = 0.0
    benign_fpr: float = 0.0
    counts: dict[str, int] = field(default_factory=dict)
    misses: list[str] = field(default_factory=list)  # attack ids not detected
    false_positives: list[str] = field(default_factory=list)  # benign ids blocked


def evaluate_injection(
    attacks: Sequence[dict[str, Any]],
    benign: Sequence[dict[str, Any]],
    scanner: InjectionScanner,
    policy: GuardrailsPolicy,
) -> InjectionReport:
    fam_tp: dict[str, int] = {}
    fam_fn: dict[str, int] = {}
    misses: list[str] = []
    prompt_tp = 0  # prompt-surface attacks blocked (for precision)

    for rec in attacks:
        fam = _family(rec["category"])
        surface = "document" if fam == "F" else "user_prompt"
        dec = decide_injection(rec["text"], surface=surface, scanner=scanner, policy=policy)
        if dec.blocked:
            fam_tp[fam] = fam_tp.get(fam, 0) + 1
            if fam != "F":
                prompt_tp += 1
        else:
            fam_fn[fam] = fam_fn.get(fam, 0) + 1
            misses.append(rec["id"])

    def _recall(fams: Sequence[str]) -> tuple[int, int, float]:
        tp = sum(fam_tp.get(f, 0) for f in fams)
        fn = sum(fam_fn.get(f, 0) for f in fams)
        return tp, fn, (tp / (tp + fn) if tp + fn else 1.0)

    per_family: dict[str, dict[str, Any]] = {}
    for fam in sorted(set(fam_tp) | set(fam_fn)):
        tp, fn = fam_tp.get(fam, 0), fam_fn.get(fam, 0)
        per_family[fam] = {"tp": tp, "fn": fn, "recall": tp / (tp + fn) if tp + fn else 1.0}

    fp_ids: list[str] = []
    for rec in benign:
        dec = decide_injection(rec["text"], surface="user_prompt", scanner=scanner, policy=policy)
        if dec.blocked:
            fp_ids.append(rec["id"])

    h_tp, h_fn, headline = _recall(HEADLINE_FAMILIES)
    _, _, b_recall = _recall(["B"])
    _, _, f_recall = _recall(["F"])
    fp = len(fp_ids)
    precision = prompt_tp / (prompt_tp + fp) if (prompt_tp + fp) else 1.0
    fpr = fp / len(benign) if benign else 0.0

    return InjectionReport(
        per_family=per_family,
        headline_recall=headline,
        family_b_recall=b_recall if ("B" in fam_tp or "B" in fam_fn) else None,
        family_f_recall=f_recall if ("F" in fam_tp or "F" in fam_fn) else None,
        precision=precision,
        benign_fpr=fpr,
        counts={
            "headline_tp": h_tp,
            "headline_fn": h_fn,
            "prompt_attacks_blocked": prompt_tp,
            "benign_total": len(benign),
            "benign_blocked": fp,
        },
        misses=misses,
        false_positives=fp_ids,
    )


def evaluate_pii(records: Sequence[dict[str, Any]], guardrail: PiiGuardrail) -> dict[str, Any]:
    per_type: dict[str, dict[str, Any]] = {}
    misses: list[str] = []
    for rec in records:
        want = rec["expected_type"]
        found = {r.entity_type for r in guardrail.analyze(rec["text"])}
        bucket = per_type.setdefault(want, {"total": 0, "detected": 0})
        bucket["total"] += 1
        if want in found:
            bucket["detected"] += 1
        else:
            misses.append(rec["id"])
    for b in per_type.values():
        b["recall"] = b["detected"] / b["total"] if b["total"] else 1.0
    return {"per_type": per_type, "misses": misses}
