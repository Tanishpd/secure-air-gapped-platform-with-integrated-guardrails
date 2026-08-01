"""Injection-classifier bake-off — decide whether a replacement model is worth a swap.

Runs in ``.venv-provision`` (torch/transformers): a candidate classifier is scored
through the SAME ``InjectionScanner`` + ``decide_injection`` + ``evaluate_injection``
as production, over the SAME labelled corpus, with the SAME thresholds and
heuristics. The scoring METHOD is held constant — both baseline and candidate are
run with the torch scorer below — so a difference in the numbers is a difference in
the MODEL, not the runner. (The runtime FP32 ONNX was already gated to match torch
within parity at provision, so the torch-baseline stands in for it here.)

The point is invariant 12 made mechanical: **a swap must never lower attack recall.**
The swap-gate is HARD on recall regression (any headline family, or B/C jailbreak,
or F indirect, dropping below baseline → ``REJECT``) and only then looks at whether
the candidate actually improves the benign-FPR / precision ceiling that motivates a
swap in the first place. A ``RECOMMEND`` verdict means "worth the next step" — ONNX
export + the FP32↔INT8 parity gate + the measured-RSS budget gate in
``07_gates.py`` — NOT "deploy now". Accuracy is comparable here; deployed RSS and
latency are not (torch ≠ the ONNX session), so those are reported as architecture
proxies only.

Usage (online, PROVISION phase)::

    .venv-provision/bin/python scripts/eval_classifier_candidate.py \\
        --candidate deepset/deberta-v3-base-injection --name deepset-v1

Writes ``docs/metrics/candidates/<name>.json`` and prints a comparison table. Never
writes model weights anywhere tracked (invariant 4) — only the JSON scorecard.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from sagp.guardrails.candidate_gate import GATED_FAMILIES, swap_verdict
from sagp.guardrails.evaluate import InjectionReport, evaluate_injection
from sagp.guardrails.injection.labels import LabelResolutionError, resolve_injection_index
from sagp.guardrails.injection.scanner import InjectionScanner, WindowScore
from sagp.guardrails.policy import GuardrailsPolicy, InjectionPolicy, load_policy

ROOT = Path(__file__).resolve().parents[1]

# The provisioned baseline: model weights at the top dir, tokenizer files under onnx/.
BASELINE_MODEL = ROOT / "models/hf/injection"
BASELINE_TOKENIZER = ROOT / "models/hf/injection/onnx"


class TorchScorer:
    """``Scorer`` protocol (``score_max``) backed by transformers — accuracy eval only.

    Truncates to ``max_length`` (one window). Every corpus item is well under 512
    tokens, so this equals the production ONNX max-over-windows path for what is
    measured here; a longer input would window in production, but none in the corpus
    does. The INJECTION index is resolved from the model's own ``id2label`` (invariant
    5) — a candidate that ships opaque ``LABEL_n`` labels is rejected at load, exactly
    as the runtime would refuse to boot on it.
    """

    def __init__(self, model_ref: str | Path, tokenizer_ref: str | Path, policy: InjectionPolicy):
        self._tok = AutoTokenizer.from_pretrained(str(tokenizer_ref))
        self._model = AutoModelForSequenceClassification.from_pretrained(str(model_ref))
        self._model.eval()
        self._idx = resolve_injection_index(
            self._model.config.id2label, policy.labels.positive_aliases
        )
        self._max_len = policy.window.max_length
        self.n_params = sum(p.numel() for p in self._model.parameters())

    @torch.no_grad()  # type: ignore[misc]
    def score_max(self, text: str) -> WindowScore:
        enc = self._tok(text, truncation=True, max_length=self._max_len, return_tensors="pt")
        logits = self._model(**enc).logits[0]
        probs = torch.softmax(logits, dim=-1)
        return WindowScore(max_score=float(probs[self._idx].item()), n_windows=1, truncated=False)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _report_dict(r: InjectionReport) -> dict[str, Any]:
    return {
        "headline_recall": round(r.headline_recall, 4),
        "precision": round(r.precision, 4),
        "benign_fpr": round(r.benign_fpr, 4),
        "family_b_recall": r.family_b_recall,
        "family_f_recall": r.family_f_recall,
        "per_family": {f: round(v["recall"], 4) for f, v in r.per_family.items()},
        "misses": r.misses,
    }


def _evaluate(
    scorer: TorchScorer, policy: GuardrailsPolicy, attacks: list, benign: list
) -> InjectionReport:
    scanner = InjectionScanner(scorer, policy.injection)
    return evaluate_injection(attacks, benign, scanner, policy)


def main() -> int:
    ap = argparse.ArgumentParser(description="Injection-classifier bake-off (swap-gate)")
    ap.add_argument("--candidate", required=True, help="HF repo id or local dir of the candidate")
    ap.add_argument(
        "--candidate-tokenizer", default=None, help="tokenizer ref (defaults to --candidate)"
    )
    ap.add_argument("--name", required=True, help="slug for docs/metrics/candidates/<name>.json")
    args = ap.parse_args()

    policy = load_policy(ROOT / "config/guardrails.yaml")
    attacks = _load_jsonl(ROOT / "tests/corpus/attacks.jsonl")
    benign = _load_jsonl(ROOT / "tests/corpus/benign.jsonl")

    print(f"baseline: {BASELINE_MODEL.name} (torch)")
    base_scorer = TorchScorer(BASELINE_MODEL, BASELINE_TOKENIZER, policy.injection)
    base_report = _evaluate(base_scorer, policy, attacks, benign)

    print(f"candidate: {args.candidate} (torch)")
    try:
        cand_scorer = TorchScorer(
            args.candidate, args.candidate_tokenizer or args.candidate, policy.injection
        )
    except LabelResolutionError as exc:
        # Invariant 5: a candidate we cannot resolve an INJECTION index for is a
        # hard reject — the runtime would refuse to boot on it. Report, don't crash.
        out = ROOT / "docs" / "metrics" / "candidates" / f"{args.name}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        result = {
            "candidate": args.candidate,
            "verdict": "REJECT_UNRESOLVABLE_LABELS",
            "detail": str(exc),
            "baseline": _report_dict(base_report),
        }
        out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nVERDICT: REJECT_UNRESOLVABLE_LABELS\n  {exc}\nwrote {out}")
        return 0
    cand_report = _evaluate(cand_scorer, policy, attacks, benign)

    sv = swap_verdict(base_report, cand_report)

    result = {
        "candidate": args.candidate,
        "verdict": sv.verdict,
        "detail": sv.detail,
        "recall_regressions": sv.regressions,
        "baseline": _report_dict(base_report),
        "candidate_metrics": _report_dict(cand_report),
        "size_proxy": {
            "baseline_params_m": round(base_scorer.n_params / 1e6, 1),
            "candidate_params_m": round(cand_scorer.n_params / 1e6, 1),
            "note": "params only. Deployed RSS/latency need ONNX export + 07_gates measurement — "
            "torch here is not the ONNX session.",
        },
        "policy_sha256": policy.sha256,
        "method": "torch, method held constant across baseline+candidate; truncate@max_length "
        "(== ONNX windowing for all corpus items). Accuracy is comparable; RSS/latency are not.",
    }
    out = ROOT / "docs" / "metrics" / "candidates" / f"{args.name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    regressed = {str(r["family"]) for r in sv.regressions}
    print("\n  family        baseline  candidate")
    for fam in GATED_FAMILIES:
        b = base_report.per_family.get(fam, {}).get("recall")
        c = cand_report.per_family.get(fam, {}).get("recall")
        if b is None and c is None:
            continue
        mark = "  <-- REGRESSION" if fam in regressed else ""
        bv = b if b is not None else 1.0
        cv = c if c is not None else 1.0
        print(f"  {fam:<12}  {bv:>7.3f}  {cv:>8.3f}{mark}")
    b_inj, c_inj = base_report, cand_report
    print(f"\n  headline recall  {b_inj.headline_recall:.3f} -> {c_inj.headline_recall:.3f}")
    print(f"  precision        {b_inj.precision:.3f} -> {c_inj.precision:.3f}")
    print(f"  benign FPR       {b_inj.benign_fpr:.3f} -> {c_inj.benign_fpr:.3f}  (ceiling 0.10)")
    bp, cp = base_scorer.n_params / 1e6, cand_scorer.n_params / 1e6
    print(f"  params (M)       {bp:.1f} -> {cp:.1f}")
    print(f"\nVERDICT: {sv.verdict}\n  {sv.detail}\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
