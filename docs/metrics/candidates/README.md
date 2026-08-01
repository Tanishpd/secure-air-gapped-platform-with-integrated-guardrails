# Injection-classifier candidate scorecards

Each `*.json` here is the output of the bake-off harness
(`scripts/eval_classifier_candidate.py`, `make eval-candidate CANDIDATE=… NAME=…`):
one candidate injection classifier scored against the **committed baseline**
(`protectai/deberta-v3-base-prompt-injection-v2`) over the same labelled corpus,
through the same `InjectionScanner` + `decide_injection` + heuristics, with the
scoring method held constant (torch for both) so a difference is a difference in the
*model*, not the runner.

Only the JSON scorecards live here — **never model weights** (invariant 4). The
harness runs in `.venv-provision` (torch/transformers), online, PROVISION phase.

## The swap-gate (`src/sagp/guardrails/candidate_gate.py`)

Invariant 12 made mechanical — a replacement must **never lower attack recall**:

| verdict | meaning |
|---|---|
| `REJECT_RECALL_REGRESSION` | a gated family (A,C,D,E,G,H,I, plus B jailbreak, F indirect) lost recall vs baseline. Hard stop, regardless of any FPR gain. |
| `REJECT_UNRESOLVABLE_LABELS` | the candidate ships opaque `LABEL_n` labels — no INJECTION index can be resolved (invariant 5); the runtime would refuse to boot on it. |
| `RECOMMEND_PROCEED_TO_EXPORT` | recall held **and** benign FPR or precision improved. This means "worth the next step" — ONNX export + FP32↔INT8 parity + measured-RSS budget gate (`07_gates.py`) — **not** "deploy now". |
| `NO_IMPROVEMENT` | recall held but the FPR/precision ceiling did not move. Not worth the swap risk. |

Accuracy (recall/precision/FPR) is comparable across candidates here; deployed RSS
and latency are **not** (torch ≠ the ONNX session), so `size_proxy` reports parameter
count only — real RSS needs the ONNX export + `07_gates` measurement.

## Results — the ungated landscape, swept

| candidate | params (M) | headline recall | precision | benign FPR | recall regressions | verdict |
|---|---|---|---|---|---|---|
| **baseline** (protectai v2) | 184 | **1.000** | 0.854 | 0.24 | — | — |
| `deepset/deberta-v3-base-injection` (v1) | 184 | 1.000 | 0.761 | 0.44 | none | `NO_IMPROVEMENT` |
| `testsavantai/…-small-v0` | 29 | 0.903 | 0.909 | 0.12 | A, C, B, F | `REJECT_RECALL_REGRESSION` |
| `testsavantai/…-base-v0` | 67 | 0.968 | 0.861 | 0.20 | D, B, F | `REJECT_RECALL_REGRESSION` |
| `testsavantai/…-large-v0` | 184 | 0.968 | 0.944 | **0.08** | A, F | `REJECT_RECALL_REGRESSION` |
| `jackhhao/jailbreak-classifier` | 110 | 0.774 | 0.900 | 0.12 | C, D, E, B, F | `REJECT_RECALL_REGRESSION` |

**The finding: on this corpus, every ungated model that improves the FPR ceiling does
so by trading away attack recall.** Four of five would have looked like an upgrade on
the headline FPR/precision numbers — and every one of those silently drops attacks the
baseline catches:

- `testsavantai-large` is the sharpest lesson. It **meets the 0.10 FPR target (0.08)**
  and lifts precision to 0.94 — the numbers you would swap for. But it misses **20% of
  direct (family A)** and **50% of indirect, document-planted (family F)** attacks.
  Family F is the highest-value RAG threat. Blind-swapping to hit the FPR number would
  have halved indirect-injection detection.
- `testsavantai-small` (6× smaller, tempting for the 8 GB budget) improves both ceiling
  metrics but misses **40% of family A** and **50% of jailbreaks (B)**.
- `jackhhao/jailbreak-classifier` — a *jailbreak*-named model — scores family B at 0.75,
  worse than the baseline's 1.0, and craters headline recall to 0.77.

The baseline's recall-1.0 is bought with a higher FPR; the ungated alternatives make
the opposite trade. **No ungated candidate offers a strictly-better point on the
recall/FPR frontier** — which is exactly why the swap needs a genuinely stronger,
multilingual model rather than a lateral move. Not evaluated (`gated=auto`, need a
token): `Epivolis/Hyperion`, `qualifire/prompt-injection-sentinel`.

Every REJECT here is the gate (`candidate_gate.py`) doing its one job: refusing a model
that would have shipped a security regression disguised as a metrics win.

## The real target is blocked on you

The classifier best positioned to close the documented FPR ceiling (over-firing on
quoted-attack English and on non-English text — LIMITATIONS 6/9) is **Llama Prompt
Guard 2** (`meta-llama/Llama-Prompt-Guard-2-86M` / `-22M`): multilingual, designed for
lower FPR, actively maintained. It is **`gated=manual` on Hugging Face** — it cannot
be fetched here without you accepting Meta's licence and providing an HF token. The
moment that token exists, `make eval-candidate CANDIDATE=meta-llama/Llama-Prompt-Guard-2-86M
NAME=prompt-guard-2` runs it through this exact gate. (Note: PG2 uses `LABEL_0/1`
labels, so it would first need an alias entry or a config with real label names —
invariant 5.)
