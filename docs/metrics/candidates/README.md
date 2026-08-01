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

## Results so far

| candidate | recall | precision | benign FPR | verdict |
|---|---|---|---|---|
| baseline (protectai v2) | 1.00 | 0.854 | 0.24 | — |
| `deepset/deberta-v3-base-injection` (v1 ancestor) | 1.00 | 0.761 | **0.44** | `NO_IMPROVEMENT` |

The v1 ancestor holds recall but nearly **doubles** the false-positive rate — data
quantifying why v2 is the baseline, and a live demonstration of the gate declining a
non-improving swap.

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
