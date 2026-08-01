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

## Results — 8 candidates, incl. Prompt Guard 2

Sorted worst-to-best FPR. **F** is family F recall — indirect, document-planted injection,
the highest-value RAG threat. Read that column first.

| candidate | params (M) | recall | precision | FPR | **F** | verdict |
|---|---|---|---|---|---|---|
| **baseline** (protectai v2) | 184 | **1.000** | 0.854 | 0.24 | **1.00** | — |
| `deepset/…-injection` (v1) | 184 | 1.000 | 0.761 | 0.44 | 1.00 | `NO_IMPROVEMENT` |
| `testsavantai/…-base-v0` | 67 | 0.968 | 0.861 | 0.20 | 0.75 | `REJECT` (D,B,F) |
| `protectai/…-prompt-injection` (v1) | 184 | 0.935 | 0.912 | 0.12 | 0.25 | `REJECT` (D,B,F) |
| `testsavantai/…-small-v0` | 29 | 0.903 | 0.909 | 0.12 | 0.75 | `REJECT` (A,C,B,F) |
| `jackhhao/jailbreak-classifier` | 110 | 0.774 | 0.900 | 0.12 | 0.50 | `REJECT` (C,D,E,B,F) |
| `testsavantai/…-large-v0` | 184 | 0.968 | 0.944 | 0.08 | 0.50 | `REJECT` (A,F) |
| **Llama Prompt Guard 2 (22M)** ᵍ | 71 | 0.968 | 0.941 | 0.08 | 0.25 | `REJECT` (D,B,F) |
| **Llama Prompt Guard 2 (86M)** ᵍ | 279 | 0.968 | **0.970** | **0.04** | 0.25 | `REJECT` (D,B,F) |

ᵍ Prompt Guard 2 evaluated via the **ungated** ONNX re-host `gravitee-io/Llama-Prompt-Guard-2-{86,22}M-onnx`
(which ships real `BENIGN`/`MALICIOUS` labels + `model.safetensors`), so no Meta licence
or PII disclosure was needed to *measure* it. Deploying PG2 would still require resolving
the licence (the genuine gated Meta model, or gravitee's redistribution terms) — but the
measurement already settles whether that is worth doing.

**The finding — one column tells the whole story: the baseline is the ONLY model that
holds family F (indirect injection) at 1.0.** Every alternative, without exception, buys
a lower FPR by sacrificing document-poisoning detection, dropping F to 0.25–0.75.

- **Prompt Guard 2 is the sharpest case, and it settles H5.** It posts the best FPR of
  anything tested (0.04, well under the 0.10 target) and the best precision (0.97) — the
  numbers you'd change a security control for. But it misses **50% of jailbreaks (B)** and
  **75% of indirect attacks (F → 0.25)**. This is not a fluke: Meta tuned PG2 to *ignore*
  instruction-like text embedded in third-party content precisely to cut false positives —
  which is exactly family F. **So the Meta licence + PII form is not worth pursuing: PG2
  would gut the highest-value RAG defence.** Path-3 (ungated hunting) answered the gated
  question for free.
- The whole protectai/Prompt-Guard lineage (`protectai-v1`, PG2-22M, PG2-86M) collapses F
  to 0.25. The baseline (protectai **v2**) is the outlier that fixed it.

**Conclusion: no off-the-shelf model — gated or ungated, 29M to 279M — closes the FPR gap
without regressing recall.** The recall/FPR tradeoff is a genuine frontier, and the baseline
sits at the recall-maximising corner (recall 1.0, F 1.0). Closing the FPR gap while holding
recall is therefore **not a swap** — it needs one of: an *ensemble* (baseline for recall +
a low-FPR model as a benign-corroborator that may never veto a detection — non-trivial,
because PG2 misses F), or *fine-tuning* on the deployed corpus. Both are real engineering,
scoped in LIMITATIONS 9. Not evaluated (`gated=auto`, need a plain token): `Epivolis/Hyperion`,
`qualifire/prompt-injection-sentinel`.

Every REJECT here is the gate (`candidate_gate.py`) doing its one job: refusing a model that
would have shipped a security regression disguised as a metrics win — including the one I'd
have told you to get a licence for.
