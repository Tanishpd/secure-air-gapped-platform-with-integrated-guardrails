# ADR-0004: ONNX Runtime only at runtime — FP32 (INT8 rejected at M1 by the parity gate)

Records how the injection classifier is executed on the sealed host — ONNX Runtime with no torch — and the outcome of the INT8 quantization attempt.

- **Status:** Accepted; **INT8 branch REJECTED at M1 — runtime classifier is FP32 ONNX.**
- **Date:** 2026-07-27 (decision); **2026-07-30 (M1 measurement)**
- **Deciders:** Project architect
- **Supersedes:** —

> **M1 OUTCOME (measured, 2026-07-30) — this supersedes the INT8 body below.**
> The parity gate (`07_gates.py`) ran and **INT8 dynamic quantization FAILED**: on this
> `deberta-v3-base-prompt-injection-v2` checkpoint, `quantize_dynamic` (default op set, QInt8)
> **inverts the classifier** — measured `max |ΔP(INJECTION)| = 0.98`, **3 label flips**; the INT8
> model scores the attack *"Ignore all previous instructions"* as **0.02 INJECTION (i.e. SAFE)**.
> Using it would silently admit every attack. The gate correctly refused and the fallback ladder
> selected **FP32 ONNX**, which is verified correct (attacks → INJECTION 1.0, benign → SAFE 1.0).
> This resolves **OQ-2** (INT8 parity fails) and reshapes **OQ-1**: the *FP32* session RSS was
> measured in a fresh interpreter at **0.30 GB** — the same as the old INT8 estimate, because ORT
> mmaps the weights — so the RAM budget is **unchanged** by the fallback (the "FP32 costs 0.80 GB"
> estimate below is wrong; measured is 0.30 GB). The runtime reads
> `models/derived/classifier_choice.json` to know which model to load. The broken INT8 artifact is
> deleted by the gate; `06_quantize.py` still produces it each run so the gate re-proves the rejection.

## Context

The injection classifier is `protectai/deberta-v3-base-prompt-injection-v2` @ `90c9989b1a342275dd0d1a95aad283c04e075671`. The repository ships both `onnx/model.onnx` (738,563,188 B) and `model.safetensors` (737,719,272 B), ungated, Apache-2.0. The forces:

- **RAM.** 8 GB hard ceiling. The app-process budget is 1.16 GB (ESTIMATE) with a boot gate at 1.40 GB. An FP32 ONNX session for this model was *budgeted* at 0.80 GB — projected to fit *only* with the embedded-Qdrant profile and the 1B LLM. The INT8 session was budgeted at **0.30 GB**. **(Superseded by the M1 outcome above: the FP32 session was measured at 0.30 GB — not 0.80 GB, because ORT mmaps the weights — and INT8 was rejected; OQ-1 is resolved.)**
- **No torch at runtime.** Settled in [ADR-0003](0003-two-virtualenvs.md). Execution is `onnxruntime==1.28.0` (arm64 cp311 wheel, 19,130,506 B); tokenization is `tokenizers==0.23.1`.
- **A near-miss bug in the source specs.** One spec claimed the default `quantize_dynamic` op-type set is "MatMul only" and proposed passing `op_types_to_quantize=["MatMul","Gather"]` to widen it. That is backwards.
- **The label index must never be hardcoded.** One spec had `torch.softmax(logits,-1)[:,1]`. The actual `id2label` is `{"0": "SAFE", "1": "INJECTION"}` — but a hardcoded index silently *inverts* the guardrail if the checkpoint ever changes: benign blocked, attacks passed.

## Decision

**The sealed runtime executes the classifier through `onnxruntime.InferenceSession` on `CPUExecutionProvider`, with no `torch`, no `transformers`, no `optimum`.** This ONNX-Runtime-only / no-torch decision stands and is verified. The session originally decided on was the **INT8 dynamically quantized** model at `models/derived/injection-int8/model.onnx` — **superseded at M1: the shipped session is FP32 ONNX; INT8 was rejected by the parity gate (see the M1 outcome above).** Quantization (still run each provision so the gate re-proves the rejection) uses **the defaults**:

```python
# scripts/provision/06_quantize.py  (runs in .venv-provision, needs ~3 GB transient)
from onnxruntime.quantization import quantize_dynamic, QuantType
quantize_dynamic("models/hf/injection/onnx/model.onnx",
                 "models/derived/injection-int8/model.onnx",
                 op_types_to_quantize=None,      # THE DEFAULT — do not pass a list
                 weight_type=QuantType.QInt8)    # also the default
```

**Passing `["MatMul","Gather"]` would NARROW the set, not widen it.** `Gather` is already a member of `CommonOpsRegistry`, which is a subset of `IntegerOpsRegistry`; the default therefore already quantizes it, along with everything else in that registry. Supplying an explicit two-element list is a restriction dressed up as an optimization.

**The label index is resolved at boot**, never hardcoded: `guardrails/injection/labels.py` reads `id2label` from `config.json` and matches aliases **casefolded** (`"INJECTION"`, `"injection"`, `"prompt_injection"` …). An opaque positional id such as `"LABEL_1"` is treated as an **unresolvable mapping and refuses to boot** — matching it would silently re-introduce exactly the positional assumption this decision eliminates (a checkpoint that renumbered its labels would then invert the guard). Session inputs are built from `sess.get_inputs()` — DeBERTa-v2 has `type_vocab_size: 0`, so `token_type_ids` must never be assumed.

**Parity is a hard build gate, not a spot check.** `scripts/provision/07_gates.py` compares torch-FP32 (in `.venv-provision`) against ONNX-INT8 over the full corpus and requires **`|Δ P(INJECTION)| < 0.05` with zero label flips**. It also measures on-disk size and steady-state session RSS and **fails provisioning if RSS > 0.35 GB**. It ran at M1: the FP32↔INT8 parity **failed** (INT8 rejected — see the M1 outcome above), and the FP32 session RSS **measured 0.30 GB**. **Fallback ladder, in order:** `INT8` → `FP32 ONNX` (kept on disk for exactly this reason) → drop the LLM to `llama3.2:1b` to buy back the RAM the FP32 session costs — this run stopped at the FP32 rung.

### OPEN QUESTIONS carried by this decision — both now RESOLVED at M1

**OQ-1 — RESOLVED (measured).** The size/RSS figures are no longer arithmetic: `07_gates.py` measured the **FP32** session RSS in a fresh interpreter at **0.30 GB** (< the 0.35 GB gate). ORT mmaps the weights, so the FP32 fallback did not change the RAM budget. The classifier line of the §7 RAM table is now a measurement, not a projection. (The original blocking concern — that the INT8 RSS estimate was unmeasured — is moot: INT8 is not shipped.)

**OQ-2 — RESOLVED (parity failed, as feared).** Default op types quantized the **relative-position embedding Gather**, the most quantization-sensitive part of this architecture, and the parity gate **did not pass**: `max |ΔP(INJECTION)| = 0.98` with 3 label flips, inverting the classifier. This was exercised before any seal — the gate caught it and the fallback ladder selected FP32 ONNX, exactly as designed.

## Alternatives considered

| Option | Why it lost |
|---|---|
| **torch + `transformers` at runtime** | ~0.45 GB RSS on the sealed process and a genuine `ResolutionImpossible` between the `transformers` and `huggingface-hub` pins. See [ADR-0003](0003-two-virtualenvs.md). |
| **`op_types_to_quantize=["MatMul","Gather"]`** | Narrows the default set. `Gather` ∈ `CommonOpsRegistry` ⊂ `IntegerOpsRegistry`; the explicit list removes every other quantizable op and yields a *larger*, not smaller, model. |
| **FP32 ONNX as the shipped default** | Rejected at decision time on a 0.80 GB classifier-session estimate → a projected 7.25 GB system total in the embedded-Qdrant profile. **Superseded at M1: that estimate was wrong — the FP32 session measured 0.30 GB (ORT mmaps the weights) — so FP32 IS the shipped default, and the 3B model is retained.** |
| **`protectai/deberta-v3-small-prompt-injection-v2` as the INT8 fallback** | The repo is `gated: auto`. **A sealed system must not depend on a credential**, and a gated artifact cannot be re-provisioned after an unseal without one. Removed from the ladder entirely. |
| **Static / QDQ quantization with a calibration set** | Needs a representative calibration corpus and a second toolchain, and the accuracy question (OQ-2) is about the relative-position embedding, which static quantization does not obviously rescue. Not worth the complexity before OQ-2 is even measured. |
| **`optimum.onnxruntime` for the whole pipeline** | Pulls `transformers`. On the explicit not-installed list. |

## Consequences

### Positive
- The classifier session is **measured at 0.30 GB** (M1, FP32), which is what the projection says lets the 3B LLM and the demo profile coexist under 8 GB. No torch anywhere in the serving process; `import torch` failing is itself a smoke-test assertion (`[ 1/14]`).
- The inverted-guardrail bug class is closed by construction (`CLAUDE.md` invariant 5 — never hardcode the injection label index): the index comes from `config.json`, matched casefolded, and boot fails rather than guesses.
- The fallback ladder is pre-provisioned. Provisioning has run (M1): FP32 ONNX is on disk (0.74 GB) and selected as the runtime classifier, and `llama3.2:1b` is pulled (1.30 GB), so exercising the ladder needs no network.

### Negative
- The headline 0.30 GB figure is **now MEASURED** (FP32 session RSS, M1), so the classifier line of the RAM table no longer rests on an estimate (OQ-1 resolved). The rest of the RAM table remains projections.
- **INT8 parity did fail** on this architecture (OQ-2 resolved): the shipped configuration is FP32 ONNX. Because the FP32 session measured 0.30 GB — unchanged from the INT8 estimate, since ORT mmaps the weights — the LLM stayed at `llama3.2:3b` and the `llama3.2:1b` rung was **not** needed. Any answer-quality difference is between INT8 and FP32, and FP32 is the higher-fidelity side.
- Quantization needs ~3 GB transient RAM during PROVISION. It runs before Ollama is started, so it does not contend — but provisioning cannot be interleaved with serving.
- Dropping `transformers` means the runtime cannot fall back to a `transformers`-native path if the ONNX graph misbehaves. The tokenizer parity gate is the entire safety net.

### Neutral
- `model.safetensors` (0.74 GB) is to be fetched **only** as the parity gate's reference input and is excluded from the runtime manifest subset. ORT session options are fixed at `intra_op_num_threads=4, inter_op_num_threads=1`, leaving 4 cores for Ollama.

## Verification

```bash
# The gates. `make provision` exits non-zero if any of these fail. Ran at M1:
#   tokenizer parity      : byte-identical input_ids/attention_mask       -> PASSED
#   FP32 <-> INT8 parity  : |dP(INJECTION)| < 0.05, ZERO label flips      -> FAILED (OQ-2): INT8 rejected
#   embedding parity      : atol=1e-4 vs sentence-transformers            -> PASSED (1.6e-07)
#   session RSS, measured : must FAIL above 0.35 GB                       -> 0.30 GB (OQ-1)
.venv-provision/bin/python scripts/provision/07_gates.py

! .venv/bin/python -c "import torch" 2>/dev/null           # no torch on the sealed side
.venv/bin/python -c "from sagp.guardrails.injection.labels import resolve_injection_idx as r; \
                     print(r('models/hf/injection/config.json'))"   # 1, resolved from id2label
```

Gates (implemented; `make smoke` reports 14/14): `make smoke` check `[ 5/14]` requires the classifier to load, `INJECTION_IDX` to resolve from `config.json`, and the boot self-test to pass **through the real policy path** — `guardrails/injection/selftest.py` refuses to start the app on failure. `make eval` ran at M6: headline injection recall is **1.0** (target ≥ 0.90). Precision was 0.81 and benign FPR 0.32 at M6, but the later corroboration-gating fix lifted precision to **0.854 (now MEETS ≥ 0.85)** and FPR to **0.24** (improved from 0.32, still over the 0.10 target — the one remaining OPEN known gap); jailbreak (family B) and indirect-injection (family F) are reported separately, never averaged in. Closing the residual FPR needs an ensemble or a fine-tune, not a model swap — the full candidate field (8 models, incl. Llama Prompt Guard 2) was swept and none beats the baseline without regressing recall (see `docs/metrics/candidates/`). Note also that the model card for this archived checkpoint states it does **not** detect jailbreak attacks and does not handle non-English prompts.

---

[ADR index](../ARCHITECTURE.md) · [ADR-0003: Two virtualenvs](0003-two-virtualenvs.md) · [ADR-0001: Ollama over vLLM](0001-ollama-over-vllm.md) · [Blueprint](../BLUEPRINT.md) · [Limitations](../LIMITATIONS.md)
