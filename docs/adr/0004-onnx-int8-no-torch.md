# ADR-0004: ONNX Runtime only at runtime, with INT8 dynamic quantization behind a hard parity gate

Records how the injection classifier is executed on the sealed host — ONNX Runtime with no torch — how it is quantized, and the two open questions that could still force the fallback ladder.

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Project architect
- **Supersedes:** —

## Context

The injection classifier is `protectai/deberta-v3-base-prompt-injection-v2` @ `90c9989b1a342275dd0d1a95aad283c04e075671`. The repository ships both `onnx/model.onnx` (738,563,188 B) and `model.safetensors` (737,719,272 B), ungated, Apache-2.0. The forces:

- **RAM.** 8 GB hard ceiling. The app-process budget is 1.16 GB (ESTIMATE) with a boot gate at 1.40 GB. An FP32 ONNX session for this model is budgeted at 0.80 GB — projected to fit *only* with the embedded-Qdrant profile and the 1B LLM. The INT8 session is budgeted at **0.30 GB**. Every figure here is an unmeasured projection (OQ-1).
- **No torch at runtime.** Settled in [ADR-0003](0003-two-virtualenvs.md). Execution is `onnxruntime==1.28.0` (arm64 cp311 wheel, 19,130,506 B); tokenization is `tokenizers==0.23.1`.
- **A near-miss bug in the source specs.** One spec claimed the default `quantize_dynamic` op-type set is "MatMul only" and proposed passing `op_types_to_quantize=["MatMul","Gather"]` to widen it. That is backwards.
- **The label index must never be hardcoded.** One spec had `torch.softmax(logits,-1)[:,1]`. The actual `id2label` is `{"0": "SAFE", "1": "INJECTION"}` — but a hardcoded index silently *inverts* the guardrail if the checkpoint ever changes: benign blocked, attacks passed.

## Decision

**The sealed runtime executes the classifier through `onnxruntime.InferenceSession` on `CPUExecutionProvider`, with no `torch`, no `transformers`, no `optimum`.** The shipped session is the **INT8 dynamically quantized** model at `models/derived/injection-int8/model.onnx`. Quantization uses **the defaults**:

```python
# scripts/provision/06_quantize.py  (runs in .venv-provision, needs ~3 GB transient)
from onnxruntime.quantization import quantize_dynamic, QuantType
quantize_dynamic("models/hf/injection/onnx/model.onnx",
                 "models/derived/injection-int8/model.onnx",
                 op_types_to_quantize=None,      # THE DEFAULT — do not pass a list
                 weight_type=QuantType.QInt8)    # also the default
```

**Passing `["MatMul","Gather"]` would NARROW the set, not widen it.** `Gather` is already a member of `CommonOpsRegistry`, which is a subset of `IntegerOpsRegistry`; the default therefore already quantizes it, along with everything else in that registry. Supplying an explicit two-element list is a restriction dressed up as an optimization.

**The label index is resolved at boot**, never hardcoded: `guardrails/injection/labels.py` reads `id2label` from `config.json` and matches aliases **casefolded** (`"INJECTION"`, `"injection"`, `"LABEL_1"` …). An unresolvable mapping refuses to boot. Session inputs are built from `sess.get_inputs()` — DeBERTa-v2 has `type_vocab_size: 0`, so `token_type_ids` must never be assumed.

**Parity is a hard build gate, not a spot check.** `scripts/provision/07_gates.py` — not yet written, and never run — is specified to compare torch-FP32 (in `.venv-provision`) against ONNX-INT8 over the full corpus and to require **`|Δ P(INJECTION)| < 0.05` with zero label flips**. It is also specified to measure on-disk size and steady-state session RSS and to **fail provisioning if RSS > 0.35 GB**. No parity result and no RSS measurement exists today. **Fallback ladder, in order:** `INT8` → `FP32 ONNX` (kept on disk for exactly this reason) → drop the LLM to `llama3.2:1b` to buy back the RAM the FP32 session costs.

### OPEN QUESTIONS carried by this decision

**OQ-1 — the INT8 size and RSS figures are arithmetic, not measured.** `~190–220 MB on disk / ~0.30 GB RSS` was derived from the 128,100 × 768 embedding table, and the Gather-op rationale it originally rested on was wrong. **BLOCKING for the RAM budget.** `07_gates.py` must measure both and fail above 0.35 GB. The gate is 0.35 rather than 0.30 because the RAM table still closes at a projected 7.05 GB in the embedded profile if INT8 lands at 0.60 GB. Do not publish the §7 RAM table as measured until this number is real.

**OQ-2 — INT8 parity on DeBERTa-v3's disentangled attention may simply fail.** Default op types also quantize the **relative-position embedding Gather**, the most quantization-sensitive part of this architecture. The parity gate may not pass. That is an acceptable outcome — the ladder is the answer — but it **must be exercised before sealing**, not discovered afterwards.

## Alternatives considered

| Option | Why it lost |
|---|---|
| **torch + `transformers` at runtime** | ~0.45 GB RSS on the sealed process and a genuine `ResolutionImpossible` between the `transformers` and `huggingface-hub` pins. See [ADR-0003](0003-two-virtualenvs.md). |
| **`op_types_to_quantize=["MatMul","Gather"]`** | Narrows the default set. `Gather` ∈ `CommonOpsRegistry` ⊂ `IntegerOpsRegistry`; the explicit list removes every other quantizable op and yields a *larger*, not smaller, model. |
| **FP32 ONNX as the shipped default** | 0.80 GB classifier session → a projected 7.25 GB system total in the embedded-Qdrant profile. It is projected to fit only with embedded Qdrant *and* `llama3.2:1b`, which forfeits both the demo profile and the 3B model. Retained on disk as the fallback rung, not as the default. |
| **`protectai/deberta-v3-small-prompt-injection-v2` as the INT8 fallback** | The repo is `gated: auto`. **A sealed system must not depend on a credential**, and a gated artifact cannot be re-provisioned after an unseal without one. Removed from the ladder entirely. |
| **Static / QDQ quantization with a calibration set** | Needs a representative calibration corpus and a second toolchain, and the accuracy question (OQ-2) is about the relative-position embedding, which static quantization does not obviously rescue. Not worth the complexity before OQ-2 is even measured. |
| **`optimum.onnxruntime` for the whole pipeline** | Pulls `transformers`. On the explicit not-installed list. |

## Consequences

### Positive
- The classifier session is budgeted at 0.30 GB instead of 0.80 GB, which is what the projection says lets the 3B LLM and the demo profile coexist under 8 GB. No torch anywhere in the serving process; `import torch` failing is itself a specified smoke-test assertion.
- The inverted-guardrail bug class is closed by construction (`CLAUDE.md` invariant 5 — never hardcode the injection label index): the index comes from `config.json`, matched casefolded, and boot fails rather than guesses.
- The fallback ladder is pre-provisioned. Once provisioning has run, FP32 ONNX is on disk (0.74 GB) and `llama3.2:1b` is pulled (1.30 GB), so exercising the ladder needs no network. Provisioning has not run.

### Negative
- **The headline 0.30 GB figure is UNVERIFIED** and the whole RAM table depends on it (OQ-1).
- **INT8 parity may fail** on this architecture (OQ-2), in which case the shipped configuration degrades to FP32 + `llama3.2:1b` and answer quality drops.
- Quantization needs ~3 GB transient RAM during PROVISION. It runs before Ollama is started, so it does not contend — but provisioning cannot be interleaved with serving.
- Dropping `transformers` means the runtime cannot fall back to a `transformers`-native path if the ONNX graph misbehaves. The tokenizer parity gate is the entire safety net.

### Neutral
- `model.safetensors` (0.74 GB) is to be fetched **only** as the parity gate's reference input and is excluded from the runtime manifest subset. ORT session options are fixed at `intra_op_num_threads=4, inter_op_num_threads=1`, leaving 4 cores for Ollama.

## Verification

```bash
# The gates, as specified. `make provision` must exit non-zero if any of these fail.
# None of this has been run; no result below has been observed.
.venv-provision/bin/python scripts/provision/07_gates.py
#   tokenizer parity      : byte-identical input_ids/attention_mask over 63 cases
#   FP32 <-> INT8 parity  : |dP(INJECTION)| < 0.05, ZERO label flips        <- OQ-2
#   embedding parity      : atol=1e-4 vs sentence-transformers, 200 fixtures
#   session RSS, measured : must FAIL above 0.35 GB                         <- OQ-1

! .venv/bin/python -c "import torch" 2>/dev/null           # no torch on the sealed side
.venv/bin/python -c "from sagp.guardrails.injection.labels import resolve_injection_idx as r; \
                     print(r('models/hf/injection/config.json'))"   # 1, resolved from id2label
```

Gates (specifications — no make target, test or model artifact exists yet): `make smoke` check `[ 5/14]` is specified to require the classifier to load, `INJECTION_IDX` to resolve from `config.json`, and the boot self-test to pass **through the real policy path** — `guardrails/injection/selftest.py` must refuse to start the app on failure. `make eval` is specified to enforce recall ≥ 0.90, precision ≥ 0.85, benign FPR ≤ 0.10 — **build-gate targets set at M6, not measurements; nothing has been evaluated** — with jailbreak and indirect-injection families reported separately and never averaged in. Note also that the model card for this archived checkpoint states it does **not** detect jailbreak attacks and does not handle non-English prompts.

---

[ADR index](../ARCHITECTURE.md) · [ADR-0003: Two virtualenvs](0003-two-virtualenvs.md) · [ADR-0001: Ollama over vLLM](0001-ollama-over-vllm.md) · [Blueprint](../BLUEPRINT.md) · [Limitations](../LIMITATIONS.md)
