# ADR-0003: Two virtualenvs — `.venv` sealed runtime, `.venv-provision` online only

Records why this project has two Python environments instead of one, and what that structural split buys: a dissolved dependency deadlock and ~0.45 GB of torch RSS removed from the sealed process.

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Project architect
- **Supersedes:** —

## Context

The five source subsystem specs each assumed a single environment, and they could not agree on what was in it. Two concrete problems resulted.

**1. A real `ResolutionImpossible`.** The injection subsystem wanted `transformers` for tokenization and label handling. The provisioning subsystem wanted a modern `huggingface-hub`. `transformers==4.57.6` requires `huggingface-hub<1.0,>=0.34.0` (read from its published `requires_dist` metadata; no resolve has been run in this repository). Pinning `huggingface-hub==1.25.1` alongside it is unsatisfiable. There is no single environment that holds both.

**2. The RAM ceiling.** The host has 8 GB unified, hard. `torch` costs roughly **0.45 GB of RSS** in the serving process (ESTIMATE — unmeasured) before it does any work, and the app process budget is 1.16 GB total (ESTIMATE) with a boot gate at 1.40 GB. The original repo spec's dependency list projects to 8.32 GB in the embedded-Qdrant profile (PROJECTION) — it does not fit at all.

Both problems have the same shape: the *provisioning* toolchain and the *serving* runtime want different, incompatible things, and only one of them ever runs on the sealed box.

## Decision

**Two virtualenvs, both built from `~/.local/bin/python3.11` (Python 3.11.15) by `scripts/bootstrap_venvs.sh`. No uv, no poetry, no conda.**

```
.venv-provision/   ONLINE ONLY. huggingface-hub==0.35.3, transformers==4.57.6, torch==2.9.1,
                   onnx==1.22.0, onnxruntime[quantization]==1.28.0, sentence-transformers==5.6.1,
                   pytest==9.1.1. Used by scripts/provision/*.py. Deleted or left inert after `make seal`.

.venv/             THE SEALED RUNTIME. No torch, no transformers, no huggingface-hub,
                   no sentence-transformers, no onnx, no chromadb, no optimum, no sentencepiece.
                   Tokenization: tokenizers==0.23.1  ->  Tokenizer.from_file()
                   Inference:    onnxruntime==1.28.0 ->  InferenceSession
                   NER:          spacy==3.8.13 + en_core_web_md 3.8.0
```

Each has its own hash-pinned lockfile (`requirements.runtime.lock`, `requirements.provision.lock`) and its own wheelhouse (`vendor/wheelhouse/`, `vendor/wheelhouse-provision/`). `bin/sagp-serve` execs `.venv`; `bin/sagp-provision` execs `.venv-provision`. Neither script can reach the other's interpreter.

**What makes dropping `transformers` safe is a gate, not an assumption.** `scripts/provision/07_gates.py` — which does not exist yet — is specified to assert that `tokenizers.Tokenizer.from_file(...)`, configured `max_length=512, stride=128, strategy="longest_first"`, padded to 512 with `pad_id=0`, produces **byte-identical** `input_ids` and `attention_mask` to `transformers.AutoTokenizer.from_pretrained(...)` over the full 63-case corpus. Any divergence must fail the build. The gate has not been run, so the parity is a requirement, not a result.

## Alternatives considered

| Option | Why it lost |
|---|---|
| **One venv with `transformers`, no hub pin** | Does not dissolve the deadlock — it only hides it until the resolver picks a hub version, and it leaves torch (a `transformers` install target for real use) and ~0.45 GB of RSS on the sealed critical path. |
| **One venv, `huggingface-hub==1.25.1`, drop `transformers`** | Closest to viable, but `huggingface-hub` at runtime is precisely the library that phones home. Assertion 28 in the reconciliation ledger exists because HF offline env vars loaded via pydantic-settings are a **no-op** — they are read at import time. With the two-venv split the runtime assertion becomes the far stronger "`huggingface_hub` is not importable at all". |
| **One venv, install then `pip uninstall torch`** | Leaves dangling metadata and a lockfile that does not describe the installed set. `--require-hashes` reproducibility is the whole point of the sealed install; a post-hoc uninstall breaks it. |
| **Docker for the provisioning toolchain** | Adds the Docker VM to the provisioning path, and the quantization step needs ~3 GB transient RAM that would then come out of a VM allocation on an 8 GB host. Also puts torch behind a boundary that `07_gates.py` must reach across to run parity checks. |
| **`optimum` to bridge transformers and ONNX at runtime** | `optimum` pulls `transformers`, which is the thing being removed. It is on the explicit not-installed list. |

## Consequences

### Positive
- The `ResolutionImpossible` is gone, not worked around. Each lockfile resolves independently.
- ~0.45 GB of torch RSS is removed from the serving process (ESTIMATE — unmeasured), which is what is projected to make the 1.16 GB app-process budget reachable.
- The offline assertion gets stronger: `import huggingface_hub` raising `ModuleNotFoundError` in `.venv` is something the smoke test can check directly, unlike an env var that may or may not have been read in time.
- Supply-chain surface on the sealed box shrinks to the runtime closure only. The provisioning closure — the larger one, ~2.20 GB of wheels (ESTIMATE) — never ships.

### Negative
- Two lockfiles, two wheelhouses, two `pip download` runs. Projected disk cost: `.venv` ~0.45 GB + `.venv-provision` ~1.60 GB + both wheelhouses ~2.80 GB (ESTIMATES, BLUEPRINT §8).
- Any change to the injection or embedding model must re-run the parity gates in `.venv-provision`, which means unsealing. That is intentional friction, but it is friction.
- Two interpreters to keep at 3.11.15. A drifted `.venv-provision` produces parity fixtures that do not describe the runtime.
- Contributors will reach for `transformers` out of habit. `CLAUDE.md` invariant 10 — never install torch/transformers/huggingface-hub into the runtime venv — exists specifically to catch that: *"if you think you need one, you need `tokenizers` or `onnxruntime` instead — say so rather than adding it."*

### Neutral
- `pytest` lives in `.venv-provision` for provisioning gates; the runtime test set installs `[dev]` into `.venv` separately. The `[dev]` extra is enumerated with pins in BLUEPRINT §2.2 (pytest, hypothesis, pytest-asyncio, ruff, mypy — the last two being what `make lint`/`make typecheck` invoke); it is a test/lint dependency set and is never present on the sealed runtime path.
- After `make seal`, `.venv-provision` may be deleted outright. Nothing in OPERATE reads it.

## Verification

```bash
# The sealed runtime must not be able to import any of the four.
for m in torch transformers huggingface_hub sentence_transformers; do
  .venv/bin/python -c "import $m" 2>/dev/null && { echo "FAIL: $m importable in .venv"; exit 1; }
done
.venv/bin/python -c "import sys; assert sys.version.split()[0] == '3.11.15'"

# The provisioning venv must have them.
.venv-provision/bin/python -c "import torch, transformers, huggingface_hub; print('provision ok')"

# Hash-pinned installs only.
grep -q -- '--require-hashes' Makefile
```

Gates (specifications — neither the make targets nor the tests exist yet): `make smoke` check `[ 1/14]` is specified as literally *".venv present, Python 3.11.15, torch NOT importable"*. `scripts/provision/07_gates.py` is specified to run the tokenizer parity gate over the 63-case corpus and to exit non-zero on any divergence, so that `make provision` cannot succeed — and therefore `make seal` cannot run — with a tokenizer that disagrees with the one the model was trained against. `tests/security/test_no_network_imports.py` is specified to walk the AST of `src/sagp/` and fail on any import of the four forbidden packages.

---

[ADR index](../ARCHITECTURE.md) · [ADR-0004: ONNX INT8, no torch](0004-onnx-int8-no-torch.md) · [Blueprint](../BLUEPRINT.md) · [Air-gap runbook](../AIRGAP_RUNBOOK.md)
