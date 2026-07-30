# ADR-0001: Ollama as the local LLM runtime, not vLLM

Records why the sealed host serves `llama3.2:3b-instruct-q4_K_M` through Ollama rather than through vLLM, and what would have to change for that to be revisited.

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Project architect
- **Supersedes:** —

## Context

The target machine is an Apple M2, arm64, macOS Darwin 25.5.0, **8 GB unified RAM (hard ceiling)**, 8 cores. That single hardware fact drives every runtime choice below. Every RAM figure quoted in this ADR is a PROJECTION against that ceiling; nothing in this repository has been measured. See the RAM table in [BLUEPRINT §7](../BLUEPRINT.md) and [PLAN §6](../PLAN.md).

Forces:

| Force | Value | Source |
|---|---|---|
| RAM ceiling | 8 GB unified, shared with a macOS baseline of 3.00 GB (measured — the only measured row in BLUEPRINT §7; every other RAM figure is an estimate) | BLUEPRINT §7 |
| Budget left for the LLM after the app process (1.16 GB, ESTIMATE) | ~2.6 GB steady state, embedded-Qdrant profile (PROJECTION) | BLUEPRINT §7 |
| Python pin | **3.11.15**, chosen as the intersection of the `spacy==3.8.13` / `presidio-analyzer==2.2.364` wheel matrix — an intersection pin taken for safety, not a forced one (BLUEPRINT §1.1) | BLUEPRINT §2.1 |
| Quantization required | 4-bit (`q4_K_M`) — a 3B model at fp16 alone is ~6.4 GB (this ADR's own arithmetic: 3.2B params × 2 bytes) | — |
| Accelerator | Apple Metal via the unified memory pool; no CUDA device exists | host hardware facts |
| Network posture | The runtime must never resolve a hostname; the model must already be on disk | BLUEPRINT §6 Phase 2 |

The LLM runtime also sits **outside** both Python egress-guard layers — it is a separate process either way, covered only by the optional pf anchor ([THREAT_MODEL](../THREAT_MODEL.md), [LIMITATIONS](../LIMITATIONS.md) item 3). So the choice is not about isolation; it is about whether the runtime fits and whether it can be provisioned offline.

## Decision

**Serve the LLM with Ollama**, bound to `127.0.0.1:11434`, models stored under `OLLAMA_MODELS="$PWD/models/ollama"`, called through `ollama==0.6.2` from the sealed venv. vLLM is not a dependency of this project in any venv.

Specifics: `llama3.2:3b-instruct-q4_K_M` (2.0 GB) is the default; `OLLAMA_CONTEXT_LENGTH=4096`, `OLLAMA_KV_CACHE_TYPE=q8_0`, `OLLAMA_MAX_LOADED_MODELS=1`, `OLLAMA_NUM_PARALLEL=1`, `keep_alive="30m"`. `num_ctx` is never passed per request — that forces a full model reload. `llama3.2:1b` is pulled during provisioning as the fallback rung of the [ADR-0004](0004-onnx-int8-no-torch.md) ladder. `llama3:8b` is pulled during provisioning so it is one env var away, but is documented as **does not fit** (projects to 9.28 GB in the embedded profile against an 8 GB ceiling — PROJECTION, unmeasured) and is specified to trigger a loud startup warning below 16 GB of host RAM.

## Alternatives considered

| Option | Why it lost |
|---|---|
| **vLLM on Metal** | There is no practical Metal / macOS-arm64 backend. vLLM's supported accelerators are CUDA, ROCm, TPU and CPU; the macOS path is a source build of the CPU backend. A CPU-only 3B decode on an M2 forfeits the GPU that the unified memory pool exists to feed. |
| **vLLM on CPU** | The CPU backend does not offer 4-bit weight quantization. Without `q4_K_M` the 3B model does not fit under the ~2.6 GB the RAM table leaves for the LLM. |
| **vLLM under the pinned interpreter** | vLLM's macOS/CPU build instructions target a newer Python than the **3.11.15** this project pins for the spaCy/Presidio wheel matrix. Adopting vLLM means either a second interpreter for the serving process or moving off that pin. (UNVERIFIED — no vLLM build was attempted on this host; this is a design-time assessment, not a measured result.) |
| **vLLM's memory model** | vLLM preallocates a PagedAttention KV pool sized as a fraction of device memory at engine start. On a unified-memory host that pool is taken from the same 8 GB the guardrail models live in, and it is claimed whether or not a request is in flight. The RAM budget projects 1.25 GB of headroom in the embedded-Qdrant profile (and none to speak of in `PROFILE=demo`); a preallocated pool consumes it unconditionally. |
| **llama.cpp / `llama-server` directly** | Technically viable and the same GGUF weights. Rejected on provisioning ergonomics: Ollama gives one command (`ollama pull`) that produces content-addressed blobs whose digests go straight into `MANIFEST.json`, plus a stable HTTP contract and a maintained Python client. The gain from dropping the Ollama layer is small; the loss in runbook simplicity is not. |
| **Any hosted API** | Terminates the project. `CLAUDE.md` invariant 2 — never add a network call — permits exactly two egress targets, both loopback. |

## Consequences

### Positive
- Projected to fit the budget: weights 2.0 + KV @ q8_0 0.24 + compute graph 0.35 = **2.59 GB (ESTIMATE)**, giving a projected system total of **6.75 GB in the default embedded-Qdrant profile** with 1.25 GB of projected headroom. The `PROFILE=demo` (Docker) profile projects 7.60 GB instead. Both totals are sums of estimates — neither has been measured.
- Provisioning is offline-completable: `OLLAMA_MODELS=… ollama pull` during PROVISION, blob digests recorded in `MANIFEST.json`, nothing fetched at request time.
- Memory is claimed lazily and released on `keep_alive` expiry, so an idle box does not hold the pool.

### Negative
- Ollama is a separate Go process outside both Python guard layers. Its egress is covered only by `make seal-pf`, and its binary sha256 in `MANIFEST.json` is the only integrity control on it.
- Throughput ceiling: single request, `OLLAMA_NUM_PARALLEL=1`. There is no continuous batching. This is deliberate — concurrency is capped at `anyio.CapacityLimiter(2)` anyway — but it makes the design unsuitable for multi-tenant load without revisiting.
- The 0.35 GB compute-graph figure is an **ESTIMATE** derived from typical llama.cpp Metal allocations, not measured on this M2 (**OPEN QUESTION OQ-8**).

### Neutral
- Buffer-then-scan generation only; SSE stage events carry no content. That constraint comes from the output guardrail, not from Ollama.
- Swapping runtimes later means reimplementing `llm/ollama_client.py` against the `LLMClient` protocol in `llm/base.py`; nothing above that boundary changes.

## Verification

```bash
# 1. The runtime is reachable, loopback-only, and holds the pinned tag.
curl -sS http://127.0.0.1:11434/api/tags | grep -q 'llama3.2:3b-instruct-q4_K_M'
lsof -nP -iTCP -sTCP:LISTEN | grep 11434 | grep -q '127.0.0.1'   # never 0.0.0.0

# 2. OQ-8: measure the runner footprint and validate the RAM table.
ollama ps          # SIZE column is the real allocation; expected ~2.59 GB (ESTIMATE)

# 3. No vLLM in either venv, ever.
! .venv/bin/pip show vllm            > /dev/null 2>&1
! .venv-provision/bin/pip show vllm  > /dev/null 2>&1
```

Gates (specifications — no make target or test exists yet): `make smoke` check `[ 8/14]` is specified to assert Ollama is reachable and the tag is present. `make serve` is specified to refuse to boot above 90% projected RSS. `tests/e2e/` is specified to perform one real generation under the `needs_ollama` marker.

---

[ADR index](../ARCHITECTURE.md) · [Blueprint](../BLUEPRINT.md) · [Plan](../PLAN.md) · [Limitations](../LIMITATIONS.md)
