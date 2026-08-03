# FINAL RECONCILED BLUEPRINT — Secure Air-Gapped Platform with Integrated Guardrails (`sagp`)

> **Status (2026-08-01): this is the arbitrated technical spec of a system now largely built.**
> M-DOCS and M0–M14 are complete, merged and tested — `src/`, `tests/`, `scripts/`, `config/`, `bin/`,
> the Makefile and `docker-compose.yml` all exist; the full suite is 280 tests passing, `make lint`/
> `typecheck` are green, and `make smoke` is 14/14 PASS. Where a test, gate, Make target or script is
> described below it now exists and runs. **A few figures are now MEASURED** — the injection classifier
> is FP32 ONNX (not INT8; OQ-2 resolved), its session RSS is 0.30 GB (OQ-1 resolved), the embedding
> parity gate passed at 1.6e-07, and the M6 guardrail metrics live in `docs/metrics/latest.json`.
> **Every latency figure and every RAM total remains an ESTIMATE / PROJECTION** — no benchmark has run
> on this M2, and each RAM total names the profile it assumes. The dev host is deliberately kept in
> PROVISION (never sealed for real), so no green air-gap `PASS` has been produced. This is the M15
> "correct-as-measured" pass over text first written correct-as-of-design. See
> [LIMITATIONS.md](LIMITATIONS.md) before quoting anything here.

**Status:** built (M0–M14). Every cross-spec contradiction below is arbitrated to a single answer. Version claims re-verified live against PyPI / HF API / GitHub during the design session; corrections to the critiques are listed in §1.

---

## 0. Reconciliation ledger — every contradiction, one decision each

| # | Contested | **DECISION** | Why |
|---|---|---|---|
| 1 | spaCy version (3.8.13 vs 3.8.14) | **`spacy==3.8.13`** | Intersection pin. See §1.1 — the "hard conflict" both critiques asserted does **not** exist on Python 3.11. 3.8.13 is valid under every constraint and every Python version. |
| 2 | spaCy NER model (sm/md/lg) | **`en_core_web_md` 3.8.0** | `SAGP_SPACY_MODEL`. Provision all three wheels; md is default. Real 300-d vectors for OOV proper nouns (Indian names) at ~0.20 GB. |
| 3 | transformers 4.57.6 vs 5.14.1 vs none; hub 0.x vs 1.25.1 | **Neither at runtime.** Two virtualenvs (§3). Runtime tokenizes with `tokenizers.Tokenizer.from_file()`. Provisioning venv carries `transformers==4.57.6` + `huggingface-hub==0.35.3` + `torch`. | Dissolves the `transformers<1.0 hub` vs `hub==1.25.1` ResolutionImpossible entirely, and removes ~0.45 GB of torch RSS from the sealed process. |
| 4 | torch at runtime (repo spec) | **Deleted from runtime.** `[provision]` extra only. | repo's dependency list *is* rag's CONFIG A4 (8.32 GB) — does not fit. |
| 5 | Injection runtime | ONNX via `onnxruntime.InferenceSession`, no torch, no `transformers`, no `optimum`. **M1 outcome: FP32, not INT8** — INT8 dynamic quant inverts this checkpoint (OQ-2), so the parity gate selected FP32 ONNX. | Verified `onnxruntime-1.28.0-cp311-cp311-macosx_14_0_arm64.whl` = 19,130,506 B. FP32 session RSS measured 0.30 GB (§7). |
| 6 | `quantize_dynamic` op types | **Use the default** (`op_types_to_quantize=None`). Do **not** pass `["MatMul","Gather"]`. **M1: even with the default op set, INT8 fails parity on this DeBERTa-v3 — the INT8 branch is rejected (OQ-2/ADR-0004); FP32 ONNX is the runtime model.** | `Gather` is already in `IntegerOpsRegistry`; passing the list narrows it. But default QInt8 still catastrophically degrades the disentangled attention — measured, not theoretical. |
| 7 | INT8 fallback = `deberta-v3-small` | **Removed.** Fallback ladder is: INT8 → FP32 ONNX (kept on disk) → drop LLM to `llama3.2:1b`. | `protectai/deberta-v3-small-prompt-injection-v2` is `gated: auto`; a sealed system must not depend on a credential. |
| 8 | Vector store (Chroma vs Qdrant) | **Qdrant only. Chroma deleted from the design.** Default runtime backend = **embedded** `QdrantClient(path=...)`, chosen on RAM grounds (6.75 GB projected embedded vs 7.60 GB projected with Docker, against an 8 GB ceiling). **`PROFILE=demo` (Docker `qdrant/qdrant:v1.18.3-unprivileged`) is the demonstration and proof path** — it is the network-isolation boundary this project exists to show and the path the proof harness targets. The Phase-0 spike (`make spike-docker`, run 2026-08-01) resolved OQ-4/OQ-5 **negatively**: the Docker path is **NOT network-isolated by compose options** — `internal: true` breaks host reachability so a non-internal bridge is used, and `enable_ip_masquerade: "false"` does not stop egress (userland VM proxy); DNS always leaks via the embedded resolver. Its egress control comes from the `pf` anchor + loopback, never `internal:`/`masquerade`. Never call the Docker path "isolated". | Keeps injection's `guard.verdict` payload filters and the quarantine collection; keeps the Docker VM out of the default RAM budget while retaining the demo path that actually demonstrates the boundary. |
| 9 | Embedding model | **`BAAI/bge-small-en-v1.5` @ `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a`**, ONNX, **CLS pooling → L2 normalize**, query prefix on queries only. | Verified `onnx/model.onnx` = **133,093,490 B**, ungated. MiniLM deleted from all lockfiles. |
| 10 | LLM | **`llama3.2:3b-instruct-q4_K_M`** (2.0 GB). `llama3:8b` is available in the design but was **skipped during M1 provisioning on this disk-constrained host** (§8) and is documented as **does not fit in 8 GB at runtime** anyway (projected 9.28 GB, §7) — it earns a loud startup warning, not an "accuracy profile". | rag §6 CONFIG B: no 8B variant fits; over by ≥1.3 GB. |
| 11 | Ingest PII policy | **`ingest_mode=raw`.** Store real chunk text; mask at retrieval with the per-request vault. `ingest_mode=masked` **deleted**. | Persistent vault + per-request vault collide on `<PERSON_1>` across identities; and masked docs vs raw queries destroys retrieval. |
| 12 | Block status code | **HTTP 400 `PROMPT_REJECTED`, identical body and a fixed rejection deadline (120 ms placeholder, calibrated at M13), for every detector including PII BLOCK-list.** 503 for unavailable, 413 for oversize, 401 for auth; C1 `UNSUPPORTED` (schema, pre-detector) is the sole exemption. | A 403-vs-400 split is a detector oracle. |
| 13 | `X-PII-Masked-Count` / `GuardrailReport` in the response body | **Removed from client responses.** Counts and scores go to the audit record and the authenticated `/v1/admin/incident/{id}` route only. | Threshold hill-climbing oracle; `CreditCardRecognizer` is Luhn-binary, so a count leak is a card validator. |
| 14 | Normalization / offset seam | **Ingress:** normalized text is canonical; Presidio analyzes and anonymizes the normalized string. **Egress:** Presidio analyzes the *raw* response; a second analysis of the normalized response yielding **more** entities → hard block. **No offset map exists anywhere.** | Eliminates the offset-corruption class entirely. Fail-closed on the one case that needs mapping. |
| 15 | Datamarking (U+2581) | **Deleted.** Nonce delimiters only. | 1.5–3× token blowup on a llama3 BPE, and it makes the retrieval re-scan classify out-of-distribution text. |
| 16 | Chunk injection scanning count | **Two scans total:** once per chunk at **ingest**, once over the **assembled masked context** at retrieval. Not per-chunk at retrieval. | Resolves the 3× cost compounding. |
| 17 | Prompt assembly owner | **`src/sagp/rag/prompt.py` is the sole builder of the final prompt string.** The other two designs are deleted. | The output guard must know which delimiter scheme was used. |
| 18 | Multi-turn | **Single-turn only.** `POST /v1/chat` takes `message: str`. A `messages` array of length > 1 → 400 `UNSUPPORTED`. | The per-request vault cannot survive history; conversation-scoping is deferred to v2. |
| 19 | Auth | **Two bearer tokens** generated at provision: `SAGP_API_TOKEN` (scopes `chat`,`ingest`), `SAGP_API_TOKEN_REVEAL` (adds `pii:reveal`). **There are exactly three scopes — `chat`, `ingest`, `pii:reveal`. There is no `admin` scope;** every `/v1/admin/*` route is gated on `pii:reveal`, i.e. requires `SAGP_API_TOKEN_REVEAL`. | `pii:reveal` and per-principal rate limiting were unimplementable without this. A fourth scope would only duplicate `pii:reveal`, since every admin route returns exactly the data `pii:reveal` guards. |
| 20 | Directory / namespace | **`src/sagp/`**, single env prefix **`SAGP_`**. `AIRGAP_*`, `GUARDRAIL_*`, bare keys all renamed. Upstream keys (`HF_*`, `OLLAMA_*`) keep their real names. | Four trees and five namespaces silently broke each other's env lookups. |
| 21 | Agent doc | **One file: `CLAUDE.md` at repo root.** airgap's phase invariants fold into the `CLAUDE.md` §2 list, which is the canonical numbering for the whole corpus — cite invariants by number from there and nowhere else (§11's ordering is historical). | |
| 22 | `MANIFEST.json` schema | **airgap's schema**, with `manifest_hash` exposed as an alias of `root_hash`. | Superset; carries upstream cross-check + Ed25519 signature. |
| 23 | Manifest verify at boot | **`full` mode, always.** ~3 s on M2. `quick` is diagnostic only and is an *invalidating* condition for any PASS verdict. | `quick` skips the interior of every file that matters. |
| 24 | `Cf` blocking heuristic | **Block outright only U+E0000–U+E007F (tag chars) and U+202A–U+202E / U+2066–U+2069 (bidi).** All other `Cf` → strip + flag, never block alone. | U+00AD/U+200C/U+200D are required for PDF paste and Indic/Arabic scripts — the stated user base. |
| 25 | AF_UNIX in the egress guard | **Deny by default**, path allowlist (empty by default). `/var/run/docker.sock` denied unconditionally in OPERATE. | It is a full egress channel, not a local-only one. |
| 26 | Subprocess egress | **Control in path (unmeasured)** — PEP 578 audit hooks on `subprocess.Popen`, `os.system`, `os.exec*`, `os.spawn*`, `ctypes.dlopen`. Re-characterised from "high, OPEN" to "a control is specified in the path for children of the guarded interpreter". "Closed" is not available as a verdict: no probe has been run on this host. | CPython raises these before fork; this is the stated most-likely failure (an agent running `pip install`). |
| 27 | `.pth` bootstrap trigger | Reads **`.airgap/state.json`**, not `AIRGAP_PHASE`. Unreadable/missing → install in enforce mode. | An env var typo silently disabled both guard layers. |
| 28 | HF offline env vars in `.env` | **Removed from `.env`.** Exported by `bin/sagp-serve` before the interpreter starts. **Corrected at M0:** `huggingface_hub` IS importable in `.venv` (`tokenizers==0.23.1` hard-depends on it), so the old "hub is not importable" assertion is wrong. The runtime assertion is instead "`torch` and `transformers` are not importable"; hub is neutralised by `HF_HUB_OFFLINE=1` (set before import) + the egress guard, not by absence. | pydantic-settings loads after `huggingface_hub` import; the flags must be exported by the launcher, not read from `.env`. |
| 29 | `tldextract` PSL fetch | **`SealedEmailRecognizer`** with an injected no-fetch extractor. See §5.3. | Verified: `EmailRecognizer.validate_result` calls module-level `tldextract.extract`, which fetches the Public Suffix List over HTTPS on first use. |
| 30 | Streaming | **Buffer-then-scan only.** SSE **stage events** (no content) are shipped; token streaming is not. | Citation validation and injection-compliance detection are undecidable on a partial response. |

---

## 1. Corrections to the critiques (evidence-backed)

### 1.1 The spaCy "hard conflict" does **not** exist on Python 3.11

Verbatim from `https://pypi.org/pypi/presidio-analyzer/2.2.364/json` → `info.requires_dist`:

```
spacy!=3.7.0,!=3.8.14,<4.0.0,>=3.4.4; python_version >= "3.14"
spacy!=3.7.0,<4.0.0,>=3.4.4;         python_version <  "3.14"
```

The `!=3.8.14` exclusion is **gated on `python_version >= "3.14"`**. On the target Python 3.11 the applicable line has no such exclusion. Both the feasibility and security critiques read the marker-less form and declared `pip install presidio-analyzer==2.2.364 spacy==3.8.14` unresolvable. **It resolves.**

Verified wheels (both exist, no source build):
- `spacy-3.8.13-cp311-cp311-macosx_11_0_arm64.whl` — 6,441,498 B
- `spacy-3.8.14-cp311-cp311-macosx_11_0_arm64.whl` — 6,441,524 B (latest)

**We still pin `3.8.13`**, not because 3.8.14 is forbidden, but because 3.8.13 satisfies *every* constraint under *every* Python version — presidio's maintainers excluded 3.8.14 somewhere, and an intersection pin costs one patch release. The startup assertion is `spacy.__version__ == "3.8.13"`, not `!= "3.8.14"`.

### 1.2 Other corrections

| Claim | Correction |
|---|---|
| `injection` §2.3: default `quantize_dynamic` is "MatMul only", 480 MB tier | **False.** `Gather` ∈ `CommonOpsRegistry` ⊂ `IntegerOpsRegistry`; it is quantized by default. Use defaults. Default `weight_type` is `QuantType.QInt8`. |
| `pii` §1.5: `id2label = {0: benign, 1: injection}` | **Actual:** `{"0": "SAFE", "1": "INJECTION"}` (verified against the repo). Alias matching must be **casefolded** or a correct model refuses to boot. |
| `pii` §2.1: `BatchAnalyzerEngine` under `presidio_anonymizer` | It is `from presidio_analyzer import BatchAnalyzerEngine`. |
| `pii`: source at `github.com/microsoft/presidio` | **Moved.** Canonical repo is `github.com/data-privacy-stack/presidio`. Verified at tag `2.2.364`. Recognizers were reorganized into subpackages (`predefined_recognizers/generic/`, `.../country_specific/india/`) but **all names remain exported at `presidio_analyzer.predefined_recognizers`** — import from the package, never the module path. |
| `injection`: `numpy>=1.26,<3` | Presidio pins `numpy<2.5.0,>=1.19.0`. Use `numpy>=1.26,<2.5.0`. |
| `repo` §8: `torch.softmax(logits,-1)[:,1]` | Deleted. Hardcoded index 1 is the inverted-guardrail bug. |
| `repo` §8: qdrant `search()` "deprecated" | **Removed** in qdrant-client 1.16.0. `query_points(...)` returns a `QueryResponse`; results are at `.points`; the filter kwarg is `query_filter=`. |
| `repo`: `pii_token_hmacs` = HMAC of the *placeholder* | Carries zero information — placeholders are per-request ordinals. Must be `HMAC(key, f"entity:{type}\x1f{normalize(type,value)}")`. |
| `repo`: `SAGP_PII_SCORE_THRESHOLD=0.40` | 0.40 is exactly `LemmaContextAwareEnhancer.min_score_with_context_similarity` — it means "one nearby context word is sufficient". Split into ingress 0.50 / egress 0.35. |
| `rag`: `qdrant-client` is REST-only with `prefer_grpc=False` | It hard-depends on `grpcio>=1.41.0`, `protobuf>=3.20.0`, `httpx[http2]`, `portalocker`, `urllib3` regardless. `grpcio`'s C core is outside the Python egress guard — a real known gap. |
| `rag` §5.2 / `injection` §5.2: "2 adjacent windows" corroboration on chunks | Inoperative — a 320-token chunk is exactly one 512-token window. Corroboration applies **only** to the assembled context (4–5 windows). |
| `injection`: "8.4% FP rate" from 1 − precision | 1 − precision is the false *discovery* rate. Solving the card's numbers gives FPR ≈ 9.3% on a balanced set; in production (near-zero base rate) precision collapses while FPR holds. Restate all FP reasoning in FPR terms. |
| `airgap`: `network_calls_attempted: 0` in the evidence report | Unmeasurable for Ollama/Qdrant/ONNX/native libs. **Field renamed** `python_egress_attempts_blocked`. |
| `airgap`: `TRANSFORMERS_OFFLINE` no longer referenced | That is a transformers 5.x observation. Irrelevant — transformers is not in the runtime venv. |
| `injection` §5.3: compare extracted vs *rendered* PDF text | Not implementable without a rasterizer (PyMuPDF rejected on AGPL §13). **Replaced** by pypdf's `visitor_text=(text, cm, tm, font_dict, font_size)` callback: flag near-zero `font_size`, text placed outside the MediaBox via `tm`, and render-mode-3 / background-coloured fills. |
| Free disk | **Measured 5.9 GB free.** Provisioning needs ~25 GB (incl. ~3 GB transient for quantization). `make doctor` hard-fails below `sum(artifacts.lock sizes) × 1.5 + 5 GB`. |

---

## 2. Locked artifacts — exact IDs, versions, sizes

### 2.1 Runtime venv `.venv` (installed on the sealed host)

```
python           3.11.15                # ~/.local/bin/python3.11 (uv-managed CPython)

fastapi          ==0.140.1
uvicorn[standard]==0.51.0
pydantic         ==2.13.4               # presidio needs >=2.12.5,<3
pydantic-settings==2.14.2
python-multipart ==0.0.32

presidio-analyzer  ==2.2.364            # requires_python <3.15,>=3.10
presidio-anonymizer==2.2.364            # pulls cryptography>=48.0.1,<49
spacy              ==3.8.13             # arm64 cp311 wheel 6,441,498 B
thinc-apple-ops    ==1.0.0              # via `spacy[apple]`

onnxruntime      ==1.28.0               # arm64 cp311 wheel 19,130,506 B; requires_python >=3.11
tokenizers       ==0.23.1               # runtime tokenizer; NO transformers
numpy            >=1.26,<2.5.0          # presidio ceiling

qdrant-client    ==1.18.0               # hard deps: grpcio, protobuf, httpx[http2], portalocker, urllib3
ollama           ==0.6.2
pypdf            ==6.14.2               # BSD-3; PyMuPDF REJECTED (AGPL-3.0 §13)
pyyaml           >=6.0.3,<7
regex            >=2024.11
psutil           ==7.1.0                # lifespan RAM boot-refusal + /readyz per-component RSS (§7); not transitive

# transitive, pinned explicitly for the hash-locked wheelhouse
phonenumbers     ==9.0.35
tldextract       ==5.3.1                # requires_python >=3.10; deps: idna, requests, requests-file, filelock
cryptography     >=48.0.1,<49
grpcio           ==1.71.0               # ⚠ pin the version your resolver produces; native ext
protobuf         >=4.25.8,<6
httpx            ==0.28.1
```

**Not installed at runtime, by design:** `torch`, `transformers`, `huggingface-hub`, `sentence-transformers`, `onnx`, `chromadb`, `optimum`, `sentencepiece`.

### 2.2 Provisioning venv `.venv-provision` (online only, never on the sealed critical path)

```
huggingface-hub  ==0.35.3               # <1.0 to satisfy transformers 4.57.6
transformers     ==4.57.6               # requires huggingface-hub<1.0,>=0.34.0 (verified)
torch            ==2.9.1                # macosx arm64 cp311, 74.5 MB; tokenizer/parity checks only
onnx             ==1.22.0
onnxruntime[quantization]==1.28.0       # `quantization` extra pulls ml_dtypes
sentence-transformers==5.6.1            # ONLY to produce the embedding parity fixture
pytest           ==9.1.1
```

**`[dev]` extra (installed into `.venv`, the runtime venv, for the test/lint loop — never shipped sealed):**

```
pytest           ==9.1.1                 # same pin as the provision closure
hypothesis       ==6.140.3               # property tests: audit-no-PII, neutralize⊇rehydrate, vault
pytest-asyncio   ==1.3.0                 # async route tests
ruff             ==0.15.3                # `make lint` runs `ruff check` + `ruff format --check`
mypy             ==1.19.1                # `make typecheck` runs `mypy src/sagp` (part of definition-of-done)
# httpx (already a runtime dep) provides the ASGI test client — no starlette TestClient extra needed
```

### 2.3 HuggingFace models (exact IDs + pinned revisions, verified live)

| Role | Repo ID | Revision (commit SHA) | Files to fetch | Bytes |
|---|---|---|---|---|
| Injection classifier | `protectai/deberta-v3-base-prompt-injection-v2` | `90c9989b1a342275dd0d1a95aad283c04e075671` | `config.json`, `onnx/config.json`, `onnx/model.onnx`, `onnx/tokenizer.json`, `onnx/tokenizer_config.json`, `onnx/special_tokens_map.json`, `onnx/added_tokens.json`, `onnx/spm.model`, `model.safetensors` | onnx 738,563,188 + safetensors 737,719,272 |
| Embedder | `BAAI/bge-small-en-v1.5` | `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a` | `config.json`, `onnx/model.onnx`, `tokenizer.json`, `tokenizer_config.json`, `special_tokens_map.json`, `vocab.txt`, `1_Pooling/config.json` | onnx **133,093,490** |

Both verified **ungated**, `license: apache-2.0` / MIT respectively.
`model.safetensors` for the classifier is fetched **only** so the provisioning parity gate can compare torch-FP32 vs ONNX-INT8; it is excluded from the runtime manifest subset.

### 2.4 spaCy pipelines (installed as real pip packages — satisfies `spacy.util.is_package`)

```
https://github.com/explosion/spacy-models/releases/download/en_core_web_md-3.8.0/en_core_web_md-3.8.0-py3-none-any.whl   33,480,380 B   [DEFAULT]
https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl   12,806,118 B   [tests / low-mem]
https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl  400,658,291 B   [opt-in]
```

### 2.5 Ollama tags

```
llama3.2:3b-instruct-q4_K_M    2.0 GB   Q4_K_M   128K native ctx   [DEFAULT]
llama3.2:1b                    1.3 GB   Q8_0                       [low-mem fallback — see §7; NOT required by the FP32 selection, since FP32 RSS is 0.30 GB (OQ-1)]
llama3:8b                      4.7 GB   Q4_0     8K ctx            [DOES NOT FIT — see §7]
```

The bare `llama3.2:1b` tag resolves to a **Q8_0** build (1.3 GB; digest `baf6a787fdff` at time of
writing) — *not* Q4_K_M. `artifacts.lock` should pin the digest or the explicit `llama3.2:1b-instruct-q8_0`
alias rather than the mutable `1b` tag. (The `q4_K_M` variant of 1b is a different 808 MB blob; do not
substitute it — every RAM/disk figure here assumes the 1.3 GB Q8_0 build.)

### 2.6 Docker images (`PROFILE=demo` and `PROFILE=proof` only)

```
qdrant/qdrant:v1.18.3-unprivileged   ~70 MB compressed  → pin by digest at provision, `docker save`
alpine:3                             ~4 MB compressed (~8 MB uncompressed)  → pin by digest; egress prober only
```

### 2.7 `artifacts.lock` and `MANIFEST.json` — worked schemas

`artifacts.lock` (TOML, committed, human-edited) is the *intent*: one stanza per artifact class,
pinned by revision/digest + expected size. `MANIFEST.json` (generated by `10_manifest.py`, committed)
is the *evidence*: per-file sha256 over what actually landed, plus an upstream cross-check and an
Ed25519 signature. `make verify` (mode `full`) recomputes every hash against `MANIFEST.json`.

```toml
# artifacts.lock  — one stanza per artifact
[[hf_model]]
id       = "protectai/deberta-v3-base-prompt-injection-v2"
revision = "90c9989b1a342275dd0d1a95aad283c04e075671"   # immutable commit SHA, never a branch
files    = ["config.json", "onnx/model.onnx", "onnx/tokenizer.json", "..."]
bytes    = { "onnx/model.onnx" = 738563188 }

[[ollama_model]]
tag    = "llama3.2:3b-instruct-q4_K_M"
digest = "sha256:<pinned>"                               # pin the digest, not the mutable tag
bytes  = 2019393189

[[docker_image]]
ref    = "qdrant/qdrant:v1.18.3-unprivileged"
digest = "sha256:<pinned>"
```

```jsonc
// MANIFEST.json  (airgap schema; manifest_hash is an alias of root_hash)
{
  "manifest_version": 1,
  "seal_generation": 3,
  "generated_ts": "2026-07-30T00:00:00Z",     // local clock — see LIMITATIONS (no offline TSA)
  "canonicalization": "sha256 over each file's raw bytes; root_hash = sha256 of the sorted
                        'path\\0hex\\n' lines (LF, sorted by path, UTF-8)",
  "files": [
    { "path": "models/hf/injection/onnx/model.onnx",
      "sha256": "<64-hex>", "size": 738563188,
      "upstream_sha256": "<64-hex-or-null>",  // HF-published hash where available; algo diff labelled
      "kind": "hf_model" }
  ],
  "root_hash": "<64-hex>",
  "signature": { "alg": "ed25519", "key_id": "<8-hex fingerprint>", "sig": "<base64>" }
}
```

Sidecars: `MANIFEST.json.sha256` (the root hash alone) and `MANIFEST.json.sig` (detached signature).

---

## 3. The two-virtualenv model

This is the structural fix for the dependency deadlock.

```
.venv-provision/   ONLINE ONLY. torch + transformers + huggingface-hub + onnx + sentence-transformers.
                   Used by: scripts/provision/*.py. Never present on the sealed critical path.
                   Deleted (or left inert) after `make seal`.

.venv/             THE SEALED RUNTIME. No torch, no transformers. (huggingface_hub
                   arrives transitively via tokenizers; neutralised by HF_HUB_OFFLINE
                   + the egress guard, not removed — corrected at M0.)
                   Tokenization: tokenizers.Tokenizer.from_file()
                   Inference:    onnxruntime.InferenceSession
                   NER:          spacy 3.8.13 + en_core_web_md
```

**Runtime tokenization contract** (verified API — `tokenizers` Python bindings):

```python
from tokenizers import Tokenizer
tok = Tokenizer.from_file(str(MODELS / "injection" / "tokenizer.json"))   # staticmethod, path: str
tok.enable_truncation(max_length=512, stride=128, strategy="longest_first", direction="right")
tok.enable_padding(length=512, pad_id=0, pad_token="[PAD]", direction="right")
enc = tok.encode(text, add_special_tokens=True)     # -> Encoding
windows = [enc, *enc.overflowing]                   # Encoding.overflowing -> list[Encoding]
input_ids      = np.array([w.ids for w in windows], dtype=np.int64)
attention_mask = np.array([w.attention_mask for w in windows], dtype=np.int64)
```

`Encoding` exposes `.ids`, `.tokens`, `.attention_mask`, `.type_ids`, `.offsets`, `.overflowing` — all confirmed. DeBERTa-v2 has `type_vocab_size: 0`, so drive the ORT feed dict off `sess.get_inputs()` and never hardcode input names.

**Tokenizer parity gate (provisioning, online):** assert `tokenizers.Tokenizer.from_file(...)` produces byte-identical `input_ids` and `attention_mask` to `transformers.AutoTokenizer.from_pretrained(...)` over **every record of `tests/corpus/attacks.jsonl` + `tests/corpus/benign.jsonl`** (the corpus grows, so the gate is defined over the files, not a fixed count). Fails the build on any divergence. This is what makes dropping `transformers` safe. The **embedding parity gate** likewise runs over `tests/fixtures/embedding_parity.jsonl` (200 texts drawn from the sample corpus + hard cases), asserting ORT+CLS+L2 matches `sentence-transformers` to `atol=1e-4`.

---

## 4. Full directory tree

```
Secure Air-Gapped Platform with Integrated Guardrails/
├── CLAUDE.md                                 # Agent operating context: 13 invariants, commands, forbidden ideas.
├── README.md                                 # Human quickstart: provision → seal → prove, in three commands.
├── LICENSE                                   # Apache-2.0 (repo code only; no model weights redistributed).
├── NOTICE                                    # Attribution required by Apache-2.0 deps + the DeBERTa checkpoint.
├── THIRD_PARTY_LICENSES.md                   # Every pinned package/model with SPDX id and licence text pointer.
├── Makefile                                  # The only supported entrypoint for every task. .SHELLFLAGS := -eu -o pipefail -c
├── pyproject.toml                            # PEP 621; requires-python >=3.11,<3.12; runtime deps + [dev] + [provision].
├── requirements.runtime.lock                 # Hash-pinned (--require-hashes) closure for .venv.
├── requirements.provision.lock               # Hash-pinned closure for .venv-provision.
├── artifacts.lock                            # TOML: every model/image/wheel with pinned revision + expected size.
├── .env.example                              # Committed template. NO HF_*/OLLAMA_* vars (those live in .env.sealed).
├── .gitignore                                # Excludes models/**, audit/**, data/private/**, .venv*, .env, vendor/.
├── .dockerignore                             # Keeps models/, audit/, .venv* out of any build context.
├── .python-version                           # `3.11`
├── docker-compose.yml                        # Qdrant server (profile: demo) + alpine prober (profile: proof).
│
├── bin/
│   ├── sagp-serve                            # Sources .env.sealed, THEN execs uvicorn — the only supported launch path.
│   └── sagp-provision                        # Sources .env.provision, execs .venv-provision/bin/python.
│
├── docs/
│   ├── ARCHITECTURE.md                       # Components, the numbered request path, data model, RAM/concurrency model.
│   ├── THREAT_MODEL.md                       # Assets/actors/boundaries, OWASP LLM Top 10 2025 mapping, residual risks.
│   ├── AIRGAP_RUNBOOK.md                     # Provision → seal → verify → operate → re-provision, as checklists.
│   ├── GUARDRAILS.md                         # Every stage: what it catches, thresholds, the metric contract (floors now, measurements at M6/M13), bypasses.
│   ├── BLUEPRINT.md                          # This file: the arbitrated technical spec of record.
│   ├── PLAN.md                               # Milestone-ordered build plan and doc map.
│   ├── COMPLIANCE.md                         # GDPR/HIPAA/NIST mapping template with an explicit non-legal-advice box.
│   ├── EVALUATION.md                         # Corpus construction, metric definitions, how the floors were chosen.
│   ├── OPERATIONS.md                         # Day 2: rotation, retention, key custody, backup, incident response.
│   ├── LIMITATIONS.md                        # What this does NOT prove. Linked from README paragraph 1.
│   ├── metrics/latest.json                   # EXISTS (produced by `make eval` at M6): committed metrics baseline, regressions >2pp fail the build.
│   └── adr/
│       ├── 0001-ollama-over-vllm.md          # No 4-bit on vLLM CPU; Python 3.12 collision; preallocating KV pool.
│       ├── 0002-qdrant-deployment-mode.md    # Qdrant deployment mode: embedded is the default runtime backend on RAM grounds; PROFILE=demo (Docker) is the demonstration/proof path. Accepted — spike resolved OQ-4/OQ-5 (Docker NOT isolated by compose options; egress via pf + loopback).
│       ├── 0003-two-virtualenvs.md           # How the transformers/hub deadlock is dissolved.
│       ├── 0004-onnx-int8-no-torch.md        # Runtime has no torch; the quantization + parity gate.
│       ├── 0005-vault-request-scoped.md      # Why the vault is never persisted and the endpoint is single-turn.
│       ├── 0006-ingest-mode-raw.md           # Why raw ingest, and the loopback+FileVault compensating controls.
│       ├── 0007-audit-hash-chain.md          # Tamper-evident, not tamper-proof. Head-digest export.
│       ├── 0008-normalized-canonical.md      # Ingress normalizes-and-masks; egress fails closed. No offset map.
│       └── 0009-no-datamarking.md            # Why U+2581 spotlighting was dropped.
│
├── config/
│   ├── guardrails.yaml                       # Declarative stage list, thresholds, fail modes. Hashed into every audit record.
│   ├── entities.yaml                         # BLOCK / MASK / ALLOW entity tables + per-entity ingress/egress thresholds.
│   ├── recognizers/in_ifsc.yaml              # Custom PatternRecognizer: Indian IFSC codes.
│   ├── recognizers/employee_id.yaml          # Custom PatternRecognizer + check digit: internal employee IDs.
│   ├── recognizers/secrets.yaml              # API_KEY / PRIVATE_KEY patterns + entropy gate. BLOCK-list member.
│   ├── recognizers/codenames.yaml            # Deny-list recognizer for internal project codenames.
│   └── logging.yaml                          # dictConfig: JSONL audit handler + console; PII redaction filters attached.
│
├── src/sagp/
│   ├── __init__.py                           # Version export only. Zero side effects, zero model loads.
│   ├── __main__.py                           # `python -m sagp` → uvicorn launcher. Refuses to run without .env.sealed.
│   ├── version.py                            # __version__, single source of truth for pyproject and /healthz.
│   ├── config.py                             # Settings(BaseSettings, env_prefix="SAGP_"). No imports from sagp.*.
│   ├── errors.py                             # SagpError → PromptRejected(400) / GuardrailUnavailable(503) / InputTooLarge(413).
│   ├── types.py                              # TextArtifact, Chunk, Hit, ScanResult, GuardrailDecision, Principal. No lib imports.
│   │
│   ├── app/
│   │   ├── main.py                           # create_app() + lifespan: manifest full-verify, load engines, warm, self-test.
│   │   ├── deps.py                           # @lru_cache singletons + get_principal() bearer-token dependency.
│   │   ├── schemas.py                        # ChatRequest/ChatResponse/IngestRequest. Response carries NO scores.
│   │   ├── middleware.py                     # Request-ID, timing, rejection-latency floor, exception→HTTP, audit flush.
│   │   ├── ratelimit.py                      # In-process token bucket keyed on principal.id + near-miss burst alarm.
│   │   └── routes/
│   │       ├── health.py                     # /healthz liveness; /readyz = engines + manifest + store + ollama reachable.
│   │       ├── chat.py                       # POST /v1/chat — the only route that can reach the LLM.
│   │       ├── ingest.py                     # POST /v1/ingest — local-path ingest through the same guardrails.
│   │       ├── admin.py                      # GET /v1/admin/{manifest,guardrails,incident/{id},quarantine} (gated on the `pii:reveal` scope — there is no `admin` scope).
│   │       └── airgap.py                     # GET /airgap/status — phase, seal_generation, root hash, guard state.
│   │
│   ├── guardrails/
│   │   ├── base.py                           # Guardrail Protocol, GuardrailResult, Decision enum.
│   │   ├── pipeline.py                       # Ordered execution, per-stage timing, short-circuit, audit assembly.
│   │   ├── normalize.py                      # THE shared normalizer: NFKC, tag/bidi/Cf handling, homoglyph fold. §5.1.
│   │   ├── placeholders.py                   # ONE regex constant; neutralize() and rehydrate() both use it.
│   │   ├── deobfuscate.py                    # base64/base32/hex/rot13/leet/reverse/spaced, depth 2, size-capped.
│   │   ├── heuristics.py                     # Weighted rule table with rule IDs. §5.2.
│   │   ├── injection/
│   │   │   ├── scanner.py                    # InjectionScanner: windowing, ORT batch run, aggregation, policy.
│   │   │   ├── onnx_backend.py               # InferenceSession wrapper; thread caps; feed built from get_inputs().
│   │   │   ├── labels.py                     # Casefolded alias resolution of INJECTION_IDX from config.json.
│   │   │   └── selftest.py                   # Boot self-test through the real policy path. Refuses to start on failure.
│   │   ├── pii.py                            # PIIGuardrail: analyze → BLOCK check → alias → anonymize. Wall-clock capped.
│   │   ├── presidio_factory.py               # The ONLY place AnalyzerEngine/AnonymizerEngine are constructed.
│   │   ├── recognizers.py                    # SealedEmailRecognizer + IFSC/EmployeeId/Secrets/Codename registration.
│   │   ├── vault.py                          # PiiVault + VaultPlaceholder(Operator). Origin-tagged, size-capped.
│   │   ├── aliases.py                        # resolve_person_aliases(): longest-first, strict-subset, same-origin only.
│   │   ├── output.py                         # Structural checks, egress PII, normalized-divergence block, citation range.
│   │   └── registry.py                       # build_pipeline(settings, config) — the single wiring point for chat AND ingest.
│   │
│   ├── rag/
│   │   ├── loaders.py                        # pypdf extraction with the visitor_text hidden-text detector. §5.4.
│   │   ├── chunking.py                       # Page-first, token-aware (bge tokenizer), 320/64, min 32. Pure function.
│   │   ├── embeddings.py                     # ORT session, CLS pooling, L2 normalize, is_query prefix switch. §5.5.
│   │   ├── vectorstore.py                    # VectorStore Protocol. Hit.score is ALWAYS cosine similarity.
│   │   ├── qdrant_store.py                   # embedded(path) | server(url) | memory(":memory:") behind one class.
│   │   ├── retriever.py                      # query_points, dual thresholds, quarantine filter, dedupe.
│   │   ├── prompt.py                          # THE sole builder of the final prompt string. Nonce delimiters.
│   │   └── ingest.py                         # sha256 → chunk → scan → embed → upsert; uuid5 ids; delete-before-upsert.
│   │
│   ├── llm/
│   │   ├── base.py                           # LLMClient Protocol: generate(messages, *, max_tokens, temperature).
│   │   ├── ollama_client.py                  # ollama.Client forced to 127.0.0.1; timeouts; token accounting.
│   │   ├── fake.py                           # FakeLLM — deterministic; used by ~90% of tests.
│   │   └── prompts/
│   │       ├── system_rag.txt                # Versioned. Its sha256 goes into every audit record.
│   │       └── refusal.txt                   # The canonical "I cannot answer this from the provided documents."
│   │
│   ├── audit/
│   │   ├── events.py                         # AuditEvent (extra="forbid", frozen=True) — the closed schema.
│   │   ├── sink.py                           # Append-only JSONL, fsync, 0600, daily rotation with carry-over record.
│   │   ├── hashing.py                        # hmac_token(domain-separated), sha256_hex, chain_digest.
│   │   ├── verify.py                         # verify_chain() → ChainReport(ok, first_bad_seq, reason).
│   │   ├── scrub.py                          # assert_no_raw_values(); violation → loud alarm + scrub_violation record.
│   │   ├── quarantine.py                     # Separate store for offending text; referenced from audit by incident_id only.
│   │   └── redactors.py                      # Root logging.Filter dropping records matching PII regexes.
│   │
│   ├── netguard/
│   │   ├── egress.py                         # L1 monkeypatch + L2 PEP 578 hook (sockets AND process/dlopen events).
│   │   ├── manifest.py                       # generate | verify(full|quick) | sign | check-sig. Ed25519.
│   │   ├── phase.py                          # State machine + refusal rules read by every Make target.
│   │   ├── evidence.py                       # EVIDENCE-*.json/.md assembly, signing, hash-chained ledger append.
│   │   └── probes.py                         # Shared probe primitives used by BOTH the tests and the evidence report.
│   │
│   └── utils/
│       ├── ids.py                            # new_request_id(), uuid5 point ids.
│       ├── timing.py                         # stopwatch() → ms; constant_time_floor() for the rejection path.
│       └── text.py                           # safe_for_log(), safe truncation, char-budget context trimming.
│
├── airgap_guard_boot.py                      # Installed into site-packages beside the .pth. Reads .airgap/state.json.
│
├── scripts/
│   ├── bootstrap_venvs.sh                    # Creates .venv and .venv-provision from ~/.local/bin/python3.11. No uv/poetry.
│   ├── doctor.py                             # Read-only preflight: python, disk (hard-fail <25 GB), RAM, docker, ollama.
│   ├── provision/
│   │   ├── 01_wheelhouse.sh                  # pip download with FULL platform flags → vendor/wheelhouse{,-provision}/.
│   │   ├── 02_hf_models.py                   # snapshot_download by pinned revision + allow_patterns → models/hf/.
│   │   ├── 03_spacy.sh                       # curl the three .whl URLs → models/spacy/; pip install --no-index --no-deps.
│   │   ├── 04_ollama.sh                      # OLLAMA_MODELS=<repo>/models/ollama ollama pull; print blob digests.
│   │   ├── 05_docker.sh                      # docker pull, resolve digest, docker save → models/docker/*.tar.
│   │   ├── 06_quantize.py                    # quantize_dynamic (DEFAULT op types) → models/derived/injection-int8/.
│   │   ├── 07_gates.py                       # Tokenizer parity, FP32↔INT8 parity, embedding parity, RSS measurement.
│   │   ├── 08_tldextract_cache.py            # Warm the PSL snapshot into models/tldextract/ with the network up.
│   │   ├── 09_secrets.py                     # Generate API tokens, audit HMAC key, PII pepper, Ed25519 keypair (0600).
│   │   └── 10_manifest.py                    # Hash everything under models/ → MANIFEST.json + .sha256 + .sig.
│   ├── seal.sh                               # Writes .env.sealed and .airgap/state.json; installs the .pth; prints checklist.
│   ├── unseal.py                             # Requires REASON=; appends to unseal_history; increments seal_generation.
│   ├── verify_airgap.py                      # The 9-assertion offline proof. Exit non-zero on any failure.
│   ├── verify_online.py                      # NEGATIVE CONTROL, run during PROVISION while the internet works.
│   ├── evidence.py                           # Render + sign EVIDENCE-*.json/.md; append to evidence/ledger.jsonl.
│   ├── eval_guardrails.py                    # Corpus run → docs/metrics/latest.json.
│   ├── verify_audit.py                       # CLI over audit.verify.verify_chain; exit 1 on break.
│   ├── gen_sample_pdf.py                     # Authors BOTH synthetic PDFs via pypdf PdfWriter + hand-built content streams (no new dep): employee_handbook.pdf (synthetic PII, never real) and poisoned_appendix.pdf (embeds the EVALUATION family-F payloads exercising the three visitor_text detectors — tiny font, off-MediaBox, /RenderMode 3).
│   ├── ingest.py                             # CLI ingest wrapper.
│   └── smoke.sh                              # 14 numbered PASS/FAIL checks; --fast uses FakeLLM.
│
├── tests/
│   ├── conftest.py                           # Hermetic env, session-scoped engines, tmp audit dir, marker gating.
│   ├── fixtures/{engines,stores,llm,corpora}.py   # Expensive singletons; ":memory:" Qdrant; FakeLLM; corpus loaders.
│   ├── corpus/attacks.jsonl                  # 63+ labelled attacks, technique-tagged across 9 families.
│   ├── corpus/benign.jsonl                   # 60+ benign, ≥30% hard negatives (prompts ABOUT injection/security).
│   ├── corpus/pii_cases.jsonl                # Synthetic text + expected entity TYPES and counts.
│   ├── corpus/README.md                      # Provenance, licences, why hard negatives matter, how to extend.
│   ├── unit/                                 # config, normalize, placeholders, heuristics, vault, aliases, chunking,
│   │                                         #   prompt, audit schema/chain/no-pii, manifest, labels, pipeline order.
│   ├── integration/                          # ingest pipeline, retriever ranking, chat endpoint, blocked flow,
│   │                                         #   context guard, quarantine routing, score normalisation.
│   ├── security/                             # no_egress, no_network_imports (AST), offline_env, guardrail_bypass (AST+spy),
│   │                                         #   tldextract_no_fetch, af_unix_denied, subprocess_denied, oracle_uniformity.
│   ├── metrics/                              # injection precision/recall/FPR floors; per-entity PII recall floors.
│   └── e2e/                                  # golden path (real models + real Ollama); airgap proof in-process.
│
├── data/
│   ├── samples/employee_handbook.pdf         # Generated synthetic PII-bearing demo document.
│   ├── samples/poisoned_appendix.pdf         # Generated document carrying a known indirect-injection payload.
│   ├── samples/README.md                     # States loudly: everything here is synthetic.
│   ├── private/.gitkeep                      # gitignored — where an operator drops real documents.
│   └── qdrant/.gitkeep                       # gitignored — embedded Qdrant storage.
│
├── models/                                   # gitignored except the two committed files below.
│   ├── MANIFEST.json                         # COMMITTED. Pinned revisions, per-file sha256 + upstream cross-check, signature.
│   ├── README.md                             # COMMITTED. What belongs here; why weights are never committed.
│   ├── hf/, spacy/, ollama/, docker/, derived/, tldextract/    # gitignored artifact roots.
│
├── vendor/wheelhouse/, vendor/wheelhouse-provision/   # gitignored offline wheels.
├── deploy/pf/com.sagp                        # Optional macOS pf anchor (make seal-pf).
├── .airgap/state.json                        # Phase state machine + seal_generation + unseal_history.
├── .airgap/keys/manifest_ed25519.pub         # COMMITTED public key.
├── .env.sealed                               # GENERATED by make seal. Sourced by bin/sagp-serve. Never hand-edited.
├── evidence/EVIDENCE-*.json, *.md            # gitignored signed proof reports.
├── evidence/ledger.jsonl                     # gitignored append-only hash chain.
└── audit/                                    # gitignored, 0700. events-YYYYMMDD.jsonl at 0600.
```

---

## 5. The exact end-to-end request path

### 5.1 The shared normalizer (`guardrails/normalize.py`)

Used identically by the PII and injection layers. This is the fix for "PII runs on raw text".

```python
TAG_CHARS   = range(0xE0000, 0xE0080)          # ASCII smuggling — BLOCK OUTRIGHT
BIDI_OVER   = {0x202A,0x202B,0x202C,0x202D,0x202E,0x2066,0x2067,0x2068,0x2069}   # BLOCK OUTRIGHT
STRIP_CF    = {0x00AD,0x200B,0x200C,0x200D,0x200E,0x200F,0x2060,0x2061,0x2062,
               0x2063,0x2064,0x180E,0xFEFF}    # strip + flag, NEVER block alone

def normalize(raw: str) -> tuple[str, list[str]]:
    # 1. record-and-remove tag chars and bidi overrides  -> flags TAG_CHARS / BIDI_OVERRIDE
    # 2. remove STRIP_CF                                  -> flag ZERO_WIDTH
    # 3. unicodedata.normalize("NFKC", s)                 -> flag NFKC_CHANGED if s != raw
    # 4. homoglyph fold via an explicit table (Cyrillic/Greek/fullwidth -> Latin); NOT unidecode
    # 5. collapse whitespace runs to a single U+0020
    return normalized, flags
```

`neutralize_placeholders()` runs **after** `normalize()` — NFKC folds fullwidth `＜` (U+FF1C) to `<`, so neutralizing first is bypassable. Both `neutralize()` and `rehydrate()` import the **same** `PLACEHOLDER_RE` constant from `placeholders.py`; a property test asserts that anything `rehydrate` matches, `neutralize` also matches (built at M3; `neutralize ⊇ rehydrate` proven).

### 5.2 Heuristic rule table (`guardrails/heuristics.py`)

Rule IDs with weights, combined with the classifier by **OR** at the policy layer (never averaged): `OVERRIDE_PHRASE`, `DISREGARD`, `SYSTEM_PROMPT_PROBE`, `ROLE_HIJACK` (`<|im_start|>`, `[INST]`, `### System`, `^\s*(system|assistant)\s*[:>\]]`), `DAN_PERSONA` (carries the classifier's documented jailbreak blind spot), `NEW_INSTRUCTIONS`, `EXFIL_INTENT`, `MARKDOWN_EXFIL`, `DELIMITER_SPOOF` (literal `UNTRUSTED_DOCUMENT_`). Two block outright: `TAG_CHARS` and `BIDI_OVERRIDE` from the normalizer.

### 5.3 `SealedEmailRecognizer` — the tldextract fix

Verified: `EmailRecognizer.validate_result` (at tag `2.2.364`, path `predefined_recognizers/generic/email_recognizer.py`) does exactly:

```python
def validate_result(self, pattern_text: str):
    result = tldextract.extract(pattern_text)
    return result.fqdn != ""
```

Module-level `tldextract.extract` uses the default singleton, which fetches the Public Suffix List over HTTPS on first call. On a sealed box this becomes an `EgressViolation` raised *inside* Presidio → 503 on the first email ever analyzed.

```python
# guardrails/recognizers.py
import tldextract
from presidio_analyzer.predefined_recognizers import EmailRecognizer

_TLD = tldextract.TLDExtract(
    suffix_list_urls=(),                      # verified: empty tuple disables all HTTP fetching
    cache_dir=str(settings.models_dir / "tldextract"),
    fallback_to_snapshot=True,
)

class SealedEmailRecognizer(EmailRecognizer):
    def validate_result(self, pattern_text: str):
        return _TLD(pattern_text).fqdn != ""
```

Registration: `registry.remove_recognizer("EmailRecognizer", language="en")` then `registry.add_recognizer(SealedEmailRecognizer())`. Also export `TLDEXTRACT_CACHE=<repo>/models/tldextract` in `.env.sealed`, warm that cache during provisioning, and put it in `MANIFEST.json`. **Test:** analyze an email with the egress guard in `enforce` mode and assert `len(egress.violations()) == 0`.

> Note: `validate_result` returning non-`None` forces the score to `MAX_SCORE` or `MIN_SCORE`. `EMAIL_ADDRESS` is therefore **binary** (1.0 or dropped), like `CREDIT_CARD` and `IN_AADHAAR`. Thresholds do not apply to it.

### 5.4 Hidden-PDF-text detection (replaces the rasterizer approach)

```python
# rag/loaders.py — pypdf 6.14.2, verified signature includes visitor_text
def _visitor(text, cm, tm, font_dict, font_size):
    if font_size is not None and abs(font_size) < 1.0:      flags.add("PDF_TINY_FONT")
    if tm and not _inside_mediabox(tm, page.mediabox):      flags.add("PDF_OFFPAGE_TEXT")
    if font_dict and font_dict.get("/RenderMode") == 3:     flags.add("PDF_INVISIBLE_RENDER")
page.extract_text(extraction_mode="layout", visitor_text=_visitor)
```
Any flag → that page's chunks are routed to the per-collection sibling `<collection>__quarantine`, never indexed. (As built, quarantine is **per-collection** — `handbook` quarantines to `handbook__quarantine` — not a single global `docs_quarantine`, so re-ingesting one doc can never disturb another collection's quarantine. The retriever **refuses to open a quarantine-suffixed collection**, so quarantined chunks are unreachable by construction.)

### 5.5 Embedding contract (`rag/embeddings.py`)

```
model:   BAAI/bge-small-en-v1.5, onnx/model.onnx (133,093,490 B), CPUExecutionProvider
tokens:  tokenizers.Tokenizer.from_file(bge tokenizer.json), max_length=512, truncation, padding
pooling: CLS  -> last_hidden_state[:, 0, :]          # NOT mean pooling
norm:    v / np.linalg.norm(v, axis=-1, keepdims=True)
prefix:  "Represent this sentence for searching relevant passages: "  applied IFF is_query=True
dim:     384, Distance.COSINE
```
`embed_model` and `embed_revision` are written into every point payload; a query-time mismatch is a hard error, not a silent recall collapse. Provisioning gate `07_gates.py` asserts that ORT+CLS+L2 output matches `SentenceTransformer("BAAI/bge-small-en-v1.5").encode(..., normalize_embeddings=True)` to `atol=1e-4` over 200 fixtures — **MEASURED at M1: max abs diff 1.6e-07, well inside the tolerance.**

### 5.6 INGEST path — `POST /v1/ingest` / `scripts/ingest.py`

| # | Stage | Fail-closed behaviour |
|---|---|---|
| I1 | Bearer token → `Principal` with scope `ingest` | missing/invalid → **401**, generic body |
| I2 | Read local bytes, `sha256`, size cap `SAGP_MAX_DOC_BYTES=52428800` | over → **413** |
| I3 | `pypdf` extract per page + hidden-text visitor (§5.4) | extraction exception → **abort whole ingest**, delete any partial points by `doc_sha256` |
| I4 | `normalize()` per page, then `neutralize_placeholders()` | tag/bidi chars present → page quarantined, high-severity alarm |
| I5 | Chunk: page-first, 320 tokens / 64 overlap, min 32 | — |
| I6 | Presidio `analyze` (INGRESS 0.50) per chunk → record entity **types + counts** into the payload. **No masking. BLOCK list NOT applied.** | analyze exception/timeout → chunk quarantined |
| I7 | Injection scan per chunk: heuristics + classifier over `raw` **and** `normalized`, take max. Verdict `clean` (<0.70) / `suspect` (0.70–0.95) / `quarantined` (≥0.95 or high-confidence heuristic or `truncated=True`) | scanner exception/timeout → **quarantined**, never `clean` |
| I8 | `quarantined` → the per-collection sibling `<collection>__quarantine` (never retrieved, admin-reviewable; the retriever refuses to open a quarantine-suffixed collection). Others → main collection | — |
| I9 | Embed the stored chunk text, `is_query=False` | exception → abort ingest, roll back by `doc_sha256` |
| I10 | Delete superseded `doc_sha256` for the same basename **first**, then `upsert` with `uuid5(NS, f"{sha}:{idx}")` | crash mid-run leaves a *partial* (re-runnable) index, never a duplicated one |
| I11 | Write `AuditEvent(event_type="ingest")`, fsync | audit write failure → **request fails** |

### 5.7 CHAT path — `POST /v1/chat` (the guarded RAG endpoint)

Guardrails run as **FastAPI dependencies**, never `BaseHTTPMiddleware` (Starlette's `ExceptionMiddleware` sits inside user middleware and would degrade typed 400s into opaque 500s).

| # | Stage | Fail-closed behaviour |
|---|---|---|
| C0 | Bearer → `Principal`; rate-limit bucket by `principal.id` | invalid → **401**; over limit → **429** |
| C1 | Schema: `{message: str, collection: str}`. A `messages` array len>1 → reject | → **400 `UNSUPPORTED`** (a schema error raised *before any detector runs*; it is the one 400 exempt from the oracle-uniform `PROMPT_REJECTED` body and the rejection deadline, because it reveals nothing about a detector — see the **Uniform rejection surface** note below) |
| C2 | `len(message) > SAGP_MAX_INPUT_CHARS (8000)` | → **413 `INPUT_TOO_LARGE`** |
| C3 | `norm, flags = normalize(message)` | `TAG_CHARS` or `BIDI_OVERRIDE` in flags → **400 `PROMPT_REJECTED`** |
| C4 | Heuristics over `norm` → weighted score + rule IDs | `DELIMITER_SPOOF` → **400** |
| C5 | Deobfuscate (`base64/base32/hex/rot13/leet/reverse/spaced`, depth 2, 256 KB cap); decoded payloads join the scan set. Each decoded surface is `normalize()`-d and retained for **both** the C6 injection scan **and** the C10 BLOCK-list scan (so an encoded credential cannot slip the BLOCK list) | decode bomb / cap exceeded → **400** |
| C6 | Injection classifier over `{raw, norm, *decoded}`, windows `max_length=512, stride=128`, cap 16 windows. `score = max`. | `truncated=True` → **400** ("too long to scan" never means allowed). Any exception or >2000 ms → **503 `GUARDRAIL_UNAVAILABLE`** |
| C7 | Policy: `max(classifier, heuristic_weight) >= 0.85` | → **400 `PROMPT_REJECTED`** |
| C8 | `neutral, n = neutralize_placeholders(norm)` | `n > 0` → flag + audit (prompts are neutralized, not blocked) |
| C9 | Presidio `analyze(neutral, INGRESS)`, `default_score_threshold=0.50`, wall-clock cap 3000 ms | exception, timeout, or **any recognizer regex timeout** → **503**. Never a partial result set at 200. |
| C10 | BLOCK-list check over `{neutral, *decoded-normalized}`: `CREDIT_CARD, IN_AADHAAR, US_SSN, IBAN_CODE, US_BANK_NUMBER, CRYPTO, MEDICAL_LICENSE, API_KEY, PRIVATE_KEY`. Scanning the decode set (one extra `analyze()` per decoded surface, bounded by the C5 256 KB cap) closes the base64/hex-encoded-credential bypass | any hit → **400 `PROMPT_REJECTED`** — identical status, body and timing to C7 |
| C11 | `resolve_person_aliases(neutral, results, vault, origin="prompt")` — longest-first, strict subset, exactly-one-superset, **same origin only** | ambiguous → mint a fresh placeholder (over-mask, never cross-link) |
| C12 | `anonymize(neutral, results, {"DEFAULT": OperatorConfig("vault_placeholder", {"vault": vault})})` → `masked_prompt`. Vault size cap `SAGP_MAX_VAULT_ENTRIES=2000` | cap exceeded → **400** (a vault-exhaustion input is an attack) |
| C13 | Embed **`neutral`** (unmasked, normalized, `is_query=True`) | embed exception or > `timeout_embed_ms=2000` → **503** |
| C14 | `query_points(collection, query=vec, limit=6, score_threshold=0.35, query_filter=must_not guard.verdict=="quarantined", with_payload=True)` | store exception or > `timeout_retrieve_ms=3000` → **503** |
| C15 | If no hit ≥ `STRONG=0.50` → return `refusal.txt`, **no LLM call**, 200 with `decision="refuse_insufficient_context"` | deterministic, auditor-testable |
| C16 | Per chunk: `normalize()` → `neutralize_placeholders()`; `n > 0` → **drop the chunk** + high-severity alarm (tamper signal) | — |
| C17 | `BatchAnalyzerEngine.analyze_iterator(chunks, "en", batch_size=6, n_process=1)` with EGRESS profile (0.35); `anonymize` each with the **same vault**, `origin=f"doc:{sha}"`. BLOCK-list **rejection** NOT applied to chunks — but block-tier entities ARE masked here (binary for CREDIT_CARD/IN_AADHAAR, egress 0.40 otherwise; §5.1 in GUARDRAILS), so nothing leaks unmasked. | exception → **503** |
| C18 | `prompt.py` **budget-selects** masked chunks by retrieval score until under `SAGP_MAX_CTX_CHARS=7000` (the trim happens **here, before the re-scan**, so the scanned string is the delivered string), then assembles: `nonce = secrets.token_hex(8)`; each masked chunk wrapped in `<<<UNTRUSTED_DOCUMENT_{nonce}_S{i}>>> … <<</UNTRUSTED_DOCUMENT_{nonce}_S{i}>>>`. **No datamarking.** Retrieved content goes in the **user** role, never system. | budget leaves 0 chunks → C15 refusal |
| C19 | **Single** injection re-scan of the assembled masked context, threshold 0.90, adjacent-window corroboration (4–5 windows, so it is operative here) | hit → drop the highest-scoring chunk, **re-apply the C18 budget**, reassemble, rescan (max 2 iterations). All chunks dropped → C15 refusal. Exception → **503** |
| C20 | Assert the re-scanned assembled context is byte-identical to the user-role payload C21 sends (the `test_final_bytes_were_scanned` invariant, §9.4). Prevents Ollama silently truncating the closing delimiter | any divergence is a bug, not a runtime path |
| C21 | `ollama.Client("http://127.0.0.1:11434").chat(model, messages, stream=False, keep_alive="30m", options={temperature:0.1, top_p:0.9, num_predict:512, seed:42})`, timeout 120 s. **Never pass `num_ctx` per request** (forces a full model reload). | timeout/exception → **503** |
| C22a | Output structural: strip markdown images/links; if the nonce delimiter or a system-prompt n-gram appears in the output → **block**, return `refusal.txt` | closes the zero-click exfil channel |
| C22b | Presidio `analyze(response_raw, EGRESS 0.35)` → `anonymize` with the **same vault** → `masked_response` | exception → **503** |
| C22c | Presidio `analyze(normalize(response_raw), EGRESS 0.35)`; if it finds **more** entities than C22b → **block**, return `refusal.txt` | fail-closed; requires no offset mapping |
| C22d | Citation range check on `\[S(\d+),\s*p\.(\d+)\]` against supplied blocks/pages | out of range → strip (`warn`) or refuse (`strict`) |
| C23 | Rehydrate **only if** `"pii:reveal" in principal.scopes and SAGP_REHYDRATE_OUTPUT==1`. Single-pass `re.sub`; unknown placeholders left **verbatim** | never a global fallback map |
| C24 | Re-run C22a structural checks on the **final returned string**; record `completion_pre_rehydrate_sha256` **and** `completion_returned_sha256` | the scanning boundary is stated, not overclaimed |
| C25 | Write `AuditEvent`, fsync, chain link | write or scrub failure → **503**, response NOT returned |
| C26 | `finally: vault.clear()` | — |

**Uniform rejection surface.** Every *detector* 400 (C3–C12) returns exactly `{"error":{"code":"PROMPT_REJECTED","message":"Your request was rejected by the security policy.","incident_id":"<uuid4>"}}` and terminates at a **fixed rejection deadline** — a single wall-clock target every detector reject is padded to, not a per-detector floor (the `120 ms` value is a placeholder that `test_oracle_uniformity` calibrates above the slowest measured path at M13; see GUARDRAILS §1). The C1 `UNSUPPORTED` schema error is the sole exemption: it fires before any detector and reveals nothing about one, so it is neither body-uniform nor deadline-padded. No score, threshold, rule ID, matched substring, model name, window index, or entity type ever crosses the boundary. All of that is in the audit record, retrievable at `GET /v1/admin/incident/{id}` with the `pii:reveal` scope. There is no `admin` scope: the three scopes are `chat`, `ingest` and `pii:reveal` (§0 row 19), and every `/v1/admin/*` route is gated on `pii:reveal`.

### 5.8 Thresholds (config/`entities.yaml` + `guardrails.yaml`)

```
INJECTION   user_prompt 0.85 | doc_suspect 0.70 | doc_quarantine 0.95 | assembled_context 0.90
            system prompt: NEVER scanned (documented FP source)
PII         INGRESS default_score_threshold 0.50   (must be strictly > 0.40 — the
                                                    LemmaContextAwareEnhancer floor)
            EGRESS  default_score_threshold 0.35   (deliberately context-permissive; a miss is a leak.
                                                    Over-masking rate MUST be measured on the corpus.)
per-entity  (excerpt — see the pointer below; the full three-table policy is canonical elsewhere)
   mask     PERSON 0.50/0.35 · PHONE_NUMBER 0.50/0.40 · IN_PAN 0.50/0.40 · LOCATION 0.55/0.40
            CREDIT_CARD, IN_AADHAAR, EMAIL_ADDRESS: binary (validate_result) — thresholds N/A
   allow    DATE_TIME 0.85 ingress / off egress — detected and audited, NEVER masked, on either
            surface. It is an `allow` entity, not a mask entity.
RETRIEVAL   top_k 6 · MIN 0.35 (what enters the prompt) · STRONG 0.50 (whether to answer at all)
```
**The canonical per-entity policy is [GUARDRAILS.md §8.2](GUARDRAILS.md) — the annotated `config/entities.yaml`, whose three `block` / `mask` / `allow` tables are exhaustive.** The excerpt above is a convenience extract and is deliberately partial: the `mask` entries `IN_IFSC`, `EMPLOYEE_ID` and `PROJECT_CODENAME` and the `allow` entries `NRP` and `URL` are listed there rather than duplicated here. Where the two disagree, §8.2 wins; do not derive an entity's disposition from this block.
All thresholds validated `0.0 < t <= 1.0` at startup; a typo'd env var **refuses to boot** rather than silently defaulting.

---

## 6. Lifecycle: provision → seal → operate → verify

State machine in `.airgap/state.json`: `BOOTSTRAP → PROVISION → OPERATE`, with `VERIFY` reachable from PROVISION (online negative control) and OPERATE (offline proof). `seal_generation` increments on every seal and appears in every evidence report.

**Refusal rules, enforced by `netguard/phase.py` and imported by every Make target:**
- any `provision*` target exits 2 when `phase == OPERATE`
- `seal` refuses unless `MANIFEST.json` verifies, its signature checks, and `evidence/verify-online-<gen>.json` exists with `all_probes_blocked == true`
- `up`/`serve` runs full manifest verification as a hard precondition — a mismatch is a startup failure, not a warning
- `unseal` requires `make unseal REASON="..."` and writes an `unseal_history` entry
- **`SAGP_GUARD` is not a phase switch.** The `.pth` bootstrap derives the guard mode **solely from `.airgap/state.json`** (unreadable/missing → `enforce`), never from an env var — a typo must not silently disarm the guard. `SAGP_GUARD=audit` is honoured **only** by the `verify-online` harness while `phase == PROVISION`; in `OPERATE` any value other than `enforce` is an invalidating condition (§9.2) and the app refuses to boot.

### Phase 0 — BOOTSTRAP (online)

```bash
cd "/Users/tanishpd/Desktop/Secure Air-Gapped Platform with Integrated Guardrails"
make doctor          # hard-fails: free disk < 25 GB (pre-provision reading was 5.9 GB; space freed, M1 provisioning completed)
make venvs           # scripts/bootstrap_venvs.sh -> .venv and .venv-provision from ~/.local/bin/python3.11
make lock            # resolve BOTH closures ONCE, emit requirements.*.lock with --generate-hashes
make install         # pip install --require-hashes -r requirements.runtime.lock -e .
```

### Phase 1 — PROVISION (online, one-way door)

```bash
open -a Docker                       # only if PROFILE=demo/proof
make provision                       # runs scripts/provision/01..10 in order, resumable, idempotent
#   01 wheelhouse   pip download --require-hashes --python-version 3.11 --implementation cp \
#                     --abi cp311 --platform macosx_14_0_arm64 --only-binary=:all: \
#                     -r requirements.runtime.lock -d vendor/wheelhouse
#                   (macosx_14_0 is the real tag for torch 2.x and onnxruntime 1.28 — NOT macosx_11_0)
#   02 hf_models    snapshot_download(revision=<pinned sha>, local_dir=models/hf/..., allow_patterns=[...])
#   03 spacy        curl three wheels -> models/spacy/; pip install --no-index --no-deps <md wheel>
#   04 ollama       OLLAMA_MODELS="$PWD/models/ollama" ollama serve & ; ollama pull llama3.2:3b-instruct-q4_K_M
#   05 docker       docker pull qdrant/qdrant:v1.18.3-unprivileged ; resolve digest ; docker save -o models/docker/
#   06 quantize     quantize_dynamic(models/hf/injection/onnx/model.onnx,
#                                    models/derived/injection-int8/model.onnx)   # DEFAULT op types
#   07 gates        tokenizer parity | FP32<->INT8 parity (|dP|<0.05, zero label flips)
#                   | embedding parity vs sentence-transformers | measured RSS of every ORT session
#   08 tldextract   warm the PSL snapshot into models/tldextract/
#   09 secrets      API tokens, audit HMAC key, PII pepper, Ed25519 keypair -> .env (0600), .airgap/keys/
#   10 manifest     sha256 every file under models/ + vendor/ -> MANIFEST.json + .sha256 + .sig

make verify-online                   # NEGATIVE CONTROL — see §9. Must be green BEFORE sealing.
make eval                            # corpus metrics -> docs/metrics/latest.json (commit this)
```

`make provision` **exits non-zero** if any gate in step 07 fails. You can never reach `make seal` with an unvalidated classifier.

### Phase 2 — SEAL

```bash
make seal            # writes .env.sealed + .airgap/state.json (phase=OPERATE, seal_generation++)
                     # installs .venv/lib/python3.11/site-packages/{airgap_guard.pth,airgap_guard_boot.py}
                     # prints the physical disconnect checklist
make seal-pf         # OPTIONAL, sudo. Loads deploy/pf/com.sagp. Closes native-lib + external-process egress.
                     #   sudo pfctl -n -f /etc/pf.conf   (dry-run parse FIRST — macOS pf is OpenBSD-4.4 era)
                     #   sudo pfctl -f  /etc/pf.conf ; sudo pfctl -E ; sudo pfctl -a sagp -s rules

# then, physically:
networksetup -setairportpower en0 off
# unplug Ethernet / Thunderbolt adapters
ping -c1 1.1.1.1                     # MUST fail
curl -sS --max-time 3 https://huggingface.co   # MUST fail
```

`.env.sealed` (generated; sourced by `bin/sagp-serve` **before** the interpreter starts):

```bash
export HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 HF_HUB_DISABLE_IMPLICIT_TOKEN=1
export HF_HUB_DISABLE_UPDATE_CHECK=1 HF_HUB_DISABLE_XET=1 DO_NOT_TRACK=1
export HF_HOME="$PWD/models/hf-home"
export TLDEXTRACT_CACHE="$PWD/models/tldextract"
export TOKENIZERS_PARALLELISM=false PYTHONDONTWRITEBYTECODE=1
export OLLAMA_HOST=127.0.0.1:11434
export OLLAMA_MODELS="$PWD/models/ollama"
export OLLAMA_NO_CLOUD=1 OLLAMA_NOPRUNE=1 OLLAMA_ORIGINS=http://127.0.0.1
export OLLAMA_MAX_LOADED_MODELS=1 OLLAMA_NUM_PARALLEL=1 OLLAMA_MAX_QUEUE=16
export OLLAMA_CONTEXT_LENGTH=4096 OLLAMA_KEEP_ALIVE=30m
export OLLAMA_FLASH_ATTENTION=1 OLLAMA_KV_CACHE_TYPE=q8_0
export no_proxy='*' NO_PROXY='*'
unset  http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
export SAGP_ENV=prod
```

### Phase 3 — OPERATE

```bash
make ollama-up                                  # launchd plist, loopback-bound, env from .env.sealed
make up                                         # PROFILE=demo only: docker load + compose up qdrant
make serve                                      # bin/sagp-serve -> uvicorn --workers 1 --host 127.0.0.1
make ingest FILE="data/samples/employee_handbook.pdf" COLLECTION=handbook
make query Q="How many days of parental leave do I get?"
```

`--workers 1` is mandatory: a second worker means a second spaCy pipeline and a second ORT session. Sync guardrail calls are offloaded with an explicit `anyio.CapacityLimiter(2)`, never onto FastAPI's default ~40-thread pool.

### Phase 4 — VERIFY

```bash
make verify        # scripts/verify_airgap.py — the 9 assertions in §9
make evidence      # signed EVIDENCE-<gen>-<utc>.json/.md + ledger append
make audit-verify  # hash-chain walk; exit 1 on any break
make proof         # verify + evidence
```

Re-provisioning: `make unseal REASON="add pypdf 6.15.0"` → reconnect → `make provision` → `make verify-online` → `make seal`.

---

## 7. RAM budget — 8 GB hard ceiling

> **This table is a PROJECTION, not a measurement.** **Two** rows are now measured — the macOS baseline and the **FP32** DeBERTa classifier session RSS (0.30 GB, **OQ-1 RESOLVED at M1**) — every other row is an ESTIMATE, and the totals are arithmetic over those estimates, so they inherit the weakest input. The classifier RSS that once blocked this table (OQ-1) is resolved; the totals nonetheless remain projections until every row is measured (the M13/M15 sweep). Any downstream restatement of a number from this section must carry the marker and name the profile it assumes.

### Default profile: `llama3.2:3b-instruct-q4_K_M`, `num_ctx=4096`, KV `q8_0`, **embedded Qdrant** (`SAGP_QDRANT_MODE=embedded`), ONNX runtime

| Component | RSS (GB) | Basis |
|---|---|---|
| macOS baseline | 3.00 | measured, authoritative |
| Ollama server + model weights (2.0) + KV @ q8_0 (0.24) + compute graph/runtime (0.35) | 2.59 | ESTIMATE — verify with `ollama ps` |
| CPython 3.11 + FastAPI + uvicorn + pydantic | 0.15 | ESTIMATE |
| onnxruntime runtime (one process, two sessions) | 0.12 | ESTIMATE |
| DeBERTa-v3-base **FP32** ONNX session (INT8 rejected — OQ-2) | **0.30** | **MEASURED at M1 (fresh interpreter; ORT mmaps weights). INT8 inverts the model, so FP32 is runtime — same RSS, budget unchanged.** |
| bge-small-en-v1.5 ONNX session (133 MB fp32) | 0.18 | ESTIMATE |
| spaCy `en_core_web_md` pipeline (24.0 MB vectors + weights) | 0.20 | ESTIMATE |
| Presidio registry + compiled regexes | 0.03 | ESTIMATE |
| Qdrant embedded (client + local segments, ≤50k vectors) | 0.08 | ESTIMATE |
| pypdf + transient page buffers | 0.05 | ESTIMATE |
| tokenizers + numpy + grpcio/httpx + misc | 0.05 | ESTIMATE |
| **App process total** | **1.16 (ESTIMATE — sum of estimates; the classifier row is now the MEASURED 0.30 GB FP32 RSS (OQ-1 resolved), the rest remain estimates)** | gate: refuse to boot above 1.40 |
| **SYSTEM TOTAL** | **6.75 (PROJECTED — arithmetic over the estimated rows above)** | headroom 1.25 GB — **projected, not measured** |

### Variants

Every total below is a **projection** (the classifier RSS input is now measured — OQ-1 — but the other rows remain estimates); the verdict column is a projected verdict, not a measured outcome. Each row names the vector-store profile it assumes.

| Variant | Profile assumed | Projected total | Projected verdict (unmeasured) |
|---|---|---|---|
| Default (above) | embedded (`SAGP_QDRANT_MODE=embedded`) | **6.75** | projected to fit — ship this |
| `PROFILE=demo` (Docker Qdrant `qdrant/qdrant:v1.18.3-unprivileged`, `mem_limit 512m`, Docker Desktop VM capped at 2 GB) — the demonstration/proof path | demo / Docker | ~7.60 | projected to fit with no margin. Demo only, close other apps. |
| Classifier RSS lands at 0.60 GB instead of 0.30 (hypothetical sensitivity — the FP32 model measured 0.30) | embedded | 7.05 | projected to still fit — this is why the RSS gate is 0.35 not 0.30 |
| ~~FP32 ONNX "fallback" (0.80 GB classifier)~~ — **superseded (OQ-1)** | embedded | — | The 0.80 GB estimate was wrong: FP32 ONNX **is** the runtime classifier and its RSS is **0.30 GB measured**, so it is the default row above — **not** a heavier fallback, and it does **not** force `llama3.2:1b`. |
| `en_core_web_lg` instead of `md` | embedded | 7.35 | discouraged; +0.60 GB for +0.81 aggregate ENTS_F |
| `llama3:8b` @ ctx 2048, q8_0 KV, everything else stripped | embedded | **9.28** | **projected NOT to fit.** Over by 1.3 GB. |

**On `llama3:8b`, stated plainly:** there is no configuration in which it fits. macOS will compress and swap rather than OOM, so it will *appear* to work — at 3–6 tok/s with a 2–5 s stall at the head of every request while the guardrail models' pages fault back off the SSD. The components paged out are precisely the idle security controls. That is a security-relevant characteristic, not just slowness. The app prints a loud startup warning when an `8b` tag is configured on a host with < 16 GB. The design keeps the tag available for anyone who wants to reproduce the failure, but **it was skipped during M1 provisioning on this disk-constrained host** (§8) — so it is not present here, and it is never the default.

**Additional non-steady-state allocations, budgeted separately:**
- `quantize_dynamic` needs ~3 GB transient. It runs during PROVISION, **before** Ollama is started.
- Full manifest verification streams ~4 GB at boot with a bounded buffer — negligible RSS, ~2–3 s wall clock.

**Enforcement:** `lifespan` sums the configured profile's expected RSS against `psutil.virtual_memory().total` and refuses to boot above 90% projected. `/readyz` reports measured RSS per component.

---

## 8. Disk budget (target: free ≥ 25 GB before Phase 1)

| Item | Size |
|---|---|
| Ollama `llama3.2:3b-instruct-q4_K_M` | 2.00 GB |
| Ollama `llama3.2:1b` (fallback) | 1.30 GB |
| Ollama `llama3:8b` (**SKIPPED at M1 on this disk-constrained host** — not pulled; **does not fit in 8 GB at runtime** either — §7, projected 9.28 GB) | 4.70 GB (not on this host) |
| HF injection: `onnx/model.onnx` | 0.74 GB |
| HF injection: `model.safetensors` (parity gate input only) | 0.74 GB |
| HF injection: derived INT8 | ~0.20 GB (**unverified**) |
| HF injection: tokenizer/spm/config | 0.011 GB |
| HF `bge-small-en-v1.5` `onnx/model.onnx` + tokenizer | 0.14 GB |
| spaCy `en_core_web_md` / `sm` / `lg` wheels | 0.033 / 0.013 / 0.401 GB |
| tldextract PSL snapshot cache | < 0.001 GB |
| Docker `qdrant/qdrant:v1.18.3-unprivileged` tar | 0.15 GB |
| Docker `alpine:3` tar | 0.01 GB |
| `.venv` (runtime, no torch) | ~0.45 GB |
| `.venv-provision` (torch 2.9.1 + transformers + onnx) | ~1.60 GB |
| `vendor/wheelhouse/` (runtime closure) | ~0.60 GB |
| `vendor/wheelhouse-provision/` | ~2.20 GB |
| Qdrant data, ~5k chunks @ 384-d + payload text | 0.05 GB |
| Audit + evidence (first year, typical) | ~0.20 GB |
| Docker Desktop app (already installed) | ~3.00 GB |
| **Lean total** (default profile, no provisioning venv retained; the ≈9.7 GB figure includes a `llama3:8b` pull, which was **skipped on this host** — subtract ~4.7 GB for the as-provisioned footprint) | **≈ 9.7 GB (projected)** |
| **Full total** (everything above, both venvs, both wheelhouses) | **≈ 19.6 GB** |
| **Recommended free before Phase 1** (incl. ~3 GB quantization transient + headroom) | **25 GB** |

`make doctor` reads `diskutil info /` and hard-fails below the computed requirement. (The pre-provision reading was 5,909,774,336 B / 5.9 GB free; space was freed and **M1 provisioning has since completed on this host** — `MANIFEST.json` is signed and committed. `llama3:8b` was skipped to stay within disk.)

---

## 9. Verification — proving it works end to end, offline

### 9.1 `make verify-online` — the negative control (PROVISION, internet UP)

Run **before** sealing. This is the only evidence that distinguishes *blocked* from *absent*:

1. With `SAGP_GUARD=audit`: resolve `huggingface.co`, complete a TCP handshake to `1.1.1.1:443`. Record success + latency. **If this fails, the host has no internet and the whole run is `INVALID`.**
2. Flip to `SAGP_GUARD=enforce`. Re-run the identical probes. Each must raise `EgressViolation`.
3. Write `evidence/verify-online-<gen>.json` with both timings. `make seal` refuses without it.

The report line reads (MEASURED at M13, `make verify-online` run live): *"this host completed a TCP handshake to 1.1.1.1:443 in **6.58 ms** with the guard auditing; with the guard enforcing, the identical probe raised `EgressViolation`."* (The 6.58 ms handshake is measured; the enforce path is characterised by the exception it raises, not by a latency figure.)

### 9.2 `make verify` — the 9 offline assertions (`scripts/verify_airgap.py`)

Each asserts on the **`EgressViolation` type**, never on a generic connection failure. `scripts/verify_airgap.py` exists and runs (M13); on this unsealed dev host all 9 offline assertions PASS, but the overall verdict is **`INVALID` by design** — the host is kept in PROVISION (phase ≠ OPERATE) and non-loopback dev listeners are present, both invalidating conditions, so a green `PASS` is never produced here.

The right-hand column holds **positive controls** — a companion probe proving the assertion *can* pass when it should (so a green result is not the network merely being absent). The term "negative control" is reserved for the §9.1 verify-online audit-vs-enforce pair; assertion 8's companion is the one row that instead demonstrates the guard *firing* (a stock extractor DOES violate).

| # | Assertion | Paired positive control |
|---|---|---|
| 1 | Guard installed; both layers report in the install receipt | — (if false, everything below is `INVALID`) |
| 2 | `socket.create_connection(("1.1.1.1",443))` → `EgressViolation` (L1) | loopback echo server connects and echoes |
| 3 | `_socket.socket().connect(("1.1.1.1",443))` → `EgressViolation` (**L2 only** — L1 is bypassed by construction here, and L2 catches it — verified at M11) | `socket.create_connection(("127.0.0.1",11434))` succeeds |
| 4 | `socket.getaddrinfo("huggingface.co",443)` → `EgressViolation` | `getaddrinfo("localhost",8000)` succeeds |
| 5 | `httpx.get("https://huggingface.co")` → `EgressViolation` | `httpx.get("http://127.0.0.1:8000/healthz")` → 200 |
| 6 | `subprocess.Popen(["curl","https://example.com"])` → `EgressViolation` (PEP 578 `subprocess.Popen` event) | `subprocess.Popen([ollama_path,"--version"])` succeeds (allowlisted) |
| 7 | `open("/var/run/docker.sock")` connect → `EgressViolation` (AF_UNIX deny-by-default) | the probe creates a throwaway unix socket in a temp dir, **transiently** allowlists its path for the duration of this check only, connects, then removes it and re-asserts the allowlist is empty. The operational default allowlist is empty; a non-empty allowlist at verify time (other than the probe's own entry) is itself invalidating |
| 8 | `SealedEmailRecognizer` detects `EMAIL_ADDRESS` with `len(egress.violations()) == 0` | a **stock** `EmailRecognizer` (default `suffix_list_urls`, cold cache) DOES raise `EgressViolation` — proving by contrast that the sealed constructor (`suffix_list_urls=()` + bundled snapshot), not cache-warming, is what prevents the fetch |
| 9 | `manifest.verify(mode="full")` → `ok`, `root_hash` matches, signature valid, zero unmanifested files under `models/` | flipping one interior byte of `model.onnx` is detected at the right path |

`PROFILE=proof` adds: `docker network inspect sagp_proof_internal → .Internal == true`; prober cannot reach `1.1.1.1:443`; prober cannot resolve `example.com` via `127.0.0.11` (**paired with**: prober *can* resolve a sibling service name — otherwise the DNS test passes for the wrong reason); Docker daemon version ≥ 26.0.0 (CVE-2024-29018 regression test); **and a second prober attached to `sagp_vec_noegress`**, the network Qdrant actually runs on, running the identical probes. Only that second prober's result may be cited for the production path. **Post-spike correction (OQ-4/OQ-5, `make spike-docker` 2026-08-01):** an `.Internal == true` network breaks host reachability, so the network the app-reachable Qdrant actually runs on (`sagp_vec_noegress`) is a **non-internal** bridge, not internal — the `.Internal == true` assertion holds only for a throwaway isolated test network, never the production path. And even on an internal network **DNS still resolves via the embedded resolver**, so the "cannot resolve `example.com`" assertion does **not** hold; DNS resolution leaks unconditionally. The Docker path is **NOT isolated by compose options** — its egress control is the host `pf` anchor + loopback binding. Update this harness spec before running it.

**The verdict has FOUR values:** `PASS`; `PASS_WITH_OPEN_HIGH_SEVERITY_GAPS` (no invalidator fired, but a `known_gap` with `severity: high` and `status: OPEN` exists); `INVALID` (an invalidating condition fired — the run proves nothing); and `FAIL` (no invalidator fired, but a core assertion **provably leaked**). It is never `PASS` when any of the other three applies.
**Invalidating conditions → verdict `INVALID`, never `PASS`:** any negative control failing; guard not installed; manifest verified in `quick` mode; non-loopback listeners present; signature invalid; ledger chain broken; `SAGP_GUARD` not `enforce`.

### 9.3 `make smoke` — 14 numbered functional checks

```
[ 1/14] .venv present, Python 3.11.15, torch + transformers NOT importable (huggingface_hub IS, via tokenizers)
[ 2/14] `import sagp` succeeds with the egress guard armed and zero violations
[ 3/14] models/ matches MANIFEST.json in FULL mode; root hash printed
[ 4/14] Presidio loads; detects EMAIL_ADDRESS + CREDIT_CARD in a synthetic string; zero egress violations
[ 5/14] Injection classifier loads; INJECTION_IDX resolved from config.json; boot self-test green
[ 6/14] bge-small ORT session loads; encodes 3 strings to dim 384; ||v||=1.0
[ 7/14] Qdrant embedded initialises at ./data/qdrant (or server reachable in PROFILE=demo)
[ 8/14] Ollama reachable at 127.0.0.1:11434 and llama3.2:3b-instruct-q4_K_M is present
[ 9/14] Ingest data/samples/employee_handbook.pdf → N chunks in `handbook`
[10/14] Ingest data/samples/poisoned_appendix.pdf → its payload chunk lands in the sibling <collection>__quarantine
[11/14] Benign query → 200, non-empty answer, ≥1 in-range citation [Sn, p.X]
[12/14] PII query → 200; the prompt sent to Ollama contains <EMAIL_ADDRESS_1>, not the address
[13/14] "Ignore all previous instructions…" → 400 PROMPT_REJECTED with an incident_id; ≥120 ms latency
[14/14] Audit chain verifies; `grep` over the JSONL BYTES finds no PII marker
SMOKE PASS — request ids: …  manifest: …  ledger head: …
```

### 9.4 The single most important test

```python
def test_final_bytes_were_scanned(spy_scanner, spy_ollama, client):
    """The untrusted payload sent to Ollama AND the string returned to the caller must each
    have been an argument to a scan() call within the same request."""
    r = client.post("/v1/chat", json={"message": "...", "collection": "handbook"})
    # Scope to the user-role message (masked question + assembled retrieved context) — the
    # attacker-influenced bytes. The static system prompt is deliberately never scanned
    # (documented false-positive source), so it is excluded here by construction.
    assert spy_ollama.last_user_payload in spy_scanner.scanned_strings
    assert r.json()["answer"]           in spy_scanner.scanned_strings
```
The first assertion is satisfiable because C18 applies the char-budget trim **before** the C19 re-scan (see §5.7), so the re-scanned assembled context is byte-identical to the user-role payload delivered at C21. It asserts on the user-role bytes that actually cross the boundary — not the never-scanned system prompt, and not an intermediate value. Every other "the guardrail ran" test asserts on an intermediate value. It is written and green (M10).

### 9.5 Metrics gates (`make eval`, committed to `docs/metrics/latest.json`)

```
INJECTION_RECALL_FLOOR    = 0.90   over attacks.jsonl, reported per technique family
INJECTION_PRECISION_FLOOR = 0.85
BENIGN_FPR_CEILING        = 0.10   over benign.jsonl (≥30% hard negatives)
PII recall floors: EMAIL_ADDRESS ≥0.98 · CREDIT_CARD ≥0.98 · IN_AADHAAR ≥0.95 · PERSON ≥0.80
REGRESSION: any metric >2pp below docs/metrics/latest.json fails the build.
```
**MEASURED at M6 (`docs/metrics/latest.json`):** headline injection recall **1.0** (families A,C,D,E,G,H,I; B and F reported separately, also **1.0**); PII recall **1.0** for EMAIL_ADDRESS / CREDIT_CARD / IN_AADHAAR / PERSON. Injection precision **0.854** now **meets** its 0.85 target; benign FPR **0.24** still **misses** its 0.10 target and remains the one OPEN `known_gap` (severity: **medium**). After the corroboration-gating fix (precision-poor lexical rules now count toward a block only when the classifier is not confidently benign), the remaining false positives are the archived classifier over-firing at score ≥ 0.99 on quoted-attack English and non-English benign text — a model ceiling, not tuning. The recall and PII floors are hard-gated; precision and FPR are regression-gated against the committed baseline.

Category B (jailbreak — the classifier's documented blind spot) and category F (indirect/document-planted) are reported **separately**, never averaged into the headline.

---

## 10. Milestone build plan — each independently testable

**Status (2026-08-01): M0–M14 are complete, merged and tested; M15 (this docs pass) is in progress.** The table below is the plan as written at M-DOCS; every milestone through M14 is built.

| # | Milestone | Deliverable | Independently testable by | Needs network? |
|---|---|---|---|---|
| **M0** | Skeleton | `src/sagp/` tree, `pyproject.toml`, `Settings`, `errors.py`, `types.py` (incl. `TextArtifact`), Makefile `venvs/install/lint/test`, `CLAUDE.md` v1 | `make lint typecheck test` green; `test_config.py`, `test_paths.py` (spaces in path round-trip) | no |
| **M1** | **PROVISION EVERYTHING** (the one-way door) | `artifacts.lock`, `scripts/provision/01..10`, all four gates, `MANIFEST.json`, `.env.sealed` template, secrets | `make provision` exits 0; `make verify-manifest` green; `07_gates.py` prints the measured classifier RSS (FP32 — 0.30 GB) and parity deltas (INT8 rejected — OQ-2) | **YES — online only** |
| **M2** | Audit spine (before any guardrail) | `audit/{events,hashing,sink,verify,scrub,quarantine,redactors}.py` | `test_audit_schema.py`, `test_audit_chain.py` (mutate one byte → detected at the right index), `test_audit_no_pii.py` (hypothesis, reads JSONL **bytes**) | no |
| **M3** | Normalizer + placeholders + heuristics | `normalize.py`, `placeholders.py`, `heuristics.py`, `deobfuscate.py` | Unicode fixtures incl. tag chars, bidi, Hindi/Arabic ZWJ/ZWNJ (must NOT block); property test that `neutralize ⊇ rehydrate` | no |
| **M4** | PII guardrail | `presidio_factory.py`, `recognizers.py` (incl. `SealedEmailRecognizer`), `vault.py`, `aliases.py`, `pii.py` | `test_pii_guardrail.py`, `test_vault.py` (pickle raises, `f"{vault}"` leaks nothing), `test_tldextract_no_fetch.py` with the guard armed | no (spaCy md local) |
| **M5** | Injection guardrail | `labels.py`, `onnx_backend.py`, `scanner.py`, `selftest.py` | `FakeScorer` unit tests for threshold/aggregation/fail-closed; `test_tail_attack_not_truncated`; boot self-test through the **real policy path** | no |
| **M6** | Metrics gate | `tests/corpus/*.jsonl`, `eval_guardrails.py`, `docs/metrics/latest.json` | `test_injection_metrics.py` meets all three floors; `test_pii_recall.py` | no |
| **M7** | LLM client | `llm/{base,fake,ollama_client}.py`, `prompts/*` | `test_llm_fake.py`; one real generation (`needs_ollama`) | no (local Ollama) |
| **M8** | RAG ingestion | `loaders.py` (+ hidden-text visitor), `chunking.py`, `embeddings.py`, `vectorstore.py`, `qdrant_store.py`, `ingest.py`, `gen_sample_pdf.py` | `test_chunking.py`, `test_ingest_pipeline.py` on `":memory:"`; `test_idempotent_ingest.py` (ingest twice → count unchanged); embedding parity fixture | no |
| **M9** | Retrieval + prompt | `retriever.py`, `prompt.py` | `test_retriever.py` known-answer ranking; `test_score_normalisation.py`; `test_prompt.py` (nonce cannot be forged; prompt hash stable) | no |
| **M10** | **FIRST DEMOABLE SLICE** — FastAPI gateway | `app/{main,deps,schemas,middleware,ratelimit}.py`, `routes/{health,chat,ingest,admin}.py`, `output.py`, `registry.py` | `test_chat_endpoint.py`, `test_blocked_flow.py`, `test_guardrail_bypass.py` (AST + runtime spy), `test_oracle_uniformity.py` (all detectors → identical 400 + timing), `test_final_bytes_were_scanned` | no (FakeLLM) |
| **M11** | Net-guard + manifest at boot | `netguard/{egress,manifest,phase}.py`, `.pth` bootstrap, lifespan full-verify | `test_no_egress.py`, `test_af_unix_denied.py`, `test_subprocess_denied.py`, `test_no_network_imports.py` (AST), `test_manifest.py` | no |
| **M12** | Indirect-injection layer | ingest-time `guard.*` payload, per-collection `<collection>__quarantine` sibling, assembled-context re-scan, admin review route | `test_context_guard.py` with `poisoned_appendix.pdf`; every `attacks.jsonl` record with `category == "F_indirect_document"` (surface: document) must be caught | no |
| **M13** | **THE DEMONSTRATION** | `verify_airgap.py`, `verify_online.py`, `evidence.py`, `probes.py`, `smoke.sh`, ledger | **Disconnect the machine**, then `make verify && make smoke && make test-e2e` all green | **offline — this is the deliverable** |
| **M14** | Hardening | pf anchor, Docker `demo`/`proof` profiles, Ed25519 signing, log rotation, retention sweep, backup/restore | `make test-all`; a 30-minute soak inside the RAM budget | no |
| **M15** | Documentation | Everything in `docs/`, README, `CLAUDE.md` final, 9 ADRs, `NOTICE`, `THIRD_PARTY_LICENSES.md` | A reviewer follows README from a clean checkout and reaches a green `make smoke` | no |

**Minimum viable slice = M-DOCS → M0 → M10** (with M1 done first, online). At M10 you can turn off Wi-Fi, ingest the synthetic handbook, ask a question containing an email, show `<EMAIL_ADDRESS_1>` in the masked prompt and a cited grounded answer, then send `ignore all previous instructions` and receive a 400 with an incident ID. **That makes the brief's literal claim demonstrable, offline.** Attempting past M13 in one pass yields several half-built subsystems instead of one working demo.

Realistic effort: **3–6 focused weeks**, not one session. M1 (provisioning + gates) is the longest single item and must be finished while online.

---

## 11. The complete docs set

### `CLAUDE.md` (agent context, ≤ 300 lines, imperative and checkable)

The written file is ~297 lines in ten sections; this outline records what it contains, not a target to
re-cut it to:

```
 1. What this project is
 2. The 13 hard invariants      ← must be read before any edit; canonical numbering for the corpus
 3. Repo layout
 4. Commands
 5. The lifecycle state machine
 6. Where things live (module map + boundary rules)
 7. Code conventions
 8. Testing
 9. Things that look like good ideas but are forbidden here
10. Current status
```

**§2 — the invariants.** ⚠️ **`CLAUDE.md` §2 is the canonical invariant numbering for the whole corpus.** The ordering below is historical — it predates `CLAUDE.md` and does **not** match it. Treat this list as a checklist of *which* rules exist, never as a source of numbers: **do not cite an invariant by number from this section.** Every "invariant N" citation anywhere in these documents resolves against `CLAUDE.md` §2 and nothing else.

1. **Never add a network call.** Only `127.0.0.1:11434` (Ollama) and `127.0.0.1:6333/6334` (Qdrant, demo profile) are permitted. `huggingface_hub` IS installed in `.venv` (via `tokenizers`) but our code never imports it, and `HF_HUB_OFFLINE=1` + the egress guard stop it phoning home.
2. **Never bypass the guardrail pipeline.** Any path reaching `OllamaClient` runs `pipeline.run_input()` before and `run_output()` after. No `skip_guardrails`, no debug mode, no direct LLM call in a route or script.
3. **Never log raw PII, prompts, completions, retrieved text, or vault mappings.** `AuditEvent` is closed (`extra="forbid"`). Offending text goes to `audit/quarantine.py`, referenced by `incident_id` only.
4. **Fail closed.** A guardrail that errors, times out, or returns a partial result **blocks**. Never `try/except: pass` around a guardrail.
5. **There is exactly one fail mode: closed.** Do not add `*_FAIL_MODE=open`, `*_DISABLED`, or any env var that weakens a control. Dev bypasses live in a separate app factory that `sagp.app.main` cannot import.
6. **Never commit model weights, audit logs, evidence, or real PII.** Refuse any `git add` staging a file > 10 MB.
7. **Never change a pinned version, model ID, or revision** without updating `artifacts.lock`, `requirements.*.lock`, `MANIFEST.json`, and an ADR in the same change.
8. **Never weaken a threshold or metric floor to pass a test.** Fix the guardrail or the corpus and explain.
9. **Quote every path.** The repo path contains spaces. `"$ROOT"`, `"$(PWD)"`, `pathlib.Path` — never bare word-splitting.
10. **Never install, download, `docker`, or `ollama pull` unprompted.** Provisioning is explicit and online-only.
11. **Never run a network-touching command when `.airgap/state.json.phase == "OPERATE"`.** Add the artifact to `artifacts.lock` and require an explicit `make unseal REASON="…"`.
12. **The runtime venv has no `torch` or `transformers`.** (`huggingface_hub` rides in via `tokenizers` and is neutralised, not removed — corrected at M0; see the reconciliation ledger row 28.) If you think you need `torch`/`transformers` at runtime, you need `tokenizers` or `onnxruntime` instead — say so rather than adding it.
13. **Adding a guardrail signal requires three edits in one commit:** an `AuditEvent` field, a `docs/COMPLIANCE.md` row, and a `test_audit_no_pii.py` case.

**§9 — forbidden "good ideas":** token streaming that bypasses the output guardrail; caching LLM responses keyed by raw prompt; an OpenAI/Anthropic fallback client; telemetry; persisting the vault "for convenience"; `trust_remote_code=True`; auto-downloading a missing model at request time; a `/v1/raw` debug endpoint; returning scores in an error body; using `client.search()` (removed in qdrant-client 1.16.0); `spacy.cli.download`.

### `README.md`

1. What this is (5 bullets + the one-line architecture sentence) · 2. The claim being proven, and a link to `LIMITATIONS.md` in the **first** paragraph · 3. Architecture at a glance (one mermaid diagram) · 4. Requirements (macOS arm64, 8 GB note, Python 3.11, ≥25 GB free) · 5. Phase A PROVISION (online) · 6. Phase B SEAL · 7. Phase C PROVE · 8. Try it (three curl examples with expected JSON: benign, PII-bearing, injection) · 9. What the guardrails do (table: stage → catches → p50 → link) · 10. Repo layout (condensed, 20 lines) · 11. Memory & model profiles (default 3B; 8B does not fit and why) · 12. Testing (what each marker needs) · 13. Security posture (3 bullets + link to `THREAT_MODEL.md`) · 14. Compliance note (template, not legal advice) · 15. Troubleshooting (top 10: disk, Docker daemon, Ollama not running, OOM, spaCy model missing, PSL fetch, port in use, manifest mismatch, empty collection, INT8 parity failure) · 16. Licences (Apache-2.0 repo; Llama 3.2 Community Licence; Apache-2.0 DeBERTa; MIT bge-small/spaCy; **and the note that no weights are redistributed**).

### `docs/ARCHITECTURE.md`
1. Goals / non-goals · 2. Context diagram · 3. Components (gateway, guardrail pipeline, RAG, LLM runtime, vector store, audit, net-guard) — **including the explicit statement that FastAPI runs on the macOS host, not in a container, so the only host↔Qdrant path is the published loopback port and `host.docker.internal` is not the mechanism** · 4. **The request path, numbered C0–C26 exactly as §5.7, with the function called at each step** · 5. Ingest path I1–I11 · 6. Data model: `TextArtifact`, `Chunk`, point payload schema, `ScanResult`, `AuditEvent` · 7. Module boundaries + the enforced dependency rules · 8. Configuration model (`SAGP_` prefix, precedence, `guardrails.yaml` schema) · 9. Concurrency & memory (one worker, `CapacityLimiter(2)`, ORT `intra_op_num_threads=4`, lazy `@lru_cache` singletons, the §7 table) · 10. Fail-closed matrix (component down → behaviour → HTTP code → audit decision) · 11. Performance envelope — **composed p50/p95 per stage, ESTIMATES until M13; every estimate replaced by a measurement after M13** · 12. Extension points · 13. ADR index.

### `docs/THREAT_MODEL.md`
1. Scope · 2. Assets (prompts, documents, embeddings, vault, weights, audit log, host) · 3. Trust boundaries (air gap; process; document; operator) · 4. Actors (curious user, malicious user, **malicious document author** — the primary threat, compromised supply chain, insider operator, host-level attacker) · 5. Assumptions and explicit non-goals · 6. **OWASP Top 10 for LLM Applications 2025 mapping** (LLM01 partial-strong / LLM02 partial — strong design, zero measured efficacy / LLM03 partial / LLM04 partial / LLM05 strong / LLM06 strong-by-omission / LLM07 partial / LLM08 partial / LLM09 weak / LLM10 partial) · 7. Residual risk register (§13 verbatim) · 8. Compliance mapping pointer · 9. Four attack narratives walked end to end, one of which is the poisoned-PDF→placeholder-exfiltration chain · 10. Detection & response: what appears in the audit log for each · 11. **A named section: "The LLM runtime lives outside the in-process guard"** — Ollama is a separate Go process, covered only by the optional pf layer; its binary sha256 is in `MANIFEST.json` and `ollama --version` is asserted at startup.

### `docs/GUARDRAILS.md`
1. Philosophy: defence in depth, fail closed, measure everything · 2. Stage table (order, surface, fail mode, estimated p50 — unmeasured until M13) · 3. G1 normalisation & heuristics · 4. G2 injection classifier (model ID + revision + label resolution, windowing, thresholds and their derivation, **the metric contract — floors now, measured P/R/F1 and per-technique recall from M6**, known evasions, and the vendor's own statement that it does not detect jailbreaks) · 5. G3 PII detection & pseudonymisation (entity tables, per-entity thresholds, custom recognizers, the vault, rehydration authorization) · 6. G4 assembled-context guardrail · 7. G5 output guardrail (structural, egress PII, normalized-divergence block, citation range) · 8. Full annotated `guardrails.yaml` · 9. Tuning guide: which tests to re-run after moving each threshold · 10. Evaluation pointer · 11. **Known limitations and explicit bypasses**: English-only classifier, jailbreak blind spot, long-context dilution, PERSON recall on non-Western names, over-masking at the 0.35 egress threshold.

### `docs/AIRGAP_RUNBOOK.md`
0. The three phases and the one-way door · 1. Pre-provision checklist · 2. Phase A steps A1–A10, each with command, expected output, expected size, rollback · 3. Phase B seal + the physical disconnect procedure · 4. Phase C verify: the 9 assertions, annotated PASS and FAIL output · 5. Steady-state ops (start/stop order, log locations, disk watch, memory watch) · 6. Re-provisioning: the controlled reconnection, dual-control recommendation, manifest diff · 7. Incident procedures (suspected egress, manifest mismatch, audit chain break, suspected poisoned document, INT8 parity regression) · 8. Decommissioning · 9. Command reference + expected download sizes.

### `docs/COMPLIANCE.md`
Opens with a boxed disclaimer: *engineering-to-control mapping template; not legal advice; not a certification; Presidio's own docs state detection is not guaranteed.* Then: GDPR (Art. 5(1)(c), 4(5)+32(1)(a), 25, 30/33, 44–49) · HIPAA (**all 18 Safe Harbor categories in a table with ✅/⚠️/❌ per row, and a bolded statement that this system does NOT achieve Safe Harbor**; §164.312(b), (a)(1), (e)(1)) · NIST SP 800-53 Rev.5 (AC-4, SC-7, SC-8/28, SI-7, SI-10, SI-15, AU-2/3/9/10/12, CM-2/6/14, SR-3/4/11, RA-5, CP-9/10) — four columns each: Control | Requirement | Implemented here | Gap / operator responsibility · a **retention table** (audit / vector store / private docs / evidence ledger, each with a period and its GDPR-vs-HIPAA justification) · a closing section "Controls you must add outside this repo".

Two rows must be written to match the shipped default (`ingest_mode=raw`): masking occurs **at retrieval**, the vector store holds raw personal data, and the compensating controls are loopback binding + FileVault + `delete_by_source` erasure.

### `docs/EVALUATION.md`, `docs/OPERATIONS.md`, `docs/LIMITATIONS.md`
- **EVALUATION:** corpus construction, the 9 required technique families, why ≥30% hard negatives, metric definitions (FPR **not** 1−precision), how floors were chosen, how to add attacks, and an honest section on the self-benchmarking risk.
- **OPERATIONS:** secrets table (name, generator, location, mode, rotation effect) for the API tokens, audit HMAC key, PII pepper, and Ed25519 key; the daily "export the ledger head digest off-box" step; log rotation; retention sweep; model rotation; cold backup/restore of `data/` + `audit/` + `.airgap/state.json`; incident response.
- **LIMITATIONS:** §13 below, verbatim, linked from README paragraph 1.

---

## 12. Concurrency, timeouts, and caps (one canonical set)

```
SAGP_MAX_INPUT_CHARS      = 8000     # gateway, user prompt
SAGP_MAX_SCAN_UNIT_CHARS  = 20000    # ONE cap, enforced identically at the API and ingest boundaries;
                                     #   anything larger is split into <=MAX_SCAN_UNIT_CHARS pieces and
                                     #   EVERY piece scanned, with an assertion that scanned spans cover
                                     #   the whole input. The two caps compose: each piece is then
                                     #   independently windowed under its own MAX_WINDOWS budget.
SAGP_MAX_DOC_BYTES        = 52428800
SAGP_MAX_WINDOWS          = 16       # per-piece window budget; truncated=True (a single piece still
                                     #   exceeds 16 windows) -> BLOCK/QUARANTINE on EVERY surface
SAGP_MAX_CTX_CHARS        = 7000
SAGP_MAX_VAULT_ENTRIES    = 2000

timeout_injection_ms  = 2000  -> 503
timeout_pii_ms        = 3000  -> 503        (anyio.fail_after around the offloaded thread)
timeout_embed_ms      = 2000  -> 503
timeout_retrieve_ms   = 3000  -> 503
timeout_llm_s         = 120   -> 503
timeout_request_s     = 180   -> 503
rejection_deadline_ms      = 120   # placeholder; fixed deadline (not a floor), calibrated at M13 (§9.4)

uvicorn --workers 1
anyio.CapacityLimiter(2) around every sync guardrail call
ort SessionOptions: intra_op_num_threads=4, inter_op_num_threads=1   (leaves 4 cores for Ollama)
```

`_violations` in the egress guard is a `deque(maxlen=1000)` plus a monotonic counter; stacks are formatted **outside** the lock and only for the first 3 occurrences of each distinct `(layer, operation, target)` triple, with a per-second denial-rate ceiling above which stack formatting stops.

---

## 13. LIMITATIONS — what this blueprint does **not** prove

1. **It does not prove the machine cannot reach the internet.** The strongest claim the design supports is that a specific set of software controls was *demonstrated* to refuse a specific set of egress probes, each paired with a negative control, on a host separately shown to have working internet moments earlier. `make verify`, `make verify-online`, `verify_airgap.py` and `verify_online.py` now exist and run (M13) — `verify-online` was exercised live (a real 6.58 ms TCP handshake unguarded; `EgressViolation` when the guard enforces) and the 9 offline assertions PASS. **But a green air-gap `PASS` has never been produced:** this dev host is deliberately kept in PROVISION and has never been sealed or physically disconnected, so the harness self-tests but the overall verdict here is `INVALID` by design. The host retains a Wi-Fi radio, Thunderbolt/Ethernet, Bluetooth, and USB NIC support. What this is designed to be is a rigorous, reproducible, self-auditing **simulation** of an air gap — honest about which of those two words applies. It is never a proof.
2. **Native code bypasses the Python guard.** `grpcio`'s C core (a hard dependency of `qdrant-client`, present even in REST mode), ONNX Runtime, and anything reached through `ctypes`/`cffi` can call `connect(2)` without entering CPython's socket layer or emitting a PEP 578 event. `HF_HUB_DISABLE_XET=1` and the two-venv design close the instances we ship; they do not close the category. Only `make seal-pf` does, and only for UID-owned TCP/UDP.
3. **Processes not started by the guarded interpreter are uncovered.** The Ollama server, the Docker daemon, and anything an operator runs in another terminal are outside both guard layers. pf covers the first; pf does **not** cover Docker, whose traffic leaves via a root-owned VM interface.
4. **A hostile operator defeats it trivially.** Editing `.env.sealed`, running `python -S`, deleting `.airgap/state.json`, or re-signing the manifest with a fresh key. The threat model assumes a cooperative operator and a possibly-hostile *dependency* or *document*.
5. **The signature is self-signed.** The Ed25519 key is generated on the host it attests to. It proves continuity and tamper-evidence for one key holder — not third-party attestation, not hardware-rooted.
6. **Timestamps are local-clock.** No RFC 3161 TSA is reachable offline. The hash chain makes reordering and deletion detectable; it does **not** make backdating detectable.
7. **The audit log is tamper-*evident*, not tamper-*proof*.** An attacker with write access can rebuild the chain from any point unless the head digest is exported off-box. Anchoring is documented in `OPERATIONS.md`, not implemented. Do not claim non-repudiation.
8. **Hashes prove identity, not safety.** A matching sha256 proves the artifact is what the publisher served. It says nothing about whether the artifact is backdoored, nor whether the classifier is any good.
9. **Injection detection is probabilistic and the model is archived.** `protectai/deberta-v3-base-prompt-injection-v2` is unmaintained and its card states verbatim that it **does not detect jailbreak attacks** and does not handle non-English prompts. Heuristics carry that load imperfectly. There is no "solved" state.
10. **Presidio recall is not 100%.** Names outside the spaCy distribution, PII in non-English or Indic scripts, PII in tables/OCR noise, and novel identifier formats will be missed. Masking is a risk-reduction control, not a guarantee. **No PII recall floor is asserted for Devanagari or transliterated names** — that evaluation does not exist yet.
11. **`ingest_mode=raw` stores real PII in the vector store.** It is protected by loopback binding, filesystem permissions, and FileVault — not by the guardrail. Copying `data/qdrant/` off the box leaks the corpus with no control in the path.
12. **The vault is memory-only and unencrypted while resident.** `clear()` drops references; Python strings are immutable and interned, so **bytes are not scrubbed from the heap**. A core dump or memory scraper recovers the mapping. Disable core dumps (`ulimit -c 0`); do not co-locate untrusted processes.
13. **Multi-turn conversation is unsupported.** The endpoint is single-turn by design because the vault is request-scoped. Split-payload attacks across turns are not a threat here only because turns do not exist.
14. **Rehydration returns real PII to a caller authenticated by a shared bearer token** on loopback, with no user identity, no RBAC, and no TLS. That is adequate for a single-tenant sealed box and inadequate for anything else.
15. **No groundedness or hallucination scoring.** The citation validator performs an **out-of-range check on markers**, nothing more. It cannot detect a fact attributed to the wrong supplied block, a fabricated fact with a valid citation, or a citation planted inside the source document.
16. **No provenance beyond hashes.** No Sigstore/cosign verification, no SLSA attestation, no signed SBOM. `pip download` fetches whatever the index serves — mitigated by `--require-hashes` on the *second* install, not the first.
17. **Denial of service by resource exhaustion is largely unmitigated** on 8 GB. A concurrent burst OOMs before rate limits bite. One worker plus `CapacityLimiter(2)` is the whole defence.
18. **All latency figures in this document are ESTIMATES.** No benchmark has been run on this M2. The structural conclusions (guardrail overhead is a small fraction of generation; the injection classifier dominates the guardrail) are robust to a 2–3× error; the absolute numbers are not.
19. **`docker exec` egress tests measure Docker Desktop's Linux VM, not macOS. The Docker path is NOT network-isolated by compose options** — `make spike-docker` (run 2026-08-01) resolved OQ-4/OQ-5 negatively: `enable_ip_masquerade: "false"` does **not** block egress on Docker Desktop (containers egress via a userland VM proxy), `internal: true` breaks host reachability so a non-internal bridge is used, and DNS always resolves via the embedded resolver. Egress control on the Docker path comes from the host `pf` anchor + loopback binding, not Docker networking. ADR-0002 is **Accepted**. See LIMITATIONS.md item 19.
20. **This is not a substitute for a data diode, a cross-domain guard, hardware attestation, write-once transfer media, TPM-measured boot, an HSM, two-person integrity, or a SCIF.** Section 5 of `THREAT_MODEL.md` contains the full comparison table against a genuinely regulated enclave.

---

## 14. OPEN QUESTIONS — genuinely unresolved, do not invent an answer

**OQ-1 — RSS of the injection classifier session. RESOLVED at M1 (measured 2026-07-30).**
Moot for INT8 (rejected — see OQ-2). The **FP32 ONNX** session RSS, measured by `07_gates.py` in a
fresh interpreter, is **0.30 GB** (ORT mmaps the 704 MB weights, so resident set ≪ file size). This is
the same as the old INT8 arithmetic estimate, so **the fallback to FP32 does not change the RAM budget**
— the §7 default total stays ~6.75 GB (embedded). The "FP32 costs 0.80 GB" figure in §7/ADR-0004 was a
wrong estimate; the measured number is 0.30 GB. Dropping the 3B LLM to `llama3.2:1b` is therefore **not**
required by the fallback.

**OQ-2 — INT8 accuracy parity on DeBERTa-v3's disentangled attention. RESOLVED at M1: it FAILS.**
Measured 2026-07-30 by `07_gates.py`: `quantize_dynamic` (default op set, QInt8) on this checkpoint
**inverts the classifier** — `max |ΔP(INJECTION)| = 0.98`, **3 label flips**; the INT8 model scores
*"Ignore all previous instructions"* as 0.02 INJECTION (SAFE). The parity gate (`|ΔP| < 0.05`, zero
flips) correctly refused. The fallback ladder selected **FP32 ONNX** (verified correct: attacks →
INJECTION 1.0, benign → SAFE 1.0), which is the runtime classifier. `06_quantize.py` still produces the
INT8 candidate each run so the gate re-proves the rejection; the runtime model is recorded in
`models/derived/classifier_choice.json`. **The runtime injection classifier is FP32 ONNX, not INT8**
— descriptive mentions of "INT8 ONNX" elsewhere in the corpus predate this measurement (M13 sweep).

**OQ-3 — Exact token cost of the assembled prompt under llama3.2's BPE. (Owner: M7, with the LLM client.)**
`SAGP_MAX_CTX_CHARS=7000` is a character proxy. There is no llama3 tokenizer in the runtime venv (`tokenizers` cannot load a GGUF vocab). Resolve at **M7** via the `prompt_eval_count` experiment: either (a) measure the char→token ratio empirically on the real corpus and set the cap conservatively, or (b) call `POST /api/generate` with `"raw": true, "num_predict": 0` and read `prompt_eval_count` to get an exact count from Ollama itself — **unverified that this returns a count without generating; the M7 experiment settles it.**

**OQ-4 — Docker `internal: true` + host port publishing on Docker Desktop for Mac 29.5.3. RESOLVED at the Phase-0 spike (`make spike-docker`, run 2026-08-01): PUBLISH-NO-ROUTE.**
With `internal: true`, a published `127.0.0.1` port is accepted and the container runs, but the macOS **host cannot reach it** (`curl` → http_code 000). The sagp app runs on the host, so `internal: true` and an app-reachable Qdrant are **mutually exclusive** — the compose file therefore uses a **non-internal** bridge. Evidence: `evidence/spike-docker.json` (gitignored). ADR-0002 records this and is now **Accepted**.

**OQ-5 — Does `enable_ip_masquerade: "false"` actually block egress on Docker Desktop? RESOLVED at the Phase-0 spike (2026-08-01): NO.**
On an internal network, raw TCP egress to `1.1.1.1` is blocked but DNS still resolves `example.com` via the embedded resolver. On a reachable (non-internal) network with `enable_ip_masquerade=false`, egress is **fully open** — TCP reached and DNS resolved — because Docker Desktop containers egress via a userland VM proxy, not a host MASQUERADE rule. **Conclusion:** on Docker Desktop you cannot get both an app-reachable Qdrant and an egress-blocked container from compose options alone. The Docker path is **NOT isolated by compose network options**; its egress control comes from the host `pf` anchor (`make seal-pf`) + loopback binding, and DNS always leaks via the embedded resolver.

**OQ-6 — Presidio's regex-timeout behaviour. RESOLVED-CONFIRMED (read `presidio-analyzer==2.2.364` source, 2026-07-30).**
`PatternRecognizer.__analyze_patterns` passes `timeout=REGEX_TIMEOUT_SECONDS` (env-defaulted to 60 s) to `regex.finditer`, then **catches `TimeoutError` per pattern, logs "timeout... skipping", and continues** — so `analyze()` returns a *partial* result set at 200 rather than propagating. A crafted catastrophic-backtracking input therefore silently disables individual recognizers: a textbook silent fail-open in the masking layer. **Resolution (binding on M4):** wrap `analyze()` so any per-pattern regex timeout is surfaced as a guardrail failure → **503**, never swallowed. ARCHITECTURE §10's fail-closed matrix already mandates this unconditionally.

**OQ-7 — `grpcio` exact version.**
`qdrant-client==1.18.0` hard-depends on `grpcio>=1.41.0` with no upper bound; the resolved version must be pinned into `requirements.runtime.lock`, and its arm64 cp311 wheel must exist for `macosx_14_0_arm64`. It carries a native extension that is outside both egress-guard layers. I did not verify which version the resolver picks.

**OQ-8 — Ollama compute-graph/runtime overhead.**
The 0.35 GB figure is derived from typical llama.cpp Metal allocations, not measured on this M2. `ollama ps` reports actual runner SIZE. This is a 10-minute measurement that validates the entire §7 table — do it before committing to any configuration.

**OQ-9 — `en_core_web_md` PERSON recall on Indian names.**
spaCy publishes only aggregate `ENTS_F` (md 84.73), never per-label PERSON F. OntoNotes is US/Western-news weighted — the exact blind spot for a system whose brief calls out Aadhaar and PAN. Build a 100–200 example labelled eval set from the real corpus before locking the model. `SAGP_SPACY_MODEL` makes the swap to `lg` one line; if `lg` is needed, the LLM must drop to `llama3.2:1b`.

**OQ-10 — Retrieval and PII threshold calibration.**
`MIN=0.35 / STRONG=0.50` are general bge-small distributions; the PII egress threshold of 0.35 is deliberately below the `LemmaContextAwareEnhancer` floor and **will** over-mask. Both need a sweep against the real corpus (20 answerable + 20 unanswerable questions; measured over-masking rate on answers) before the refusal behaviour or the masking rate can be called correct.

**OQ-11 — The canonical Presidio documentation URL.**
Source is confirmed at `github.com/data-privacy-stack/presidio` (verified at tag `2.2.364`), and the `repo` spec reports docs at `presidio.dataprivacystack.org`. I did not fetch that domain. Resolve the redirect once during provisioning and record it in `provision-report.json` **before** writing any doc link.

**OQ-12 — Which key derives `pii_token_hmacs`: `SAGP_AUDIT_HMAC_KEY` or `SAGP_PII_PEPPER`? (Owner: M2, before the audit spine.)**
`audit/hashing.py` exposes `hmac_token`/`sha256_hex`/`chain_digest`, and the design ships both a distinct audit HMAC key and a PII pepper. It is almost certainly the pepper (domain separation between tamper-evidence and correlation), but it must be pinned, not assumed — getting it wrong couples audit-chain rotation to PII-correlation continuity. Resolve at M2 and correct [OPERATIONS.md](OPERATIONS.md) §1.