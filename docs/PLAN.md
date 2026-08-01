# Secure Air-Gapped Platform with Integrated Guardrails (`sagp`)

## Context

**Why this exists.** You want a reference blueprint for running an LLM inside a network-isolated
enclave — the deployment shape regulated industries actually require — with the two controls that
make such an enclave usable in practice: automated PII de-identification before anything reaches the
model, and prompt-injection blocking before anything reaches the retriever. The deliverable is a
*template* others can copy, not a one-off demo.

**Where we are.** As of 2026-08-01, M-DOCS and **M0–M14 are complete, merged and tested**. `src/`,
`tests/`, `scripts/`, `config/`, `bin/`, the Makefile, `docker-compose.yml` and `pyproject.toml` all
exist; the full suite is **258 tests passing**, `make lint`/`typecheck` are green, and `make smoke` is
**14/14 PASS**. Indirect injection (M12), the offline demonstration harness (M13) and hardening (M14)
are built. The dev host is deliberately kept in **PROVISION** phase — never sealed for real — so no
green air-gap `PASS` has been produced (verdict `INVALID` by design). **M15 — this pass — revisits the
docs to make them correct-as-measured.** The design-time text of this section read "documentation
only, no code committed"; that was true at M-DOCS (2026-07-27), not now.

**The intended outcome.** Disconnect the machine from the internet, ingest a local PDF, embed it
locally, store the vectors locally, ask a question containing personal data, and get a grounded,
cited answer — while the prompt that reached the model contained `<EMAIL_ADDRESS_1>` and not the real
address. Then send `Ignore all previous instructions` and get a `400` with an incident ID. All of it
offline, and all of it evidenced by paired negative controls rather than asserted.

**How this plan was produced.** A 9-agent workflow: 5 parallel subsystem designs (PII, injection,
air-gap, RAG, repo/docs), then 3 adversarial critiques (feasibility, security, completeness), then a
synthesis pass that arbitrated every conflict. The critiques were valuable — all three independently
concluded the five specs, written in isolation, *contradicted each other on nearly every load-bearing
choice* (three different spaCy models, two mutually exclusive dependency pins, four directory trees).
Section 2 below is the arbitration.

**Docs live in the repo.** Step one is **M-DOCS**: every markdown file — including this plan and the
full 93 KB reconciled blueprint (currently only in a scratchpad) — is written into the project
directory *before any code*. Nothing of value stays outside the repo.

---

## 1. Environment constraints (measured, not assumed)

| Fact | Value | Consequence |
|---|---|---|
| RAM | **8 GB unified, M2** — hard ceiling | Drives every model-size decision below |
| Disk free | 5.9 GB now; **you are freeing space** | Need **≥ 25 GB** free before Phase 1 |
| Python | 3.14.6 default — too new for spaCy | Pin **3.11.15** (`~/.local/bin/python3.11`) |
| Docker | 29.5.3 installed, **daemon stopped** | `open -a Docker` before the Qdrant profile |
| Ollama | client 0.30.10, **no server, no models** | Everything pulled during PROVISION |
| Network | online now | PROVISION must complete *before* sealing |

*These are the BOOTSTRAP-time (pre-provision) readings. M1 PROVISION has since completed on this host —
models fetched (`llama3:8b` skipped, disk-constrained), gates run, `MANIFEST.json` signed and committed
— and the host is held in PROVISION phase (not sealed).*

**The headline resource finding:** `llama3:8b` does not fit. Best case — 2048 context, q8_0 KV, every
other component stripped — projects to **9.28 GB against an 8 GB ceiling**. macOS will compress and
swap rather than OOM, so it will *appear* to work at 3–6 tok/s, with a 2–5 s stall at the head of
each request **(ESTIMATE)** while the guardrail models fault back off SSD. The pages evicted are precisely the idle
security controls. That is a security property, not just slowness.

**Three facts about `llama3:8b`, stated together so no other document has to guess.** (1) It **was
skipped on this host** — M1 did not pull the tag (disk-constrained; and it does not fit in 8 GB
anyway), so this host does not carry it. The design keeps it available for hosts that want to
reproduce the failure. (2) It is **one env var away on a host that carries it** — set
`SAGP_LLM_MODEL=llama3:8b` and it is live; the default remains `llama3.2:3b-instruct-q4_K_M`. (3) It
**does not fit** — it projects to 9.28 GB against the 8 GB ceiling, so the app prints a loud startup
warning whenever an `8b` tag is set on a host under 16 GB and the projected-RSS boot refusal applies.
Available is not the same as supported: the tag exists so the trade-off can be demonstrated, not
because the configuration is recommended.

---

## 2. Locked stack — the arbitration

Every row below was a genuine contradiction between subsystem specs. One answer each.

| Area | Decision | Why |
|---|---|---|
| **Runtime inference** | **ONNX Runtime only. No `torch`, no `transformers`, no `huggingface-hub` in the serving venv.** | Removes ~0.45 GB RSS and dissolves a real `ResolutionImpossible` between `transformers` and `huggingface-hub` pins |
| **Two virtualenvs** | `.venv` (sealed runtime) + `.venv-provision` (online only: torch, transformers, onnx) | The provisioning toolchain never sits on the sealed critical path |
| Injection model | `protectai/deberta-v3-base-prompt-injection-v2` @ `90c9989b…`, **FP32 ONNX** (INT8 dynamic quant *inverts* this DeBERTa-v3 checkpoint — its disentangled-attention relative-position embeddings break under INT8; OQ-2, RESOLVED at M1 — so the parity gate selected FP32) | The name in your brief (`DeBERTa-v3-base-injection`) is the v1 ancestor; this is the ONNX-shipping successor — itself **archived and unmaintained upstream** (§11 item 6), chosen as the best available checkpoint despite that, not because it is maintained |
| Label resolution | Read `id2label` from `config.json` at boot; **never hardcode index 1** | Hardcoding silently *inverts* the guardrail — blocks benign, allows attacks |
| Quantization | `quantize_dynamic(..., op_types_to_quantize=None)` (the default) — but the INT8 candidate it produces **failed the parity gate on this checkpoint (OQ-2)**, so **FP32 ONNX ships**; the quantizer still runs each provision so the gate re-proves the rejection | Passing `["MatMul","Gather"]` *narrows* the set — `Gather` is already in `IntegerOpsRegistry` |
| Embeddings | `BAAI/bge-small-en-v1.5` @ `5c38ec7c…`, ONNX, **CLS pooling → L2 norm**, 384-d | MiniLM dropped. Pooling is specified because a hand-rolled ONNX path that mean-pools silently halves recall |
| **Vector store** | **Qdrant only** — Chroma deleted. `SAGP_QDRANT_MODE=embedded` is the **default runtime backend**; `PROFILE=demo` → Docker is the **demonstration and proof path** | See §3 |
| LLM | `llama3.2:3b-instruct-q4_K_M` default; `llama3.2:1b` fallback; `llama3:8b` available + warned | §1 |
| PII engine | `presidio-{analyzer,anonymizer}==2.2.364`, `spacy==3.8.13`, `en_core_web_md` | **The asserted hard conflict does not exist.** 2.2.364's `requires_dist` gates its `spacy!=3.8.14` exclusion on `python_version >= "3.14"`, which does not apply on the pinned Python 3.11 (BLUEPRINT §1.1 quotes the metadata verbatim). `3.8.13` is an **intersection pin chosen for safety**, not a forced one. `md` for real 300-d vectors on OOV proper nouns |
| **Ingest PII policy** | `ingest_mode=raw` — store real chunk text, **mask at retrieval** | Masking at ingest collides placeholders across identities and destroys retrieval (raw queries vs masked corpus) |
| Masking scheme | Custom `VaultPlaceholder` operator → `<PERSON_1>`; **request-scoped, in-memory, never persisted** | Presidio's `encrypt`/`decrypt` ties ciphertext to a long-lived key; a request vault cannot leak across requests |
| PDF | `pypdf==6.14.2` (BSD-3) | **PyMuPDF rejected on AGPL-3.0 §13** — it would infect a compliance-themed template |
| Blocked-request response | **HTTP 400, identical body and a fixed rejection deadline (120 ms placeholder, calibrated above the slowest detector at M13) for every detector** | A 400-vs-403 split, a returned score, or a stage-dependent latency is a detector oracle an attacker tunes against |
| Conversation | **Single-turn.** `messages` array len > 1 → 400 | The vault is request-scoped; multi-turn would need cross-turn identity resolution |
| Namespace | `src/sagp/`, one env prefix `SAGP_` | Four trees and five prefixes silently broke each other's lookups |

### Four bugs the critiques caught that would have shipped

1. **`tldextract` phones home.** Presidio's `EmailRecognizer.validate_result` calls module-level
   `tldextract.extract`, which fetches the Public Suffix List over **HTTPS on first use**. On a sealed
   box the first email ever analyzed raises inside Presidio → 503. Fix: `SealedEmailRecognizer` with
   `TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)`, cache warmed at provision.
2. **The egress monkeypatch is bypassable.** `_socket.socket().connect()` skips the patched
   `socket.socket.connect` entirely — it bypasses L1 by construction — the L2 audit hook catches it (verified at M11). Fix: dual layer —
   monkeypatch (L1) **plus** `sys.addaudithook` on PEP 578 socket events (L2), which fires at C level.
3. **Provisioning fetched the wrong files.** The artifact lock excluded `onnx/*` while the runtime was
   ONNX-only — the sealed system would have had no model to load.
4. **`quick` manifest verification skips file interiors.** Boot uses `full` mode always (~3 s).

---

## 3. The Qdrant-in-Docker decision — flagged

Qdrant is the store; Chroma does not exist in this design. There are two ways to run it, and they
have **different jobs**:

- **`SAGP_QDRANT_MODE=embedded` is the default runtime backend**, on RAM grounds. Embedded Qdrant
  projects to **6.75 GB** (1.25 GB projected headroom); Docker Desktop's Linux VM plus the container
  puts the system at **~7.60 GB of 8 GB** — it fits, with essentially no margin. Against an 8 GB
  ceiling that margin is the whole argument.
- **`PROFILE=demo` (Docker, `qdrant/qdrant:v1.18.3-unprivileged`) is the demonstration and proof
  path** — the network-isolation boundary this project exists to show, the path you asked for, and
  the one the proof harness targets. It is opt-in, not the default.

**One unknown, in two parts — now RESOLVED.** The Phase-0 spike (`make spike-docker`) was run
2026-08-01 on Docker Desktop 29.5.3 and settled OQ-4/OQ-5 **negatively**. OQ-4: `internal: true` and an
app-reachable Qdrant are **mutually exclusive** — with `internal: true` a published `127.0.0.1:6333` port
is accepted but the macOS host cannot reach it (http_code 000), and the sagp app runs on the host, so the
compose file uses a **non-internal** bridge. OQ-5: `com.docker.network.bridge.enable_ip_masquerade: "false"`
does **not** block egress on Docker Desktop — on a reachable network egress is fully open (TCP and DNS both
reach out) because containers egress via a userland VM proxy rather than a host MASQUERADE rule; even on an
internal network DNS still resolves via the embedded resolver.

**Conclusion:** on Docker Desktop you cannot get both an app-reachable Qdrant and an egress-blocked
container from compose network options alone. The Docker path is **NOT network-isolated by compose
options**; its egress control comes from the host `pf` anchor (`make seal-pf`) plus loopback binding, and
DNS resolution always leaks via the embedded resolver. ADR-0002 is now **Accepted** (was Proposed).
Evidence: `evidence/spike-docker.json` (gitignored). No document may call the Docker path "isolated" — the
honest word is "not isolated by compose options", which is a stronger, evidence-based statement than the
old "untested".

**Any RAM number in this document names the profile it assumes:** 6.75 GB = embedded, 7.60 GB =
demo/Docker. See §6.

---

## 4. Architecture

```
src/sagp/
├── config.py errors.py types.py            # Settings(env_prefix="SAGP_"); typed errors; TextArtifact/Chunk/ScanResult
├── app/
│   ├── main.py deps.py middleware.py       # lifespan: manifest full-verify → load engines → warm → self-test
│   └── routes/{chat,ingest,admin,health,airgap}.py
├── guardrails/
│   ├── pipeline.py base.py                 # ordered stages, per-stage timing, short-circuit, fail-closed
│   ├── normalize.py placeholders.py        # NFKC + homoglyph fold + Cf handling; placeholder neutralize/rehydrate
│   ├── heuristics.py deobfuscate.py        # weighted rules OR'd with the classifier; base64/hex/rot13 depth-2
│   ├── injection/{labels,onnx_backend,scanner,selftest}.py
│   ├── pii.py presidio_factory.py recognizers.py vault.py aliases.py
│   ├── registry.py
│   └── output.py                           # egress PII scan + citation range check + divergence block
├── rag/{loaders,chunking,embeddings,vectorstore,qdrant_store,retriever,prompt,ingest}.py
├── llm/{base,fake,ollama_client}.py
├── audit/{events,hashing,sink,verify,scrub,quarantine,redactors}.py
└── netguard/{egress,manifest,phase,evidence,probes}.py  # dual-layer socket guard; sha256 manifest; lifecycle
```

The five PII modules are **flat under `guardrails/`** — there is no `guardrails/pii/` subpackage; every
dotted reference in the corpus (`guardrails/pii.PIIGuardrail.analyze`, `sagp.guardrails.recognizers`)
assumes the flat form. Only the injection modules live in a subpackage. This tree is abridged;
BLUEPRINT §4 is the single authority on the file list.

Plus `config/{guardrails,entities}.yaml` (thresholds are data, hashed into every audit record),
`scripts/provision/01..10`, `bin/sagp-serve` (sources `.env.sealed` **before** exec'ing the
interpreter — HF offline flags are read at import time, so `.env` loading is too late), `Makefile`,
`docker-compose.yml`, `tests/`, `docs/`.

### Request path — `POST /v1/chat`

Guardrails run as **FastAPI dependencies, never `BaseHTTPMiddleware`** (Starlette's exception
middleware sits inside user middleware and would degrade typed 400s into opaque 500s).

This is a **condensed** view of the authoritative C0–C26 table in BLUEPRINT.md §5.7 and
ARCHITECTURE.md §4.1 — same steps, same order, fewer words. Where they differ, they win.

```
C0  bearer token → Principal; rate-limit           invalid → 401 · over → 429
C1  single-turn schema check                       messages[] len>1 → 400 UNSUPPORTED
C2  length cap (8000 chars)                        → 413
C3  normalize(): NFKC, homoglyph fold, Cf strip    tag chars U+E00xx / bidi override → 400
C4  heuristic rules → weighted score               DELIMITER_SPOOF → 400
C5  deobfuscate (base64/hex/rot13…, depth 2)       decode bomb → 400
C6  injection classifier over {raw, norm, decoded} truncated → 400 · error/timeout → 503
    windows max_length=512 stride=128 cap 16, score = max over windows
C7  policy: max(classifier, heuristic) ≥ 0.85      → 400 PROMPT_REJECTED
C8  neutralize_placeholders()                      user-supplied "<PERSON_1>" defanged
C9  Presidio analyze(threshold 0.50)               error/timeout/regex-timeout → 503, never partial
C10 BLOCK list: CREDIT_CARD, AADHAAR, SSN, IBAN…   → 400, byte-identical to C7
C11 PERSON alias resolution (longest-first)        ambiguous → fresh placeholder (over-mask, never cross-link)
C12 anonymize → masked_prompt + request vault      vault cap 2000 → 400
--- retrieval ---
C13 embed the NEUTRAL query (normalized + placeholder-neutralized, unmasked — not the masked one)  masked queries destroy recall
C14 Qdrant query_points, MIN 0.35, must_not quarantined   store error/timeout → 503
C15 refusal gate: no hit ≥ STRONG 0.50             → refusal.txt, NO LLM call, 200 refuse_insufficient_context
C16 per chunk: normalize() → neutralize_placeholders()    placeholder found → drop chunk + tamper alarm
C17 mask PII in retrieved chunks into the SAME vault (EGRESS profile, no BLOCK list)
C18 budget-select chunks by score under MAX_CTX_CHARS=7000 (trim BEFORE the scan), then assemble:
    masked chunks wrapped in per-request nonce delimiters marked UNTRUSTED
C19 single re-scan of the ASSEMBLED MASKED context, threshold 0.90  hit → drop top chunk, re-apply
    budget, reassemble, rescan (max 2 iterations); all chunks dropped → C15 refusal
C20 assert the re-scanned context is byte-identical to what C21 sends (test_final_bytes_were_scanned)
--- generation ---
C21 Ollama generate (buffered, not streamed)       timeout 120 s → 503
--- egress ---
C22a output structural: strip md images/links, nonce/system-prompt n-gram present → block
C22b egress PII scan → anonymize into the same vault
C22c divergence: re-analyze normalize(response); more entities than C22b → block
C22d citation range check on [S{n}, p.{n}]         out of range → strip (warn) or refuse (strict)
C23 rehydrate placeholders IFF principal holds pii:reveal
C24 re-run C22a on the FINAL returned string; hash pre-rehydrate and returned bytes
C25 audit record (hash-chained), fsync             write or scrub failure → 503, response NOT returned
C26 finally: vault.clear()                         unconditional
```

**Three orderings are load-bearing, and none of them are accidental.**

1. **Injection detection runs on *normalized* text before masking** (C3–C7 before C9–C12). Reversed,
   an attacker embeds the payload inside something Presidio masks, and the classifier then scans
   `<PERSON_1>` instead of the attack.
2. **Chunks are masked (C17) before the context is assembled (C18)**, so the re-scan at C19 runs over
   the **assembled masked** context — one scan across 4–5 windows, not one scan per chunk.
3. **The refusal gate (C15) fires before any chunk work**, so a query with no hit ≥ 0.50 never
   reaches the LLM at all, and the refusal is deterministic and auditor-testable.

Any document showing C0–C21, or re-scanning before masking, or omitting C15 / C26, is stale.

**The highest-value control — indirect injection.** Attacker-planted instructions inside an ingested
PDF are the real RAG threat, and most demos scan only the user prompt. Here every chunk is scanned at
**ingest** (`clean` / `suspect` / `quarantined`), quarantined chunks go to a separate never-retrieved
**per-collection sibling `<collection>__quarantine`** (per-collection so re-ingesting one doc can't
disturb another collection's quarantine; the retriever refuses to open a quarantine-suffixed
collection, so those chunks are unreachable by construction), and the **assembled context is
re-scanned** at retrieval. Plus hidden-text detection in
the PDF loader — sub-1.0pt fonts, off-mediabox text, `/RenderMode 3` invisible text — via pypdf's
`visitor_text` hook.

---

## 5. Lifecycle

```bash
# Phase 0 — BOOTSTRAP (online)
make doctor        # hard-fails under 25 GB free
make venvs lock install
make spike-docker  # RUN 2026-08-01: resolved OQ-4/OQ-5 → ADR-0002 (Accepted)

# Phase 1 — PROVISION (online, one-way door)
make provision     # 01 wheelhouse · 02 hf_models · 03 spacy · 04 ollama · 05 docker
                   # 06 quantize · 07 GATES · 08 tldextract warm · 09 secrets · 10 manifest
make verify-online # NEGATIVE CONTROL — must be green before sealing
make eval          # metrics baseline → docs/metrics/latest.json

# Phase 2 — SEAL
make seal          # .env.sealed + state.json + .pth guard bootstrap + disconnect checklist
make seal-pf       # OPTIONAL, sudo, pf anchor — dry-run parse first
networksetup -setairportpower en0 off

# Phase 3 — OPERATE
make ollama-up up serve
make ingest FILE=data/samples/employee_handbook.pdf COLLECTION=handbook
make query Q="How many days of parental leave do I get?"

# Phase 4 — VERIFY
make proof         # verify + signed evidence report
```

`make provision` exits non-zero if any **gate** fails, so you can never reach `make seal` with an
unvalidated classifier. The four gates: tokenizer parity · FP32↔INT8 parity (`|Δ P(INJECTION)| < 0.05`,
**zero label flips** across the corpus — **at M1 the INT8 candidate FAILED this and was rejected in
favour of FP32 ONNX**, OQ-2) · embedding parity vs `sentence-transformers` (atol 1e-4, 200 fixtures —
**MEASURED at M1: 1.6e-07**) · **measured RSS** of every ORT session (**FP32 classifier 0.30 GB at
M1**, OQ-1).

### The air-gap demonstration

The thing that makes this a blueprint rather than a claim is the **negative control**. Asserting
"the connection failed" proves nothing — it fails identically when the network is merely absent. So:
while the host **demonstrably has internet**, run the probes with the guard in `audit` mode and record
the successes; flip to `enforce`; re-run the identical probes and require `EgressViolation` each time.

The evidence line reads (MEASURED at M13 via `make verify-online`, run live):

> *"this host completed a TCP handshake to 1.1.1.1:443 in **6.58 ms** with the guard auditing;
> with the guard enforcing, the identical probe raised `EgressViolation`."*

(The 6.58 ms audit-mode handshake is measured; the enforce path is characterised by the exception it
raises, not by a latency figure.)

Nine offline assertions, each network assertion asserting on the **`EgressViolation` type** (never a
generic connection failure) and each **paired with a positive control** so a test cannot pass for the
wrong reason: guard-install receipt (if absent, everything below is INVALID) · L1 patch · L2 audit
hook (where L1 is bypassed by construction) · DNS · httpx · subprocess (PEP 578) · AF_UNIX deny incl.
`docker.sock` · Presidio-email-with-zero-violations · full manifest verify.

The proof verdict has **four** values: `PASS`; `PASS_WITH_OPEN_HIGH_SEVERITY_GAPS` (an OPEN
`severity: high` gap); `INVALID` (an invalidating condition fired — proves nothing); and `FAIL` (no
invalidator fired but a core assertion **provably leaked**). Any negative control failing, guard not
installed, `quick`-mode manifest, or an open high-severity gap yields `INVALID` or
`PASS_WITH_OPEN_HIGH_SEVERITY_GAPS` — never `PASS`. `make verify` runs today (M13); on this unsealed
dev host all nine offline assertions PASS, but the overall verdict is `INVALID` by design (phase ≠
OPERATE and non-loopback dev listeners present).

---

## 6. Budgets

**RAM — default runtime profile: `SAGP_QDRANT_MODE=embedded`** (3B, `num_ctx=4096`, q8_0 KV,
embedded Qdrant, ONNX). Every figure below is the **embedded** profile; the demo/Docker profile is a
different number and is quoted separately.

| | GB |
|---|---|
| macOS baseline (measured) | 3.00 |
| Ollama: weights 2.0 + KV 0.24 + graph 0.35 | 2.59 **(ESTIMATE — OQ-8)** |
| App process total (ORT ×2, spaCy md, Presidio, FastAPI) | 1.16 **(ESTIMATE — sum of estimates; the classifier row is now the MEASURED 0.30 GB FP32 RSS — OQ-1 resolved; the rest remain estimates)** |
| **Total (embedded profile)** | **6.75 (PROJECTED)** → 1.25 GB **projected** headroom |

Projected verdicts, unmeasured, all against the 8 GB ceiling: `PROFILE=demo` (Docker Qdrant)
≈ **7.60** — fits, no margin · `en_core_web_lg` ≈ 7.35 · **`llama3:8b` ≈ 9.28 — does not fit**. (The
old "FP32 fallback ≈ 7.25" verdict is superseded: FP32 ONNX **is** the shipped runtime classifier and
its RSS is **0.30 GB measured** — OQ-1 — not a heavier 0.80 GB fallback, and it does not force
`llama3.2:1b`.) **Two** inputs are now measured — the macOS baseline and the FP32 classifier RSS — the
rest of the table is still estimated. `07_gates.py` and OQ-8 replace the remainder with measurements.

The app refuses to boot above 90% projected RSS, and `/readyz` reports measured per-component RSS.

**Disk:** ~9.7 GB lean *as projected* (that figure includes a `llama3:8b` pull, which was **skipped on
this host** — subtract ~4.7 GB for the as-provisioned footprint), **~19.6 GB full** (both venvs + both
wheelhouses), per BLUEPRINT §8. Plus ~3 GB *transient* for `quantize_dynamic`. **Free ≥ 25 GB** before
Phase 1; `make doctor` enforces it.

---

## 7. Build order

**Status (2026-08-01): M-DOCS and M0–M14 are complete, merged and tested; M15 (this docs pass) is in progress.** The order below is the plan as written at M-DOCS.

**M-DOCS first** (see §8) → M0 skeleton → **M1 provision everything (online, longest single item)** → M2 audit spine →
M3 normalizer → M4 PII → M5 injection → M6 metrics gate → M7 LLM client → M8 ingestion →
M9 retrieval → **M10 FastAPI gateway ← first demoable slice** → M11 net-guard + manifest →
M12 indirect injection → **M13 THE DEMONSTRATION (offline)** → M14 hardening → M15 docs.

M2 lands **before any guardrail exists** — a guardrail with nowhere to record its decision is
untestable.

**Minimum viable slice = M-DOCS → M0 → M10** (M1 first, while online). At M10 you can turn off Wi-Fi, ingest
the handbook, ask a question containing an email, show `<EMAIL_ADDRESS_1>` in the prompt that reached
Ollama alongside a cited grounded answer, then send `ignore all previous instructions` and get a 400
with an incident ID. **That is your brief's literal claim, demonstrable, offline.**

**Honest scoping:** the full M0–M15 blueprint was estimated at **3–6 focused weeks**, not one session,
because pushing past M13 in one pass yields several half-built subsystems instead of one working demo.
In the event the build reached **M14** (M0–M14 complete, merged and tested); M15 is this docs pass.

---

## 8. M-DOCS — every markdown file, written into the repo first

This is the **first milestone**, done before any Python. All paths are relative to
`/Users/tanishpd/Desktop/Secure Air-Gapped Platform with Integrated Guardrails/`.

### Agent context (your "my context")

| File | Contents |
|---|---|
| `CLAUDE.md` | **13 hard invariants** an agent must never violate — CLAUDE.md §2 is the sole authority for their numbering, and this table deliberately does not re-enumerate them (re-enumeration is how the two lists drifted apart). Plus the phase-transition rules and the exact commands |

### Human context (your "your context")

| File | Contents |
|---|---|
| `README.md` | Quickstart: provision → seal → prove in three commands. Links `LIMITATIONS.md` in paragraph 1 |
| `docs/PLAN.md` | **This plan**, verbatim — so the reasoning lives with the code |
| `docs/BLUEPRINT.md` | **The full 93 KB reconciled spec** — exact API signatures, byte-level file sizes, pinned commit SHAs, the reconciliation ledger, verbatim critique findings. The implementation reference |
| `docs/ARCHITECTURE.md` | Components, numbered request path C0–C26, ingest path I1–I11, data model, concurrency/RAM model, fail-closed matrix |
| `docs/THREAT_MODEL.md` | Assets, trust boundaries, actors (**malicious document author is the primary threat**), **OWASP LLM Top 10 2025** mapping with honest partial/strong/weak ratings, four end-to-end attack narratives, residual-risk register |
| `docs/GUARDRAILS.md` | Every stage: what it catches, thresholds and their derivation, the **metric contract** — floors and definitions, with measurements landed at M6 (`docs/metrics/latest.json`) and revisited at M13/M15 — and **known bypasses** |
| `docs/AIRGAP_RUNBOOK.md` | Phase-by-phase checklists with expected output per step, incident procedures, decommissioning |
| `docs/COMPLIANCE.md` | GDPR / HIPAA / NIST SP 800-53 mapping. Boxed non-legal-advice disclaimer. All 18 HIPAA Safe Harbor categories ✅/⚠️/❌ **and a bolded statement that this system does not achieve Safe Harbor** |
| `docs/EVALUATION.md` | Corpus construction, metric definitions (FPR ≠ 1−precision), how floors were chosen |
| `docs/OPERATIONS.md` | Day 2: key custody, rotation, retention, backup/restore, ledger-head export |
| `docs/LIMITATIONS.md` | §11 of this plan, expanded |
| `docs/adr/0001…0009*.md` | Nine decision records — one per contested choice in §2 |
| `NOTICE`, `THIRD_PARTY_LICENSES.md` | Attribution; every pinned package/model with SPDX id. Records that **no model weights are redistributed** |

Also in this pass (both done): **`git init`**, and a `.gitignore` excluding `models/**`, `audit/**`,
`data/private/**`, `.venv*`, `.env`, `vendor/` — so weights and PII can never be committed. The
`.gitignore` is itself a control; see [CLAUDE.md](../CLAUDE.md) invariant 4.

### Two rules for these docs

1. **Estimates are labelled as estimates.** Every unmeasured number carries an explicit marker until a
   measurement replaces it. A compliance doc quoting invented latencies is worse than none. (Latencies
   and RAM totals remain estimates today; the M6 metrics and the M1 RSS/parity figures are measured.)
2. **Docs are revisited at M15**, once the metrics (M6), evidence report (M13) and measured figures
   become real. The M-DOCS pass writes them correct-as-of-design; **the M15 pass — this one — makes
   them correct-as-measured.**

---

## 9. Verification

```
make smoke        # 14 numbered checks, ending: SMOKE PASS — request ids · manifest · ledger head
make verify       # the 9 air-gap assertions + paired negative controls
make eval         # injection recall ≥0.90 · precision ≥0.85 · benign FPR ≤0.10
                  #   PII recall: EMAIL ≥0.98 · CREDIT_CARD ≥0.98 · AADHAAR ≥0.95 · PERSON ≥0.80
                  #   any metric >2pp below baseline fails the build
make audit-verify # hash-chain walk; mutate one byte → detected at the right index
```

Jailbreak (the classifier's documented blind spot) and indirect/document-planted attacks are reported
**as separate categories, never averaged into the headline number**.

The single most important test asserts on the bytes that actually crossed the boundary, not on an
intermediate value:

```python
def test_final_bytes_were_scanned(spy_scanner, spy_ollama, client):
    r = client.post("/v1/chat", json={"message": "...", "collection": "handbook"})
    assert spy_ollama.last_prompt in spy_scanner.scanned_strings
    assert r.json()["answer"]     in spy_scanner.scanned_strings
```

---

## 10. Open questions — resolved by measurement during the build, not guessed

| | Question | Resolution |
|---|---|---|
| OQ-1 | Injection classifier RSS — **RESOLVED at M1**: measured **0.30 GB** for the **FP32** ONNX session (INT8 rejected — OQ-2); ORT mmaps the weights, so RSS ≪ file size and the RAM budget is unchanged | `07_gates.py` measured it; the gate fails provisioning above 0.35 GB (FP32 passed at 0.30) |
| OQ-2 | INT8 parity on DeBERTa-v3's disentangled attention — **RESOLVED at M1: it FAILS** (INT8 dynamic quant *inverts* the classifier — `max \|ΔP\| ≈ 0.98`, label flips) | Hard parity gate correctly refused INT8; the fallback ladder selected **FP32 ONNX**, which is the runtime model |
| OQ-4/5 | Docker `internal: true` + published port; does `enable_ip_masquerade:false` block egress on Docker Desktop? — **RESOLVED at spike (2026-08-01), both NEGATIVE**: `internal:true` blocks host reachability (→ non-internal bridge); `enable_ip_masquerade:false` does not stop egress (userland VM proxy), DNS leaks via the embedded resolver | Phase-0 spike RAN → ADR-0002 **Accepted** (§3); Docker path NOT isolated by compose options, egress relies on `pf` + loopback |
| OQ-6 | Does Presidio's regex timeout propagate out of `analyze()` or get swallowed into a **partial result set**? | Read `PatternRecognizer.__analyze_patterns` before M4 — if swallowed, that is a silent fail-open in the masking layer |
| OQ-8 | Ollama compute-graph overhead (0.35 GB estimated) | `ollama ps` — a 10-minute measurement that validates the whole RAM table |
| OQ-9 | `en_core_web_md` PERSON recall on **Indian names** — spaCy publishes only aggregate `ENTS_F`, and OntoNotes is Western-news weighted | Build a 100–200 example labelled eval set before locking the model |

**All latency figures in the source blueprint are estimates.** No benchmark has run on this M2. The
structural conclusions hold; the absolute numbers get replaced with measurements at M13.

---

## 11. What this will not prove

Stated up front because a compliance-themed template that overclaims is worse than none:

1. **It does not prove the machine cannot reach the internet.** At most it shows that a specific set of
   software controls refused every egress attempt we could construct, on a host separately shown to
   have working internet moments earlier. `make verify` and `make verify-online` now exist and run
   (M13) — `verify-online` was exercised live (a real 6.58 ms TCP handshake unguarded; `EgressViolation`
   when enforcing) and the nine offline assertions PASS — **but a green air-gap `PASS` has never been
   produced**: this host is deliberately kept unsealed (verdict `INVALID` by design), and a real PASS
   would require a genuine seal plus a physical disconnect. The Wi-Fi radio, Thunderbolt, Bluetooth
   and USB-NIC support all still exist. This is a rigorous, self-auditing **simulation** of an air gap —
   and it is honest about which of those two words applies.
2. **Native code bypasses the Python guard.** `grpcio`'s C core (a hard `qdrant-client` dependency,
   present even in REST mode), ONNX Runtime, and anything reached via `ctypes` can call `connect(2)`
   without entering CPython's socket layer. Only `make seal-pf` closes that category, and only for
   UID-owned traffic.
3. **Ollama and Docker are outside both guard layers** — separate processes. pf covers Ollama; pf does
   *not* cover Docker, whose traffic leaves via a root-owned VM interface.
4. **A hostile operator defeats it trivially** (`python -S`, edit `.env.sealed`, delete state). The
   threat model assumes a cooperative operator and a possibly-hostile *dependency* or *document*.
5. **The signature is self-signed** and timestamps are local-clock. Tamper-**evident**, not
   tamper-proof, and not non-repudiation — the ledger head must be exported off-box to mean anything.
6. **Injection detection is probabilistic**, the model is archived and unmaintained, and its own card
   states it **does not detect jailbreaks** and does not handle non-English prompts.
7. **Presidio recall is not 100%.** Non-Western names, Indic scripts, OCR noise and novel identifier
   formats will be missed. Masking is risk reduction, not a guarantee.
8. **`ingest_mode=raw` stores real PII in the vector store**, protected by loopback binding and
   FileVault — not by the guardrail. Copying `data/qdrant/` off the box leaks the corpus.
9. **The vault is memory-only but not scrubbed** — Python strings are immutable, so a core dump
   recovers the mapping. `ulimit -c 0`.
10. **No substitute for** a data diode, cross-domain guard, hardware attestation, TPM-measured boot,
    an HSM, or a SCIF.
