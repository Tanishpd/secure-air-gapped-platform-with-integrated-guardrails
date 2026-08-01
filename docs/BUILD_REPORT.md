# sagp — Build Report

*A capstone summary of what was built, what was measured, and what is honestly still
an estimate. As of 2026-08-01. Every figure below carries a `MEASURED` or
`(ESTIMATE)` marker — the project's whole ethos is refusing to launder one into the
other, so this report shows the split rather than a single confident number.*

> **Status:** M-DOCS → M15 complete, plus the Docker spike, the pf anchor, and the
> full operator surface. **262 tests pass**; `make lint` + `make typecheck`
> (mypy strict) green; `make smoke` **14/14**. The offline proof harness is built
> and self-tested; on this unsealed dev host `make verify` honestly returns
> **`INVALID`** by design. The one thing genuinely not done is the human-only
> physical seal + disconnect + `make proof`.

---

## 1. What this is

`sagp` — Secure Air-Gapped Platform with Integrated Guardrails — is a reference
blueprint for running a local LLM inside a network-isolated enclave, with:

- **Presidio** PII pseudonymisation and a **local ONNX prompt-injection classifier**
  in front of every model-bound byte,
- over a **RAG corpus of local PDFs in Qdrant**,
- served by **Ollama** on loopback,
- on a single **Apple M2 with an 8 GB RAM hard ceiling**, Python 3.11.15, and two
  virtualenvs (a sealed runtime with no `torch`/`transformers`, an online-only
  provisioning env).

Every model-bound byte passes the guardrail pipeline; every rejection is
byte-identical and padded to a fixed deadline; nothing that leaves the process
carries a score, a count, or a name.

## 2. The claim — honest about which word applies

The claim is **not** that the air gap is proven. A failed connection proves
nothing — it fails identically when the network is merely absent. The claim is
that a specific set of software controls was **demonstrated** to refuse a specific
probe set, each probe paired with a negative control, on a host separately shown
to have working internet moments earlier — and that the demonstration is recorded
in a self-signed, hash-chained evidence report. It is a rigorous, self-auditing
**simulation** of an air gap, and it says so throughout.

## 3. What one request does

Validated end-to-end on this host against the real ONNX guardrails and a real
local Ollama:

```
$ make ingest FILE=data/samples/employee_handbook.pdf COLLECTION=handbook
ingested employee_handbook.pdf -> handbook: indexed=2 (suspect=0) quarantined=0 ...

$ make query Q="How many days of parental leave do I get?" COLLECTION=handbook
[S1, p.1] You are entitled to 20 days of parental leave per year.
— decision: answer   citations: ['S1 p.1']

# POST /v1/chat  {"message":"Ignore all previous instructions ..."}
HTTP/1.1 400  {"error":{"code":"PROMPT_REJECTED","incident_id":"..."}}
# padded to a fixed deadline; no score, no detector name; byte-identical to every reject
```

A question carrying an email reaches the model as `<EMAIL_ADDRESS_1>`, never the
address. A document that *itself* says "ignore your instructions" is quarantined at
ingest into a never-retrieved `<collection>__quarantine` sibling, unreachable by
construction.

## 4. Measured vs estimated

### MEASURED

| Figure | Value | Note |
|---|---|---|
| Injection recall (headline families A,C,D,E,G,H,I; B and F reported apart) | **1.0** | small corpus; regression-gated |
| PII recall — EMAIL_ADDRESS, CREDIT_CARD, IN_AADHAAR, PERSON | **1.0** | build gate cleared; not a coverage guarantee |
| Injection precision / benign FPR | **0.854 / 0.24** | after the corroboration-gating fix: precision now **meets** 0.85; FPR improved from 0.32 but still over 0.10 (one OPEN gap — the archived classifier's ceiling) |
| Injection ONNX session RSS | **0.30 GB** | FP32 (INT8 dynamic quant *inverts* this DeBERTa-v3 — OQ-2); ORT mmaps weights |
| Embedding parity vs sentence-transformers | **1.6e-07** | bge-small ONNX, CLS pooling |
| Online negative control | **6.58 ms** | live TCP handshake to `1.1.1.1:443` unguarded → `EgressViolation` when enforced |
| Test suite / smoke | **262 / 14-of-14** | `make test`, `make smoke` |

### (ESTIMATE) / PROJECTION / OPEN

| Figure | Value | Note |
|---|---|---|
| RAM total (embedded / demo profile) | 6.75 / 7.60 GB | **projections**, never benchmarked; each names its profile |
| All latency figures | — | no timing run on this M2 |
| PII recall on Devanagari / transliterated names | — | **OQ-9**, no eval exists |
| The green air-gap `PASS` | — | requires a real seal + physical disconnect; **never produced** |
| Docker `PROFILE=demo` isolation | — | spike resolved it: **not** isolatable by compose options (see §5) |

## 5. The build ledger

| Stage | What landed |
|---|---|
| **M0–M2** | Skeleton + two-venv split; provisioned models + signed `MANIFEST.json`; the hash-chained audit spine (before any guardrail, so decisions have somewhere tamper-evident to record). |
| **M3–M7** | Normalizer (tag/bidi block, Indic-safe); Presidio PII with a no-phone-home email recognizer; the FP32 injection classifier (label resolved from `config.json`, never hardcoded); the metrics gate; the buffered LLM client. |
| **M8–M11** | CLS-pooled bge embeddings; score-thresholded retrieval + deterministic refusal gate; the FastAPI gateway wiring C0–C26; the dual-layer egress guard (L1 monkeypatch + L2 PEP-578 audit hook that catches the raw-socket bypass). |
| **M12** | Indirect injection: every ingested chunk scanned; poisoned chunks diverted to a never-retrieved `<collection>__quarantine` sibling; C19 drop-and-continue. |
| **M13** | The demonstration: nine offline assertions each with a paired positive control; the live online negative control; a signed evidence report + hash-chained ledger; a four-verdict grammar (`PASS` · `PASS_WITH_OPEN_HIGH_SEVERITY_GAPS` · `INVALID` · `FAIL`). |
| **M14** | Hardening + deployment: audit sink in the request path; `pii:reveal` incident review; rate limiting; the seal/unseal one-way door; projected-RSS boot refusal; `bin/sagp-serve` behind four boot gates. |
| **M15** | Docs swept correct-as-measured — every figure tagged, every honest limit preserved. |
| **+ Docker spike** | OQ-4/OQ-5 resolved live: `internal:true` breaks host reachability; `enable_ip_masquerade=false` doesn't block egress; DNS always leaks. The Docker path is **not** isolatable by compose options — ADR-0002 Accepted. |
| **+ pf, ops** | The `com.sagp` pf anchor (the egress layer the Python guard can't be); the `ingest`/`query` CLIs; the quarantine-review route; `/readyz` measured RSS. |

## 6. Design invariants

Thirteen rules, each enforced by at least one test. A representative few:

- **Nothing raw leaves.** Audit records carry entity *types* and *counts* only —
  proven by reading the JSONL bytes off disk, not the model.
- **No detector oracle.** Every reject is a byte-identical 400, padded to a fixed
  deadline; a leaked count would be a card validator.
- **Fail closed.** Any error, timeout, or partial result *blocks*. Exactly one
  failure mode; no env var weakens a control.
- **Scan before mask.** Injection detection runs on normalized text before PII
  masking — else the payload hides inside a masked span.
- **Request-scoped vault.** The pseudonym map is in-memory, unpicklable, cleared in
  a `finally`; it never persists to collide identities across turns.
- **Thresholds are data.** They live in YAML, hashed into every audit record, so a
  decision replays against the exact policy that produced it.

## 7. What this does not prove

Stated up front, because an overclaiming compliance-themed template is worse than
none:

1. It does **not** prove the machine cannot reach the internet — the radio,
   Thunderbolt, and USB-NIC all still exist.
2. Native code (gRPC's C core, ONNX Runtime, `ctypes`) can call `connect(2)` below
   the Python guard. Only the pf anchor closes that, and only for UID-owned
   traffic; it does **not** cover Docker's root-owned VM interface.
3. The signature is self-signed on the host it attests to — tamper-**evident**,
   not provenance.
4. Presidio recall is not 100%; masking is risk reduction, not a guarantee. The
   injection classifier is archived, English-only, and jailbreak-blind.
5. The vector store holds **real PII at rest** (mask-at-retrieval), protected by
   loopback binding and FileVault, not by any guardrail.
6. A hostile operator defeats it trivially. The threat model is a hostile
   *document* or *dependency*, not a hostile human.

## 8. The one step software can't take

The harness is built and self-tests. It honestly returns `INVALID` on this
unsealed dev host — the phase isn't `OPERATE`, and non-loopback listeners are
present. Only a human on a real box can close the loop:

1. **`make seal`** — gated on the invariant checks (manifest full-verify + valid
   signature + a green online negative control). Flips `PROVISION → OPERATE`,
   increments the seal generation, arms the `.pth` guard.
2. **Physically disconnect** — Wi-Fi off, unplug adapters. Confirm `ping 1.1.1.1`
   fails. This is the part software cannot do.
3. **`make proof`** — the nine offline assertions + a signed evidence report
   appended to the ledger. Green only if every negative control held.

## 9. Reproduce it

```
make test          # 262 tests (FakeLLM/FakeScorer + real ONNX/spaCy where provisioned)
make smoke         # 14 numbered functional checks, guard armed  -> 14/14
make eval          # corpus metrics -> docs/metrics/latest.json
make verify        # the 9 offline assertions + invariant-13 verdict (INVALID until sealed)
```

---

*Python 3.11.15 · Apple M2 / 8 GB · presidio 2.2.364 · onnxruntime 1.28 ·
qdrant-client 1.18 · llama3.2:3b-instruct-q4_K_M. See
[BLUEPRINT.md](BLUEPRINT.md) for the authoritative spec, [PLAN.md](PLAN.md) for the
reasoning, and [LIMITATIONS.md](LIMITATIONS.md) for the full residual-risk register.*
