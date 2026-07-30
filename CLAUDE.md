# CLAUDE.md — agent operating context for `sagp`

This is the file a coding agent loads before touching this repo. It is a set of rules and pointers, not a tutorial; the authoritative technical spec is [docs/BLUEPRINT.md](docs/BLUEPRINT.md) and the condensed decision table is [docs/PLAN.md](docs/PLAN.md). Where this file and BLUEPRINT.md disagree, BLUEPRINT.md wins — and fix this file in the same change.

---

## 1. What this project is

`sagp` — Secure Air-Gapped Platform with Integrated Guardrails — is a reference blueprint for running a local LLM inside a network-isolated enclave, with Presidio PII pseudonymisation and a local ONNX prompt-injection classifier in front of every model-bound byte, over a RAG corpus of local PDFs in Qdrant. It targets a single Apple M2 with **8 GB unified RAM as a hard ceiling**, Python 3.11.15, two virtualenvs (`.venv` sealed runtime, `.venv-provision` online only), and Ollama serving `llama3.2:3b-instruct-q4_K_M` on loopback. The deliverable is a *template others can copy*. Its central claim is not that the air gap is proven — it is that specific software controls were demonstrated to refuse a specific probe set, each probe paired with a negative control, and that the demonstration is recorded in a signed (self-signed) evidence report.

**Sealed threat posture, one line:** the operator is assumed cooperative, the host is assumed intact, and the adversary is a hostile *document* or a hostile *dependency* — so every control fails closed, every rejection is byte-identical, and nothing that leaves the process carries a score, a count, or a name.

**Read this file as a specification, not a report.** Nothing described below has been built or run: there is no `src/`, `tests/`, `scripts/`, `config/` or Makefile (§10). Every *Check:* line in §2, every target in §4, every test in §8 and every metric floor states what must exist — read them as "will", never as "did". No figure anywhere in this repo has been measured.

---

## 2. The 13 hard invariants

**This numbering is canonical.** Every "invariant N" citation anywhere in the corpus resolves to the list below; BLUEPRINT.md §11 gives a subset in a different order and is superseded on that point.

Read these before any edit. Each is to be enforced by at least one test; none of those tests exists yet (§10), so every *Check:* line names what must be written. A change that makes a check pass by weakening the check is a violation of the invariant, not a fix.

**1. Never log, print, or serialise raw PII. Audit records carry entity TYPES and COUNTS only.**
`AuditEvent` is a closed schema (`extra="forbid"`, `frozen=True`) in `src/sagp/audit/events.py`. Offending text goes to `audit/quarantine.py` and is referenced from the audit record by `incident_id` alone. PII tokens are `HMAC(key, f"entity:{type}\x1f{normalize(type,value)}")` — never an HMAC of the placeholder, which is a per-request ordinal and carries zero information.
*Check:* `tests/unit/test_audit_no_pii.py` will be hypothesis-driven and must read the JSONL **bytes** off disk, not the model; `audit/scrub.py::assert_no_raw_values()` at write time; smoke check 14 is specified to grep the audit bytes for PII markers.

**2. Never add a network call. The runtime is sealed; any new host is an `EgressViolation`.**
Only `127.0.0.1:11434` (Ollama) and `127.0.0.1:6333/6334` (Qdrant, `PROFILE=demo`) are permitted destinations. The egress guard is dual-layer: an L1 monkeypatch plus an L2 `sys.addaudithook` on PEP 578 events, because a raw `_socket.socket().connect()` never touches the patched `socket.socket` and so bypasses L1 by construction (unverified on this host). Neither layer sees native code (grpcio's C core, ONNX Runtime, `ctypes`) or the sibling Ollama and Docker processes.
*Check:* `tests/security/test_no_network_imports.py` (AST scan for new imports/hosts), `test_no_egress.py`, `test_af_unix_denied.py`, `test_subprocess_denied.py`; `make verify` assertions 2–7.

**3. Never bypass the guardrail pipeline. All model-bound text goes through `src/sagp/guardrails/pipeline.py`.**
Any path that can reach `OllamaClient` runs `pipeline.run_input()` before and `run_output()` after. No `skip_guardrails` kwarg, no debug mode, no direct LLM call from a route or a script. `guardrails/registry.py::build_pipeline()` is the single wiring point for both chat and ingest.
*Check:* `tests/security/test_guardrail_bypass.py` (AST reachability + runtime spy); `tests/e2e/test_final_bytes_were_scanned` (§8).

**4. Never commit model weights, audit logs, `.env`, or anything under `models/` or `data/private/`.**
Weights are not redistributable and audit logs contain quarantined text. `.gitignore` excludes `models/**` (except `MANIFEST.json` and `models/README.md`), `audit/**`, `data/private/**`, `evidence/**`, `.venv*`, `.env`, `vendor/`.
*Check:* refuse any `git add` that stages a file > 10 MB; `make verify` assertion 9 also fails on unmanifested files under `models/`.

**5. Never hardcode the injection label index. Resolve from `config.json` `id2label` at boot.**
The checkpoint ships `{"0": "SAFE", "1": "INJECTION"}` — but a hardcoded index 1 silently *inverts* the guardrail: it blocks benign traffic and admits attacks, and every downstream test would still pass. Alias matching in `guardrails/injection/labels.py` must be **casefolded**, or a correct model refuses to boot.
*Check:* `tests/unit/test_labels.py`; the boot self-test in `guardrails/injection/selftest.py` is specified to run a known attack and a known benign string through the real policy path and to refuse to start on either failure.

**6. Never let an `except` silently disable a guardrail. Every failure path is fail-CLOSED.**
An error, a timeout, or a partial result from any guardrail **blocks**: 400 for a rejection, 503 for unavailability, 413 for oversize. There is exactly one fail mode and it is closed. Do not add `*_FAIL_MODE=open`, `*_DISABLED`, or any env var that weakens a control; dev bypasses live in a separate app factory that `sagp.app.main` cannot import.
*Check:* `tests/integration/test_blocked_flow.py`; the fail-closed matrix in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §10 must have a row per component. Note **OQ-6** (RESOLVED-CONFIRMED against `presidio-analyzer==2.2.364` source): `PatternRecognizer.__analyze_patterns` **catches `TimeoutError` per pattern, logs "skipping", and returns a partial result set** — a crafted catastrophic-backtracking input silently disables individual recognizers while `analyze()` returns normally. This is a silent fail-open in the masking layer; M4 must treat a per-pattern regex timeout as a guardrail failure (→ 503), not swallow it.

**7. Never mask before scanning. Injection detection runs on normalized text BEFORE PII masking.**
Reverse the order and an attacker plants the payload inside a span Presidio masks; the classifier then scans `<PERSON_1>` instead of the attack. The canonical order is C3 normalize → C4–C7 injection → C8 neutralize placeholders → C9–C12 PII, per BLUEPRINT §5.7.
*Check:* `tests/unit/test_pipeline_order.py` is specified to assert stage identity and order against `config/guardrails.yaml` (schema: GUARDRAILS §8.1, canonical); that file's sha256 goes into every audit record.

**8. Never return guardrail scores, entity counts, or detector identity to the client.**
Every 400 returns exactly `{"error":{"code":"PROMPT_REJECTED","message":"Your request was rejected by the security policy.","incident_id":"<uuid4>"}}`, padded by `constant_time_floor(120ms)`. A 400-vs-403 split, a returned score, or an `X-PII-Masked-Count` header is a detector oracle — and because `CreditCardRecognizer` is Luhn-binary, a leaked count is a card validator. Detail lives in the audit record and `GET /v1/admin/incident/{id}`, gated on the `pii:reveal` scope — there are exactly three scopes (`chat`, `ingest`, `pii:reveal`) across two tokens, and there is no `admin` scope.
*Check:* `tests/security/test_oracle_uniformity.py` — every detector path must produce byte-identical bodies and indistinguishable timings.

**9. Never persist the pseudonym vault. It is request-scoped and in-memory.**
A persistent vault collides on `<PERSON_1>` across identities and turns the placeholder scheme into a cross-request identity link. `chat.py` ends in `finally: vault.clear()`. Rehydration happens only if `"pii:reveal" in principal.scopes and SAGP_REHYDRATE_OUTPUT==1`, single-pass, with unknown placeholders left verbatim — never a global fallback map.
*Check:* `tests/unit/test_vault.py` must require that pickling raises, that `f"{vault}"` and `repr(vault)` leak nothing, and that the size cap `SAGP_MAX_VAULT_ENTRIES=2000` returns 400 rather than growing.

**10. Never install `torch` or `transformers` into the runtime venv.**
They cost ~0.45 GB RSS the 8 GB budget does not have, and the `transformers`/`huggingface-hub` pin conflict is what the two-venv split exists to dissolve. If you think you need one at runtime, you need `tokenizers==0.23.1` or `onnxruntime==1.28.0` instead — say so rather than adding it. `torch` and `transformers` live in `.venv-provision` only. **`huggingface_hub` is the exception, corrected empirically at M0:** `tokenizers==0.23.1` hard-depends on it, so it *is* present in `.venv` and cannot be removed while keeping the runtime tokenizer. It is **neutralised, not absent** — `HF_HUB_OFFLINE=1` is exported by `bin/sagp-serve` before any import, and the egress guard turns any phone-home into an `EgressViolation`. Our code must never import it.
*Check:* smoke check 1 asserts **`torch` and `transformers` are not importable** (both confirmed absent at M0); `huggingface_hub` **is** importable and that is expected. `tests/security/test_no_network_imports.py` is an AST scan that must fail the build if any module under `src/sagp/` imports `torch`, `transformers`, or `huggingface_hub` — the rule is that our code never touches hub, not that hub is uninstalled.

**11. Never run more than one uvicorn worker.**
A second worker means a second spaCy pipeline, a second DeBERTa ORT session and a second bge session — roughly +0.8 GB (ESTIMATE) against the 1.25 GB headroom the *embedded* profile projects (0.40 GB projected under `PROFILE=demo`). `bin/sagp-serve` execs `uvicorn --workers 1 --host 127.0.0.1`. Sync guardrail calls are offloaded through an explicit `anyio.CapacityLimiter(2)`, never FastAPI's default ~40-thread pool.
*Check:* `bin/sagp-serve` is the only supported launch path; `lifespan` is specified to sum the profile's projected RSS against `psutil.virtual_memory().total` and refuse to boot above 90% projected.

**12. Never edit thresholds in Python. They live in `config/guardrails.yaml` and `config/entities.yaml`.**
Thresholds are data, and their file hash is written into every audit record so a decision can be replayed against the policy that produced it. All thresholds are validated `0.0 < t <= 1.0` at startup; a typo'd env var refuses to boot rather than silently defaulting.
*Check:* `tests/unit/test_config.py`; grep for float literals in `guardrails/**` during review. Also invariant-adjacent: **never weaken a threshold or a metric floor to make a test pass** — fix the guardrail or the corpus and explain in the commit.

**13. Never mark a verification PASS when a negative control failed or a high-severity gap is open.**
"The connection failed" proves nothing — it fails identically when the network is merely absent. Invalidating conditions, each yielding `INVALID` and never `PASS`: any negative control failing, the guard not installed, the manifest verified in `quick` mode, non-loopback listeners present, an invalid signature, a broken ledger chain, or `SAGP_GUARD != enforce`. A `known_gap` with `severity: high` and `status: OPEN` yields `PASS_WITH_OPEN_HIGH_SEVERITY_GAPS`, never `PASS`.
*Check:* `scripts/verify_airgap.py` exits non-zero; `scripts/verify_online.py` is the paired online negative control and `make seal` refuses without `evidence/verify-online-<gen>.json` carrying `all_probes_blocked == true`.

---

## 3. Repo layout

Condensed from BLUEPRINT §4 — that section is authoritative and lists every file. **None of this tree exists yet** (§10); it is the target layout.

```
.
├── CLAUDE.md  README.md  Makefile  pyproject.toml       # Makefile is the only supported entrypoint
├── requirements.{runtime,provision}.lock  artifacts.lock  # hash-pinned; artifacts.lock = every model/image, revision + size
├── bin/sagp-serve  bin/sagp-provision                   # each sources its .env THEN execs (order matters)
├── config/
│   ├── guardrails.yaml                                  # thresholds, weights, fail modes — schema: GUARDRAILS §8.1 (canonical); hashed into audit
│   ├── entities.yaml                                    # BLOCK/MASK/ALLOW tables + per-entity thresholds — GUARDRAILS §8.2 (canonical)
│   ├── recognizers/{in_ifsc,employee_id,secrets,codenames}.yaml
│   └── logging.yaml                                     # dictConfig: JSONL audit handler + PII redaction filters
├── src/sagp/
│   ├── config.py errors.py types.py version.py          # config.py imports nothing from sagp.*
│   ├── app/{main,deps,schemas,middleware,ratelimit}.py  # lifespan: manifest full-verify → engines → warm → self-test
│   ├── app/routes/{health,chat,ingest,admin,airgap}.py  # chat.py is the ONLY route that can reach the LLM
│   ├── guardrails/
│   │   ├── pipeline.py base.py registry.py              # ordered stages; build_pipeline() is the single wiring point
│   │   ├── normalize.py placeholders.py                 # one shared normalizer; ONE PLACEHOLDER_RE constant
│   │   ├── heuristics.py deobfuscate.py                 # weighted rule IDs; base64/hex/rot13, depth 2, size-capped
│   │   ├── injection/{labels,onnx_backend,scanner,selftest}.py
│   │   ├── pii.py presidio_factory.py recognizers.py vault.py aliases.py
│   │   └── output.py                                    # structural, egress PII, divergence block, citation range
│   ├── rag/{loaders,chunking,embeddings,vectorstore,qdrant_store,retriever,prompt,ingest}.py   # prompt.py is the SOLE prompt builder
│   ├── llm/{base,fake,ollama_client}.py  llm/prompts/*.txt
│   ├── audit/{events,sink,hashing,verify,scrub,quarantine,redactors}.py
│   ├── netguard/{egress,manifest,phase,evidence,probes}.py
│   └── utils/{ids,timing,text}.py
├── airgap_guard_boot.py                                 # installed beside the .pth; reads .airgap/state.json
├── scripts/{doctor,seal.sh,unseal,verify_airgap,verify_online,evidence,eval_guardrails,smoke.sh,…}
├── scripts/provision/01_wheelhouse.sh … 10_manifest.py  # the one-way door, online only
├── tests/{unit,integration,security,metrics,e2e}/  tests/corpus/*.jsonl
├── data/{samples,private,qdrant}/   models/   vendor/   audit/   evidence/   .airgap/
└── docs/                                                # BLUEPRINT, PLAN, ARCHITECTURE, THREAT_MODEL, …, adr/0001-0009
```

---

## 4. Commands

Every task is to run through the Makefile (`.SHELLFLAGS := -eu -o pipefail -c`); the repo path contains spaces, so quote every path everywhere — `"$ROOT"`, `"$(PWD)"`, `pathlib.Path`, never bare word-splitting in shell and never string concatenation for paths in Python. **No Makefile and no target below exists yet** (§10) — this table specifies them, and no target has ever been run.

| Target | What it does | Network? | Safe to re-run? |
|---|---|---|---|
| **BOOTSTRAP** | | | |
| `make doctor` | Read-only preflight: Python 3.11.15, free disk (hard-fail < 25 GB), RAM, Docker, Ollama | no | yes |
| `make venvs` | Creates `.venv` and `.venv-provision` from `~/.local/bin/python3.11` | no | yes |
| `make lock` | Resolves both closures once → `requirements.*.lock` with `--generate-hashes` | **yes** | yes (output changes) |
| `make install` | `pip install --require-hashes -r requirements.runtime.lock -e .` | **yes** | yes |
| `make spike-docker` | 10-minute empirical resolution of OQ-4/OQ-5; decides ADR-0002 (status: Proposed until it runs) | **yes** | yes |
| **PROVISION** | | | |
| `make provision` | Runs `scripts/provision/01..10` in order; exits non-zero if any gate in 07 fails | **yes** | yes — resumable and idempotent |
| `make verify-online` | The negative control: probes succeed in `audit` mode, raise `EgressViolation` in `enforce` | **yes, required** | yes |
| `make eval` | Corpus run; **creates** `docs/metrics/latest.json` at M6 — the file does not exist today (commit the result) | no | yes |
| `make verify-manifest` | `manifest.verify(mode="full")` standalone | no | yes |
| **SEAL** | | | |
| `make seal` | Writes `.env.sealed` + `.airgap/state.json` (phase=OPERATE, `seal_generation++`), installs the `.pth` guard | no | yes — increments generation each time |
| `make seal-pf` | OPTIONAL, sudo. Loads `deploy/pf/com.sagp`. Dry-run parse first: `sudo pfctl -n -f /etc/pf.conf` | no | yes |
| `make unseal REASON="…"` | Returns phase to PROVISION; appends to `unseal_history`. Refuses without `REASON=` | no | yes |
| **OPERATE** | | | |
| `make ollama-up` | launchd plist, loopback-bound, env from `.env.sealed` | no (loopback) | yes |
| `make up` | `PROFILE=demo` only: `docker load` + `compose up qdrant`; the container's network isolation is **untested** until `make spike-docker` runs | no (loopback) | yes |
| `make serve` | `bin/sagp-serve` → `uvicorn --workers 1 --host 127.0.0.1`; full manifest verify is a hard precondition | no (loopback) | yes |
| `make ingest FILE=… COLLECTION=…` | Ingest a local PDF through the same guardrails | no | yes — `delete_by doc_sha256` then upsert; count unchanged |
| `make query Q="…"` | One guarded chat request | no | yes |
| **VERIFY** | | | |
| `make verify` | The 9 offline assertions, each with a paired positive control | no — must be offline | yes |
| `make evidence` | Signed `EVIDENCE-<gen>-<utc>.json/.md` + ledger append | no | yes — appends |
| `make audit-verify` | Hash-chain walk; exit 1 on any break | no | yes |
| `make proof` | `verify` + `evidence` | no | yes |
| `make smoke` | 14 numbered PASS/FAIL checks; `--fast` uses `FakeLLM` | no | yes |
| **DEV** | | | |
| `make lint` / `typecheck` / `test` | Fast suites, `FakeLLM` + `FakeScorer`; `make test-all` / `test-e2e` add the `needs_models` / `needs_ollama` markers | no | yes |

---

## 5. The lifecycle state machine

State is to live in `.airgap/state.json`; `src/sagp/netguard/phase.py` owns the transitions and **every Make target must import it**. `seal_generation` increments on every seal and appears in every evidence report.

```
BOOTSTRAP ──make provision──▶ PROVISION ──make seal──▶ OPERATE
                                  │                       │
                                  │                       └─ make verify ──▶ VERIFY (offline evidence run)
                                  └─ make verify-online ──▶ VERIFY (online negative control)

OPERATE ──make unseal REASON="…"──▶ PROVISION      (one controlled reconnection; logged)
```

Refusal rules — an agent that runs a provision target on a sealed box must understand *why* it failed:

- Any `provision*` target **exits 2 when `phase == OPERATE`**. This is not a bug and not a permissions problem. The sealed host is past a one-way door; the correct move is to add the artifact to `artifacts.lock` and require an explicit `make unseal REASON="…"`, not to work around the check.
- `make seal` refuses on the preconditions in invariant 13; you cannot reach it with an unvalidated classifier, because `make provision` exits non-zero on any gate failure in step 07. The Ed25519 signature on the manifest and on evidence is **self-signed on the host it attests to** — it detects later tampering, it does not establish provenance to a third party.
- `make up` / `make serve` run full manifest verification as a hard precondition; a mismatch is a startup failure, not a warning. `make unseal` without `REASON=` exits non-zero and writes nothing.
- The `.pth` bootstrap must read `.airgap/state.json`, **not** an env var — an `AIRGAP_PHASE` env var would let a single typo silently disable both guard layers. Unreadable or missing state → install in `enforce` mode.

Re-provisioning is: `make unseal REASON="add pypdf 6.15.0"` → reconnect → `make provision` → `make verify-online` → `make seal`.

---

## 6. Where things live

| Want to change… | Edit… |
|---|---|
| An injection or retrieval threshold | `config/guardrails.yaml` (never a Python literal) |
| A PII entity's BLOCK/MASK/ALLOW policy or per-entity threshold | `config/entities.yaml` |
| A custom Presidio recognizer (IFSC, employee ID, secrets, codenames) | `config/recognizers/*.yaml`, registered in `src/sagp/guardrails/recognizers.py` |
| How `AnalyzerEngine`/`AnonymizerEngine` are built | `src/sagp/guardrails/presidio_factory.py` — the only construction site |
| The system prompt or refusal text | `src/sagp/llm/prompts/system_rag.txt`, `refusal.txt` (their sha256 goes into every audit record) |
| How the final prompt string is assembled | `src/sagp/rag/prompt.py` — the sole builder; nonce delimiters, retrieved text in the **user** role |
| A pinned model ID, revision, or expected byte size | `artifacts.lock` **and** `MANIFEST.json` **and** an ADR under `docs/adr/`, in one commit |
| A pinned package version | `pyproject.toml` → `make lock` → both `requirements.*.lock` → ADR, in one commit |
| The egress allowlist (hosts, AF_UNIX paths, allowlisted subprocesses) | `src/sagp/netguard/egress.py`; `/var/run/docker.sock` is denied unconditionally in OPERATE. Subprocess entries match on **(resolved absolute binary path AND exact argv tuple)** — never path alone, since an allowlisted binary can egress via its own arguments (e.g. `ollama pull`); the sole default entry is `[<resolved ollama path>, "--version"]` |
| Runtime env exported before the interpreter starts | `scripts/seal.sh`, which generates `.env.sealed` — never hand-edit `.env.sealed` |
| Caps and timeouts (`SAGP_MAX_*`, `timeout_*_ms`) | `src/sagp/config.py` defaults + `.env`; canonical set in BLUEPRINT §12 |
| Which spaCy pipeline loads | `SAGP_SPACY_MODEL` (`en_core_web_md` default; `lg` costs +0.60 GB (ESTIMATE) and forces `llama3.2:1b`) |
| Vector store backend | `SAGP_QDRANT_MODE` — Qdrant is the only vector store. `embedded` is the **default runtime backend**, on RAM grounds (6.75 GB projected, vs 7.60 GB projected with Docker, against an 8 GB ceiling). `PROFILE=demo` (Docker, `qdrant/qdrant:v1.18.3-unprivileged`) is the **demonstration and proof path** — the network-isolation boundary this project exists to show, and what the proof harness targets. Its isolation is **untested**, never "isolated", until `make spike-docker` resolves OQ-4 (`internal: true` alongside a published `127.0.0.1:6333`) and OQ-5 (does `enable_ip_masquerade: "false"` block egress on Docker Desktop, where containers egress via a userland VM proxy?). ADR-0002 is **Proposed — blocked on that spike** |

---

## 7. Code conventions

- **Python 3.11.15 only.** `requires-python >=3.11,<3.12`. Type hints are required on every public function; `make typecheck` is part of the definition of done.
- **pydantic v2** (`==2.13.4`, floor set by Presidio). Settings are `Settings(BaseSettings, env_prefix="SAGP_")`. Upstream keys (`HF_*`, `OLLAMA_*`, `TLDEXTRACT_CACHE`) keep their real names and are exported by `bin/sagp-serve` before the interpreter starts, because pydantic-settings loads too late to matter.
- **`src/sagp/config.py` imports nothing from `sagp.*`.** Same for `types.py` — no library imports at all. They are the base of the dependency graph.
- **Dependency direction:** `config`/`errors`/`types` → `utils` → `audit` → `guardrails` → `rag`/`llm` → `app`. `netguard` depends only on `config`/`errors`. No edge points backwards; no module in `guardrails/` imports from `app/`.
- **Errors:** one root `SagpError` in `errors.py`. The full taxonomy and its converting layer (a single exception handler registered in `app/main.py`, never `BaseHTTPMiddleware`): `PromptRejected` → 400 `PROMPT_REJECTED` (the uniform opaque body, padded to the fixed rejection deadline — covers every detector reject, C3–C12, including BLOCK-list and vault-cap); `UnsupportedRequest` → 400 `UNSUPPORTED` (multi-turn / schema, non-detector, not deadline-padded); `AuthError` → 401; `RateLimited` → 429; `InputTooLarge` → 413; `GuardrailUnavailable` → 503 (any guardrail error, timeout, or — per OQ-6 — a swallowed regex timeout). `EgressViolation` is raised by `netguard` and is deliberately *not* a `SagpError` — it must never be caught by a handler that turns it into a 500. See BLUEPRINT §5.7 for which stage raises which.
- **Singletons are lazy.** Engines are created by `@lru_cache`-decorated factories in `src/sagp/app/deps.py` and nowhere else. **Never construct a model, an ORT session, a spaCy pipeline, or a Presidio engine at import time** — `import sagp` must be free of side effects and must not touch the filesystem or the network. The Presidio analyzer in particular is not process-safe to share.
- **Guardrails are FastAPI dependencies, never `BaseHTTPMiddleware`.** Starlette's `ExceptionMiddleware` sits inside user middleware and would degrade a typed 400 into an opaque 500.
- **Presidio imports come from the package**, `from presidio_analyzer.predefined_recognizers import …`, never a module path — recognizers were reorganised into subpackages at 2.2.364 but all names remain exported at the package level.
- **Qdrant:** `query_points(...)` returning `QueryResponse`, results at `.points`, filter kwarg `query_filter=`. `client.search()` was **removed** in qdrant-client 1.16.0.
- **ONNX:** build the feed dict from `sess.get_inputs()`; never hardcode input names. DeBERTa-v2 has `type_vocab_size: 0`. `SessionOptions(intra_op_num_threads=4, inter_op_num_threads=1)` leaves four cores for Ollama.

---

## 8. Testing

```bash
make test        # unit + integration, FakeLLM + FakeScorer, no models — the loop you run constantly
make test-all    # adds needs_models (real ONNX + spaCy) and needs_ollama
make test-e2e    # golden path against real models and a real Ollama; the air-gap probe set in-process
make eval        # metrics gates; writes docs/metrics/latest.json at M6
```

No test exists yet and none has been run (§10); everything here is the specified shape of the suite. Markers are to be gated in `tests/conftest.py`: `needs_models` requires `models/` to verify against `MANIFEST.json`; `needs_ollama` requires a reachable `127.0.0.1:11434` with the pinned tag present. Roughly 90% of the suite should use `FakeLLM` (deterministic) and `FakeScorer` (threshold/aggregation/fail-closed logic without a session); integration tests use Qdrant `":memory:"`; expensive engines are session-scoped fixtures in `tests/fixtures/`.

**Metric floors** — build-gate **targets**, not measurements. Nothing below has been measured; `docs/metrics/latest.json` does not exist and is first produced by `make eval` at M6:

```
INJECTION_RECALL ≥0.90 over families A,C,D,E,G,H,I (per-family recall reported; B and F reported separately, never averaged into the headline) · INJECTION_PRECISION ≥0.85
BENIGN_FPR ≤0.10 over benign.jsonl, ≥30% hard negatives
PII recall: EMAIL_ADDRESS ≥0.98 · CREDIT_CARD ≥0.98 · IN_AADHAAR ≥0.95 · PERSON ≥0.80
REGRESSION: once a baseline exists, any metric >2pp below it fails the build.
```

FPR is **not** `1 − precision` — that is the false *discovery* rate, and the confusion is what produced the "8.4% FP" figure in the source specs. Category B (jailbreak — a blind spot the injection model's own card declares, along with non-English prompts; the checkpoint is archived upstream) and category F (indirect, document-planted) are reported separately and never averaged into the headline. No PII recall floor is asserted for Devanagari or transliterated names; that evaluation does not exist yet (**OQ-9**).

**The single most important test to write:**

```python
def test_final_bytes_were_scanned(spy_scanner, spy_ollama, client):
    """The string sent to Ollama AND the string returned to the caller must each
    have been an argument to a scan() call within the same request."""
    r = client.post("/v1/chat", json={"message": "...", "collection": "handbook"})
    assert spy_ollama.last_prompt in spy_scanner.scanned_strings
    assert r.json()["answer"]   in spy_scanner.scanned_strings
```

Any other "the guardrail ran" test would assert on an intermediate value — a variable that was scanned before three more transformations touched it. This one asserts on the bytes that actually crossed the boundary. If a refactor breaks it, the refactor introduced an unscanned path; do not adjust the assertion.

Adding a guardrail signal requires **three edits in one commit**: an `AuditEvent` field, a `docs/COMPLIANCE.md` row, and a `test_audit_no_pii.py` case.

---

## 9. Forbidden ideas

Reasonable-sounding changes that are wrong *here*:

- **Token-by-token streaming.** You cannot un-send a leaked token. Citation validation and injection-compliance detection are undecidable on a partial response. Buffer-then-scan only; SSE *stage* events (no content) are fine.
- **Multi-turn conversation history.** The vault is request-scoped, so turn 2 cannot resolve turn 1's placeholders. `messages` array of length > 1 → 400 `UNSUPPORTED`. Conversation scoping is a v2 design problem, not a parameter.
- **Masking at ingest time (`ingest_mode=masked`).** Placeholders collide across identities in a persistent vault, and a masked corpus against raw queries destroys retrieval. Store raw, mask at retrieval — which means `data/qdrant/` holds **real unmasked PII at rest**, protected by loopback binding, filesystem permissions and FileVault, not by any guardrail. Say so wherever the corpus is described.
- **PyMuPDF for PDF text or rasterisation.** AGPL-3.0 §13 would infect a compliance-themed template. Use `pypdf==6.14.2` (BSD-3) with the `visitor_text` hidden-text detector.
- **Mean pooling for bge-small.** This checkpoint is **CLS** pooling then L2 normalize. Mean pooling produces plausible vectors and silently halves recall — nothing errors.
- **`quick` manifest verification at boot** "because full takes 3 seconds". `quick` skips the interior of every file that matters, and a `quick` verification is an invalidating condition for any PASS verdict.
- **Caching LLM responses keyed by the raw prompt.** The key is PII.
- **An OpenAI/Anthropic/any remote fallback client**, telemetry of any kind, or auto-downloading a missing model at request time (all three are invariant 2); likewise `trust_remote_code=True`, `spacy.cli.download`, or a `/v1/raw` debug endpoint.
- **Datamarking with U+2581.** Deleted by decision: 1.5–3× token blowup on llama3's BPE, and it pushes the retrieval re-scan out of distribution.
- **Scanning the system prompt.** It is a documented false-positive source and is never scanned.
- **Passing `num_ctx` per request to Ollama.** It forces a full model reload.
- **Blocking on `U+00AD`/`U+200C`/`U+200D`.** Those are required for PDF paste and for Indic and Arabic scripts — the stated user base. Only tag chars (U+E0000–U+E007F) and bidi overrides (U+202A–U+202E, U+2066–U+2069) block outright; all other `Cf` is strip-and-flag.
- **`llama3:8b` as an "accuracy profile".** It projects to 9.28 GB against an 8 GB ceiling. macOS will compress and swap rather than OOM, so it *appears* to work — while the pages evicted are precisely the idle guardrail models. That is a security property, not just slowness.

---

## 10. Current status

**As of 2026-07-27 this repository contains documentation only. No code has been written.**

- **Present:** `README.md`, `CLAUDE.md`, `THIRD_PARTY_LICENSES.md`, `NOTICE`, `LICENSE`, `.gitignore`, `docs/{BLUEPRINT,PLAN,ARCHITECTURE,THREAT_MODEL,GUARDRAILS,AIRGAP_RUNBOOK,COMPLIANCE,EVALUATION,OPERATIONS,LIMITATIONS}.md`, and `docs/adr/0001`–`0009`. All of those documents are written; none is "planned".
- **Absent:** `src/`, `tests/`, `scripts/`, `config/`, `Makefile`, `docker-compose.yml`, `pyproject.toml`, `docs/metrics/`.
- **Version control:** the repository is initialised and the documentation corpus is committed on `main`. No code has ever been committed, so the git history is not evidence that anything was built.

**Nothing in this corpus has been measured — no metric, no latency, no RAM figure, no recall number.** The only facts established on this host are the environment facts in PLAN §1: 8 GB RAM, 5.9 GB free disk (**provisioning needs ≥ 25 GB and cannot complete until space is freed**), Docker 29.5.3 with the daemon stopped, Ollama client 0.30.10 with no server and no models pulled. Every RAM figure in BLUEPRINT §7 except the 3.00 GB macOS baseline is an ESTIMATE, and the INT8 classifier RSS (0.30 GB) is **UNVERIFIED and blocking** — see **OQ-1**.

This warning scopes over **every document listed above, without exception** — README, this file, BLUEPRINT, PLAN, ARCHITECTURE, THREAT_MODEL, GUARDRAILS, AIRGAP_RUNBOOK, COMPLIANCE, EVALUATION, OPERATIONS, LIMITATIONS and all nine ADRs. Every latency, RAM, recall, precision and FPR figure in any of them is an ESTIMATE, a PROJECTION, a build-gate TARGET, or an unverified arithmetic derivation; every RAM total must name the profile it assumes (6.75 GB = embedded, 7.60 GB = `PROFILE=demo`). Do not launder any of them into a fact, and never cite one without its marker.

**Build order** — `M-DOCS → M0 → M1 → M2 → … → M15`, per [docs/PLAN.md](docs/PLAN.md) §7 and BLUEPRINT §10:

```
M-DOCS  all markdown into the repo, git init         ← DONE
M0      skeleton: src/sagp tree, Settings, errors, types, Makefile   ← next
M1      PROVISION EVERYTHING (online, one-way door, longest single item)
M2      audit spine — lands BEFORE any guardrail exists
M3 normalizer · M4 PII · M5 injection · M6 metrics gate · M7 LLM client
M8 ingestion · M9 retrieval · M10 FastAPI gateway   ← first demoable slice
M11 net-guard · M12 indirect injection · M13 THE DEMONSTRATION (offline, paired negative controls)
M14 hardening · M15 documentation revisited with real measurements
```

Minimum viable slice is **M-DOCS → M0 → M10**, with M1 done first while the host is still online. Realistic effort for M0–M15 is 3–6 focused weeks (ESTIMATE); attempting past M13 in one pass yields several half-built subsystems instead of one working demo. The M-DOCS pass writes the docs correct-as-of-design; **M13 rewrites them correct-as-measured**.
