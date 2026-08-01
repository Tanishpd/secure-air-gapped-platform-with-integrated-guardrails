# Guardrails

The operator's reference for every guardrail stage in `sagp`: what each stage protects, what it
catches, the exact thresholds and where they came from, how to tune them, and — stated plainly —
what each one does not catch. Authority for every number here is
[BLUEPRINT.md](BLUEPRINT.md); where the blueprint marks something ESTIMATE, UNVERIFIED, or an OPEN
QUESTION, this document carries the same marker.

Related: [Architecture](ARCHITECTURE.md) · [Threat model](THREAT_MODEL.md) ·
[Evaluation](EVALUATION.md) · [Limitations](LIMITATIONS.md) · [Plan](PLAN.md) · [README](../README.md)

---

## 1. Philosophy

**Defence in depth.** No single stage is trusted to be correct. The user prompt is normalized, then
heuristically scored, then classified, then PII-scanned — and the document that answers it was
scanned at ingest, re-scanned as assembled context, and the model's answer is scanned again on the
way out. Each layer is expected to have a false-negative rate. The design bets on their failure
modes being *different*, not on any one of them being good.

**Fail closed.** Every guardrail has exactly one failure mode: it blocks. A stage that raises, times
out, exceeds a window cap, or returns a partial result set produces a rejection or a `503`, never a
`200` with the check skipped. There is no `*_FAIL_MODE=open`, no `SAGP_DISABLE_*`, no debug bypass.
`CLAUDE.md` invariants 3 (never bypass the guardrail pipeline) and 6 (never let an `except` silently
disable a guardrail — fail-CLOSED) exist to keep it that way, and
`tests/security/test_guardrail_bypass.py` enforces them with an AST walk plus a
runtime spy. That test exists and passes as of M10 (per BLUEPRINT §10).

Concretely, fail-closed means these are all the same answer:

| Situation | Result |
|---|---|
| Classifier says 0.91 on a 0.85 threshold | `400 PROMPT_REJECTED` |
| Input needs 17 windows, cap is 16 (`truncated=True`) | `400 PROMPT_REJECTED` |
| ONNX session raises | `503 GUARDRAIL_UNAVAILABLE` |
| Presidio exceeds its 3000 ms wall clock | `503 GUARDRAIL_UNAVAILABLE` |
| A recognizer's regex times out and Presidio returns fewer entities | `503` — never a partial set at 200 |
| Audit write or scrub check fails after a good answer | `503`, and the answer is **not** returned |

"Too long to scan" never means "allowed". "The scanner is broken" never means "allowed".

**Measure everything, into the audit record — not into the response.** Every stage emits its score,
rule IDs, timing, and entity counts to the hash-chained audit log and to
`GET /v1/admin/incident/{id}`, which is gated on the `pii:reveal` scope. There is no `admin` scope —
there are exactly three scopes (`chat`, `ingest`, `pii:reveal`) across two bearer tokens, and
`/v1/admin/*` is guarded by `pii:reveal`. None of it crosses the client boundary.

**No detector oracle.** Every blocked request — injection classifier, heuristic rule, PII BLOCK-list
hit, delimiter spoof, vault exhaustion — returns byte-identical output:

```json
{"error":{"code":"PROMPT_REJECTED",
          "message":"Your request was rejected by the security policy.",
          "incident_id":"<uuid4>"}}
```

with HTTP 400 and a **fixed rejection deadline** applied to the response path — every detector
rejection (C3 through C12) is padded to the *same* wall-clock deadline, not merely to a floor each
detector might already exceed. This matters: the injection classifier's own estimated path (60–200 ms)
plus a late-stage PII reject (another 30–120 ms) would exceed a bare 120 ms floor, so a *minimum*
would leak stage identity through timing. The `120 ms` value is therefore a **placeholder**: at M13,
`test_oracle_uniformity.py` measures the slowest detector path and sets the deadline strictly above it,
and any reject that overruns the deadline is itself a finding. No score, threshold, rule ID, matched
substring, entity type, model name, or window index ever leaves the box. A 403-vs-400 split, a
returned score, or an `X-PII-Masked-Count` header would each let an attacker hill-climb the thresholds
— and because `CreditCardRecognizer` is Luhn-binary, a leaked count is literally a card-number
validator. `tests/security/test_oracle_uniformity.py` asserts that every detector
produces the same bytes **and terminates at the same deadline**; the test exists and passes (M10), and
its deadline value is still to be calibrated from measured latencies at M13 — no latency benchmark has
run on the M2 yet, so 120 ms remains a placeholder. (The one
exception is C1 `UNSUPPORTED`, a pre-detector schema error that reveals nothing about a detector and is
not padded — see BLUEPRINT §5.7.)

---

## 2. Stage table

Surfaces: **prompt** (what the user sent), **document** (what was ingested), **context** (the
assembled, masked prompt that reaches the LLM), **response** (what the LLM produced).

| # | Stage | Surface | Fail mode | Latency p50 (ESTIMATE) |
|---|---|---|---|---|
| G0a | Bearer token → `Principal`, rate-limit bucket (C0) | prompt | 401 / 429 | < 1 ms |
| G0b | Single-turn schema; `messages[]` len > 1 rejected (C1) | prompt | 400 `UNSUPPORTED` | < 1 ms |
| G0c | Length cap `SAGP_MAX_INPUT_CHARS=8000` (C2) | prompt | 413 `INPUT_TOO_LARGE` | < 1 ms |
| **G1a** | `normalize()` — NFKC, tag/bidi/Cf policy, homoglyph fold (C3, I4) | prompt + document | 400 on `TAG_CHARS` / `BIDI_OVERRIDE` | 1–3 ms |
| **G1b** | Heuristic rule table → weighted score + rule IDs (C4) | prompt + document | 400 on `DELIMITER_SPOOF`; else feeds G2 policy | 1–3 ms |
| **G1c** | Deobfuscate: base64/base32/hex/rot13/leet/reverse/spaced, depth 2, 256 KB cap (C5) | prompt | 400 on decode bomb / cap | 2–10 ms |
| **G2** | Injection classifier over `{raw, norm, *decoded}`, max over ≤16 windows (C6–C7, I7) | prompt + document | 400 at ≥ 0.85; 400 on `truncated`; 503 on error / >2000 ms | 60–200 ms |
| **G3a** | `neutralize_placeholders()` (C8) | prompt | flag + audit (defang, not block) | < 1 ms |
| **G3b** | Presidio `analyze` INGRESS 0.50 (C9) | prompt | 503 on exception / timeout / partial | 30–120 ms |
| **G3c** | BLOCK-list check (C10) | prompt | 400, byte-identical to G2 | < 1 ms |
| **G3d** | PERSON alias resolution + `anonymize` into the request vault (C11–C12) | prompt | 400 on vault cap (2000) | 5–20 ms |
| — | Retrieval: embed, `query_points`, `MIN 0.35` / `STRONG 0.50` (C13–C15) | — | 503 on store error; deterministic refusal below STRONG | 20–60 ms |
| **G4a** | Per-chunk `normalize()` + `neutralize_placeholders()`; `n > 0` → drop chunk (C16) | context | chunk dropped + high-severity alarm | 1–5 ms |
| **G4b** | `BatchAnalyzerEngine` EGRESS 0.35 mask of retrieved chunks into the same vault (C17) | context | 503 | 40–150 ms |
| **G4c** | Per-chunk drop-and-continue (C19a) + re-scan of the assembled context at 0.90 (C18–C19b) | context | flagged chunks dropped; all dropped → refusal; assembled-string hit → refusal; 503 on error | 150–350 ms |
| — | Ollama generate, buffered, `stream=False`, 120 s timeout (C21) | — | 503 | seconds |
| **G5a** | Output structural: strip images/links; nonce or system-prompt n-gram present → block (C22a) | response | `refusal.txt` | 1–5 ms |
| **G5b** | Egress PII scan of the **raw** response at 0.35, masked into the same vault (C22b) | response | 503 | 40–150 ms |
| **G5c** | Normalized-divergence check: more entities on the normalized copy → hard block (C22c) | response | `refusal.txt` | 40–150 ms |
| **G5d** | Citation range check on `[S<n>, p.<m>]` (C22d) | response | strip (`warn`) or refuse (`strict`) | < 1 ms |
| **G5e** | Rehydrate iff `pii:reveal` scope; re-run G5a on the final string (C23–C24) | response | placeholders left verbatim if unknown | < 1 ms |
| — | Audit record, fsync, chain link; `vault.clear()` (C25–C26) | — | 503, response withheld | 1–5 ms |

**Every latency figure in this table is an ESTIMATE.** No benchmark has been run on the target M2.
The only hard numbers are the configured timeouts (injection 2000 ms, PII 3000 ms, embed 2000 ms,
retrieve 3000 ms, LLM 120 s, request 180 s) and the 120 ms rejection floor. The structural claim —
the injection classifier dominates guardrail cost, and total guardrail cost is a small fraction of
generation — is robust to a 2–3× error; the absolute numbers are not. They are replaced with
measurements at M13.

---

## 3. G1 — Normalization and heuristics

`src/sagp/guardrails/normalize.py` is the single normalizer used identically by the PII and injection
layers. On ingress, **the normalized string is canonical**: Presidio analyzes and anonymizes it, the
classifier scans it, and it is what gets embedded and sent onward. There is no offset map anywhere in
the system — see [ADR-0008](adr/0008-normalized-canonical.md).

### 3.1 The Unicode policy (BLUEPRINT.md §5.1, reconciliation ledger row 24)

Two tiers, and the distinction matters more than it looks.

**Tier 1 — BLOCKED outright.** Presence in the input is, by itself, a rejection.

| Codepoints | Name | Why block, not strip |
|---|---|---|
| `U+E0000`–`U+E007F` | Unicode Tag characters | The ASCII-smuggling channel: a full invisible ASCII alphabet that renders as nothing and survives copy-paste. There is no legitimate use in a prompt or a corporate PDF. |
| `U+202A`–`U+202E` | LRE, RLE, PDF, LRO, RLO | Bidi overrides let displayed text and logical text disagree. What a reviewer reads is not what the model receives. |
| `U+2066`–`U+2069` | LRI, RLI, FSI, PDI | Isolates, same class of attack. |

In the pipeline: `normalize()` records and removes them, sets the flag `TAG_CHARS` or
`BIDI_OVERRIDE`, and C3 turns either flag into a `400 PROMPT_REJECTED`. At ingest (I4) the same flags
quarantine the page and raise a high-severity alarm.

**Tier 2 — stripped and flagged, never a block on their own.**

| Codepoints | Name |
|---|---|
| `U+00AD` | Soft hyphen |
| `U+200B` | Zero-width space |
| `U+200C` | Zero-width **non-joiner** (ZWNJ) |
| `U+200D` | Zero-width **joiner** (ZWJ) |
| `U+200E`, `U+200F` | LRM, RLM |
| `U+2060`–`U+2064` | Word joiner, invisible times/separator/plus |
| `U+180E` | Mongolian vowel separator |
| `U+FEFF` | Zero-width no-break space / BOM |

These are removed from the canonical string and raise the flag `ZERO_WIDTH`, which is recorded in the
audit event and contributes to the heuristic score, but never blocks alone.

### 3.2 Why ZWJ and ZWNJ must not be blocked outright

This is the single most load-bearing decision in G1, and it is a decision about who the users are.

`U+200C` (ZWNJ) and `U+200D` (ZWJ) are not decoration. They are **orthographic control characters
required by Devanagari and Arabic script**:

- In Devanagari, ZWNJ after a virama forces the explicit half-form instead of a ligated conjunct
  (`क्‌ष` vs `क्ष`), and ZWJ requests the joined form. Hindi, Marathi and Nepali text that has been
  typed correctly contains them. So do a great many corporate PDFs produced by Indic-aware
  typesetting.
- In Arabic script, ZWJ and ZWNJ control the initial/medial/final/isolated joining forms. Urdu,
  Persian and Arabic text depend on them for correct word shaping.

This project's stated user base is exactly the population that needs them: the entity table carries
`IN_AADHAAR`, `IN_PAN` and `IN_IFSC`, and the demo corpus is an Indian-context employee handbook.
A blanket "block all `Cf` characters" rule — the obvious hardening move, and the one both subsystem
specs originally proposed — would reject correctly-typed Hindi and Urdu prompts as attacks. That is
not a security control; it is a locale exclusion with a security-sounding name.

So: they are stripped from the analysis copy and flagged. An attacker who splits `ignore all
previous instructions` with zero-width joiners gets their payload reassembled by the strip step and
then classified — which is the actual defence. The character's presence is evidence, not a verdict.

> **OPEN QUESTION (not resolved in BLUEPRINT.md).** Because the normalized string is canonical on
> ingress, stripping ZWNJ/ZWJ also removes them from the text that reaches the LLM and the embedder.
> For Latin-script input this is harmless. For Devanagari or Arabic input it changes correct
> orthography into slightly-wrong orthography before generation. The alternative — normalize for
> *scanning* only, and send the raw string onward — reintroduces the offset/canonicalization seam
> that ADR-0008 exists to eliminate. This trade has not been evaluated against real Indic input, and
> no test asserts on Indic round-trip fidelity. Resolve it before claiming Indic-language support.

### 3.3 Order of operations

```python
def normalize(raw: str) -> tuple[str, list[str]]:
    # 1. record + remove tag chars and bidi overrides -> flags TAG_CHARS / BIDI_OVERRIDE
    # 2. remove STRIP_CF                              -> flag ZERO_WIDTH
    # 3. unicodedata.normalize("NFKC", s)             -> flag NFKC_CHANGED if changed
    # 4. homoglyph fold via an explicit table (Cyrillic/Greek/fullwidth -> Latin); NOT unidecode
    # 5. collapse whitespace runs to a single U+0020
    return normalized, flags
```

`neutralize_placeholders()` runs **after** `normalize()`, never before. NFKC folds fullwidth `＜`
(U+FF1C) to `<`, so a neutralizer running first is trivially bypassed by typing the placeholder in
fullwidth. Both `neutralize()` and `rehydrate()` import the same `PLACEHOLDER_RE` constant from
`placeholders.py`; a property test asserts that anything `rehydrate` matches,
`neutralize` matches too (shipped at M3) — otherwise a user-supplied `<PERSON_1>` in the prompt could be rehydrated into somebody else's
real name on the way out.

The homoglyph fold is an explicit, auditable table. `unidecode` is rejected: it transliterates
Devanagari and Arabic into Latin wholesale, which would destroy exactly the input this system is
supposed to handle.

### 3.4 Heuristic rule table (`guardrails/heuristics.py`)

| Rule ID | Catches | Proposed weight | Notes |
|---|---|---|---|
| `TAG_CHARS` | U+E0000–U+E007F present | **block** | From the normalizer. Not scored — blocks outright. |
| `BIDI_OVERRIDE` | U+202A–E / U+2066–9 present | **block** | From the normalizer. Blocks outright. |
| `DELIMITER_SPOOF` | Literal `UNTRUSTED_DOCUMENT_` in user input | **block** | An attempt to forge the context frame. No benign use. |
| `OVERRIDE_PHRASE` | "ignore/override/forget … (all) (previous/prior/above) instructions" | 0.9 | The canonical direct injection. **Corroboration-only** (§3.5): fires on benign contracts ("ignore the previous clause") and quoted attacks; the classifier catches real overrides at ~1.0, so gating it costs no recall. |
| `DISREGARD` | "disregard …", "pay no attention to …" | 0.9 | Paraphrase family of the above. **Corroboration-only** (§3.5). |
| `SYSTEM_PROMPT_PROBE` | "repeat/print/reveal your system prompt / initial instructions / rules" | 0.85 | System-prompt extraction. Blocks independently (high-precision — rare in benign text). |
| `ROLE_HIJACK` | `<\|im_start\|>`, `[INST]`, `### System`, `^\s*(system\|assistant)\s*[:>\]]` | 0.85 | Chat-template injection. **Corroboration-only** (§3.5): fires on security docs that quote `[INST]` markers (BH-004); the classifier catches real role-hijacks at ~1.0. |
| `DAN_PERSONA` | DAN / "developer mode" / "you are now …, you have no restrictions" | 0.90 | **Corroboration-only** (see §3.5). It fires on benign text that merely *discusses* jailbreaks ("explain what a DAN jailbreak is" — BH-005), so as of the post-M6 hardening it counts toward a block only when the classifier is not confidently-benign (score ≥ `corroboration_floor` = 0.15). Verified recall-safe: the corpus's DAN jailbreaks (A-B-001/004) score **0.999–1.0** on the classifier — the archived model actually *did* catch them, so gating dropped no attack. Residual: a jailbreak the classifier also scores < 0.15 would slip; that is the model's documented jailbreak blind spot, now a narrow residual rather than an unconditional-block hedge. See §4.5. |
| `NEW_INSTRUCTIONS` | "new instructions:", "updated system message", "the real task is" | 0.75 | Instruction reframing, common in documents. Deliberately **sub-0.85**: it does *not* block a user prompt alone (too common in benign text), but clears the 0.70 document-suspect threshold, so it is an operative signal on the *document* surface, not the prompt surface. |
| `EXFIL_INTENT` | "send/POST/upload … to http(s)://", "email the above to" | 0.85 | Zero-click exfiltration setup. |
| `MARKDOWN_EXFIL` | `![...](http…)` / `[...](http…)` with an interpolated value | 0.85 | Image-beacon exfiltration; also stripped structurally at G5a. |

**The weight column is a proposal, not a calibration.** These are the canonical values — §8.1 carries
the same set — and M6 (`scripts/eval_guardrails.py`) has now run them against
`tests/corpus/attacks.jsonl` and `tests/corpus/benign.jsonl`, but did **not** recalibrate them: the
weights below remain the un-swept priors. That corpus is where ≥30% hard negatives (prompts *about*
prompt injection and security) earn their place, because every rule above fires on a legitimate
question like "how would you detect someone typing 'ignore all previous instructions'?" — and it is
why benign FPR came in at 0.32 at M6. The post-M6 hardening (§3.5, corroboration-gating) makes the
precision-poor rules require the classifier's agreement, cutting FPR to **0.24** (§10.2).

### 3.5 Heuristics are OR'd with the classifier, never averaged — but precision-poor rules are corroboration-gated

The policy at C7 is `max`, not `mean`: the two detectors exist to cover each other's blind spots, and
averaging lets a confident negative from one dilute a confident positive from the other. But a plain
`max(classifier, heuristic_weight)` has a cost — a precision-poor lexical rule (one that fires on any
text *mentioning* attack vocabulary) then blocks even when the classifier is confidently-benign, which
is what drove benign FPR to 0.32 (a benign "explain what a DAN jailbreak is" trips `DAN_PERSONA` while
the classifier scores 0.0). The post-M6 policy adds **corroboration-gating**:

```python
# High-precision / structural rules (SYSTEM_PROMPT_PROBE, EXFIL_INTENT, MARKDOWN_EXFIL,
# DELIMITER_SPOOF) count independently, as before.
# "Mentions-attack-vocabulary" rules (corroboration_only: OVERRIDE_PHRASE, DISREGARD,
# ROLE_HIJACK, DAN_PERSONA) count ONLY when the classifier is not confidently-benign:
w = heuristic_weight
if rule in corroboration_only and classifier_score < corroboration_floor:   # floor = 0.15
    w = 0.0
if max(classifier_score, w) >= threshold:   # 0.85 on the user prompt
    reject()
```

This was chosen empirically, not by feel: dumping the false positives showed the corroboration-only
rules' real attacks all score **≥ 0.996** on the classifier (the model catches direct overrides,
role-hijacks, and even the corpus's DAN jailbreaks at ~1.0), so gating them dropped **no** attack —
recall stays **1.0** across all families — while removing the two benign false rejects where a rule
fired but the classifier said 0.0. High-precision rules (`EXFIL_INTENT`/`MARKDOWN_EXFIL`) are *not*
gated: family-G exfiltration attacks depend on them (one scores 0.0 on the classifier), so they keep
blocking alone.

The cost is still paid in false positives, honestly: benign FPR was **0.32** at M6 and **0.24** after
corroboration-gating, against a ≤ 0.10 floor — an OPEN `known_gap` (§10.2). Every remaining false
positive is now the archived classifier itself over-firing at ≥ 0.99 on benign text that quotes an
attack or on non-English text — a model ceiling, not a rule to tune.

---

## 4. G2 — Injection classifier

### 4.1 The model

| Field | Value |
|---|---|
| Repo ID | `protectai/deberta-v3-base-prompt-injection-v2` |
| Revision (pinned) | `90c9989b1a342275dd0d1a95aad283c04e075671` |
| Runtime artifact | `models/hf/injection/onnx/model.onnx` — **FP32 ONNX** (the choice is recorded in `models/derived/classifier_choice.json`). INT8 was rejected — see the parity row below |
| Source ONNX | `onnx/model.onnx`, 738,563,188 B |
| Fallback ladder | INT8 was the first rung and **failed parity** (OQ-2), so **FP32 ONNX is the runtime**; the remaining rung is to drop the LLM to `llama3.2:1b` if RAM ever demands it |
| Runtime | `onnxruntime==1.28.0`, `CPUExecutionProvider`, `intra_op_num_threads=4`, `inter_op_num_threads=1` |
| Tokenizer | `tokenizers.Tokenizer.from_file()` — **no `transformers` at runtime** |
| Session RSS | **0.30 GB — MEASURED (OQ-1 resolved).** `07_gates.py` measures it and fails provisioning above 0.35 GB RSS. ORT mmaps the FP32 weights, so FP32 costs no more RSS than the old INT8 projection. |
| INT8 accuracy parity | **RESOLVED — OQ-2: it FAILED.** DeBERTa-v3's disentangled attention puts the relative-position embedding through the quantizer, and dynamic INT8 **inverts** this checkpoint (label flips, not `\|Δ P(INJECTION)\| < 0.05`). FP32 ships as a result. |

The feed dict is built from `sess.get_inputs()` and never hardcoded — DeBERTa-v2/v3 has
`type_vocab_size: 0`, so `token_type_ids` is absent and a hardcoded three-input feed raises at boot.

### 4.2 Label resolution — from `id2label`, never hardcoded

`config.json` for this checkpoint carries `{"0": "SAFE", "1": "INJECTION"}`. The runtime still reads
it at boot and resolves the positive index by **casefolded alias match**:

```python
POSITIVE = {"injection", "prompt_injection", "malicious", "unsafe", "attack", "positive"}
NEGATIVE = {"safe", "benign", "clean", "legitimate", "negative"}

# resolve: exactly one label casefolds into POSITIVE and exactly one into NEGATIVE,
# otherwise raise and refuse to start. Never fall back to index 1.
```

Hardcoding `probs[:, 1]` is the inverted-guardrail bug: swap the label order in a future revision and
the system blocks every benign prompt and admits every attack, with no error and no failing test that
does not specifically look for it. Casefolding is required — the earlier spec assumed lowercase
`benign`/`injection`, and a case-sensitive match against the real `SAFE`/`INJECTION` would refuse to
boot a perfectly correct model.

### 4.3 The sliding window

```python
tok.enable_truncation(max_length=512, stride=128, strategy="longest_first", direction="right")
tok.enable_padding(length=512, pad_id=0, pad_token="[PAD]", direction="right")
enc = tok.encode(text, add_special_tokens=True)
windows = [enc, *enc.overflowing]          # Encoding.overflowing -> list[Encoding]
```

| Parameter | Value | Rationale |
|---|---|---|
| `max_length` | 512 | The checkpoint's trained sequence length. |
| `stride` | 128 | 25% overlap, so a payload straddling a window boundary appears intact in one of them. |
| Window cap | `SAGP_MAX_WINDOWS=16` | Bounds worst-case latency and RSS: 16 × 512 tokens is one batched ORT call. |
| Aggregation | **`score = max` over windows** | An attack in one window of twelve is an attack. Mean would let eleven windows of innocuous prose dilute it below any usable threshold — this is the long-context dilution attack, and `max` is the answer to it. |

**Truncation means BLOCK.** If the input needs more than 16 windows, the scanner sets
`truncated=True` and the policy layer rejects — `400` on a prompt, `quarantined` on a document
chunk. This is non-negotiable and it is the reason the cap can be small. The alternative ("scan the
first 16 windows, allow the rest") is a published, trivially exploitable bypass: pad 8 KB of filler,
append the payload, and the scanner never sees it. On the chat path `SAGP_MAX_INPUT_CHARS=8000` means
a legitimate prompt never approaches the cap, so the block is effectively unreachable for real users.

Note that adjacent-window corroboration is **not** operative on document chunks: a 320-token chunk is
exactly one window. It applies only to the assembled context at G4 (C19), which spans 4–5 windows.

**Precedence at C19 — `max` governs the block decision; corroboration only escalates.** A single
window scoring **≥ 0.90 always blocks**, exactly as `aggregate: max` says (a lone hot window in an
otherwise-innocuous context is still an attack — a compact single-window payload in a `suspect`-indexed
chunk must not survive the only retrieval-time scan). Corroboration is **additive, never subtractive**:
when two adjacent windows *both* clear a lower per-window score, that combination *also* blocks — it
lowers the bar for agreeing pairs, it never raises the bar for a lone high scorer. Corroboration can
never suppress a block that `max` would have made. (If you ever intend AND-semantics — a lone window
does *not* block — that is a single-window indirect-injection bypass and must be listed in §11.)

### 4.4 Thresholds and where they come from

| Surface | Threshold | Derivation |
|---|---|---|
| User prompt (C7) | **0.85** | High-confidence-only on the surface where a false positive is a user-visible, unexplained 400. Paired with the heuristic OR so recall does not rest on the model alone. |
| Document chunk → `suspect` (I7) | **0.70** | Deliberately lower than the prompt threshold. A `suspect` chunk is still indexed but carries `guard.verdict=suspect` in its payload for admin review; being wrong is cheap. |
| Document chunk → `quarantined` (I7) | **0.95** | High bar, because quarantine permanently removes content from retrieval. Also triggered by a block-tier heuristic or `truncated=True`, regardless of score. |
| Assembled context (C19) | **0.90** | Between the two: the context has already survived per-chunk scanning at ingest, so a hit here means something the chunk-level scan missed, and the remedy is cheap (drop one chunk and re-scan) rather than a user-facing failure. Corroboration across adjacent windows is required here. |
| System prompt | **never scanned** | Documented, deliberate false-positive source: `system_rag.txt` contains instruction-shaped text by construction. Its sha256 is in every audit record instead. |

All thresholds are validated `0.0 < t <= 1.0` at startup. A typo'd env var refuses to boot rather
than silently defaulting to something permissive.

**These four numbers are unvalidated priors.** They were chosen from the shape of the decision, not
from a sweep. M6 is where they meet the corpus; expect them to move.

### 4.5 The boot self-test

`src/sagp/guardrails/injection/selftest.py` runs inside `lifespan`, **through the real policy path**
— the same scanner, windowing, aggregation and thresholds a request would take, not a direct call to
the ONNX session. It asserts:

1. `INJECTION_IDX` resolved from `config.json` `id2label` via the alias set (not defaulted).
2. A known attack string scores above the user-prompt threshold.
3. A known benign string scores below it.
4. The ORT input names match `sess.get_inputs()` and the output shape is `(n_windows, 2)`.
5. Steady-state session RSS is within budget.

**Any failure raises and the application does not start.** Not a warning, not degraded mode. A
guardrail that cannot prove it is oriented correctly is worse than no guardrail, because the system
around it will report itself as protected. `make smoke` check `[ 5/14]` asserts that the self-test is
green; the self-test shipped with the injection guardrail at M5, and `make smoke` is **14/14 PASS** as
of M13.

### 4.6 What the vendor says this model does not do

Quoted in substance from the model card, and repeated here because it is the single most important
caveat in this document:

> **The model does not detect jailbreak attacks.**
> **The model does not handle non-English prompts.**

Both are load-bearing:

- **Jailbreaks.** Persona attacks ("you are DAN", "developer mode", "for a novel I'm writing")
  are outside the training objective. `DAN_PERSONA` in the heuristic table carries that entire load,
  imperfectly, with hand-written patterns. Jailbreak results are reported as a **separate corpus
  category (B)** in [EVALUATION.md](EVALUATION.md) and are **never averaged into the headline
  recall number**. Doing so would hide the blind spot behind the model's genuine strength on direct
  injection.
- **Non-English.** An attack written in Hindi, Marathi or Urdu is, from this classifier's point of
  view, noise. The heuristic table is also English-only. For a system whose entity table is
  India-specific, that is a large hole, and it is stated as such in §11 and in
  [LIMITATIONS.md](LIMITATIONS.md).

The model is also **archived and unmaintained** upstream. There will be no fix for either gap.

### 4.7 Known evasions

> **Status describes whether a control exists in the path.** M6 has now measured headline injection
> recall at **1.0** over corpus families A,C,D,E,G,H,I, with jailbreak (B) and indirect (F) reported
> separately at **1.0** each (§10.2) — but that corpus is small, and most individual evasions below
> have not been isolated as their own slice, so read each row as a design statement and §10.2 as the
> state of the evidence. Nothing below is "closed".

| Evasion | Status |
|---|---|
| Non-English payload (Hindi, Urdu, transliterated) | **No control in path.** Vendor-documented gap. |
| Jailbreak / persona framing | **Partial control (heuristic only).** `DAN_PERSONA` carries it; family-B recall is **1.0 on the small M6 corpus**, but that is a handful of cases and the classifier itself is jailbreak-blind. |
| Long-context dilution | **Control in path — sub-window dilution remains open (§11.3).** `max` over windows, plus truncation ⇒ block. |
| Zero-width / homoglyph obfuscation | **Control in path (unmeasured)** at G1 (strip + fold, then classify the reassembled text). |
| Bidi / tag-char smuggling | **Control in path (unmeasured)** — blocked outright at G1. |
| Base64 / hex / rot13 / leet / reversed / spaced payload | **Control in path to depth 2; depth 3+ and novel codecs open.** 256 KB cap. |
| Semantic paraphrase below the 0.85 threshold | **No control in path.** This is what the threshold *is*. |
| Payload split across two documents, assembled only at retrieval | **Control in path (unmeasured)** — the assembled-context re-scan at 0.90. |
| Payload split across conversation turns | **Not applicable** — single-turn only. |
| Instructions inside a code fence or a table cell | **No control in path; unmeasured.** Corpus family F. |
| Attacks against the *retriever* (poisoning to force a chunk into context) | **No control in path.** Out of scope for this stage; see [Threat model](THREAT_MODEL.md). |

---

## 5. G3 — PII detection and pseudonymisation

Engine: `presidio-analyzer` / `presidio-anonymizer` `==2.2.364`, `spacy==3.8.13`, `en_core_web_md`
3.8.0. `src/sagp/guardrails/presidio_factory.py` is the only place `AnalyzerEngine` and
`AnonymizerEngine` are ever constructed.

### 5.1 BLOCK list — presence in a prompt rejects the request

The BLOCK **rejection** is applied at C10, to the **user prompt only** — and over the C5 decode set
`{neutral, *decoded-normalized}`, not just `neutral`, so an encoded credential (a base64 card number,
a hex-encoded key) cannot slip past it. The rejection is not applied to document chunks (I6) or
retrieved context (C17): a handbook that legitimately contains an IFSC code should be ingestable, and
*blocking* retrieval would be a denial-of-service on the corpus. But "not rejected" does **not** mean
"passed through in the clear" — on the C17 and C22b surfaces these entities are **masked** into the
vault instead (see the block-list-on-egress note below), so a card number in a retrieved chunk or in
the model's answer still never leaves the box unmasked.

| Entity | Recognizer | Ingress threshold | Notes |
|---|---|---|---|
| `CREDIT_CARD` | Presidio built-in | **binary** | `validate_result` → Luhn. Score is forced to MAX or the result is dropped. Thresholds do not apply. |
| `IN_AADHAAR` | Presidio built-in (India) | **binary** | Verhoeff checksum via `validate_result`; see [EVALUATION.md](EVALUATION.md) §5 and the binary-entity note in §5.2 below. |
| `US_SSN` | Presidio built-in | 0.50 | |
| `IBAN_CODE` | Presidio built-in | 0.50 | |
| `US_BANK_NUMBER` | Presidio built-in | 0.50 | |
| `CRYPTO` | Presidio built-in | 0.50 | |
| `MEDICAL_LICENSE` | Presidio built-in | 0.50 | |
| `API_KEY` | custom, `config/recognizers/secrets.yaml` | 0.50 + entropy gate | |
| `PRIVATE_KEY` | custom, `config/recognizers/secrets.yaml` | 0.50 | PEM headers. |

The rationale for block-rather-than-mask: these are credentials and financial identifiers. Masking a
card number into `<CREDIT_CARD_1>` and proceeding still means the number was typed into a system that
logs, embeds and generates. There is no answer the LLM could give that is worth that. The rejection
is byte-identical to an injection rejection — nothing tells the caller *which* control fired.

**Block-list entities on the document and egress surfaces are MASKed, not blocked.** The BLOCK
disposition is a *prompt-surface* policy (C10). On the retrieved-context surface (C17) and the
egress-response surface (C22b), the same entities are instead **masked into the vault** — blocking a
retrieved chunk that legitimately contains a card number would be a denial-of-service on the corpus,
and blocking the LLM's response would lose a legitimate answer. Masking thresholds on those surfaces:
`CREDIT_CARD`, `IN_AADHAAR` **binary** (validator-forced), everything else in the block table at
**egress 0.40**. So a block-list entity is *rejected* if the user types it, but *pseudonymised* if a
document or the model emits it — it never leaves the box in the clear on any surface.

### 5.2 MASK list — replaced with a vault placeholder

| Entity | Ingress | Egress | Notes |
|---|---|---|---|
| `PERSON` | 0.50 | **0.35** | spaCy NER. Lowest egress threshold in the table; see §11 on over-masking. |
| `EMAIL_ADDRESS` | **binary** | **binary** | `SealedEmailRecognizer.validate_result` forces MAX_SCORE or drops. Thresholds do not apply. |
| `PHONE_NUMBER` | 0.50 | 0.40 | `phonenumbers==9.0.35`. |
| `LOCATION` | 0.55 | 0.40 | Highest ingress threshold — spaCy `GPE`/`LOC` fires on ordinary nouns. |
| `IN_PAN` | 0.50 | 0.40 | |
| `IN_IFSC` | custom, `config/recognizers/in_ifsc.yaml` | 0.50 / 0.40 | |
| `EMPLOYEE_ID` | custom, `config/recognizers/employee_id.yaml` | 0.50 / 0.40 | Pattern + check digit. |
| `PROJECT_CODENAME` | custom deny-list, `config/recognizers/codenames.yaml` | 0.50 / 0.40 | |

Defaults for anything not listed: **ingress 0.50, egress 0.35**.

**ALLOW list — detected and audited, never masked.** `DATE_TIME` (ingress 0.85, egress off — masking
dates destroys the answer to most handbook questions), `NRP` (ingress 0.85, egress off — nationality/
religion/politics, high false-positive rate) and `URL` (off on both surfaces — handled structurally at
G5a instead). These entities appear in the audit record as a type and a count; nothing is substituted
in the text. The canonical form of all three tables is §8.2.

**Why ingress 0.50 and egress 0.35.** The original single value of 0.40 was wrong for a specific
reason: 0.40 is exactly `LemmaContextAwareEnhancer.min_score_with_context_similarity`, i.e. "one
nearby context word was enough". Sitting the global threshold on that boundary makes behaviour
depend on whether a context word happened to be within the window. Ingress moves strictly above it
(0.50, evidence must stand on its own); egress moves deliberately below it (0.35, because on the way
out a miss is a *leak* and an over-mask is only an annoyance). The asymmetry is the whole design.

> `EMAIL_ADDRESS`, `CREDIT_CARD` and `IN_AADHAAR` are effectively **binary**. Presidio's
> `validate_result` contract forces `MAX_SCORE` or drops the result entirely, so a per-entity
> threshold for them is decorative. Do not tune them; there is nothing to tune. If you need to change
> their behaviour you must change the recognizer.

### 5.3 Custom recognizers

Registered in `src/sagp/guardrails/recognizers.py`, defined as data in `config/recognizers/*.yaml`
so that changing a pattern is a config change hashed into the audit record, not a code change.

| File | Provides | Notes |
|---|---|---|
| `in_ifsc.yaml` | `IN_IFSC` | 4 alpha + `0` + 6 alphanumeric. |
| `employee_id.yaml` | `EMPLOYEE_ID` | Site-specific prefix + check digit. Edit this before deploying. |
| `secrets.yaml` | `API_KEY`, `PRIVATE_KEY` | Provider prefixes + PEM headers + a Shannon-entropy gate to suppress the "looks random" false-positive class. **BLOCK-list members.** |
| `codenames.yaml` | `PROJECT_CODENAME` | Deny-list. Site-specific. |

### 5.4 `SealedEmailRecognizer` — the tldextract fix

Presidio's stock `EmailRecognizer.validate_result` at tag `2.2.364` is:

```python
def validate_result(self, pattern_text: str):
    result = tldextract.extract(pattern_text)
    return result.fqdn != ""
```

Module-level `tldextract.extract` uses the library's default singleton, which **fetches the Public
Suffix List over HTTPS on first call**. On a sealed host that raises `EgressViolation` *inside*
Presidio, and the first email address ever analyzed turns into a 503. This is not theoretical; it is
the failure that makes an otherwise-correct air-gapped Presidio deployment unusable on day one.

```python
_TLD = tldextract.TLDExtract(
    suffix_list_urls=(),                       # empty tuple disables all HTTP fetching
    cache_dir=str(settings.models_dir / "tldextract"),
    fallback_to_snapshot=True,
)

class SealedEmailRecognizer(EmailRecognizer):
    def validate_result(self, pattern_text: str):
        return _TLD(pattern_text).fqdn != ""
```

The fix has one load-bearing part and three supporting ones:

1. **The offline guarantee** — `suffix_list_urls=()` plus `fallback_to_snapshot=True`. Verified against
   `tldextract==5.3.1` source: with an empty URL tuple the fetch loop iterates zero times and no HTTP
   request is ever constructed; the bundled `.tld_set_snapshot` is loaded via `pkgutil` instead. This
   holds **regardless of cache state** — the sealed extractor never phones home, warm cache or cold.
2. `registry.remove_recognizer("EmailRecognizer", language="en")`, then
   `registry.add_recognizer(SealedEmailRecognizer())`.
3. `export TLDEXTRACT_CACHE="$PWD/models/tldextract"` in `.env.sealed`, warmed during provisioning
   (`08_tldextract_cache.py`) **using the same sealed constructor** — tldextract's disk-cache key
   includes the `urls` tuple, so a cache warmed under the default URLs would not even be read by the
   `urls=()` extractor. Cache warming + manifest inclusion serve **PSL freshness and tamper-evidence**,
   *not* the no-egress property (which is item 1 alone).
4. Include the snapshot in `MANIFEST.json` so a missing or altered copy is a boot failure.

Checked at M13 by air-gap assertion 8, which analyzes an email with the egress guard in `enforce`
mode and asserts `len(egress.violations()) == 0` — **paired with a positive control** that a **stock**
`EmailRecognizer` (default `suffix_list_urls`, cold cache) *does* raise `EgressViolation`, proving by
contrast that the sealed constructor is what prevents the fetch. (Asserting an un-warmed *sealed* cache
violates would be unsatisfiable — the snapshot fallback means it never fetches.) The assertion and its
positive control now exist and **PASS** — assertion 8 is among the 9 offline air-gap assertions that
pass on this host (the online negative control was also run live at M13: a real 6.58 ms TCP handshake
to 1.1.1.1:443 unguarded, `EgressViolation` when enforced). The overall proof verdict on this
deliberately-unsealed dev host is **INVALID** by design, not `PASS`. The assertion set is specified in
[AIRGAP_RUNBOOK.md](AIRGAP_RUNBOOK.md) §4.

### 5.5 The vault contract

```
PiiVault                      request-scoped, in-memory, NEVER persisted
  put(entity_type, value, origin) -> "<PERSON_1>"     # ordinal per entity type, per request
  origin ∈ {"prompt", f"doc:{sha256}"}                # every entry is origin-tagged
  cap SAGP_MAX_VAULT_ENTRIES = 2000                   # exceeded -> 400 (vault exhaustion is an attack)
  __reduce__ raises                                   # pickling is impossible
  __repr__ / __str__ leak nothing                     # f"{vault}" is safe in a traceback
  cleared in a `finally:` at C26                      # one request, one vault
```

`VaultPlaceholder` is a custom `presidio_anonymizer` `Operator` producing `<PERSON_1>`,
`<EMAIL_ADDRESS_1>`, `<EMAIL_ADDRESS_2>`. Presidio's built-in `encrypt`/`decrypt` operators were
rejected: they tie ciphertext to a long-lived key, which is exactly the property a request-scoped
vault must not have. See [ADR-0005](adr/0005-vault-request-scoped.md).

Audit records never contain the mapping. They contain
`HMAC(key, f"entity:{type}\x1f{normalize(type, value)}")` — domain-separated, peppered, over the
*value*, not the placeholder. HMAC-ing the placeholder would carry zero information, since
placeholders are per-request ordinals: `<PERSON_1>` in two requests are two different people.

Rehydration (C23) happens only if `"pii:reveal" in principal.scopes` **and**
`SAGP_REHYDRATE_OUTPUT=1`. It is a single-pass `re.sub`; unknown placeholders are left verbatim
rather than resolved against any fallback map. The `pii:reveal` scope lives on a separate bearer
token (`SAGP_API_TOKEN_REVEAL`).

> Honest caveat: the vault is memory-only but **not scrubbed**. Python strings are immutable and
> interned; `clear()` drops references, it does not zero bytes. A core dump recovers the mapping.
> Run with `ulimit -c 0`.

### 5.6 PERSON alias resolution

`resolve_person_aliases()` exists because a document says "Priya Sharma" once and "Priya" or
"Ms. Sharma" nine times, and masking those into `<PERSON_1>`, `<PERSON_2>`, `<PERSON_3>` produces an
answer that reads as three different people.

The rules, all four of which must hold before two spans are linked:

| Rule | Meaning |
|---|---|
| **Longest-first** | Process the longest detected PERSON span first; it becomes the canonical entry. |
| **Strict subset** | A candidate alias must be a strict token subset of the canonical span. "Priya" ⊂ "Priya Sharma" links. "Priya Sharma Patel" does not. |
| **Unambiguous only** | The alias must have **exactly one** superset among the canonical entries. |
| **Same origin only** | Both spans must carry the same `origin` tag. A name in the prompt never links to a name in `doc:<sha>`. |

**Ambiguity mints a fresh placeholder.** If "Priya" could belong to either "Priya Sharma" or "Priya
Nair", it gets `<PERSON_7>` — its own identity — rather than being attached to a guess.

This is the asymmetry that governs the whole stage: **over-masking is safe; cross-linking two
identities is not.** An extra placeholder makes an answer slightly clumsier. Merging two people means
the system asserts that Priya Sharma's salary belongs to Priya Nair, or rehydrates one person's
placeholder into the other's real name and hands it to a caller. One is a readability cost; the other
is a data-protection incident with the guardrail's fingerprints on it. Same-origin isolation exists
for exactly the same reason: an attacker who plants "Priya" in a poisoned document must not be able
to capture the placeholder bound to a real person named in the prompt.

---

## 6. G4 — Assembled-context guardrail

Between retrieval and generation, the guardrail's job changes: it is no longer deciding whether to
serve the user, it is deciding what the model is allowed to read. The primary threat here is the
**malicious document author**, not the user.

### 6.1 Nonce delimiters

`src/sagp/rag/prompt.py` is the sole builder of the final prompt string — the other two candidate
designs were deleted precisely so that the output guard knows exactly which delimiter scheme was
used and can look for it in the response.

```
nonce = secrets.token_hex(8)                    # per request, unguessable, never reused

<<<UNTRUSTED_DOCUMENT_{nonce}_S1>>>
… masked chunk text …
<<</UNTRUSTED_DOCUMENT_{nonce}_S1>>>
```

Three properties do the work:

1. **Unguessable.** A document author cannot pre-write a closing delimiter to escape the frame,
   because the nonce did not exist when the document was written.
2. **Detectable in user input.** The literal `UNTRUSTED_DOCUMENT_` in a prompt fires
   `DELIMITER_SPOOF` at C4 and blocks outright — there is no benign reason to type it.
3. **Detectable in output.** If the nonce appears in the model's response, the model has been
   induced to echo the frame; G5a blocks and returns `refusal.txt`.

Retrieved content is placed in the **user** role, never the system role. A retrieved chunk that has
been elevated to system-role text is an instruction by construction.

### 6.2 Why datamarking (U+2581 spotlighting) was dropped

"Spotlighting" — interleaving a rare marker such as U+2581 between every token of untrusted content
so the model can distinguish data from instructions — was in the original design and was removed.
[ADR-0009](adr/0009-no-datamarking.md) records the two reasons:

1. **Token cost.** On llama3's BPE, interleaving U+2581 inflates the context by roughly 1.5–3×. With
   `SAGP_MAX_CTX_CHARS=7000` on a 4096-token window, that is not a tax the budget can pay; it would
   force the retrieved-chunk count down and cost recall directly.
2. **It breaks the re-scan.** The assembled context is re-scanned by the injection classifier at
   C19. A DeBERTa model trained on ordinary prose, handed `i▁g▁n▁o▁r▁e▁ ▁a▁l▁l`, is being asked to
   classify out-of-distribution text. The mitigation would degrade the detector that is the actual
   control — trading a measurable defence for an unmeasured one.

The nonce delimiter survives because it costs ~10 tokens per chunk and does not perturb the text the
classifier reads.

### 6.3 Drop-and-continue re-scan of retrieved context

At retrieval the re-scan runs in **two parts** (C19), both on the `retrieval` surface at threshold 0.90:

- **C19a — per-chunk drop-and-continue** (`InputGuardrail.filter_context`). Each masked retrieved chunk
  is scanned on its own and **only the flagged chunks are dropped**; the clean ones continue. A single
  poisoned chunk — indirect injection planted in one document — must not deny service to a query that
  also retrieved good chunks. If **every** retrieved chunk is flagged there is nothing safe to ground
  on, and the request returns the deterministic refusal (`decision="refuse_context_flagged"`, no LLM
  call).
- **C19b — assembled re-scan** (`InputGuardrail.scan_context`). After the C18 budget trim, the **fully
  assembled** masked string is re-scanned as one unit. This is the exact string
  `test_final_bytes_were_scanned` asserts on; a hit here returns the same deterministic refusal (no LLM
  call), and a scanner exception is a 503.

Why the assembled pass (C19b) is needed on top of the per-chunk pass:

- **It catches the attack that only exists after assembly.** A payload split across two documents is
  individually innocuous and jointly an injection. Only the assembled string contains it.
- **Corroboration becomes operative.** A 320-token chunk is exactly one 512-token window, so
  "require two adjacent windows to agree" is meaningless per chunk (and per C19a). The assembled
  context spans 4–5 windows, so the corroboration rule actually constrains something.

Before assembly, each chunk is independently `normalize()`d and run through
`neutralize_placeholders()` (C16). A retrieved chunk containing `<PERSON_1>` is a **tamper signal** —
placeholder syntax does not occur naturally in a source PDF — so the chunk is dropped and a
high-severity alarm is raised rather than being neutralized and used.

Chunks are then masked with `BatchAnalyzerEngine.analyze_iterator(..., batch_size=6, n_process=1)`
under the EGRESS profile (0.35) into the **same request vault**, tagged `origin=f"doc:{sha}"`. The
BLOCK list is deliberately not applied here. Finally the context is trimmed to
`SAGP_MAX_CTX_CHARS=7000` by dropping the lowest-scoring chunks — trimming rather than letting Ollama
silently truncate, which could cut the closing delimiter off the last chunk and leave the frame open.

---

## 7. G5 — Output guardrail

The last stage before bytes leave the process. It runs in this order, and each step can veto.

### 7.1 Structural checks (C22a)

- Strip markdown images and links. The image beacon `![](https://attacker/?d=<data>)` is a
  zero-click exfiltration channel in any client that renders markdown — no user interaction needed.
- If the request nonce, a delimiter fragment, or a system-prompt n-gram appears in the output, the
  model has been induced to echo its frame or its instructions. **Block**, return `refusal.txt`.
- Re-run these checks on the **final returned string** after rehydration (C24), because rehydration
  changes the bytes after the first check ran.

### 7.2 Egress PII scan (C22b)

`analyze(response_raw, EGRESS 0.35)` → `anonymize` with the **same request vault**. Same vault
matters: a name that came in as `<PERSON_1>` and comes back out must map to `<PERSON_1>` again, not
to a fresh ordinal. Exception or timeout → 503; the answer is not returned.

### 7.3 The normalized-divergence block (C22c)

This is the fail-closed replacement for an offset map, and it is worth understanding precisely.

```
n_raw  = len(analyze(response_raw,            EGRESS 0.35))
n_norm = len(analyze(normalize(response_raw), EGRESS 0.35))
if n_norm > n_raw:
    block  ->  refusal.txt
```

On **ingress**, the normalized string is canonical, so there is no divergence to worry about. On
**egress**, the raw response is what would be returned, so the raw response is what gets analyzed and
masked. But a model can be induced to emit PII with zero-width characters or homoglyphs sprinkled
through it — `j o​h n@eхample.com` — which defeats the recognizer on the raw string while a
human, and any downstream consumer that normalizes, reads it perfectly.

Detecting that requires either mapping normalized offsets back onto raw text — the entire class of
off-by-one bugs that [ADR-0008](adr/0008-normalized-canonical.md) exists to eliminate — or noticing
the *count* changed and refusing. We refuse. If normalizing the response reveals more entities than
the raw scan found, something is wrong with that response and we do not attempt to repair it. The
response is discarded and `refusal.txt` is returned.

The check is asymmetric on purpose: fewer entities after normalization is fine (whitespace collapse
merging two spans), more is a hard block.

### 7.4 Citation range validation (C22d)

Citation markers `\[S(\d+),\s*p\.(\d+)\]` are checked against the blocks and pages actually supplied
in the context. Out of range → strip the marker (`warn` mode) or refuse the answer (`strict` mode).

Stated precisely, because it is easy to overclaim: **this is a range check on markers and nothing
more.** It does not verify that the cited block supports the claim. It cannot detect a fact
attributed to the wrong supplied block, a fabricated fact carrying a syntactically valid citation, or
a citation planted inside the source document. There is no groundedness scoring in this system.

### 7.5 Why buffer-then-scan, not token streaming

Token streaming is explicitly forbidden — it is on the `CLAUDE.md` list of "good ideas that are
forbidden here". SSE **stage events** (guardrail stage names, no content) are shipped, so a UI can
show progress; content is buffered until every check above has passed.

The reason is one sentence: **you cannot un-send a token.** By the time the leaked email address is
on the wire, the control has failed, and no amount of closing the stream afterwards retracts it.

Beyond that, three of the five output checks are structurally undecidable on a partial response:

- **Citation validation** needs the whole answer — a marker cannot be range-checked before it is
  complete, and `[S3, p.` mid-stream is neither valid nor invalid.
- **Normalized divergence** is a comparison of two entity *counts* over the complete string.
  Streaming would require re-running it per chunk and would still miss an entity split across a chunk
  boundary.
- **Injection-compliance detection** — did the model follow a planted instruction? — is a property of
  the finished response, not of its first fifty tokens.

The cost is latency: the user waits for the full generation before seeing anything. On a 3B model at
this budget that is seconds, not minutes, and it is the correct trade for a system whose entire claim
is that nothing unscanned crosses the boundary. Buffering is also what makes
`test_final_bytes_were_scanned` possible — the single most important test in the suite **asserts**
that the **user-role payload** sent to Ollama (the masked question plus the
assembled retrieved context) *and* the exact string returned to the caller were each arguments to a
`scan()` call within the same request. It is satisfiable because C18 trims the context to budget
*before* the C19b re-scan (BLUEPRINT §5.7), so the scanned string is the delivered string; the static
system prompt is deliberately never scanned and is excluded from the assertion by construction. It
exists and passes as of M10 (see BLUEPRINT §9.4).

---

## 8. Annotated configuration

> **This section is the canonical schema for `config/guardrails.yaml` and `config/entities.yaml`.**
> §8.1 and §8.2 are the single source of truth for the top-level key layout, the heuristic weights,
> the codec list, the threshold values and the three entity tables. `ARCHITECTURE.md` §8.2/§8.3 point
> here rather than carrying a second copy; where any other document disagrees, this section wins.
> Both files now exist on disk (`config/guardrails.yaml` at M3, `config/entities.yaml` at M4). §8.1
> below is the **canonical/target schema**; the shipped `config/guardrails.yaml` is a subset of it —
> the `normalize`, `pii`, `context`, `output`, `rejection` and `limits` sections are enforced from
> `config.py` defaults and `entities.yaml` and are not yet all mirrored back into the YAML file. Where
> the reproduction and the shipped file differ in extent, the shipped file is the transcript and this
> section is the intended shape.

Thresholds are **data, not code**. Both files below are hashed and the digest is written into every
audit record, so a threshold change is visible in the audit trail without diffing the repo.

**One owner for every cap and timeout: `config/guardrails.yaml` is authoritative.** The `SAGP_MAX_*`
and `timeout_*` names that also appear in `config.py`/`.env` are **overrides, not a second source of
truth** — at boot, `config.py` loads the YAML values, applies any env override, and the *effective*
set is what gets hashed into the audit record. A `SAGP_` env var whose name has no matching YAML key
**refuses to boot** (invariant 12), so a typo cannot silently create a shadow limit. Where a value is
shown in both this section and BLUEPRINT §12, §8.1 here is canonical.

### 8.1 `config/guardrails.yaml`

```yaml
# Guardrail pipeline configuration. sha256 of this file goes into every AuditEvent.
# There is deliberately no `enabled:` key and no `*_FAIL_MODE` on any stage — see CLAUDE.md
#   invariants 3 (never bypass the guardrail pipeline) and 6 (fail-CLOSED).
# Thresholds are only ever changed here, never in Python — CLAUDE.md invariant 12.
# Every threshold is validated 0.0 < t <= 1.0 at startup; a bad value refuses to boot.
version: 1

normalize:                        # G1a — src/sagp/guardrails/normalize.py
  block_tag_chars: true           # U+E0000-U+E007F -> flag TAG_CHARS -> 400. Not tunable in practice.
  block_bidi_overrides: true      # U+202A-U+202E, U+2066-U+2069 -> flag BIDI_OVERRIDE -> 400.
  strip_format_chars: true        # U+00AD, U+200B-200F, U+2060-2064, U+180E, U+FEFF -> flag ZERO_WIDTH.
                                  #   ZWJ/ZWNJ are in THIS list, never the block list — see §3.2.
  nfkc: true                      # unicodedata.normalize("NFKC", s); flags NFKC_CHANGED if it changed.
  homoglyph_fold: true            # explicit Cyrillic/Greek/fullwidth -> Latin table. NOT unidecode:
                                  #   unidecode would transliterate Devanagari and destroy the input.
  collapse_whitespace: true       # runs of whitespace -> a single U+0020.

heuristics:                       # G1b — src/sagp/guardrails/heuristics.py
  combine_with_classifier: max    # OR at the policy layer. "mean" is NOT a legal value here (§3.5).
  block_outright:                 # these bypass scoring entirely
    - TAG_CHARS
    - BIDI_OVERRIDE
    - DELIMITER_SPOOF             # literal "UNTRUSTED_DOCUMENT_" in user input
  weights:                        # PROPOSED, not calibrated. M6 sweeps these against the corpus.
    OVERRIDE_PHRASE:     0.90
    DISREGARD:           0.90
    SYSTEM_PROMPT_PROBE: 0.85
    ROLE_HIJACK:         0.85
    DAN_PERSONA:         0.90
    NEW_INSTRUCTIONS:    0.75     # sub-0.85 by design: document-suspect signal only, not a solo prompt block
    EXFIL_INTENT:        0.85
    MARKDOWN_EXFIL:      0.85
  # Precision-poor "mentions-attack-vocabulary" rules: count toward a block only
  # when the classifier is not confidently-benign (§3.5, post-M6 hardening).
  corroboration_only: [OVERRIDE_PHRASE, DISREGARD, ROLE_HIJACK, DAN_PERSONA]
  corroboration_floor: 0.15

deobfuscate:                      # G1c — decoded payloads JOIN the scan set, they do not replace it
  codecs: [base64, base32, hex, rot13, leet, reverse, spaced]
  max_depth: 2                    # depth 3+ is an accepted, documented gap
  max_expanded_bytes: 262144      # 256 KB; exceeding it is a decode bomb -> 400

injection:                        # G2 — src/sagp/guardrails/injection/
  repo_id: protectai/deberta-v3-base-prompt-injection-v2
  revision: 90c9989b1a342275dd0d1a95aad283c04e075671   # pinned; changing it requires an ADR
  artifact: models/hf/injection/onnx/model.onnx        # FP32 ONNX — INT8 rejected (OQ-2 inverts this checkpoint); choice recorded in models/derived/classifier_choice.json
  providers: [CPUExecutionProvider]
  intra_op_num_threads: 4         # leaves 4 of 8 cores for Ollama
  inter_op_num_threads: 1
  labels:
    source: config.json#id2label  # resolved at boot. NEVER a hardcoded index — that bug inverts the guard.
    match: casefold               # real labels are "SAFE"/"INJECTION"; a case-sensitive match refuses to boot
    positive_aliases: [injection, prompt_injection, malicious, unsafe, attack, positive]
    negative_aliases: [safe, benign, clean, legitimate, negative]
  window:
    max_length: 512               # the checkpoint's trained sequence length
    stride: 128                   # 25% overlap so a boundary-straddling payload appears whole somewhere
    max_windows: 16               # SAGP_MAX_WINDOWS
    aggregate: max                # NOT mean — mean is the long-context dilution attack (§4.3)
    on_truncation: block          # "too long to scan" NEVER means allowed. Non-negotiable.
  corroboration:
    min_adjacent_windows: 2
    applies_to: [assembled_context]   # inoperative on chunks: a 320-token chunk is exactly one window
    mode: escalate_only           # ADDITIVE: a lone window >= aggregate threshold still blocks (max governs);
                                  #   corroboration only ADDS blocks for agreeing pairs, never suppresses one (§4.3)
  thresholds:
    user_prompt:        0.85      # C7
    doc_suspect:        0.70      # I7 -> indexed with guard.verdict=suspect
    doc_quarantine:     0.95      # I7 -> <collection>__quarantine sibling, never retrieved
    assembled_context:  0.90      # C19
  scan_system_prompt: false       # documented FP source; its sha256 is audited instead
  timeout_ms: 2000                # exceeded -> 503 GUARDRAIL_UNAVAILABLE
  selftest:
    on_failure: refuse_to_start   # the ONLY legal value

pii:                              # G3 / G4b / G5b — entity tables live in entities.yaml
  entities_file: config/entities.yaml
  spacy_model: en_core_web_md     # SAGP_SPACY_MODEL; `lg` costs +0.60 GB RSS (see BLUEPRINT.md §7)
  ingress_default_score_threshold: 0.50   # MUST be > 0.40 (LemmaContextAwareEnhancer floor)
  egress_default_score_threshold:  0.35   # deliberately below it: a miss on egress is a leak
  timeout_ms: 3000                # exceeded -> 503; never a partial result set at 200
  partial_results: forbidden      # a swallowed regex timeout is a silent fail-open (OQ-6)
  batch:
    batch_size: 6                 # BatchAnalyzerEngine over retrieved chunks
    n_process: 1                  # a second process means a second spaCy pipeline: RAM budget
  vault:
    max_entries: 2000             # SAGP_MAX_VAULT_ENTRIES; exceeded -> 400 (vault exhaustion is an attack)
    persist: false                # NOT a knob. `true` is rejected at startup.
    clear_on: request_end
  person_aliases:
    strategy: longest_first
    require_strict_subset: true
    require_unique_superset: true
    same_origin_only: true        # a prompt name never links to a doc name
    on_ambiguous: fresh_placeholder   # over-mask; never cross-link two identities

context:                          # G4
  delimiter: "<<<UNTRUSTED_DOCUMENT_{nonce}_S{i}>>>"
  nonce_bytes: 8                  # secrets.token_hex(8), per request, never reused
  datamarking: false              # U+2581 spotlighting — dropped, ADR-0009. Do not re-enable.
  role: user                      # retrieved content is NEVER placed in the system role
  max_ctx_chars: 7000             # SAGP_MAX_CTX_CHARS; trim lowest-scoring chunks at C18, BEFORE the C19b re-scan
  rescan:
    mode: drop_and_continue       # C19a: scan each masked chunk on the retrieval surface, drop only the flagged ones
    assembled_rescan: true        # C19b: re-scan the fully assembled masked string as one unit (the final gate)
    all_dropped: refuse           # every chunk flagged -> deterministic refusal, no LLM call

output:                           # G5
  strip_markdown_links: true
  strip_markdown_images: true     # the zero-click image-beacon exfil channel
  block_on_nonce_echo: true
  block_on_system_prompt_ngram: true
  egress_pii: true
  normalized_divergence: block    # more entities on the normalized copy -> hard block (§7.3)
  citation_check: strict          # strict = refuse | warn = strip the out-of-range marker
  streaming: buffer_then_scan     # token streaming is forbidden: you cannot un-send a token
  rehydrate:
    require_scope: "pii:reveal"
    require_env: SAGP_REHYDRATE_OUTPUT=1
    unknown_placeholder: leave_verbatim   # never resolve against a fallback map
    recheck_structural_after: true        # C24

retrieval:
  top_k: 6
  min_score: 0.35                 # what may enter the prompt
  strong_score: 0.50              # below this on every hit -> deterministic refusal, no LLM call
  exclude_filter: guard.verdict == "quarantined"

rejection:                        # the anti-oracle surface
  status: 400
  code: PROMPT_REJECTED
  body: identical_for_every_detector    # no score, rule id, entity type, or matched text. Ever.
  rejection_deadline_ms: 120            # PLACEHOLDER — fixed deadline every C3–C12 reject is padded to,
                                        #   NOT a per-detector floor. M13 sets it strictly above the
                                        #   slowest measured detector path (test_oracle_uniformity).
  include_scores: false                 # counts and scores go to the audit record only

limits:
  max_input_chars: 8000
  max_scan_unit_chars: 20000      # ONE cap, identical at the API and ingest boundaries
  max_doc_bytes: 52428800
```

### 8.2 `config/entities.yaml`

```yaml
# Entity policy. BLOCK -> reject the request. MASK -> vault placeholder. ALLOW -> detect, do not act.
# Per-entity thresholds override the defaults in guardrails.yaml.
# "binary: true" documents that Presidio's validate_result forces MAX_SCORE or drops the result —
#   the threshold fields are ignored for those entities. Do not tune them; there is nothing to tune.
# These three tables are exhaustive over WHICH ENTITIES ARE REGISTERED: an entity absent from all
#   three is not registered, not detected and not audited. IP_ADDRESS and US_DRIVER_LICENSE are
#   deliberately absent — no recognizer for either is configured. (The "defaults for anything not
#   listed" in GUARDRAILS §5.2 refers to a REGISTERED entity whose per-entity threshold is unset — it
#   inherits guardrails.yaml's ingress 0.50 / egress 0.35 — NOT to unregistered entities, which are
#   simply invisible.) sha256 of this file goes into every AuditEvent.
version: 1

block:                            # BLOCK is the prompt-surface disposition: applied at C10 to the
                                  #   USER PROMPT ONLY. On documents (I6/C17) and egress (C22b) these
                                  #   same entities are MASKed instead (GUARDRAILS §5.1): binary for
                                  #   CREDIT_CARD/IN_AADHAAR, egress 0.40 for the rest — blocking a
                                  #   retrieved chunk or the model's answer would be DoS / data loss.
  - {name: CREDIT_CARD,     ingress: binary, source: presidio,  note: "Luhn via validate_result"}
  - {name: IN_AADHAAR,      ingress: binary, source: presidio,  note: "Verhoeff checksum via validate_result"}
  - {name: US_SSN,          ingress: 0.50,   source: presidio}
  - {name: IBAN_CODE,       ingress: 0.50,   source: presidio}
  - {name: US_BANK_NUMBER,  ingress: 0.50,   source: presidio}
  - {name: CRYPTO,          ingress: 0.50,   source: presidio}
  - {name: MEDICAL_LICENSE, ingress: 0.50,   source: presidio}
  - {name: API_KEY,         ingress: 0.50,   source: recognizers/secrets.yaml, entropy_gate: true}
  - {name: PRIVATE_KEY,     ingress: 0.50,   source: recognizers/secrets.yaml}

mask:                             # replaced with <TYPE_n> from the request vault
  - {name: PERSON,          ingress: 0.50,   egress: 0.35, source: spacy_ner}
                                  # lowest egress threshold in the table: a missed name is a leak.
                                  # It WILL over-mask. Measure the rate before calling it correct.
  - {name: EMAIL_ADDRESS,   ingress: binary, egress: binary, source: SealedEmailRecognizer}
                                  # binary via validate_result; also the tldextract PSL fix (§5.4)
  - {name: PHONE_NUMBER,    ingress: 0.50,   egress: 0.40, source: presidio}
  - {name: LOCATION,        ingress: 0.55,   egress: 0.40, source: spacy_ner}
                                  # highest ingress threshold: GPE/LOC fires on ordinary nouns
  - {name: IN_PAN,          ingress: 0.50,   egress: 0.40, source: presidio}
  - {name: IN_IFSC,         ingress: 0.50,   egress: 0.40, source: recognizers/in_ifsc.yaml}
  - {name: EMPLOYEE_ID,     ingress: 0.50,   egress: 0.40, source: recognizers/employee_id.yaml}
  - {name: PROJECT_CODENAME,ingress: 0.50,   egress: 0.40, source: recognizers/codenames.yaml}

allow:                            # detected and audited; NOT masked
  - {name: DATE_TIME,       ingress: 0.85,   egress: off,  note: "masking dates destroys most answers"}
  - {name: NRP,             ingress: 0.85,   egress: off,  note: "nationality/religion/politics — high FP"}
  - {name: URL,             ingress: off,    egress: off,  note: "handled structurally at G5a instead"}
```

---

## 9. Tuning guide

Nothing in this table has been calibrated. Treat each row as "the experiment to run", not "the
adjustment to make".

| Move this | Re-run these | Expect this trade-off |
|---|---|---|
| `injection.thresholds.user_prompt` **down** (0.85 → 0.75) | `tests/metrics/test_injection_metrics.py`, `test_oracle_uniformity.py`, full benign corpus | Recall ↑ on direct injection; **benign FPR ↑**, and it will be measured against the ≤ 0.10 ceiling. Hard negatives move first. |
| `injection.thresholds.user_prompt` **up** (0.85 → 0.92) | same | FPR ↓; recall ↓ toward the 0.90 floor. More load shifts onto the heuristic OR. |
| `injection.thresholds.doc_quarantine` **down** (0.95 → 0.90) | `tests/integration/test_context_guard.py`, `test_quarantine_routing.py`, re-ingest the corpus | More poisoned chunks caught at ingest; more legitimate content silently unretrievable. Quarantine is invisible to the user — a false quarantine looks like a corpus gap. |
| `injection.thresholds.doc_suspect` **down** (0.70 → 0.60) | `test_ingest_pipeline.py`, admin review queue volume | More chunks flagged for review; review burden ↑. No user-visible effect — `suspect` chunks are still retrieved. |
| `injection.thresholds.assembled_context` **down** (0.90 → 0.80) | `test_context_guard.py` with `poisoned_appendix.pdf`, corpus family F, `test_retriever.py` | Split-payload attacks caught more often; more benign chunks dropped mid-request → more `refuse_insufficient_context` responses. Watch the refusal rate, not just recall. |
| `injection.window.max_windows` **up** (16 → 32) | `test_tail_attack_not_truncated.py`, latency budget, RSS gate | Fewer truncation blocks; latency and peak RSS ↑ roughly linearly. With an 8000-char input cap the current setting is already unreachable for real prompts. |
| `injection.window.aggregate` → `mean` | — | **Do not.** This re-opens long-context dilution. Rejected by design (§4.3). |
| `heuristics.weights.*` **up** | Full benign corpus, `test_heuristics.py` | Recall on the covered family ↑; FPR ↑ sharply on hard negatives, because every one of these rules fires on questions *about* prompt injection. |
| `heuristics.combine_with_classifier` → `mean` | — | **Do not.** A confident heuristic gets diluted by a confident-wrong model (§3.5). |
| `pii.ingress_default_score_threshold` **down** (0.50 → 0.45) | `tests/metrics/test_pii_recall.py`, `test_pii_guardrail.py` | Ingress recall ↑; more BLOCK-list false positives, each of which is a user-visible 400 with no explanation. **Never go at or below 0.40** — that is the `LemmaContextAwareEnhancer` floor and behaviour becomes context-window-dependent. |
| `pii.egress_default_score_threshold` **up** (0.35 → 0.45) | `test_pii_recall.py`, the over-masking measurement (OQ-10) | Answers read better, fewer placeholders; **leak risk ↑**. This is the one direction where the failure is a data-protection incident rather than an annoyance. |
| `PERSON` egress (0.35) **up** | `test_pii_recall.py` PERSON floor (≥ 0.80), the 20-answerable-question set | Over-masking ↓; PERSON recall ↓ toward the floor. The floor is 0.80 precisely because spaCy is not reliable enough for a higher one. |
| `LOCATION` ingress (0.55) **down** | `test_pii_recall.py`, benign corpus | More place names masked; more ordinary nouns masked too — spaCy `GPE` is the noisiest label in the set. |
| `EMAIL_ADDRESS`, `CREDIT_CARD`, `IN_AADHAAR` thresholds | — | **No effect.** They are binary via `validate_result`. Change the recognizer or nothing changes. |
| `retrieval.min_score` (0.35) **down** | `test_retriever.py`, `test_score_normalisation.py` | More context, more noise, more work for G4. Raises the chance a marginal chunk carries a payload. |
| `retrieval.strong_score` (0.50) **up** | `test_retriever.py`, the 20-unanswerable-question set | More deterministic refusals; fewer weakly-grounded answers. This is the anti-hallucination dial. |
| `rejection.rejection_deadline_ms` (120, placeholder) **down** | `test_oracle_uniformity.py` | Snappier rejections; the timing side channel reopens. The **deadline** (a fixed pad every C3–C12 reject terminates at, not a floor) must exceed the slowest detector's normal path or it does not mask anything — M13 sets it from measurement. |
| `pii.vault.max_entries` (2000) **up** | `test_vault.py`, RAM budget | Very large documents mask fully instead of 400-ing; a vault-exhaustion input becomes cheaper to mount. |
| `pii.spacy_model` → `en_core_web_lg` | `test_pii_recall.py`, the RAM gate | PERSON recall likely ↑ (**unmeasured**); +0.60 GB RSS puts the system at ~7.35 GB and forces the LLM down to `llama3.2:1b`. |

Three rules that override every row above: **never weaken a threshold to make a test pass** — a
verification is not PASS when a control failed or a high-severity gap is open (`CLAUDE.md`
invariant 13); **thresholds are only ever edited in `config/guardrails.yaml` and
`config/entities.yaml`, never in Python** (`CLAUDE.md` invariant 12); and every change to these files
must be accompanied by a re-run of `make eval` — the committed baseline is what the 2pp regression
gate will compare against once one exists (from M6; see §10.2).

---

## 10. Metrics

### 10.1 The floors

```
INJECTION_RECALL_FLOOR    = 0.90   over tests/corpus/attacks.jsonl, reported per technique family
INJECTION_PRECISION_FLOOR = 0.85
BENIGN_FPR_CEILING        = 0.10   over tests/corpus/benign.jsonl (>=30% hard negatives)

PII recall floors:
  EMAIL_ADDRESS >= 0.98
  CREDIT_CARD   >= 0.98
  IN_AADHAAR    >= 0.95
  PERSON        >= 0.80

REGRESSION GATE: any metric more than 2 percentage points below docs/metrics/latest.json
                 fails the build. Active as of M6: that file now exists (produced by `make eval`),
                 so the recall and PII floors are hard-gated and precision/FPR are regression-gated
                 against the committed baseline.
```

The two 0.98 floors are high because both entities are validator-backed and effectively binary —
if they miss, it is a recognizer bug, not a threshold choice. `PERSON` is 0.80 because spaCy NER is
not better than that on out-of-distribution names and pretending otherwise would be the overclaim
this project exists to avoid.

**FPR is not `1 − precision`.** `1 − precision` is the false *discovery* rate. In production, where
the base rate of attacks is near zero, precision collapses while FPR holds steady — so all
false-positive reasoning in this document and in [EVALUATION.md](EVALUATION.md) is stated in FPR
terms, to be measured over the benign corpus at M6.

Category **B** (jailbreak — the classifier's documented blind spot) and category **F**
(indirect/document-planted) are reported **separately and never averaged into the headline recall
number**. Averaging a strong direct-injection result with a weak jailbreak result produces a single
number that is true of nothing.

### 10.2 The measured numbers (M6)

Stated as plainly as possible, because this is a compliance-themed document:

> **The guardrail metrics have now been measured (M6) and committed to `docs/metrics/latest.json`.**
> Over a small corpus (39 attacks; 25 benign, of which 13 are hard negatives; 18 PII cases):
>
> - **Injection headline recall 1.0** over families A,C,D,E,G,H,I (floor ≥ 0.90); jailbreak (B) and
>   indirect (F) reported separately, each **1.0**.
> - **PII recall 1.0** for `EMAIL_ADDRESS`, `CREDIT_CARD`, `IN_AADHAAR` and `PERSON`
>   (floors 0.98 / 0.98 / 0.95 / 0.80).
> - **Injection precision 0.854** — now **meets** its 0.85 target after the post-M6 corroboration-gating
>   fix (§3.5); no longer a gap. **Benign FPR 0.24** — improved from 0.32 but still over the ≤ 0.10
>   target, so it is the one remaining OPEN `known_gap` (severity medium). Every remaining false
>   positive is the archived DeBERTa classifier over-firing at ≥ 0.99 on benign text that quotes an
>   attack (BH-001/003/007/010) or on non-English text (BH-011/012) — a model ceiling; closing it needs
>   a better classifier, not tuning. Recall stayed 1.0. Recall and PII floors are hard-gated;
>   precision/FPR are regression-gated from this baseline. **FPR here is benign-blocked ÷ total-benign,
>   not `1 − precision`.**
>
> Still **not** measured: every latency figure in §2 remains an ESTIMATE — no benchmark has run on the
> target M2. Every threshold in §8 is still an unvalidated prior (M6 measured *with* them; it did not
> sweep them). The INT8 accuracy-parity question (OQ-2) is now **resolved — it failed**: dynamic INT8
> inverts this DeBERTa-v3, so **FP32 ships**.

If you are evaluating this repository, treat §10.1 as the floors the build is gated on and §10.2 as
the measured evidence. Do not cite a floor as if it were the measurement — cite `latest.json`.

---

## 11. Known limitations and explicit bypasses

Ranked roughly by how likely each is to matter in practice.

**1. The classifier is English-only, by the vendor's own statement.**
`protectai/deberta-v3-base-prompt-injection-v2` does not handle non-English prompts, and the
heuristic rule table is English regex. An injection written in Hindi, Marathi, Urdu, or transliterated
Hinglish is, to G2, unremarkable text. For a system whose entity table carries `IN_AADHAAR`,
`IN_PAN` and `IN_IFSC`, this is not a corner case — it is the primary locale. **There is no control
in the path for it.** Do not deploy this against non-English input and call it protected.

**2. Jailbreaks are a documented blind spot.**
The model card states the model does not detect jailbreak attacks. The whole load is carried by one
heuristic rule (`DAN_PERSONA`) built from hand-written patterns, whose weight is an un-swept prior —
family-B recall is **1.0 on the small M6 corpus**, but that is a handful of cases, not a guarantee. The
model is archived upstream; there will be no fix. Jailbreak results are reported as their own corpus
category so the gap stays visible.

**3. Long-context dilution — mitigated, not eliminated.**
`max` over windows plus block-on-truncation closes the classic version (bury the payload in 8 KB of
filler). What remains open is *sub-window* dilution: a payload phrased so that its own 512-token
window is mostly innocuous prose. The classifier sees a diluted window and scores it low. There is no
window smaller than 512 in this design, so there is no finer granularity to fall back to.

**4. PERSON recall on non-Western names is unmeasured.**

> **OPEN QUESTION (OQ-9).** `en_core_web_md` publishes only an aggregate `ENTS_F` (84.73) — spaCy
> does not publish per-label PERSON F1, and the training data (OntoNotes) is US/Western-news
> weighted. **Its recall on Indian names has never been measured**, by us or by anyone we can cite.
> That is the exact blind spot for a system built around Aadhaar and PAN. Resolution requires a
> 100–200 example labelled evaluation set drawn from real corpus names, built before the model choice
> is locked. `SAGP_SPACY_MODEL` makes the swap to `en_core_web_lg` a one-line change — but `lg` costs
> +0.60 GB RSS, which on an 8 GB machine forces the LLM down to `llama3.2:1b`.

Related and equally unresolved: **no PII recall floor is asserted for Devanagari or transliterated
names**, because that evaluation does not exist. The `PERSON >= 0.80` floor is over the English
synthetic corpus only.

**5. Over-masking at the 0.35 egress threshold.**
The egress threshold sits deliberately *below* Presidio's `LemmaContextAwareEnhancer` floor of 0.40,
which means single-context-word matches are accepted. It **will** over-mask — job titles, product
names, and ordinary capitalised nouns turning into `<PERSON_n>` in the answer. This is the intended
direction of the error (a miss is a leak; an over-mask is a worse-reading answer), but the *rate* has
never been measured. **OQ-10** requires a sweep against 20 answerable questions with the over-masking
rate recorded before the masking behaviour can be called correct. Until then, expect answers that are
noticeably more redacted than a reader would like, and do not be surprised by it.

**6. The BLOCK list is not applied to documents or retrieved context.**
Deliberate — a handbook containing an IFSC code must be ingestable — but it means a credential
present in an ingested PDF is masked, not refused, and reaches the model as a placeholder. If your
corpus contains live secrets, the control you need is corpus hygiene, not this stage.

**7. The citation check is a range check.**
It verifies that `[S3, p.7]` refers to a block and page that were actually supplied. It does not and
cannot verify that block S3 supports the sentence it is attached to. There is no groundedness
scoring anywhere in this system.

**8. `ingest_mode=raw` means the vector store holds unmasked PII.**
Masking happens at retrieval, in the request vault. `data/qdrant/` on disk contains real chunk text,
protected by loopback binding, filesystem permissions and FileVault — **not by any guardrail**.
Copying that directory off the box leaks the corpus with no control in the path. See
[ADR-0006](adr/0006-ingest-mode-raw.md).

**9. The vault is memory-resident and unscrubbed.**
`clear()` drops references; Python strings are immutable and interned, so the bytes remain on the
heap until collected and overwritten. A core dump or a memory scraper recovers the placeholder→value
mapping. `ulimit -c 0`, and do not co-locate untrusted processes.

**10. Multi-turn split payloads are "not a threat" only because turns do not exist.**
The endpoint is single-turn by construction, since the vault is request-scoped. If multi-turn is ever
added, cross-turn payload assembly becomes an unsolved problem *and* the vault contract has to be
redesigned. Do not add it casually.

**11. Presidio silently drops recognizers on a regex timeout — mitigated, not eliminated.**

> **OQ-6 — RESOLVED-CONFIRMED** against `presidio-analyzer==2.2.364` source. Presidio passes
> `timeout=REGEX_TIMEOUT_SECONDS` to `regex.finditer` to survive catastrophic backtracking, and
> `PatternRecognizer.__analyze_patterns` **catches the `TimeoutError` per pattern, logs "skipping",
> and returns a partial result set** — so a crafted catastrophic-backtracking input silently disables
> individual recognizers while `analyze()` returns normally with fewer entities: a real silent
> fail-open in the masking layer. **M4 mitigates it:** `PIIGuardrail` wraps `analyze()` under a
> wall-clock deadline and treats a per-pattern regex timeout as a guardrail failure → **503**,
> honouring `pii.partial_results: forbidden`. The underlying Presidio behaviour is unchanged, so any
> code path that calls `analyze()` without that wrapper reintroduces the fail-open.

**12. Every guardrail here is in-process Python.**
None of it constrains Ollama (a separate Go process), the Docker daemon, or native code reached
through `ctypes`. The guardrail layer decides what text crosses the API boundary; it is not the
air-gap control. That is [`netguard/`](ARCHITECTURE.md), with its own much longer list of caveats in
[LIMITATIONS.md](LIMITATIONS.md).
