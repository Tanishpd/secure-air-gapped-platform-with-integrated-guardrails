# ADR-0009: No datamarking — per-request nonce delimiters instead of U+2581 spotlighting

Records why interleaved-token spotlighting was dropped from the prompt assembly, and what carries the untrusted-content boundary in its place.

- **Status:** Accepted — implemented (M9 sole prompt builder; ingest/context scans M8/M10/M12)
- **Date:** 2026-07-27 (decision); 2026-08-01 (implemented)
- **Deciders:** Project architect
- **Supersedes:** —

> **Status note:** decided on structural grounds. Guardrail accuracy metrics have since been measured at M6 (headline injection recall 1.0), but the *datamarking* distribution argument specifically remains unbacked by measurement: there is no llama3 tokenizer in the runtime venv, so the token-blowup figure is still a character proxy (OQ-3).

## Context

Retrieved document chunks are attacker-controllable content — the **malicious document author is the primary threat actor** in this design ([THREAT_MODEL](../THREAT_MODEL.md)). The model must be told which part of its input is data rather than instruction.

Two families of technique exist. *Spotlighting by datamarking* interleaves a rare token — commonly `U+2581`, the SentencePiece word-boundary mark — between every word of the untrusted span, so the model can see the marking is continuous and an injected instruction cannot escape it by ending a delimiter early. *Delimiting* wraps the span in a boundary the attacker cannot predict. The constraints that decided it here:

- **The context budget is tight.** `SAGP_MAX_CTX_CHARS=7000`, `OLLAMA_CONTEXT_LENGTH=4096`, top-k 6 chunks of 320 tokens each. There is no slack for a multiplier.
- **The retrieval path re-scans.** At C19 the **assembled masked context** is scanned once by the injection classifier at threshold 0.90 with adjacent-window corroboration. The classifier is `protectai/deberta-v3-base-prompt-injection-v2` — an archived, unmaintained DeBERTa checkpoint trained on ordinary prose, whose own model card states it does **not** detect jailbreak attacks and does not handle non-English prompts.
- **There is no llama3 tokenizer in the runtime venv.** `tokenizers` cannot load a GGUF vocab, so the token cost of the assembled prompt is a character proxy, not a measurement (**OPEN QUESTION OQ-3**).

## Decision

**Datamarking is deleted. The untrusted-content boundary is a per-request nonce delimiter, and `src/sagp/rag/prompt.py` is the sole builder of the final prompt string.**

```python
# rag/prompt.py — the only place the final prompt is assembled
nonce = secrets.token_hex(8)          # 64 bits, fresh per request
block  = (f"<<<UNTRUSTED_DOCUMENT_{nonce}_S{i}>>>\n"
          f"{masked_chunk}\n"
          f"<<</UNTRUSTED_DOCUMENT_{nonce}_S{i}>>>")
```

Retrieved content goes in the **user** role, never the system role. The delimiter is not forgeable in advance: the nonce is generated after retrieval, so a document ingested yesterday cannot contain it, and guessing it within a request is a 64-bit guess. The heuristic layer additionally blocks the literal string `UNTRUSTED_DOCUMENT_` in a user prompt as `DELIMITER_SPOOF` → **400** at C4, and the output guard blocks at C22a if the nonce delimiter or a system-prompt n-gram appears in the model's response.

### Why datamarking lost

**1. Token blowup of 1.5–3× on a llama3 BPE.** Interleaving `U+2581` between every word of text tokenized by a byte-level BPE that was not trained on that pattern does not produce one extra token per word — it fragments the surrounding words too, because the marker breaks the byte sequences the merge table expects. Against `SAGP_MAX_CTX_CHARS=7000` and a 4096-token context, a 1.5–3× multiplier means either half the retrieved evidence is dropped or the closing delimiter is silently truncated away. (The 1.5–3× range is the figure carried from the source analysis; **no measurement exists on this host** — see OQ-3.)

**2. It pushes the retrieval re-scan out of the classifier's training distribution.** This is the disqualifying reason. C19 scans the *assembled* context. If that context is `▁word▁word▁word`, the classifier is being asked to score text that looks nothing like the prose it was fine-tuned on. Its scores on that input are not characterised, its threshold of 0.90 has not been calibrated on it, and the recall/precision/FPR that `make eval` computed at M6 would describe a different input distribution than the one in production. Datamarking would improve one defence (the model's ability to tell data from instruction) by degrading another (the classifier that is the actual detection control) by an unknown amount. On a system whose claim is that its guardrails are *measured* against a stated corpus, that trade is not available.

## Alternatives considered

| Option | Why it lost |
|---|---|
| **U+2581 datamarking of retrieved chunks** | 1.5–3× token blowup (an unmeasured range carried from the source analysis) against a 7000-char / 4096-token budget, and it moves the C19 re-scan input out of the classifier's training distribution, invalidating the thresholds the M6 evaluation is meant to calibrate. |
| **Datamark, then re-scan the *undatamarked* text** | Restores the classifier's distribution but means the string that was scanned is not the string that reached the model — breaking the one test that matters, `test_final_bytes_were_scanned`. The scanning boundary must be the generation boundary. |
| **A cheaper marker (e.g. a single ASCII char)** | Cheaper on tokens but still out-of-distribution for the classifier, and an ASCII marker is guessable by a document author, which is exactly what the per-request nonce is designed to defeat. |
| **Base64-encoding the retrieved chunks** | Unambiguously separates data from instruction, and unambiguously prevents the classifier from reading it. The C19 re-scan would be scanning base64. It also destroys the model's ability to quote and cite. |
| **A fixed delimiter string** | Forgeable. A document author who knows the delimiter writes a closing tag and an instruction after it, and the injected text is outside the untrusted span as far as the model is concerned. The nonce makes that a 64-bit guess per request. |
| **Retrieved content in the system role** | Grants attacker-controlled text the highest-trust position in the chat template. The opposite of the intent. |

## Consequences

### Positive
- The prompt costs what the text costs — the context budget is spent on evidence, not markers. The C19 re-scan sees ordinary prose, which is the distribution the M6 evaluation was run against, so the recall/precision/FPR that `make eval` computed — and that `docs/metrics/latest.json` now carries (headline injection recall 1.0; family F, the document-planted family, reported separately at 1.0) — describes production input.
- The delimiter is not forgeable in advance (a fresh 64-bit nonce per request), and forging attempts are designed to be caught on both sides: `DELIMITER_SPOOF` on ingress (C4 → 400) and nonce-leak detection on egress (C22a → refusal).
- One builder. `rag/prompt.py` is the sole assembler, so the output guard knows exactly which scheme was used and what to look for.

### Negative
- **Delimiters are a weaker instructional signal than continuous marking.** A sufficiently persuasive injection inside a correctly-delimited block can still be obeyed. The defence-in-depth answer is that the block was scanned at ingest (I7), the assembled context is scanned again at C19, and the output is structurally checked at C22a — not that the delimiter is trusted to hold.
- A model that ignores delimiter semantics entirely gets no protection from them. Nothing here measures how well `llama3.2:3b-instruct-q4_K_M` respects the boundary; that evaluation does not exist.
- **The token cost of the assembled prompt is a character proxy.** `SAGP_MAX_CTX_CHARS=7000` is not a token count (**OPEN QUESTION OQ-3**), so context-budget enforcement is approximate in either scheme.

### Neutral
- The chunk-dropping loop at C19 (drop the highest-scoring chunk, reassemble, rescan, max 2 iterations, then refuse) is unaffected by the choice of boundary marker.
- If a future model or classifier makes datamarking cheap and in-distribution, this ADR is the thing to supersede — the change is contained to `rag/prompt.py` and the C19 threshold calibration.

## Verification

```bash
# 1. The nonce is fresh per request and the delimiter cannot be forged.
.venv/bin/pytest tests/unit/test_prompt.py -q
#   test_nonce_unique_per_request     two builds -> different nonces
#   test_nonce_not_derivable          nonce absent from chunk text and from settings
#   test_prompt_hash_stable           same inputs + same nonce -> same string

# 2. No datamarking character may appear in an assembled prompt.
! grep -rn $'▁' src/sagp/rag/prompt.py

# 3. Ingress and egress both police the delimiter.
.venv/bin/pytest tests/integration/test_context_guard.py -q
#   DELIMITER_SPOOF in a user prompt        -> 400
#   nonce delimiter echoed in a completion  -> refusal.txt
```

Gates (implemented; `make smoke` reports 14/14): `make smoke` check `[10/14]` ingests `data/samples/poisoned_appendix.pdf` and requires its payload chunk to land in the `<collection>__quarantine` sibling. `make eval` reports the indirect / document-planted family (family F) **as its own category, never averaged into the headline recall number** — measured at 1.0 at M6. `tests/e2e/test_final_bytes_were_scanned.py` asserts that the exact string sent to Ollama was an argument to a `scan()` call in the same request — which is only a meaningful assertion because the scanned text and the generated text are the same bytes.

---

[ADR index](../ARCHITECTURE.md) · [ADR-0008: Normalized text is canonical](0008-normalized-canonical.md) · [Guardrails](../GUARDRAILS.md) · [Threat model](../THREAT_MODEL.md) · [Blueprint](../BLUEPRINT.md)
