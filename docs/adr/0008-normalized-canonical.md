# ADR-0008: Normalized text is canonical on ingress; egress fails closed; no offset map exists

Records the resolution of the normalization seam — the point where a text has two representations and something has to map between them — by removing the mapping entirely.

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Project architect
- **Supersedes:** —

## Context

Every guardrail in this system needs normalized text. `guardrails/normalize.py` is shared by the PII and injection layers and does five things in a fixed order: record-and-remove tag chars (`U+E0000`–`U+E007F`) and bidi overrides (`U+202A`–`U+202E`, `U+2066`–`U+2069`) — both **block outright**; strip the `STRIP_CF` set (`U+00AD`, `U+200B`–`U+200F`, `U+2060`–`U+2064`, `U+180E`, `U+FEFF`) and flag `ZERO_WIDTH`, never blocking on those alone; `unicodedata.normalize("NFKC", s)` and flag `NFKC_CHANGED`; homoglyph-fold via an explicit table (Cyrillic/Greek/fullwidth → Latin, **not** `unidecode`); collapse whitespace runs to a single `U+0020`. It returns `(normalized, flags)`.

Every one of those steps changes string length. `U+00AD` disappears; NFKC expands ligatures and folds fullwidth forms; whitespace runs collapse. So a Presidio result at offset 412 in the normalized string does **not** point at offset 412 in the raw string.

The classic answer is an offset map: normalize, analyze, then translate spans back to raw coordinates to anonymize the original. That answer produces a specific and nasty bug class. An off-by-one in the map does not throw — it slices one character to the side of an email address and emits a masked prompt with a stray `a` where the local part began, or leaves a digit of a card number in place. The failure is silent, data-dependent, and only visible by reading output.

There is a second, non-obvious asymmetry: **the model's output is not the user's input.** On egress, the raw text is what was actually generated and what the caller expects to receive; on ingress, the raw text is attacker-controlled and normalizing it is the *point*.

## Decision

**Ingress: the normalized string is canonical. Presidio analyzes and anonymizes the normalized string, and the masked normalized string is what proceeds.** The raw prompt is never re-derived, never re-masked, and never sent anywhere. Its sha256 goes into the audit record and that is all.

Order on the ingress path is fixed and load-bearing:

| Step | Why it is where it is |
|---|---|
| C3 `normalize()` | `TAG_CHARS` or `BIDI_OVERRIDE` in flags → **400**, immediately |
| C8 `neutralize_placeholders()` — **after** normalize | NFKC folds fullwidth `＜` (U+FF1C) to `<`, so neutralizing first is trivially bypassable |
| C9 `analyze(neutral, INGRESS 0.50)` · C12 `anonymize(neutral, ...)` | both on the normalized string the offsets came from |

`neutralize()` and `rehydrate()` import the **same** `PLACEHOLDER_RE` constant from `placeholders.py`; a property test is specified to assert that anything `rehydrate` matches, `neutralize` also matches.

**Egress: analyze the raw response, and fail closed on divergence.** C22b runs `analyze(response_raw, EGRESS 0.35)` → `anonymize` with the same vault → `masked_response`. C22c then runs `analyze(normalize(response_raw), EGRESS 0.35)`; if it finds **more** entities than C22b, the response is **blocked** and `refusal.txt` is returned.

C22c is the whole trick. The dangerous case is a response whose raw form hides PII that only normalization reveals — a homoglyph in an email address, a zero-width character splitting a card number. Detecting that case needs no offset map, because the response is not *repaired*: it is **refused**. The comparison is a count, and the action is a hard block.

**No offset map exists anywhere in the codebase.** This is stated as an invariant, not a current implementation detail.

## Alternatives considered

| Option | Why it lost |
|---|---|
| **Build an offset map and mask the raw text** | The offset-corruption bug class: silent, off-by-one, data-dependent, invisible except by reading output. Every normalization step is a separate opportunity for the map to drift, and the failure mode is *partially* unmasked PII — worse than either extreme. |
| **Analyze the raw text, skip normalization on the PII path** | The original bug the shared normalizer exists to fix. Presidio on raw text misses a homoglyph-spelled email and a zero-width-split card number, so the masking layer is bypassed by a single character. |
| **Normalize only for the injection classifier, keep PII on raw** | Two normalizers, two behaviours, and the same raw-text miss above. The point of one shared `normalize.py` is that the two layers cannot disagree about what the text is. |
| **Normalize the response and return the normalized form** | The caller gets back text the model did not write — ligatures expanded, whitespace collapsed. On egress the raw form is the deliverable; normalization is used to *detect*, not to *rewrite*. |
| **Repair the divergent response by masking the normalized form** | Requires exactly the offset map this ADR removes, in the harder direction. Blocking is a one-line decision with no mapping and a deterministic, auditor-testable outcome. |
| **Block all `Cf` characters outright** | `U+00AD`, `U+200C` and `U+200D` are required for PDF paste and for Indic and Arabic scripts — the stated user base. Only tag chars and bidi overrides block outright; the rest are stripped and flagged. |

## Consequences

### Positive
- An entire bug class is gone by construction. There is no map, so it cannot be wrong.
- Both guardrail layers see byte-identical text, so a payload cannot hide in the gap between what the classifier scanned and what Presidio analyzed.
- The egress divergence check is fail-closed and needs no coordinate translation: two counts, one comparison, one refusal. C8 sits after C3, closing the fullwidth-`＜` placeholder-spoofing bypass.

### Negative
- **The masked prompt is not character-identical to what the user typed.** Whitespace collapsed, ligatures expanded, homoglyphs folded — visible if a caller diffs `prompt_sha256` against their own input, and it must be documented rather than surprising.
- The egress check runs Presidio **twice** on the response — once raw, once normalized — inside the 3000 ms PII budget.
- A benign response containing, say, a fullwidth email address is refused rather than masked. Fail-closed costs availability, and the false-refusal rate on the corpus has **not been measured**; no figure is claimed here.
- Only *more* entities triggers the block. A normalization yielding the same count but different spans is not caught, because catching it would require the comparison this ADR declines to build.

### Neutral
- `normalize()` returns flags, so `NFKC_CHANGED` and `ZERO_WIDTH` reach `normalize_flags` on every audit record whether or not they blocked. Homoglyph folding uses a reviewable explicit table, not `unidecode`, and does not transliterate whole scripts.

## Verification

```bash
# No offset map, anywhere. This is an invariant, so grep for it.
! grep -rniE 'offset_map|offsets_to_raw|map_span|raw_offset' src/sagp/

# Unicode fixtures: tag chars and bidi block; Indic/Arabic ZWJ/ZWNJ must NOT block.
.venv/bin/pytest tests/unit/test_normalize.py -q
#   test_tag_chars_block            U+E0041... -> 400
#   test_bidi_override_blocks       U+202E     -> 400
#   test_zwnj_hindi_does_not_block  U+200C in Devanagari -> allowed, flagged ZERO_WIDTH
#   test_soft_hyphen_stripped_only  U+00AD     -> allowed, flagged

.venv/bin/pytest tests/unit/test_placeholders.py -q            # rehydrate ⊆ neutralize
.venv/bin/pytest tests/integration/test_output_guard.py -q -k divergence   # fails closed
```

Gates (specifications — no make target or test exists yet): `make smoke` check `[13/14]` is specified to require a normalization-triggered rejection to return the uniform 400 body with an `incident_id` and at least 120 ms of latency. `tests/security/test_oracle_uniformity.py` is specified to assert that every detector — normalization, heuristics, classifier, PII BLOCK-list — produces a byte-identical response and the same timing floor, so that a caller cannot tell C3 from C10.

---

[ADR index](../ARCHITECTURE.md) · [ADR-0009: No datamarking](0009-no-datamarking.md) · [Guardrails](../GUARDRAILS.md) · [Threat model](../THREAT_MODEL.md)
