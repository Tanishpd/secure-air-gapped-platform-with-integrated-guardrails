# ADR-0006: `ingest_mode=raw` — store raw chunk text, mask at retrieval

Records why the vector store holds unmasked document text, why masking at ingest was deleted rather than made optional, and the compliance consequence that follows.

- **Status:** Accepted — implemented (M8 ingestion, M10 retrieval masking, M12 document scan)
- **Date:** 2026-07-27 (decision); 2026-08-01 (implemented)
- **Deciders:** Project architect
- **Supersedes:** —

## Context

Documents ingested from `data/private/` contain real personal data. There are exactly two places the masking could happen: once at ingest, so the store never holds PII, or per request at retrieval, so the store holds PII but nothing masked ever reaches the LLM unmasked. The source specs shipped both, as a configurable `ingest_mode`.

The forces:

- **Placeholders are per-request ordinals.** `<PERSON_1>` means "the first PERSON in this request" ([ADR-0005](0005-vault-request-scoped.md)). It is not an identifier.
- **Retrieval is dense and semantic.** Queries are embedded with `BAAI/bge-small-en-v1.5` (CLS pooling → L2 normalize, 384-d, `Distance.COSINE`) and the query prefix is applied to queries only. Similarity is computed between a query vector and a chunk vector.
- **The query is not masked before embedding.** C13 embeds `neutral` — the unmasked, normalized query — precisely because masked queries destroy recall.
- **Ingest already scans.** I6 runs Presidio at the INGRESS profile (0.50) per chunk and records entity **types and counts** into the point payload. I7 injection-scans every chunk. Nothing is stored blind.

Two failures make `ingest_mode=masked` unshippable rather than merely worse.

**1. Placeholder collision across identities.** A masked corpus needs a *persistent* vault to be readable. A persistent vault and the per-request vault both mint `<PERSON_1>`. Chunk A stored at ingest says `<PERSON_1>` meaning Priya Sharma; the current request's vault says `<PERSON_1>` meaning Rahul Verma. Rehydration then attributes one person's data to another. There is no reconciliation that does not amount to building the persistent identity index this design refuses to build.

**2. Retrieval collapses.** With masked chunks, the corpus vector for "Priya Sharma's parental leave entitlement" is the vector for "`<PERSON_1>`'s parental leave entitlement". The user's raw query embeds the real name. The lexical and semantic signal the name carried is gone from the corpus side and present on the query side — a systematic train/serve mismatch on every name-bearing query. Recall drops and there is no threshold that recovers it, because the information was destroyed at write time.

## Decision

**`ingest_mode=raw` is the shipped and only behaviour. `ingest_mode=masked` is deleted from the design — not defaulted off, deleted.** Chunks are stored with their real text; PII masking happens at **retrieval**, at C17, into the same request-scoped vault the prompt already populated.

Specifics:

| Stage | Behaviour |
|---|---|
| I6 (ingest) | `analyze` at INGRESS 0.50 per chunk → record `entity_types_counts` into the payload. **No masking. The BLOCK list is NOT applied** — a document legitimately containing a card number must be storable. |
| I8 (ingest) | Injection verdict routes the chunk: `quarantined` → the per-collection `<collection>__quarantine` sibling (never retrieved), otherwise the main collection. |
| C14 (retrieval) | `query_points(..., query_filter=must_not guard.verdict == "quarantined")`. |
| C17 (retrieval) | `BatchAnalyzerEngine.analyze_iterator(chunks, "en", batch_size=6, n_process=1)` at the EGRESS profile (0.35), then `anonymize` each with the **same vault**, `origin=f"doc:{sha}"`. **The BLOCK list is NOT applied to chunks** — a blocked retrieval would be a document-content oracle. |

The EGRESS threshold of 0.35 is used for chunks deliberately: on the retrieval path a miss is a leak into the prompt, so the layer is tuned permissive. It **will** over-mask, and the over-masking rate must be measured (**OPEN QUESTION OQ-10**) rather than assumed acceptable.

## Alternatives considered

| Option | Why it lost |
|---|---|
| **`ingest_mode=masked`** | Placeholder collision across identities and a systematic raw-query-vs-masked-corpus mismatch. Both are described above; either alone is disqualifying. |
| **Keep both modes, default to `raw`** | An unshippable mode behind a flag is a trap. It would need its own tests, its own persistent vault, and its own audit semantics, and the first operator to set it would get silently wrong retrieval and cross-linked identities. `CLAUDE.md` invariant 6 — never let an `except` silently disable a guardrail; there is exactly one fail mode, and it is closed — applies to configuration surface generally. |
| **Store raw text, embed masked text** | Splits the two things that must agree. The vector would describe a document the payload does not contain, and the query vector still embeds real names. Worst of both. |
| **Store masked text plus an encrypted sidecar of the mapping** | This is the persistent vault with an extra key-custody problem attached. The key that decrypts the sidecar reverses the whole corpus, and it has to live on the same sealed box. |
| **Do not store document text at all — vectors only** | Kills citation and grounding. The answer must quote supplied blocks, and `[Sn, p.X]` markers are range-checked against them at C22d. |
| **Encrypt the payload text at rest inside Qdrant** | The application would hold the key in the same process, so it protects against an offline copy of `data/qdrant/` and nothing else. Full-disk encryption (FileVault) already covers that case, at the OS layer, without a key this application has to manage. Reconsider only if the store moves off-host. |

## Consequences

### Positive
- Retrieval quality is preserved. Names, employers, locations and identifiers all remain in the corpus vectors, which is where the semantic signal for most real questions lives.
- One masking path, one vault, one set of placeholders per request. The prompt and the retrieved chunks are anonymized into the same vault, so a person named in both gets one consistent placeholder.
- Ingest keeps full-fidelity evidence for admin review. A quarantined chunk can be inspected as it actually was.
- Erasure is tractable: `delete_by_source` on `doc_sha256` removes a document's real text outright, which is a more honest GDPR Art. 17 story than "we masked it, probably".

### Negative
- **The vector store contains real personal data.** It is protected by loopback binding, filesystem permissions (`0700`/`0600`) and FileVault — **not by the guardrail**. Copying `data/qdrant/` off the box leaks the corpus with no control in the path. This is [LIMITATIONS](../LIMITATIONS.md) item 11 and it must appear in [COMPLIANCE.md](../COMPLIANCE.md) as a stated fact, not a footnote.
- Masking cost moves to the hot path: a Presidio batch analysis of 6 chunks on every request, inside the 3000 ms PII timeout, with a 503 on exception.
- Presidio recall is not 100%. A miss at C17 is a real value entering the prompt. There is no second chance at ingest, because ingest deliberately did not mask.
- The egress threshold of 0.35 sits below the `LemmaContextAwareEnhancer` floor of 0.40 and will over-mask retrieved text, occasionally degrading answers.

### Neutral
- Ingest records entity types and counts but no values, so the payload is queryable for "which documents contain card numbers" without storing any.
- The BLOCK list applies only to the user prompt (C10), never to documents (I6, C17). A document may legitimately contain what a prompt may not.

## Verification

```bash
# 1. The store really does hold raw text — assert it, do not assume it.
.venv/bin/pytest tests/integration/test_ingest_pipeline.py -q -k raw_text_stored

# 2. The prompt that reached the LLM does not.
make ingest FILE="data/samples/employee_handbook.pdf" COLLECTION=handbook
make query Q="What is the parental leave policy?"
# audit record: masked_prompt_sha256 present; retrieved_point_ids present; no values anywhere

# 3. The masked mode must not exist anywhere in the tree.
! grep -rn "ingest_mode" src/ config/ | grep -qi masked
```

Gates (implemented; `make smoke` reports 14/14): `make smoke` check `[12/14]` asserts the prompt sent to Ollama contains `<EMAIL_ADDRESS_1>` and not the address; check `[14/14]` greps the audit JSONL **bytes** for PII markers. `tests/e2e/test_final_bytes_were_scanned.py` asserts the exact string sent to Ollama was an argument to a `scan()` call in the same request — the one test that asserts on the bytes that actually crossed the boundary. `make eval` ran at M6 and **measured** PII recall at **1.0** for every enforced floor (EMAIL ≥ 0.98, CREDIT_CARD ≥ 0.98, IN_AADHAAR ≥ 0.95, PERSON ≥ 0.80 — all met); from the second run onwards it fails the build on any metric more than 2pp below the previous baseline in `docs/metrics/latest.json`, which now exists. (No PII recall floor is asserted for Devanagari or transliterated names — OQ-9, still unevaluated.)

---

[ADR index](../ARCHITECTURE.md) · [ADR-0005: Request-scoped vault](0005-vault-request-scoped.md) · [Threat model](../THREAT_MODEL.md) · [Limitations](../LIMITATIONS.md)
