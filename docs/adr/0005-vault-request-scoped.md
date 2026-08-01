# ADR-0005: The pseudonym vault is in-memory and request-scoped — and therefore the API is single-turn

Records why the placeholder↔value mapping never outlives a single HTTP request, what that forces about the chat contract, and the honest limit of `clear()` on a CPython heap.

- **Status:** Accepted — implemented (M4 vault, M10 chat lifecycle)
- **Date:** 2026-07-27 (decision); 2026-08-01 (implemented)
- **Deciders:** Project architect
- **Supersedes:** —

## Context

Masking replaces detected entities with ordinal placeholders — `<PERSON_1>`, `<EMAIL_ADDRESS_1>` — via a custom `VaultPlaceholder` operator registered with `presidio-anonymizer==2.2.364`. Something must hold the mapping from placeholder back to real value, because the same identity appearing twice in one request must get the same placeholder, and because a caller holding the `pii:reveal` scope can ask for the answer rehydrated. The forces:

- **The mapping is the most sensitive object in the system.** It is a literal index of real personal data joined to the tokens that stand for it. Every additional second it exists, and every additional place it exists, is exposure.
- **Placeholders are ordinals, not identifiers.** `<PERSON_1>` means "the first PERSON in *this* request". Two requests about two different people both produce `<PERSON_1>`.
- **Presidio's built-in `encrypt`/`decrypt` operators tie ciphertext to a long-lived key.** A key that survives the request is a key that can decrypt yesterday's logs.
- **The retrieval path must mask into the same vault as the prompt.** At C17 retrieved chunks are anonymized with `origin=f"doc:{sha}"` into the vault the prompt already populated, so a person named in both the question and a document gets one consistent placeholder. Alias resolution (`resolve_person_aliases`, longest-first, strict-subset, exactly-one-superset) is **same-origin only** and mints a fresh placeholder on ambiguity — over-masking is the correct failure; cross-linking two identities is not.

## Decision

**The vault is a plain in-process object, created per request and destroyed at the end of it. It is never persisted, never cached, never shared between requests, and never crosses a process boundary.**

```python
# guardrails/vault.py — the lifecycle, stated as a contract
vault = PiiVault(max_entries=settings.max_vault_entries)   # SAGP_MAX_VAULT_ENTRIES = 2000
try:
    ...  # C11 aliases -> C12 anonymize prompt -> C17 anonymize retrieved chunks
         # -> C22b anonymize response -> C23 rehydrate iff "pii:reveal" in principal.scopes
finally:
    vault.clear()                                          # C26 — unconditional
```

Consequences that follow directly and are therefore also decided here:

- **`POST /v1/chat` is single-turn.** The body is `{message: str, collection: str}`. A `messages` array of length > 1 is rejected with **400 `UNSUPPORTED`** at C1. Multi-turn would require the vault to survive between turns, which is the thing this ADR forbids.
- **Vault exhaustion is an attack, not a load condition.** Exceeding 2000 entries returns **400** at C12, on the same uniform rejection surface as every other block.
- **Rehydration is authorization-gated and never falls back.** C23 runs only if `"pii:reveal" in principal.scopes and SAGP_REHYDRATE_OUTPUT==1`; it is a single-pass `re.sub`, and an unknown placeholder is left **verbatim** rather than resolved against any global map. There is no global map.
- **The vault is unprintable and unpicklable.** `__repr__` and `__str__` leak nothing; pickling raises. `pii_token_hmacs` in the audit record are `HMAC(key, f"entity:{type}\x1f{normalize(type, value)}")` — never a hash of the placeholder, which would carry zero information.

**The honest note on `clear()`: it drops references, it does not scrub the heap.** Python strings are immutable and small strings are interned; there is no supported way to zero the bytes of a `str` in CPython. A core dump, a memory scraper, or a debugger attached to the live process recovers the mapping for as long as those pages remain unreclaimed. The mitigations are operational, not in-process: `ulimit -c 0`, no co-located untrusted processes, FileVault on the host. Do not describe the vault as "securely erased" — describe it as "not persisted". See [LIMITATIONS](../LIMITATIONS.md) item 12.

## Alternatives considered

| Option | Why it lost |
|---|---|
| **A persistent vault keyed by entity value** | Directly contradicts [ADR-0006](0006-ingest-mode-raw.md): a persistent vault plus a per-request vault collide on `<PERSON_1>` across identities. It is also a permanent, queryable index of every person the system has ever seen — the exact asset the design is trying not to create. |
| **Presidio `encrypt`/`decrypt` operators** | Ties ciphertext to a long-lived key. Anything that can read the audit log or a captured prompt and hold the key can reverse the masking retroactively. A request-scoped mapping cannot be applied to a request that already ended. |
| **Session-scoped vault (multi-turn chat)** | The genuinely tempting option, and the reason the API is single-turn. It requires cross-turn identity resolution ("is the `<PERSON_1>` in turn 3 the same person as in turn 1?"), a session store holding real PII for the session's lifetime, and an eviction policy. Deferred to v2 with the problem stated rather than half-solved. |
| **Deterministic pseudonyms, e.g. `HMAC(pepper, value)` truncated** | Stable placeholders across requests would enable correlation — which is exactly why they are rejected for the *prompt*: a stable token is a stable identifier, and the LLM sees it. The correlation need is real, so it is met in the audit record instead, by `pii_token_hmacs`, which never enters a prompt or a response. |
| **`SecureString` / `bytearray` + explicit zeroing** | Would let `clear()` mean something. Rejected because Presidio's analyzer and anonymizer APIs traffic in `str` throughout; the value would be copied into an ordinary string the moment it crossed into `analyze()`. It would buy a claim, not a property. |

## Consequences

### Positive
- The blast radius of a compromise **of the vault** is one in-flight request, not a corpus of identities. It is not a claim about the corpus: under `ingest_mode=raw` ([ADR-0006](0006-ingest-mode-raw.md)) the vector store holds real unmasked chunk text at rest, protected by loopback binding, filesystem permissions and FileVault — not by this design.
- No key custody problem for masking. There is no masking key to rotate, escrow, or lose. (The audit HMAC key and PII pepper are separate and never reverse anything.)
- Cross-request placeholder collision is impossible because placeholders are never compared across requests.
- The `finally: vault.clear()` at C26 means even a 503 on the audit write (C25) still drops the mapping.

### Negative
- **No multi-turn conversation.** The largest functional cost, and a design constraint rather than an oversight. It also means split-payload attacks across turns are out of scope *only because turns do not exist*.
- **The heap is not scrubbed.** `clear()` is a reference drop; the honest framing is above.
- Rehydration returns real PII to a caller authenticated by a shared bearer token on loopback, with no user identity, no RBAC and no TLS. Adequate for a single-tenant sealed box, inadequate for anything else ([LIMITATIONS](../LIMITATIONS.md) item 14).
- A person mentioned in two consecutive requests gets two unrelated placeholders, which reads oddly to a human operator.

### Neutral
- The 2000-entry cap is a resource bound as much as a security one. Alias resolution is deliberately conservative, and its over-masking rate must be measured on the corpus (**OPEN QUESTION OQ-10**) rather than assumed acceptable.

## Verification

```bash
# The vault must not be persistable, printable, or picklable.
.venv/bin/pytest tests/unit/test_vault.py -q
#   test_pickle_raises        pickle.dumps(vault) raises
#   test_repr_leaks_nothing   f"{vault}" and repr(vault) contain no stored value
#   test_cap_rejects          the 2001st entry raises -> 400 at C12

# The API contract that follows from it.
curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8000/v1/chat \
  -H "Authorization: Bearer $SAGP_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"a"},{"role":"user","content":"b"}]}'
# expect 400 (UNSUPPORTED)
```

Additional gates (implemented; `make smoke` reports 14/14): `tests/unit/test_audit_no_pii.py` is a hypothesis test that reads the audit JSONL **bytes** and asserts no stored value appears. `make smoke` check `[12/14]` asserts the prompt that reached Ollama contains `<EMAIL_ADDRESS_1>` and not the address; check `[14/14]` greps the audit bytes for PII markers. An AST test in `tests/security/` fails the build on any module-level or `lru_cache`d `PiiVault` instance — the vault must be constructed inside the request scope.

---

[ADR index](../ARCHITECTURE.md) · [ADR-0006: `ingest_mode=raw`](0006-ingest-mode-raw.md) · [ADR-0007: Audit hash chain](0007-audit-hash-chain.md) · [Threat model](../THREAT_MODEL.md) · [Limitations](../LIMITATIONS.md)
