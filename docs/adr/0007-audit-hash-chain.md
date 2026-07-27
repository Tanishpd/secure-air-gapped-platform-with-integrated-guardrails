# ADR-0007: Hash-chained JSONL audit log — tamper-evident, not tamper-proof

Records the audit log's integrity design, the keyed-HMAC tokenisation that lets an auditor correlate identities without storing them, and the exact claim this construction does and does not support.

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Project architect
- **Supersedes:** —

## Context

Every guardrail decision must be recordable, and the record must be worth something to an auditor. Three forces shape it.

- **The log must never contain what it is auditing.** Prompts, completions, retrieved text, entity values and vault mappings are all forbidden. `AuditEvent` is therefore a **closed schema** (`extra="forbid"`, `frozen=True`) carrying only hashes, counts, scores, and identifiers.
- **An auditor's real question is correlational.** "Did this same identity appear in two different incidents?" cannot be answered from an ordinal placeholder — `<PERSON_1>` means "the first PERSON in this request" and carries zero information across requests. One source spec proposed HMAC-ing the *placeholder*, which hashes the ordinal and answers nothing.
- **Everything here is local.** The signing key is generated on the host it attests to; the clock is the local clock. No RFC 3161 timestamp authority is reachable offline, and no external anchor exists.
- **The spine is built at M2 — before any guardrail exists**, because a guardrail with nowhere to record its decision is untestable.

## Decision

**Append-only JSONL, one file per day (`audit/events-YYYYMMDD.jsonl`), mode `0600` in a `0700` directory, `fsync`ed on every write, with each record chained to its predecessor as `digest = chain_digest(prev_digest, canonical_json(body))`.**

`prev_digest` and `digest` are fields of the record; daily rotation writes a carry-over record so the chain crosses file boundaries. `verify.verify_chain()` returns `ChainReport(ok, first_bad_seq, reason)` — it reports *where* the chain breaks, not merely that it does. An audit write failure or a scrub failure makes the request fail (**503**, response not returned); the record is not optional.

**Correlation without storage.** `pii_token_hmacs` is a list of `hmac_token(key, f"entity:{entity_type}\x1f{normalize(entity_type, value)}")` — domain-separated by the `entity:` prefix and the `\x1f` unit separator, keyed by the audit HMAC key generated at provision (`scripts/provision/09_secrets.py`, mode `0600`). This lets an auditor join two incidents on the same identity **without the log ever containing the identity**, and without the token being reversible by anyone who does not hold the key. It is emphatically **not** a hash of the placeholder.

**The off-box head-digest export is the property this design depends on.** A hash chain detects insertion, deletion and reordering *only if the head is pinned somewhere the attacker cannot rewrite. An attacker with write access to `audit/` can recompute the entire chain from any point forwards and produce a self-consistent log.* The daily "export the ledger head digest off-box" step in [OPERATIONS.md](../OPERATIONS.md) is therefore not a nice-to-have — it is the step that makes the chain mean anything. Anchoring is documented, not implemented.

**Stated plainly: do not claim non-repudiation.** The signature is self-signed with an Ed25519 key generated on the attested host; timestamps come from the local clock. The chain makes reordering and deletion detectable. It does **not** make backdating detectable, and it does not bind a record to an identity that a third party can verify. Tamper-**evident**, not tamper-**proof**. See [LIMITATIONS](../LIMITATIONS.md) items 5–7.

### What a record carries

| Group | Fields |
|---|---|
| Identity | `seq`, `ts_local`, `request_id`, `incident_id \| None`, `event_type`, `principal_id` |
| Chain | `prev_digest`, `digest` |
| Provenance | `config_hash`, `manifest_root_hash`, `seal_generation`, `sagp_version`, `system_prompt_sha256`, `embed_model`, `embed_revision`, `llm_model` |
| Decision | `decision`, `stages`, `injection_score`, `heuristic_rule_ids`, `normalize_flags`, `truncated` |
| PII | `entity_types_counts`, `pii_token_hmacs`, `vault_size`, `rehydrated` |
| Content — **hashes only** | `prompt_sha256`, `masked_prompt_sha256`, `completion_pre_rehydrate_sha256`, `completion_returned_sha256`, `retrieved_point_ids` |
| Egress · Timing | `python_egress_attempts_blocked` · `total_ms` and per-stage `elapsed_ms` |

Offending text goes to `audit/quarantine.py`, referenced by `incident_id` only. Scores and counts never cross the API boundary — they are retrievable at `GET /v1/admin/incident/{id}`, which is gated on the `pii:reveal` scope (`SAGP_API_TOKEN_REVEAL`) — there is no `admin` scope; the three scopes are `chat`, `ingest`, `pii:reveal` — because returning them in an error body is a threshold hill-climbing oracle.

## Alternatives considered

| Option | Why it lost |
|---|---|
| **Plain append-only JSONL, no chain** | Deletion and reordering are undetectable. The chain costs one sha256 per record and turns "the log looks fine" into "the log is internally consistent from the last exported head". |
| **A Merkle tree over records** | Better for selective disclosure and inclusion proofs, but nobody here needs to prove inclusion of one record without revealing others, and it complicates streaming append and daily rotation. A linear chain matches the access pattern. |
| **HMAC of the placeholder (`<PERSON_1>`)** | Carries zero information. Placeholders are per-request ordinals; the HMAC of `<PERSON_1>` is the same constant in every request and correlates nothing. |
| **Store the entity value, encrypted** | Recreates the persistent-identity index [ADR-0005](0005-vault-request-scoped.md) and [ADR-0006](0006-ingest-mode-raw.md) exist to avoid, and puts a reversible key on the same box as the ciphertext. The HMAC answers the correlation question without the reversibility. |
| **RFC 3161 timestamping / an external transparency log** | Requires network. The host is sealed. This is precisely why backdating remains undetectable and why the limitation is stated rather than papered over. A syslog/SIEM sink fails for the same reason — it is an egress channel by definition. |
| **Open schema with `extra="allow"`** | The single most likely way raw PII enters the log is a well-meaning `extra` field. `extra="forbid"` plus `assert_no_raw_values()` makes that a startup or write-time failure instead of a quiet leak. |

## Consequences

### Positive
- Any deletion, reordering or in-place edit of records after the last exported head is designed to be detectable, and `first_bad_seq` is designed to say where.
- The log is intended to be safe to hand to an auditor: it carries hashes, counts and keyed tokens only, and `tests/unit/test_audit_no_pii.py` is specified to read the JSONL **bytes** and check exactly that (it has not been written or run). Correlation across incidents is possible for a key holder and not otherwise.
- Fail-closed: a write or scrub failure is specified to return 503 with the response not delivered. There is no "logged best-effort" path.

### Negative
- **The head-digest export is a manual operational step.** If it is skipped, the chain's evidential value reduces to "internally consistent", which an attacker with write access can manufacture.
- Rotating the audit HMAC key breaks correlation across the rotation boundary — old and new tokens for the same identity do not match, by construction.
- `fsync` per record costs latency on every request, including blocked ones. Local-clock timestamps mean backdating is undetectable.

### Neutral
- Audit plus evidence is budgeted at ~0.20 GB of disk for a first year of typical use (ESTIMATE — unmeasured). Daily rotation with a carry-over record keeps individual files small without breaking the chain.

## Verification

```bash
make audit-verify        # scripts/verify_audit.py -> audit.verify.verify_chain; exit 1 on any break

# The chain must detect a single mutated byte AT THE RIGHT INDEX, not merely fail.
.venv/bin/pytest tests/unit/test_audit_chain.py -q      # mutate one byte -> first_bad_seq == N
# The log must not contain raw values — asserted over BYTES, not parsed objects.
.venv/bin/pytest tests/unit/test_audit_no_pii.py -q     # hypothesis, reads the JSONL bytes

[ "$(stat -f '%Lp' audit)" = "700" ] && [ "$(stat -f '%Lp' audit/events-*.jsonl)" = "600" ]
```

Gates (specifications — no make target or test exists yet): `make smoke` check `[14/14]` is specified to verify the chain and grep the JSONL bytes for PII markers, with the smoke summary line printing the **ledger head**. A broken ledger chain is an **invalidating condition** for `make verify` — the verdict becomes `INVALID`, never `PASS`; `CLAUDE.md` invariant 13 (never mark a verification PASS when a negative control failed or a high-severity gap is open) governs that verdict. Separately, `CLAUDE.md`'s three-edits rule requires that adding any guardrail signal lands three edits in one commit: the `AuditEvent` field, a `docs/COMPLIANCE.md` row, and a `test_audit_no_pii.py` case.

---

[ADR index](../ARCHITECTURE.md) · [ADR-0005: Request-scoped vault](0005-vault-request-scoped.md) · [Operations](../OPERATIONS.md) · [Threat model](../THREAT_MODEL.md) · [Limitations](../LIMITATIONS.md)
