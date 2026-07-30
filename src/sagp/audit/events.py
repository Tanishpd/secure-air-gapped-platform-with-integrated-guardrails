"""The closed audit event schema.

``AuditEvent`` is **closed** (``extra="forbid"``) and **immutable**
(``frozen=True``): it carries entity TYPES and COUNTS, injection VERDICTS and
SCORES, per-stage latencies, and the policy hashes that produced a decision —
**never a raw prompt, completion, retrieved chunk, PII value, or vault mapping**
(invariant 1). Offending text lives in the quarantine store, referenced only by
``incident_id``.

Adding a field here is one of the three edits a new guardrail signal requires
(the others: a ``docs/COMPLIANCE.md`` row and a ``test_audit_no_pii.py`` case).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

EventType = Literal["chat", "ingest", "reject", "startup", "key_rotation", "scrub_violation"]
Decision = Literal["allow", "block", "refuse", "unavailable", "unsupported"]


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    event_type: EventType
    request_id: str
    timestamp: str  # ISO-8601 UTC, set by the caller/sink
    decision: Decision
    reason_code: str | None = None

    # Reference to quarantined raw text (the ONLY link to offending content).
    incident_id: str | None = None

    # Detector detail — types + counts + correlation tokens ONLY, never values.
    entity_types: dict[str, int] = Field(default_factory=dict)
    pii_tokens: tuple[str, ...] = ()
    injection_verdict: str | None = None
    injection_score: float | None = None

    # Observability.
    stage_latencies_ms: dict[str, float] = Field(default_factory=dict)
    normalize_flags: tuple[str, ...] = ()

    # Replay provenance: which exact policy produced this decision.
    model: str | None = None
    manifest_root_hash: str | None = None
    guardrails_config_sha256: str | None = None
    entities_config_sha256: str | None = None
    system_prompt_sha256: str | None = None
