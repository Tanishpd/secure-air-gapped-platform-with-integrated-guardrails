"""Invariant 1: raw PII never reaches the audit bytes.

The property test builds an audit event the way a guardrail would — entity TYPES
and COUNTS, plus HMAC correlation tokens for the values — writes it through the
real sink, then reads the JSONL **bytes off disk** and asserts no raw value and
no email/card pattern survived. The scrub test proves a smuggled raw value is
caught at write time rather than persisted.
"""

from __future__ import annotations

import json
import re
import tempfile
from collections import Counter
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sagp.audit.events import AuditEvent
from sagp.audit.hashing import hmac_token
from sagp.audit.scrub import ScrubViolation
from sagp.audit.sink import AuditSink

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
KEY = b"pepper"

# Cryptographic-hash / token fields: opaque hex by construction, never PII. A
# degenerate value (e.g. an all-zeros card) can coincidentally appear inside a
# zero-filled hash, so the semantic-content scan excludes them.
_HASH_FIELDS = {
    "prev_hash",
    "chain_digest",
    "pii_tokens",
    "manifest_root_hash",
    "guardrails_config_sha256",
    "entities_config_sha256",
    "system_prompt_sha256",
}


def _semantic_text(record_line: str) -> str:
    """Everything persisted EXCEPT the hash/token fields, read back off disk."""
    rec = json.loads(record_line)
    parts: list[str] = []
    for key, value in rec.items():
        if key in _HASH_FIELDS:
            continue
        if isinstance(value, dict):
            parts.extend(str(k) for k in value)
        elif isinstance(value, list):
            parts.extend(str(v) for v in value)
        elif value is not None:
            parts.append(str(value))
    return "\x1f".join(parts)


emails = st.lists(st.emails(), max_size=6)
cards = st.lists(st.from_regex(r"\A[0-9]{16}\Z"), max_size=6)


@given(emails=emails, cards=cards)
def test_raw_pii_never_reaches_the_bytes(emails: list[str], cards: list[str]) -> None:
    with tempfile.TemporaryDirectory() as d:
        log = Path(d) / "audit.jsonl"
        sink = AuditSink(log)
        counts = Counter({"EMAIL_ADDRESS": len(emails), "CREDIT_CARD": len(cards)})
        tokens = tuple(
            [hmac_token(KEY, "EMAIL_ADDRESS", e) for e in emails]
            + [hmac_token(KEY, "CREDIT_CARD", c) for c in cards]
        )
        sink.append(
            AuditEvent(
                event_type="chat",
                request_id="req",
                timestamp="2026-07-30T00:00:00Z",
                decision="block",
                entity_types={k: v for k, v in counts.items() if v},
                pii_tokens=tokens,
            )
        )
        text = _semantic_text(log.read_text(encoding="utf-8").strip())
        for value in [*emails, *cards]:
            assert value not in text, f"raw value leaked into the audit content: {value!r}"
        assert not _EMAIL.search(text), "an email pattern reached the audit content"
        assert not _CARD.search(text), "a card pattern reached the audit content"


def test_scrub_catches_smuggled_value(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    sink = AuditSink(log)
    smuggled = AuditEvent(
        event_type="reject",
        request_id="req",
        timestamp="2026-07-30T00:00:00Z",
        decision="block",
        reason_code="user typed alice@example.com",  # a raw value in a str field
    )
    with pytest.raises(ScrubViolation):
        sink.append(smuggled)
    # A content-free scrub_violation marker was written in its place, and it leaks nothing.
    data = log.read_bytes().decode("utf-8")
    assert "scrub_violation" in data
    assert "alice@example.com" not in data
