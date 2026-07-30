"""AuditEvent is a closed, immutable schema."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sagp.audit.events import AuditEvent


def _event(**kw: object) -> AuditEvent:
    base: dict[str, object] = {
        "event_type": "chat",
        "request_id": "req1",
        "timestamp": "2026-07-30T00:00:00Z",
        "decision": "allow",
    }
    base.update(kw)
    return AuditEvent(**base)  # type: ignore[arg-type]


def test_minimal_event_ok() -> None:
    e = _event()
    assert e.schema_version == 1
    assert e.entity_types == {}


def test_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        _event(raw_prompt="secret text")  # closed schema (invariant 1)


def test_event_is_frozen() -> None:
    e = _event()
    with pytest.raises(ValidationError):
        e.decision = "block"  # type: ignore[misc]


def test_bad_enum_rejected() -> None:
    with pytest.raises(ValidationError):
        _event(decision="maybe")
    with pytest.raises(ValidationError):
        _event(event_type="debug")


def test_entity_types_are_counts() -> None:
    e = _event(entity_types={"EMAIL_ADDRESS": 2, "PERSON": 1}, pii_tokens=("abcd", "ef01"))
    assert e.entity_types["EMAIL_ADDRESS"] == 2
    assert e.pii_tokens == ("abcd", "ef01")
