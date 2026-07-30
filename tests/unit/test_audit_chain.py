"""Hash-chained sink: continuity, tamper detection at the right index, restart."""

from __future__ import annotations

from pathlib import Path

from sagp.audit.events import AuditEvent
from sagp.audit.sink import AuditSink
from sagp.audit.verify import verify_chain


def _event(i: int) -> AuditEvent:
    return AuditEvent(
        event_type="chat",
        request_id=f"req{i}",
        timestamp="2026-07-30T00:00:00Z",
        decision="allow",
        entity_types={"PERSON": i},
    )


def _log(tmp_path: Path) -> Path:
    return tmp_path / "audit" / "audit.jsonl"


def test_chain_verifies_clean(tmp_path: Path) -> None:
    sink = AuditSink(_log(tmp_path))
    for i in range(5):
        sink.append(_event(i))
    res = verify_chain(_log(tmp_path))
    assert res.ok, res.problem
    assert res.records == 5
    assert res.head == sink.head


def test_mutation_detected_at_right_index(tmp_path: Path) -> None:
    sink = AuditSink(_log(tmp_path))
    for i in range(5):
        sink.append(_event(i))
    lines = _log(tmp_path).read_text().splitlines()
    # Corrupt record index 2 by editing a semantic value in place.
    lines[2] = lines[2].replace('"req2"', '"reqX"')
    _log(tmp_path).write_text("\n".join(lines) + "\n")
    res = verify_chain(_log(tmp_path))
    assert not res.ok
    assert res.break_index == 2


def test_reorder_detected(tmp_path: Path) -> None:
    sink = AuditSink(_log(tmp_path))
    for i in range(4):
        sink.append(_event(i))
    lines = _log(tmp_path).read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]  # swap two records
    _log(tmp_path).write_text("\n".join(lines) + "\n")
    res = verify_chain(_log(tmp_path))
    assert not res.ok
    assert res.break_index == 1


def test_restart_continues_chain(tmp_path: Path) -> None:
    sink = AuditSink(_log(tmp_path))
    sink.append(_event(0))
    head1 = sink.head
    # New sink reads the head from disk and continues.
    sink2 = AuditSink(_log(tmp_path))
    assert sink2.head == head1
    sink2.append(_event(1))
    assert verify_chain(_log(tmp_path)).ok
