"""The append-only, hash-chained audit sink.

Each record links to the previous one via ``prev_hash``; its own ``chain_digest``
is SHA-256 over the canonical JSON of every field except ``chain_digest`` (so it
binds the semantic content *and* the link). The head digest is held in memory and
recovered from the last line on init, so a restart continues the same chain.

Every write is scrubbed first (``assert_no_raw_values``) and fsynced. A scrub
violation does not silently drop the event: a content-free ``scrub_violation``
record is written in its place and the exception re-raised (fail closed).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

from sagp.audit.events import AuditEvent
from sagp.audit.hashing import GENESIS, canonical_json, chain_digest
from sagp.audit.scrub import ScrubViolation, assert_no_raw_values


class AuditSink:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._head = self._read_head()

    def _read_head(self) -> str:
        if not self.path.exists():
            return GENESIS
        last: str | None = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last = stripped
        if last is None:
            return GENESIS
        import json

        return str(json.loads(last)["chain_digest"])

    @property
    def head(self) -> str:
        return self._head

    def _write_record(self, record: dict[str, object]) -> str:
        record["prev_hash"] = self._head
        digest = chain_digest(record)
        record["chain_digest"] = digest
        line = canonical_json(record).decode("utf-8")
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._head = digest
        return digest

    def append(self, event: AuditEvent) -> str:
        """Scrub, chain, fsync. Returns the new chain head. Raises on scrub failure."""
        with self._lock:
            record = event.model_dump()
            try:
                assert_no_raw_values(record)
            except ScrubViolation:
                # Persist a content-free marker so the incident is visible, then fail closed.
                marker = AuditEvent(
                    event_type="scrub_violation",
                    request_id=event.request_id,
                    timestamp=event.timestamp,
                    decision="unavailable",
                    reason_code="scrub_violation",
                    incident_id=event.incident_id,
                ).model_dump()
                self._write_record(marker)
                raise
            return self._write_record(record)
