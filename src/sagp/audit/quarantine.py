"""The quarantine store: where offending raw text goes.

When a request is rejected and the raw input matters for later review, the bytes
go **here**, in a file named by ``incident_id``, mode 0600 — and the audit record
references it by that id alone (invariant 1). Nothing correlates a quarantine file
to a principal or an entity except through the authenticated admin path.

The directory is gitignored and lives under ``audit/quarantine/``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


def quarantine_path(root: Path, incident_id: str) -> Path:
    return root / "audit" / "quarantine" / f"{incident_id}.json"


def write_quarantine(root: Path, incident_id: str, raw_text: str, *, kind: str = "prompt") -> Path:
    """Persist offending raw text under ``incident_id`` (0600). Returns the path."""
    path = quarantine_path(root, incident_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "incident_id": incident_id,
        "kind": kind,
        "captured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "raw_text": raw_text,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    path.chmod(0o600)
    return path
