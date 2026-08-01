"""GET /v1/admin/incident/{id} — the authenticated review path (scope: pii:reveal).

Invariant 8 keeps every score, count, entity type, and detector identity OUT of
the client-facing 400 (which is a byte-identical opaque body). The detail is not
lost — it lives in the hash-chained audit record and, for a rejection, the raw
bytes live in the quarantine store. This route is the ONLY way back to them, and
it is gated on the ``pii:reveal`` scope (there is no ``admin`` scope — invariant 8).

Returns the audit record(s) written under the incident id (types/counts/scores,
never raw values) plus, if a rejection quarantined the prompt, the raw text — the
one place a pii:reveal holder can see what was blocked.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from sagp.app.deps import Engines, get_engines, get_principal
from sagp.audit.quarantine import quarantine_path
from sagp.errors import AuthError
from sagp.types import Principal

router = APIRouter()


def _audit_records_for(engines: Engines, incident_id: str) -> list[dict[str, Any]]:
    if engines.audit is None or not engines.audit.path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in engines.audit.path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("incident_id") == incident_id:
            out.append(rec)
    return out


@router.get("/v1/admin/incident/{incident_id}")
def incident(
    incident_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),  # C0
) -> dict[str, Any]:
    if not principal.has_scope("pii:reveal"):
        raise AuthError("token lacks the pii:reveal scope")
    engines = get_engines(request)

    records = _audit_records_for(engines, incident_id)
    qpath = quarantine_path(engines.root, incident_id)
    raw_text: str | None = None
    if qpath.exists():
        raw_text = json.loads(qpath.read_text(encoding="utf-8")).get("raw_text")

    if not records and raw_text is None:
        raise HTTPException(status_code=404, detail="unknown incident")

    return {
        "incident_id": incident_id,
        "quarantined": raw_text is not None,
        "raw_text": raw_text,  # the offending prompt — pii:reveal only
        "audit_records": records,
    }
