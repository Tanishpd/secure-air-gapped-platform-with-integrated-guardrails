"""GET /airgap/status — the sealed system's own view of its lifecycle state.

Reports the phase, seal generation, manifest root hash, and whether the in-process
egress guard is armed — the facts an operator (or a paired off-box monitor) checks
to confirm the box is where it should be. Authenticated (any valid token); it
exposes no secret, only configuration identity.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from sagp.app.deps import get_engines, get_principal
from sagp.netguard import egress
from sagp.netguard.phase import current_phase, read_state
from sagp.types import Principal

router = APIRouter()


@router.get("/airgap/status")
def airgap_status(
    request: Request,
    principal: Principal = Depends(get_principal),  # C0 — any valid token
) -> dict[str, object]:
    engines = get_engines(request)
    state = read_state(engines.root)
    return {
        "phase": current_phase(engines.root).value,
        "seal_generation": state.get("seal_generation", 0),
        "manifest_root_hash": engines.provenance.manifest_root_hash,
        "guard_armed": egress.is_installed(),
    }
