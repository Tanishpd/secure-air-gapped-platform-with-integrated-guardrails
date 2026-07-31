"""Liveness and readiness."""

from __future__ import annotations

from fastapi import APIRouter, Request

from sagp.app.deps import get_engines
from sagp.version import __version__

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/readyz")
def readyz(request: Request) -> dict[str, object]:
    engines = get_engines(request)
    return {
        "status": "ready",
        "llm_model": engines.settings.llm_model,
        "policy_sha256": engines.policy.sha256,
    }
