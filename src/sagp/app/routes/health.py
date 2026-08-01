"""Liveness and readiness."""

from __future__ import annotations

from fastapi import APIRouter, Request

from sagp.app.deps import get_engines
from sagp.version import __version__

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


def _process_rss_mb() -> float | None:
    """Measured RSS of THIS process (all engines share one — invariant 11: one
    worker). True per-component RSS is not separable within a single process; the
    per-profile breakdown lives in netguard/budget.py as a PROJECTION."""
    try:
        import psutil  # type: ignore[import-untyped]

        mb: float = round(psutil.Process().memory_info().rss / (1024 * 1024), 1)
        return mb
    except Exception:  # noqa: BLE001 — /readyz must not fail on a metrics hiccup
        return None


@router.get("/readyz")
def readyz(request: Request) -> dict[str, object]:
    engines = get_engines(request)
    return {
        "status": "ready",
        "llm_model": engines.settings.llm_model,
        "policy_sha256": engines.policy.sha256,
        "process_rss_mb": _process_rss_mb(),  # MEASURED (whole process, one worker)
    }
