"""The app factory + the exception→HTTP converter.

A single exception handler (registered on the app, never ``BaseHTTPMiddleware`` —
Starlette's ExceptionMiddleware would degrade a typed 400 into an opaque 500)
maps ``SagpError`` to its status. Every **detector** rejection returns the exact
same opaque body and is padded to the rejection deadline (invariant 8), so the
rejection surface is not a detector oracle. ``UnsupportedRequest`` (C1, a
pre-detector schema error) is the one 400 that is not padded and not uniform.
"""

from __future__ import annotations

import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from sagp.app.deps import Engines
from sagp.app.routes import admin, chat, health, ingest
from sagp.errors import PromptRejected, SagpError
from sagp.utils.ids import new_incident_id
from sagp.utils.timing import constant_time_floor
from sagp.version import __version__

_REJECTED_BODY = {
    "error": {
        "code": "PROMPT_REJECTED",
        "message": "Your request was rejected by the security policy.",
    }
}


def create_app(engines: Engines) -> FastAPI:
    app = FastAPI(title="sagp", version=__version__)
    app.state.engines = engines
    app.include_router(health.router)
    app.include_router(chat.router)
    app.include_router(ingest.router)
    app.include_router(admin.router)

    @app.middleware("http")
    async def _stamp_start(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.t0 = time.monotonic()
        return await call_next(request)

    @app.exception_handler(SagpError)
    def _handle_sagp_error(request: Request, exc: SagpError) -> JSONResponse:
        if isinstance(exc, PromptRejected):
            # Uniform opaque body, padded to the fixed rejection deadline. Reuse the
            # incident_id the route already minted (so the 400, the audit record, and
            # the quarantine file share one id); mint only if the route did not.
            t0 = getattr(request.state, "t0", time.monotonic())
            constant_time_floor(t0, engines.settings.rejection_deadline_ms)
            incident_id = exc.incident_id or new_incident_id()
            body = {"error": {**_REJECTED_BODY["error"], "incident_id": incident_id}}
            return JSONResponse(status_code=exc.status_code, content=body)
        # Non-detector errors (UNSUPPORTED, 401, 413, 429, 503): distinguishable, not padded.
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": str(exc)}},
        )

    return app
