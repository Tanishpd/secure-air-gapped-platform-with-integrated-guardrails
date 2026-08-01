"""``python -m sagp`` → the uvicorn launcher.

Runs ONE worker bound to loopback (invariant 11). The app is
``bootstrap.create_serving_app``, whose lifespan runs the four boot gates
(manifest verify → RSS budget → build engines → self-test) before serving.

The supported entry point is ``bin/sagp-serve``, which exports the HF/Ollama env
BEFORE the interpreter starts (pydantic-settings loads too late for
``HF_HUB_OFFLINE`` to matter — BLUEPRINT ledger row 28). Invoking this module
directly still works but skips that pre-interpreter export.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    import uvicorn

    from sagp.app.bootstrap import create_serving_app

    host = os.environ.get("SAGP_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("SAGP_BIND_PORT", "8000"))
    # Single worker (invariant 11): a second worker doubles every model's RSS.
    uvicorn.run(create_serving_app(), host=host, port=port, workers=1, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
