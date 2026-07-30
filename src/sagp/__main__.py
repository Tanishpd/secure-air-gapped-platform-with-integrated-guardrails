"""``python -m sagp`` / the ``sagp`` console entrypoint.

The real launcher (uvicorn, single worker, loopback) lands with the FastAPI
gateway at M10. Until then this refuses to start and points at the supported
launch path, so nothing accidentally serves a half-built app.
"""

from __future__ import annotations

import sys


def main() -> int:
    sys.stderr.write(
        "sagp: no server yet — the FastAPI gateway lands at M10.\n"
        "The only supported launch path will be `bin/sagp-serve` "
        "(uvicorn --workers 1 --host 127.0.0.1) after `make seal`.\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
