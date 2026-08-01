"""Per-principal fixed-window rate limiter (pipeline C0).

A single-process, in-memory counter keyed by principal id: at most
``rate_limit_per_min`` requests per rolling 60-second window. Over the limit
raises ``RateLimited`` → 429. Single-process is sufficient because the runtime is
one uvicorn worker (invariant 11); a second worker would need a shared store, but
there is never a second worker.

The window is a monotonic clock bucket, so it is immune to wall-clock steps. The
limiter never records a principal's *content*, only a count and a window start —
nothing here is PII (invariant 1).
"""

from __future__ import annotations

import threading
import time

from sagp.errors import RateLimited


class RateLimiter:
    def __init__(self, per_min: int, *, window_s: float = 60.0) -> None:
        self._per_min = per_min
        self._window_s = window_s
        self._lock = threading.Lock()
        # principal id -> (window_start_monotonic, count_in_window)
        self._buckets: dict[str, tuple[float, int]] = {}

    def check(self, principal_id: str, *, now: float | None = None) -> None:
        """Count one request for ``principal_id``; raise ``RateLimited`` if over."""
        t = now if now is not None else time.monotonic()
        with self._lock:
            start, count = self._buckets.get(principal_id, (t, 0))
            if t - start >= self._window_s:  # window elapsed -> reset
                start, count = t, 0
            count += 1
            self._buckets[principal_id] = (start, count)
            over = count > self._per_min
        if over:
            # The message carries no count or principal — the 429 body must not be
            # an abuse-measurement oracle any more than the 400 is a detector one.
            raise RateLimited("rate limit exceeded")
