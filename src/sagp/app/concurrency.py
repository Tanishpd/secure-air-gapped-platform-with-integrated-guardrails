"""The guardrail concurrency cap (invariant 11).

The sync request path (Presidio + spaCy + two ONNX sessions) is CPU-bound: each
guardrail evaluation runs ONNX inference at ``intra_op_num_threads=4``. Left to
FastAPI's default ~40-thread pool, a burst of concurrent requests spawns dozens
of parallel inferences that thrash an 8-core M2 — measured with ``make
bench-load``: injection-reject latency ballooned ~7× (≈0.8 s → p95 ≈6 s) under
concurrency 8. Worse, unbounded CPU/RAM pressure is the exact condition that lets
macOS evict the idle guardrail models to swap — a security property, not just
slowness.

So model-bound work is offloaded through a single shared ``CapacityLimiter(2)``
(never the default pool): at most two guardrail evaluations run at once, leaving
cores for Ollama; excess requests queue rather than thrash. Two, not one, so a
cheap reject need not wait behind a slow one; not more, because a second uvicorn
worker is already forbidden (invariant 11) and four concurrent inferences over-
subscribe the cores.
"""

from __future__ import annotations

import anyio

from sagp.errors import ServiceBusy

# Created at import (anyio binds it to a loop lazily, on first use). One instance,
# shared by every request, is the whole point — a per-request limiter caps nothing.
_GUARDRAIL_LIMITER = anyio.CapacityLimiter(2)


def guardrail_limiter() -> anyio.CapacityLimiter:
    return _GUARDRAIL_LIMITER


class AdmissionGate:
    """Bounded in-flight admission control (backpressure).

    The ``CapacityLimiter(2)`` caps how many guardrail evaluations RUN at once;
    this caps how many may be *waiting* for it before the server sheds load. Under
    a burst, the first few requests queue and the rest get a fast **503
    ``ServiceBusy``** instead of every request degrading to multi-second latency
    (measured with ``make bench-load``). Graceful degradation, not collapse.

    Counter lives in the single event loop, so ``acquire``/``release`` need no lock
    — they are called synchronously in the async route, never from the worker
    threads. Always release in a ``finally``.
    """

    def __init__(self, max_in_flight: int) -> None:
        self._max = max_in_flight
        self._in_flight = 0

    def acquire(self) -> None:
        """Admit one request or raise ``ServiceBusy`` (503) if at capacity."""
        if self._in_flight >= self._max:
            raise ServiceBusy("server at capacity; retry shortly")
        self._in_flight += 1

    def release(self) -> None:
        self._in_flight = max(0, self._in_flight - 1)

    @property
    def in_flight(self) -> int:
        return self._in_flight
