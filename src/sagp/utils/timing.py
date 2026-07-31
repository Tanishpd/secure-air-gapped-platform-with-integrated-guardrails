"""Timing helpers: a stopwatch and the constant-time rejection floor.

``constant_time_floor`` pads a detector rejection to a fixed wall-clock deadline
so the rejection surface leaks no timing signal about which detector fired
(invariant 8). The 120 ms default is a placeholder — M13 calibrates it above the
slowest measured detector path via ``test_oracle_uniformity``.
"""

from __future__ import annotations

import time


class Stopwatch:
    def __enter__(self) -> Stopwatch:
        self._t0 = time.monotonic()
        self.elapsed_ms = 0.0
        return self

    def __exit__(self, *exc: object) -> None:
        self.elapsed_ms = (time.monotonic() - self._t0) * 1000.0


def constant_time_floor(start_monotonic: float, floor_ms: float) -> None:
    """Sleep until ``floor_ms`` have elapsed since ``start_monotonic`` (if not already)."""
    remaining = floor_ms / 1000.0 - (time.monotonic() - start_monotonic)
    if remaining > 0:
        time.sleep(remaining)
