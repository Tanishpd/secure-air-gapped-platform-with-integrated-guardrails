"""Per-principal fixed-window rate limiter (C0)."""

from __future__ import annotations

import pytest

from sagp.app.ratelimit import RateLimiter
from sagp.errors import RateLimited


def test_allows_up_to_the_limit() -> None:
    rl = RateLimiter(3)
    for _ in range(3):
        rl.check("alice", now=100.0)  # same window


def test_blocks_over_the_limit() -> None:
    rl = RateLimiter(3)
    for _ in range(3):
        rl.check("alice", now=100.0)
    with pytest.raises(RateLimited):
        rl.check("alice", now=100.0)  # 4th in the window


def test_window_resets() -> None:
    rl = RateLimiter(2, window_s=60.0)
    rl.check("alice", now=0.0)
    rl.check("alice", now=0.0)
    with pytest.raises(RateLimited):
        rl.check("alice", now=30.0)  # still in the first window
    rl.check("alice", now=61.0)  # new window -> allowed again
    rl.check("alice", now=61.0)


def test_principals_are_independent() -> None:
    rl = RateLimiter(1)
    rl.check("alice", now=0.0)
    rl.check("bob", now=0.0)  # bob has his own bucket
    with pytest.raises(RateLimited):
        rl.check("alice", now=0.0)


def test_rate_limited_message_carries_no_count() -> None:
    rl = RateLimiter(1)
    rl.check("alice", now=0.0)
    with pytest.raises(RateLimited) as ei:
        rl.check("alice", now=0.0)
    # The 429 body must not be an abuse-measurement oracle: no count, no id.
    msg = str(ei.value)
    assert "alice" not in msg
    assert not any(ch.isdigit() for ch in msg)
