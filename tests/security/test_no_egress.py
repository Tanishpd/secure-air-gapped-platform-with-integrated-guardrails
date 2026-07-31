"""The egress guard blocks non-loopback network access; loopback is allowed.

Each probe runs in a fresh guarded interpreter (the audit hook is permanent). A
BLOCKED result asserts on the ``EgressViolation`` type, never a generic
connection failure — "the connection failed" proves nothing (it fails identically
when the network is merely absent).
"""

from __future__ import annotations


def test_external_tcp_blocked(run_guarded) -> None:  # type: ignore[no-untyped-def]
    assert run_guarded("socket.create_connection(('1.1.1.1', 443), timeout=2)") == "BLOCKED"


def test_external_dns_blocked(run_guarded) -> None:  # type: ignore[no-untyped-def]
    assert run_guarded("socket.getaddrinfo('huggingface.co', 443)") == "BLOCKED"


def test_raw_socket_bypass_is_blocked_by_l2(run_guarded) -> None:  # type: ignore[no-untyped-def]
    # A raw _socket connect bypasses the L1 monkeypatch — the L2 audit hook catches
    # it. This is the bypass the blueprint flagged as unverified; here it is verified.
    verdict = run_guarded("import _socket; _socket.socket().connect(('1.1.1.1', 443))")
    assert verdict == "BLOCKED"


def test_loopback_dns_allowed(run_guarded) -> None:  # type: ignore[no-untyped-def]
    assert run_guarded("socket.getaddrinfo('localhost', 80)") == "ALLOWED"


def test_loopback_tcp_not_blocked(run_guarded) -> None:  # type: ignore[no-untyped-def]
    # Connecting to a closed loopback port is refused (OTHER), NOT EgressViolation —
    # proving the guard permits the loopback attempt.
    verdict = run_guarded("socket.create_connection(('127.0.0.1', 9), timeout=1)")
    assert verdict != "BLOCKED"
