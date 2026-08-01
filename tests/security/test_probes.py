"""The M13 proof probes: egress probes block, positive controls pass, and the
sealed-vs-stock email contrast proves the sealed constructor (not a warm cache)
is what prevents the phone-home. Each runs in a fresh guarded interpreter."""

from __future__ import annotations

import pytest

from sagp.netguard import probes as pb


@pytest.mark.parametrize("name", list(pb.EGRESS_PROBES))
def test_egress_probes_are_blocked(name: str) -> None:
    r = pb.run_probe(pb.EGRESS_PROBES[name])
    assert r.outcome == "blocked", f"{name}: {r.outcome} ({r.detail})"
    assert r.violations >= 1


@pytest.mark.parametrize("name", ["loopback_tcp", "loopback_getaddrinfo", "loopback_httpx"])
def test_positive_controls_are_allowed(name: str) -> None:
    # Loopback traffic the guard must permit — so a blocked egress probe is not
    # just "the network is gone". (subprocess_ollama needs ollama on PATH; the
    # unix control needs a temp bind — both covered by the security suite.)
    r = pb.run_probe(pb.POSITIVE_CONTROLS[name])
    assert r.outcome == "allowed", f"{name}: {r.outcome} ({r.detail})"
    assert r.violations == 0


def test_loopback_unix_positive_control() -> None:
    r = pb.run_probe(pb.POSITIVE_CONTROLS["loopback_unix"])
    assert r.outcome == "allowed", r.detail
    assert r.violations == 0


def test_sealed_email_makes_no_network_call() -> None:
    r = pb.run_probe(pb.SEALED_EMAIL)
    assert r.outcome == "allowed", r.detail
    assert r.violations == 0


def test_stock_email_does_fetch_by_contrast() -> None:
    # The contrast that proves the point: a stock EmailRecognizer with a cold
    # cache DOES attempt to fetch the public-suffix list (recorded as a violation).
    r = pb.run_probe(pb.STOCK_EMAIL)
    assert r.violations >= 1, f"stock recognizer did not attempt a fetch: {r.detail}"
