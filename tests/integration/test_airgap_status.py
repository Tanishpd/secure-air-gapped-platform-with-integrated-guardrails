"""GET /airgap/status — the sealed system's view of its own lifecycle state."""

from __future__ import annotations

CHAT = {"Authorization": "Bearer tok-chat"}


def test_airgap_status_reports_lifecycle(client) -> None:  # type: ignore[no-untyped-def]
    r = client.get("/airgap/status", headers=CHAT)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"phase", "seal_generation", "manifest_root_hash", "guard_armed"}
    assert body["phase"] in ("BOOTSTRAP", "PROVISION", "OPERATE")
    assert isinstance(body["seal_generation"], int)
    assert isinstance(body["guard_armed"], bool)


def test_airgap_status_requires_a_token(client) -> None:  # type: ignore[no-untyped-def]
    r = client.get("/airgap/status")
    assert r.status_code == 401
