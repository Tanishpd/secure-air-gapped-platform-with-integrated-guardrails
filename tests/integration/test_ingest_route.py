"""POST /v1/ingest (M12): scope enforcement, path confinement, and the guarded
ingest that quarantines a visible indirect-injection payload."""

from __future__ import annotations

INGEST = {"Authorization": "Bearer tok-chat"}  # tok-chat carries the ingest scope
CHAT_ONLY = {"Authorization": "Bearer tok-chatonly"}  # no ingest scope


def test_ingest_clean_pdf_indexes(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post(
        "/v1/ingest",
        json={"path": "samples/employee_handbook.pdf", "collection": "route_hb"},
        headers=INGEST,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["chunks_indexed"] > 0
    assert body["chunks_quarantined"] == 0
    assert body["collection"] == "route_hb"


def test_ingest_quarantines_visible_injection(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post(
        "/v1/ingest",
        json={"path": "samples/poisoned_visible.pdf", "collection": "route_pv"},
        headers=INGEST,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["chunks_quarantined"] >= 1  # the SYSTEM OVERRIDE payload chunk
    assert body["chunks_indexed"] >= 1  # the clean records-retention page


def test_ingest_requires_the_ingest_scope(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post(
        "/v1/ingest",
        json={"path": "samples/employee_handbook.pdf", "collection": "x"},
        headers=CHAT_ONLY,
    )
    assert r.status_code == 401


def test_ingest_requires_a_token(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post("/v1/ingest", json={"path": "samples/employee_handbook.pdf", "collection": "x"})
    assert r.status_code == 401


def test_ingest_rejects_path_traversal(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post(
        "/v1/ingest",
        json={"path": "../../../../etc/hosts", "collection": "x"},
        headers=INGEST,
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "UNSUPPORTED"


def test_ingest_rejects_non_pdf(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post(
        "/v1/ingest",
        json={"path": "samples/../samples", "collection": "x"},  # a directory, no .pdf
        headers=INGEST,
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "UNSUPPORTED"


def test_ingest_rejects_reserved_quarantine_collection(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post(
        "/v1/ingest",
        json={"path": "samples/employee_handbook.pdf", "collection": "hb__quarantine"},
        headers=INGEST,
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "UNSUPPORTED"
