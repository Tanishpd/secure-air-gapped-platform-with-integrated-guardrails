"""The happy path and auth/schema behaviour of POST /v1/chat."""

from __future__ import annotations

from sagp.app.routes.chat import run_chat

CHAT = {"Authorization": "Bearer tok-chat"}


def test_grounded_answer(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post(
        "/v1/chat",
        json={
            "message": "How many days of parental leave am I entitled to?",
            "collection": "handbook",
        },
        headers=CHAT,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "answer"
    assert body["answer"]
    # No detector signal in the response (invariant 8).
    assert "score" not in r.text.lower()
    assert "injection" not in body


def test_unauthenticated_is_401(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post("/v1/chat", json={"message": "hi", "collection": "handbook"})
    assert r.status_code == 401


def test_multi_turn_is_unsupported(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post(
        "/v1/chat",
        json={"message": "hi", "collection": "handbook", "messages": [{"a": 1}, {"b": 2}]},
        headers=CHAT,
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "UNSUPPORTED"


def test_unrelated_query_refuses_without_llm(client) -> None:  # type: ignore[no-untyped-def]
    r = client.post(
        "/v1/chat",
        json={
            "message": "orbital mechanics of binary neutron star mergers",
            "collection": "handbook",
        },
        headers=CHAT,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "refuse_insufficient_context"


def test_user_pii_is_masked_before_the_llm(chat_engines) -> None:  # type: ignore[no-untyped-def]
    scanned: list[str] = []
    run_chat(
        "My email is alice@secret.example — how many parental leave days do I get?",
        "handbook",
        chat_engines.tokens["tok-chat"],
        chat_engines,
        scanned=scanned,
    )
    sent_to_llm = chat_engines.llm.last_user
    assert sent_to_llm is not None
    assert "alice@secret.example" not in sent_to_llm  # raw PII never reaches the model
    assert "<EMAIL_ADDRESS_" in sent_to_llm  # it was pseudonymised


def test_healthz(client) -> None:  # type: ignore[no-untyped-def]
    assert client.get("/healthz").json()["status"] == "ok"
