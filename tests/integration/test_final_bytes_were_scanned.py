"""The single most important test: the bytes crossing the boundary were scanned.

The user-role payload sent to the LLM and the answer returned to the caller must
each have been an argument to a scan() call within the same request. This asserts
on the bytes that actually cross the boundary, not on an intermediate value. If a
refactor breaks it, the refactor introduced an unscanned path — do not adjust the
assertion (CLAUDE.md §8).
"""

from __future__ import annotations

from sagp.app.routes.chat import run_chat


def test_final_bytes_were_scanned(chat_engines) -> None:  # type: ignore[no-untyped-def]
    scanned: list[str] = []
    resp = run_chat(
        "How many days of parental leave am I entitled to?",
        "handbook",
        chat_engines.tokens["tok-chat"],
        chat_engines,
        scanned=scanned,
    )
    assert resp.decision == "answer"
    # The exact user-role payload sent to Ollama was scanned (C19).
    assert chat_engines.llm.last_user in scanned
    # The returned answer was scanned (C22); FakeLLM emits no PII, so masked == raw.
    assert resp.answer in scanned
