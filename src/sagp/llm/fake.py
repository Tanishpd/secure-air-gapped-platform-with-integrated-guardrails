"""Deterministic fake LLM for tests.

~90% of the suite runs against this — no Ollama, no model load. It records the
exact ``system`` and ``user`` payloads it was given so the flagship
``test_final_bytes_were_scanned`` can assert that the bytes sent to the LLM were
the bytes that were scanned.
"""

from __future__ import annotations

from collections.abc import Callable

from sagp.llm.base import LLMResult

Responder = Callable[[str, str], str]


_DEFAULT = "This is a fake grounded answer [S1, p.1]."


class FakeLLM:
    def __init__(self, response: str | Responder = _DEFAULT) -> None:
        self._response = response
        self.model = "fake"
        self.last_system: str | None = None
        self.last_user: str | None = None
        self.calls = 0

    def generate(self, *, system: str, user: str) -> LLMResult:
        self.last_system = system
        self.last_user = user
        self.calls += 1
        text = self._response(system, user) if callable(self._response) else self._response
        return LLMResult(text=text, model=self.model, prompt_eval_count=len(user.split()))
