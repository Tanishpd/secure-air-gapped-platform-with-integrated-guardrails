"""The real Ollama client (loopback only).

Buffered (``stream=False``), single-turn, with pinned deterministic options.
Any failure or timeout is fail-closed → ``GuardrailUnavailable`` (503) — a partial
or missing generation never returns as a 200. ``num_ctx`` is never passed per
request (it forces a full model reload). ``EgressViolation`` is deliberately NOT
caught here — it must propagate, never be laundered into a 503.
"""

from __future__ import annotations

import time
from types import MappingProxyType

import ollama

from sagp.errors import GuardrailUnavailable
from sagp.llm.base import LLMResult
from sagp.netguard.egress import EgressViolation

DEFAULT_OPTIONS = MappingProxyType(
    {"temperature": 0.1, "top_p": 0.9, "num_predict": 512, "seed": 42}
)


class OllamaClient:
    def __init__(
        self,
        model: str,
        *,
        host: str = "127.0.0.1:11434",
        timeout_s: int = 120,
        keep_alive: str = "30m",
        options: dict[str, object] | None = None,
    ) -> None:
        self.model = model
        self._keep_alive = keep_alive
        self._options = dict(options) if options is not None else dict(DEFAULT_OPTIONS)
        self._client = ollama.Client(host=f"http://{host}", timeout=timeout_s)

    def generate(self, *, system: str, user: str) -> LLMResult:
        start = time.monotonic()
        try:
            resp = self._client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                stream=False,
                keep_alive=self._keep_alive,
                options=self._options,
            )
        except EgressViolation:
            raise  # must never become a 503
        except Exception as exc:
            raise GuardrailUnavailable("LLM generation failed") from exc

        elapsed_ms = (time.monotonic() - start) * 1000.0
        return LLMResult(
            text=resp.message.content or "",
            model=self.model,
            prompt_eval_count=resp.prompt_eval_count,
            eval_count=resp.eval_count,
            elapsed_ms=elapsed_ms,
        )
