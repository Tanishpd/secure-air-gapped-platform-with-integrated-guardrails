"""One real generation against local Ollama (skips if unreachable)."""

from __future__ import annotations

import pytest

from sagp.llm.base import SYSTEM_RAG, load_prompt
from sagp.llm.ollama_client import OllamaClient


@pytest.mark.needs_ollama
def test_real_grounded_generation(ollama_client: OllamaClient) -> None:
    user = (
        "<<<UNTRUSTED_DOCUMENT_deadbeef_S1>>>\n"
        "[S1, p.1] The main office opens at 9:00 AM on weekdays.\n"
        "<<</UNTRUSTED_DOCUMENT_deadbeef_S1>>>\n\n"
        "Question: When does the main office open?"
    )
    r = ollama_client.generate(system=load_prompt(SYSTEM_RAG), user=user)
    assert r.text.strip(), "empty generation"
    assert r.model
    assert r.prompt_eval_count and r.prompt_eval_count > 0
    assert "9" in r.text  # grounded answer references the excerpt
