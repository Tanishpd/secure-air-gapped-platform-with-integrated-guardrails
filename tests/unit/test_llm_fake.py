"""FakeLLM, prompt loading, and the Ollama client's fail-closed path (no Ollama needed)."""

from __future__ import annotations

import dataclasses

import pytest

from sagp.errors import GuardrailUnavailable
from sagp.llm.base import REFUSAL, SYSTEM_RAG, LLMResult, load_prompt, prompt_sha256
from sagp.llm.fake import FakeLLM
from sagp.llm.ollama_client import OllamaClient


def test_fake_returns_configured_response() -> None:
    r = FakeLLM("answer [S1, p.2].").generate(system="sys", user="q")
    assert r.text == "answer [S1, p.2]."
    assert r.model == "fake"


def test_fake_records_payloads_for_spy() -> None:
    llm = FakeLLM()
    llm.generate(system="SYS", user="USER PAYLOAD")
    assert llm.last_system == "SYS"
    assert llm.last_user == "USER PAYLOAD"
    assert llm.calls == 1


def test_fake_callable_responder() -> None:
    llm = FakeLLM(lambda system, user: f"echo:{user}")
    assert llm.generate(system="x", user="hi").text == "echo:hi"


def test_llmresult_is_frozen() -> None:
    r = LLMResult(text="x", model="m")
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.text = "y"  # type: ignore[misc]


def test_prompts_load_and_hash() -> None:
    assert "retrieved" in load_prompt(SYSTEM_RAG).lower()
    assert load_prompt(REFUSAL).strip()
    assert len(prompt_sha256(SYSTEM_RAG)) == 64
    assert prompt_sha256(SYSTEM_RAG) != prompt_sha256(REFUSAL)


def test_ollama_fail_closed_on_unreachable() -> None:
    # A dead port: connection refused -> GuardrailUnavailable (503), never a 200.
    client = OllamaClient("llama3.2:3b-instruct-q4_K_M", host="127.0.0.1:1", timeout_s=2)
    with pytest.raises(GuardrailUnavailable):
        client.generate(system="s", user="u")
