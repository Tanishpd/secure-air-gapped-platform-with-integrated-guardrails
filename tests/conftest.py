"""Shared test fixtures and markers.

``needs_models`` / ``needs_ollama`` are declared in pyproject and gated here so
the fast suite (``make test``) never touches real models or a live Ollama.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def clean_sagp_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Strip every ``SAGP_`` variable from the environment for the test.

    ``Settings`` uses ``extra="forbid"``, so a stray ``SAGP_`` var in the real
    environment would otherwise make construction fail for the wrong reason.
    """
    import os

    for key in list(os.environ):
        if key.startswith("SAGP_"):
            monkeypatch.delenv(key, raising=False)
    yield


@pytest.fixture(scope="session")
def pii_guardrail():  # type: ignore[no-untyped-def]
    """Real Presidio + spaCy PII guardrail, built once per session (spaCy is slow)."""
    from sagp.guardrails.entities import load_entities
    from sagp.guardrails.pii import PiiGuardrail
    from sagp.guardrails.presidio_factory import build_analyzer, build_anonymizer

    analyzer = build_analyzer()
    anonymizer = build_anonymizer()
    entities = load_entities(Path("config/entities.yaml"))
    return PiiGuardrail(analyzer, anonymizer, entities)


@pytest.fixture(scope="session")
def injection_scanner():  # type: ignore[no-untyped-def]
    """Real ONNX injection scanner. Skips if the model has not been provisioned."""
    model = Path("models/hf/injection/onnx/model.onnx")
    if not model.exists():
        pytest.skip("injection model not provisioned (run `make provision`)")
    from sagp.guardrails.injection.onnx_backend import OnnxInjectionScorer
    from sagp.guardrails.injection.scanner import InjectionScanner
    from sagp.guardrails.policy import load_policy

    pol = load_policy(Path("config/guardrails.yaml")).injection
    scorer = OnnxInjectionScorer(
        model_path=model,
        tokenizer_path=Path("models/hf/injection/onnx/tokenizer.json"),
        config_path=Path("models/hf/injection/config.json"),
        policy=pol,
    )
    return InjectionScanner(scorer, pol)
