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


@pytest.fixture(scope="session")
def ollama_client():  # type: ignore[no-untyped-def]
    """Real Ollama client. Skips if 127.0.0.1:11434 is not reachable."""
    import socket

    sock = socket.socket()
    sock.settimeout(0.5)
    try:
        sock.connect(("127.0.0.1", 11434))
    except OSError:
        pytest.skip("Ollama not reachable at 127.0.0.1:11434 (start it with `make ollama-up`)")
    finally:
        sock.close()
    from sagp.llm.ollama_client import OllamaClient

    return OllamaClient("llama3.2:3b-instruct-q4_K_M")


_BGE_DIR = Path("models/hf/bge-small-en-v1.5")


@pytest.fixture(scope="session")
def chunk_tokenizer():  # type: ignore[no-untyped-def]
    tp = _BGE_DIR / "tokenizer.json"
    if not tp.exists():
        pytest.skip("bge tokenizer not provisioned")
    from sagp.rag.ingest import build_chunk_tokenizer

    return build_chunk_tokenizer(tp)


@pytest.fixture(scope="session")
def bge_embedder():  # type: ignore[no-untyped-def]
    model = _BGE_DIR / "onnx" / "model.onnx"
    if not model.exists():
        pytest.skip("bge model not provisioned (run `make provision`)")
    from sagp.rag.embeddings import BgeEmbedder

    return BgeEmbedder(
        model, _BGE_DIR / "tokenizer.json", revision="5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"
    )


@pytest.fixture(scope="session")
def sample_pdfs(tmp_path_factory):  # type: ignore[no-untyped-def]
    """Generate the two sample PDFs hermetically (also exercises gen_sample_pdf)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_sample_pdf", Path("scripts/gen_sample_pdf.py")
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    d = tmp_path_factory.mktemp("samples")
    handbook = d / "employee_handbook.pdf"
    handbook.write_bytes(mod.handbook())
    poisoned = d / "poisoned_appendix.pdf"
    poisoned.write_bytes(mod.poisoned_appendix())
    return {"handbook": handbook, "poisoned": poisoned}


@pytest.fixture(scope="module")
def chat_engines(injection_scanner, pii_guardrail, bge_embedder, chunk_tokenizer, sample_pdfs):  # type: ignore[no-untyped-def]
    """Full gateway engines: real guardrails, FakeLLM, :memory: store with the handbook."""
    from sagp.app.deps import assemble_engines
    from sagp.config import Settings
    from sagp.guardrails.policy import load_policy
    from sagp.llm.fake import FakeLLM
    from sagp.rag.ingest import ingest_pdf
    from sagp.rag.qdrant_store import QdrantStore
    from sagp.types import Principal

    store = QdrantStore.memory(embed_revision="test")
    ingest_pdf(
        sample_pdfs["handbook"],
        collection="handbook",
        store=store,
        embedder=bge_embedder,
        chunk_tokenizer=chunk_tokenizer,
    )
    tokens = {
        "tok-chat": Principal(id="u1", scopes=frozenset({"chat", "ingest"})),
        "tok-reveal": Principal(id="u2", scopes=frozenset({"chat", "ingest", "pii:reveal"})),
    }
    return assemble_engines(
        injection_scanner=injection_scanner,
        pii=pii_guardrail,
        embedder=bge_embedder,
        store=store,
        llm=FakeLLM("Full-time employees get 20 days of parental leave [S1, p.1]."),
        policy=load_policy(Path("config/guardrails.yaml")),
        settings=Settings(_env_file=None),  # type: ignore[call-arg]
        tokens=tokens,
    )


@pytest.fixture(scope="module")
def client(chat_engines):  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    from sagp.app.main import create_app

    return TestClient(create_app(chat_engines), raise_server_exceptions=False)
