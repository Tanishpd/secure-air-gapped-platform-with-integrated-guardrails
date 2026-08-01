"""The production launch path: build real engines and boot them behind hard
preconditions (BLUEPRINT §7 lifespan).

``create_serving_app`` returns an app whose FastAPI lifespan, before it accepts a
single request, runs four fail-closed gates in order:

1. **manifest full-verify** — every file's sha256 + the signature; a mismatch is a
   boot failure, never a warning (``quick`` mode is forbidden).
2. **projected-RSS budget** — refuse to boot above 90% of RAM (invariant 11).
3. **build engines** — the real Presidio/ONNX/bge/Ollama/Qdrant stack + audit sink.
4. **injection self-test** — a known attack and a known benign string through the
   real policy path; refuse to start if either verdict is wrong (invariant 5).

Any gate raising aborts startup — uvicorn exits non-zero rather than serving a
half-armed system. ``create_app(engines)`` (main.py) stays the pre-assembled path
the tests use; this module is what ``bin/sagp-serve`` launches.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from sagp.app.deps import Engines, assemble_engines
from sagp.audit.sink import AuditSink
from sagp.config import Settings, load_settings
from sagp.errors import ConfigError
from sagp.guardrails.entities import load_entities
from sagp.guardrails.injection.onnx_backend import OnnxInjectionScorer
from sagp.guardrails.injection.scanner import InjectionScanner
from sagp.guardrails.injection.selftest import run_selftest
from sagp.guardrails.pii import PiiGuardrail
from sagp.guardrails.policy import load_policy
from sagp.guardrails.presidio_factory import build_analyzer, build_anonymizer
from sagp.llm.ollama_client import OllamaClient
from sagp.netguard import manifest as mf
from sagp.netguard.budget import assert_rss_budget
from sagp.rag.embeddings import BgeEmbedder
from sagp.rag.ingest import build_chunk_tokenizer
from sagp.rag.qdrant_store import QdrantStore
from sagp.types import Principal

_INJECTION_DIR = Path("models/hf/injection")
_BGE_DIR = Path("models/hf/bge-small-en-v1.5")
_BGE_REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"  # pinned (artifacts.lock)


def rss_profile(settings: Settings) -> str:
    """The worst-case RAM profile the running config implies (invariant 11)."""
    if "8b" in settings.llm_model:
        return "8b"
    if settings.spacy_model == "en_core_web_lg":
        return "lg"
    return "demo" if settings.qdrant_mode == "server" else "embedded"


def _build_store(settings: Settings) -> QdrantStore:
    if settings.qdrant_mode == ":memory:":
        return QdrantStore.memory()
    if settings.qdrant_mode == "server":
        from qdrant_client import QdrantClient

        return QdrantStore(QdrantClient(url="http://127.0.0.1:6333"))
    return QdrantStore.embedded(str(settings.qdrant_path))


def _build_tokens(settings: Settings) -> dict[str, Principal]:
    """Map the two provisioned bearer tokens to principals (invariant 8: exactly
    the scopes chat/ingest and +pii:reveal, no admin scope)."""
    tokens: dict[str, Principal] = {}
    if settings.api_token is not None:
        tokens[settings.api_token.get_secret_value()] = Principal(
            id="svc", scopes=frozenset({"chat", "ingest"})
        )
    if settings.api_token_reveal is not None:
        tokens[settings.api_token_reveal.get_secret_value()] = Principal(
            id="reveal", scopes=frozenset({"chat", "ingest", "pii:reveal"})
        )
    return tokens


def build_engines(settings: Settings, *, root: Path | None = None) -> Engines:
    """Assemble the real serving stack from provisioned models + settings."""
    root = root or Path.cwd()
    policy = load_policy(settings.config_dir / "guardrails.yaml")

    pii = PiiGuardrail(
        build_analyzer(),
        build_anonymizer(),
        load_entities(settings.config_dir / "entities.yaml"),
    )
    scanner = InjectionScanner(
        OnnxInjectionScorer(
            model_path=root / _INJECTION_DIR / "onnx" / "model.onnx",
            tokenizer_path=root / _INJECTION_DIR / "onnx" / "tokenizer.json",
            config_path=root / _INJECTION_DIR / "config.json",
            policy=policy.injection,
        ),
        policy.injection,
    )
    embedder = BgeEmbedder(
        root / _BGE_DIR / "onnx" / "model.onnx",
        root / _BGE_DIR / "tokenizer.json",
        revision=_BGE_REVISION,
    )
    tokenizer = build_chunk_tokenizer(root / _BGE_DIR / "tokenizer.json")

    return assemble_engines(
        injection_scanner=scanner,
        pii=pii,
        embedder=embedder,
        store=_build_store(settings),
        llm=OllamaClient(settings.llm_model),
        policy=policy,
        settings=settings,
        tokens=_build_tokens(settings),
        chunk_tokenizer=tokenizer,
        audit=AuditSink(settings.audit_dir / "audit.jsonl"),
        root=root,
    )


def check_boot_preconditions(settings: Settings, *, root: Path | None = None) -> None:
    """Gates 1–2: manifest full-verify + RSS budget. Raise ``ConfigError`` on any
    failure (fail closed). Separated out so it is testable without loading models."""
    root = root or Path.cwd()
    res = mf.verify(root, mode="full")
    if not res.ok:
        raise ConfigError(f"manifest full-verify failed: {'; '.join(res.problems[:3])}")
    if res.signature_valid is not True:
        raise ConfigError(f"manifest signature not valid (signature_valid={res.signature_valid})")
    assert_rss_budget(rss_profile(settings))


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    check_boot_preconditions(settings)  # gates 1–2
    engines = build_engines(settings)  # gate 3
    run_selftest(engines.injection_scanner)  # gate 4 (invariant 5)
    app.state.engines = engines
    yield


def create_serving_app(settings: Settings | None = None) -> FastAPI:
    """The app ``bin/sagp-serve`` launches: engines built in the lifespan behind
    the four boot gates. Import-safe (no engine construction at import)."""
    from sagp.app.main import register_handlers

    settings = settings or load_settings()
    app = FastAPI(lifespan=_lifespan)
    app.state.settings = settings
    register_handlers(app)
    return app
