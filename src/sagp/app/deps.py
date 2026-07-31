"""Engine container, wiring, and auth.

``Engines`` holds every built component; ``assemble_engines`` is the single place
they are wired together (used by both the real app factory and the tests). Auth
is a bearer token → ``Principal`` lookup over a small token map — exactly three
scopes (``chat``, ``ingest``, ``pii:reveal``) across two tokens, no ``admin``
scope (invariant 8).
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, Request

from sagp.config import Settings
from sagp.errors import AuthError
from sagp.guardrails.injection.scanner import InjectionScanner
from sagp.guardrails.output import OutputGuardrail
from sagp.guardrails.pii import PiiGuardrail
from sagp.guardrails.pipeline import InputGuardrail
from sagp.guardrails.policy import GuardrailsPolicy
from sagp.llm.base import REFUSAL, SYSTEM_RAG, LLMClient, load_prompt
from sagp.rag.embeddings import BgeEmbedder
from sagp.rag.vectorstore import VectorStore
from sagp.types import Principal


@dataclass
class Engines:
    input_guardrail: InputGuardrail
    output_guardrail: OutputGuardrail
    pii: PiiGuardrail
    store: VectorStore
    embedder: BgeEmbedder
    llm: LLMClient
    policy: GuardrailsPolicy
    settings: Settings
    system_prompt: str
    refusal_text: str
    tokens: dict[str, Principal]  # bearer token -> principal


def assemble_engines(
    *,
    injection_scanner: InjectionScanner,
    pii: PiiGuardrail,
    embedder: BgeEmbedder,
    store: VectorStore,
    llm: LLMClient,
    policy: GuardrailsPolicy,
    settings: Settings,
    tokens: dict[str, Principal],
) -> Engines:
    return Engines(
        input_guardrail=InputGuardrail(injection_scanner, pii, policy, settings),
        output_guardrail=OutputGuardrail(pii),
        pii=pii,
        store=store,
        embedder=embedder,
        llm=llm,
        policy=policy,
        settings=settings,
        system_prompt=load_prompt(SYSTEM_RAG),
        refusal_text=load_prompt(REFUSAL).strip(),
        tokens=tokens,
    )


def get_engines(request: Request) -> Engines:
    engines: Engines = request.app.state.engines
    return engines


def get_principal(request: Request, authorization: str | None = Header(default=None)) -> Principal:
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthError("missing or malformed bearer token")
    token = authorization[len("Bearer ") :]
    engines: Engines = request.app.state.engines
    principal = engines.tokens.get(token)
    if principal is None:
        raise AuthError("invalid token")
    return principal
