"""POST /v1/chat — the only route that can reach the LLM (C0–C26).

``run_chat`` is the pure orchestration (also called directly by
``test_final_bytes_were_scanned``); the route adds auth, the scope check, and the
C1 multi-turn rejection. The request-scoped vault is cleared in a ``finally``.
"""

from __future__ import annotations

from dataclasses import replace

from fastapi import APIRouter, Depends, Request

from sagp.app.deps import Engines, get_engines, get_principal
from sagp.app.schemas import ChatRequest, ChatResponse
from sagp.errors import AuthError, UnsupportedRequest
from sagp.guardrails.placeholders import rehydrate
from sagp.guardrails.vault import PiiVault
from sagp.rag.prompt import build_prompt
from sagp.rag.retriever import Retriever
from sagp.types import Hit, Principal

router = APIRouter()


def run_chat(
    message: str,
    collection: str,
    principal: Principal,
    engines: Engines,
    *,
    scanned: list[str],
) -> ChatResponse:
    settings = engines.settings
    vault = PiiVault(max_entries=settings.max_vault_entries)
    try:
        inp = engines.input_guardrail.run_input(message, vault, scanned=scanned)  # C2–C12

        retriever = Retriever(
            engines.store, engines.embedder, engines.policy.retrieval, collection=collection
        )
        result = retriever.retrieve(inp.neutral)  # C13–C14
        if not result.answerable:  # C15
            return ChatResponse(answer=engines.refusal_text, decision="refuse_insufficient_context")

        masked_hits: list[Hit] = []
        for hit in result.hits:  # C16–C17: mask retrieved chunks into the SAME vault
            masked = engines.pii.run_egress(
                hit.chunk.text, vault, origin=f"doc:{hit.chunk.doc_sha256[:8]}"
            ).masked_text
            masked_hits.append(Hit(chunk=replace(hit.chunk, text=masked), score=hit.score))

        kept_hits, _dropped = engines.input_guardrail.filter_context(masked_hits)  # C19a
        if not kept_hits:  # every retrieved chunk was flagged — nothing safe to ground on
            return ChatResponse(answer=engines.refusal_text, decision="refuse_context_flagged")

        assembled = build_prompt(  # C18 (from the surviving chunks only)
            inp.masked_question, kept_hits, max_ctx_chars=engines.policy.retrieval.max_ctx_chars
        )
        # Citations may only reference a page that actually made it into the prompt
        # after the char-budget trim (C22 range check).
        supplied_pages = {h.chunk.page for h in assembled.chunks_used}
        # C19b: re-scan the fully assembled string as one unit.
        if not engines.input_guardrail.scan_context(assembled.user_payload, scanned=scanned):
            return ChatResponse(answer=engines.refusal_text, decision="refuse_context_flagged")

        generation = engines.llm.generate(  # C21 (buffered)
            system=engines.system_prompt, user=assembled.user_payload
        )
        out = engines.output_guardrail.run_output(  # C22
            generation.text,
            nonce=assembled.nonce,
            supplied_pages=supplied_pages,
            vault=vault,
            scanned=scanned,
        )
        if out.suppressed:
            return ChatResponse(answer=engines.refusal_text, decision="refuse_output_blocked")

        answer = out.masked_response
        if settings.rehydrate_output and principal.has_scope("pii:reveal"):  # C20
            answer = rehydrate(answer, vault.as_mapping())
        return ChatResponse(answer=answer, decision="answer", citations=out.citations)
    finally:
        vault.clear()  # C26


@router.post("/v1/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    request: Request,
    principal: Principal = Depends(get_principal),  # C0
) -> ChatResponse:
    if not principal.has_scope("chat"):
        raise AuthError("token lacks the chat scope")
    if req.messages and len(req.messages) > 1:  # C1
        raise UnsupportedRequest("multi-turn conversations are not supported")
    scanned: list[str] = []
    return run_chat(req.message, req.collection, principal, get_engines(request), scanned=scanned)
