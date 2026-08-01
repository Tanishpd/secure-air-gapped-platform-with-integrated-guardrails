"""POST /v1/chat — the only route that can reach the LLM (C0–C26).

``run_chat`` is the pure orchestration (also called directly by
``test_final_bytes_were_scanned``); the route adds auth, the scope check, the C0
rate-limit, and the C1 multi-turn rejection. The request-scoped vault is cleared
in a ``finally``.

Every terminal outcome is recorded in the hash-chained audit sink (M14): an
``allow``/``refuse`` ``chat`` event on the happy/refusal paths carrying entity
TYPES and COUNTS only (never values — invariant 1), and a ``reject`` event on a
detector rejection. A ``PromptRejected`` additionally quarantines the raw prompt
under a fresh ``incident_id`` and re-raises carrying that id, so the opaque 400
body and the audit record and the quarantine file all share the SAME id — the
only thread from an incident back to its bytes (invariant 8).
"""

from __future__ import annotations

import functools
import time
from dataclasses import replace
from datetime import UTC, datetime

import anyio
from fastapi import APIRouter, Depends, Request

from sagp.app.concurrency import guardrail_limiter
from sagp.app.deps import Engines, get_engines, get_principal
from sagp.app.schemas import ChatRequest, ChatResponse
from sagp.audit.events import AuditEvent
from sagp.audit.quarantine import write_quarantine
from sagp.errors import (
    AuthError,
    GuardrailUnavailable,
    InputTooLarge,
    PromptRejected,
    UnsupportedRequest,
)
from sagp.guardrails.pipeline import InputResult
from sagp.guardrails.placeholders import rehydrate
from sagp.guardrails.vault import PiiVault
from sagp.rag.prompt import build_prompt
from sagp.rag.retriever import Retriever
from sagp.types import Hit, Principal
from sagp.utils.ids import new_incident_id, new_request_id

router = APIRouter()

# resp.decision -> AuditEvent.decision (the closed audit Literal).
_DECISION_MAP = {"answer": "allow"}  # everything else on the success path is a refuse


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(engines: Engines, event: AuditEvent) -> None:
    if engines.audit is not None:
        engines.audit.append(event)


def _base_fields(engines: Engines) -> dict[str, object]:
    p = engines.provenance
    return {
        "model": p.model,
        "manifest_root_hash": p.manifest_root_hash,
        "guardrails_config_sha256": p.guardrails_sha256,
        "entities_config_sha256": p.entities_sha256,
        "system_prompt_sha256": p.system_prompt_sha256,
    }


def _run_pipeline(
    message: str,
    collection: str,
    principal: Principal,
    engines: Engines,
    vault: PiiVault,
    scanned: list[str],
) -> tuple[ChatResponse, InputResult]:
    """C2–C22. Returns (response, input-result). Raises on a detector rejection."""
    settings = engines.settings
    inp = engines.input_guardrail.run_input(message, vault, scanned=scanned)  # C2–C12

    retriever = Retriever(
        engines.store, engines.embedder, engines.policy.retrieval, collection=collection
    )
    result = retriever.retrieve(inp.neutral)  # C13–C14
    if not result.answerable:  # C15
        return ChatResponse(
            answer=engines.refusal_text, decision="refuse_insufficient_context"
        ), inp

    masked_hits: list[Hit] = []
    for hit in result.hits:  # C16–C17: mask retrieved chunks into the SAME vault
        masked = engines.pii.run_egress(
            hit.chunk.text, vault, origin=f"doc:{hit.chunk.doc_sha256[:8]}"
        ).masked_text
        masked_hits.append(Hit(chunk=replace(hit.chunk, text=masked), score=hit.score))

    kept_hits, _dropped = engines.input_guardrail.filter_context(masked_hits)  # C19a
    if not kept_hits:  # every retrieved chunk was flagged — nothing safe to ground on
        return ChatResponse(answer=engines.refusal_text, decision="refuse_context_flagged"), inp

    assembled = build_prompt(  # C18 (from the surviving chunks only)
        inp.masked_question, kept_hits, max_ctx_chars=engines.policy.retrieval.max_ctx_chars
    )
    # Citations may only reference a page that made it into the prompt after trim (C22).
    supplied_pages = {h.chunk.page for h in assembled.chunks_used}
    # C19b: re-scan the fully assembled string as one unit.
    if not engines.input_guardrail.scan_context(assembled.user_payload, scanned=scanned):
        return ChatResponse(answer=engines.refusal_text, decision="refuse_context_flagged"), inp

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
        return ChatResponse(answer=engines.refusal_text, decision="refuse_output_blocked"), inp

    answer = out.masked_response
    if settings.rehydrate_output and principal.has_scope("pii:reveal"):  # C20
        answer = rehydrate(answer, vault.as_mapping())
    return ChatResponse(answer=answer, decision="answer", citations=out.citations), inp


def run_chat(
    message: str,
    collection: str,
    principal: Principal,
    engines: Engines,
    *,
    scanned: list[str],
    request_id: str | None = None,
) -> ChatResponse:
    request_id = request_id or new_request_id()
    vault = PiiVault(max_entries=engines.settings.max_vault_entries)
    t0 = time.monotonic()
    try:
        resp, inp = _run_pipeline(message, collection, principal, engines, vault, scanned)
        _append(
            engines,
            AuditEvent(
                event_type="chat",
                request_id=request_id,
                timestamp=_now(),
                decision=_DECISION_MAP.get(resp.decision, "refuse"),
                reason_code=None if resp.decision == "answer" else resp.decision,
                entity_types=inp.entity_types,
                # Round: a full-precision float's 16-digit tail trips the scrub's
                # card-like digit-run check, and a score needs no such precision.
                injection_score=round(inp.injection_score, 4),
                normalize_flags=inp.normalize_flags,
                stage_latencies_ms={"total": round((time.monotonic() - t0) * 1000, 3)},
                **_base_fields(engines),
            ),
        )
        return resp
    except PromptRejected as exc:
        incident_id = exc.incident_id or new_incident_id()
        write_quarantine(engines.root, incident_id, message)  # the raw bytes, 0600
        _append(
            engines,
            AuditEvent(
                event_type="reject",
                request_id=request_id,
                timestamp=_now(),
                decision="block",
                reason_code="prompt_rejected",
                incident_id=incident_id,
                stage_latencies_ms={"total": round((time.monotonic() - t0) * 1000, 3)},
                **_base_fields(engines),
            ),
        )
        raise PromptRejected(str(exc), incident_id=incident_id) from exc
    except (UnsupportedRequest, InputTooLarge, GuardrailUnavailable) as exc:
        decision = (
            "unsupported"
            if isinstance(exc, UnsupportedRequest)
            else ("unavailable" if isinstance(exc, GuardrailUnavailable) else "block")
        )
        _append(
            engines,
            AuditEvent(
                event_type="reject",
                request_id=request_id,
                timestamp=_now(),
                decision=decision,
                reason_code=exc.code,
                **_base_fields(engines),
            ),
        )
        raise
    finally:
        vault.clear()  # C26


@router.post("/v1/chat", response_model=ChatResponse)
async def chat(
    req: ChatRequest,
    request: Request,
    principal: Principal = Depends(get_principal),  # C0
) -> ChatResponse:
    if not principal.has_scope("chat"):
        raise AuthError("token lacks the chat scope")
    engines = get_engines(request)
    if engines.rate_limiter is not None:  # C0: per-principal rate limit -> 429
        engines.rate_limiter.check(principal.id)
    if req.messages and len(req.messages) > 1:  # C1
        raise UnsupportedRequest("multi-turn conversations are not supported")
    # C0 backpressure: shed load with a fast 503 if too many are already in flight,
    # rather than letting the burst queue behind the CapacityLimiter into multi-
    # second latency. Acquire only around the expensive offload, after the cheap
    # scope/rate/multi-turn checks (a rejected request must not consume a slot).
    if engines.admission_gate is not None:
        engines.admission_gate.acquire()  # -> 503 ServiceBusy if saturated
    try:
        # C2–C26 is CPU-bound (Presidio/ONNX). Offload it through the shared
        # CapacityLimiter(2) (invariant 11) so a burst queues instead of thrashing
        # the cores and evicting the idle guardrail models. Exceptions propagate to
        # the SagpError→HTTP handler (still deadline-padded) exactly as before.
        scanned: list[str] = []
        return await anyio.to_thread.run_sync(
            functools.partial(
                run_chat, req.message, req.collection, principal, engines, scanned=scanned
            ),
            limiter=guardrail_limiter(),
        )
    finally:
        if engines.admission_gate is not None:
            engines.admission_gate.release()
