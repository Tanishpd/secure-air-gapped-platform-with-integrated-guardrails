"""Request/response schemas. The response carries NO scores, counts, or detector
identity (invariant 8) — only the answer, in-range citations, and (on a rejection)
an opaque incident id."""

from __future__ import annotations

from pydantic import BaseModel


class ChatRequest(BaseModel):
    message: str
    collection: str
    # A multi-turn messages array is UNSUPPORTED (the vault is request-scoped);
    # accepted here only so the route can reject len>1 with a typed 400.
    messages: list[dict[str, object]] | None = None


class ChatResponse(BaseModel):
    answer: str
    decision: str  # "answer" | "refuse_insufficient_context" | "refuse_context_flagged" | ...
    citations: list[str] = []
