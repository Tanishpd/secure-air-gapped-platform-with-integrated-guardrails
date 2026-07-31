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


class IngestRequest(BaseModel):
    # A server-local PDF path (air-gapped: documents live on the host, never
    # uploaded over the wire). Resolved under settings.data_dir by the route.
    path: str
    collection: str


class IngestResponse(BaseModel):
    """Operator-facing ingest report (the caller holds the ``ingest`` scope and
    supplied the document, so counts here are not the chat detector oracle that
    invariant 8 forbids on the rejection surface)."""

    doc_sha256: str
    source: str
    collection: str
    chunks_indexed: int
    chunks_suspect: int
    chunks_quarantined: int
    pages_quarantined: int
    pages_total: int
