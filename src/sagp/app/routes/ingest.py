"""POST /v1/ingest — guarded ingestion of a server-local PDF (scope: ``ingest``).

Air-gapped by design: documents live on the host and are named by a path under
``settings.data_dir``, never uploaded over the wire. The path is resolved and
confined to that root (no traversal, no absolute escape, ``.pdf`` only), then the
file goes through the SAME guardrail-bearing ingest as ``make ingest`` — every
chunk injection-scanned, quarantined chunks diverted to the never-retrieved
sibling collection (M12).

The response is an operator-facing report (chunk counts, quarantine counts). The
caller holds the ``ingest`` scope and supplied the document, so these counts are
not the chat detector oracle invariant 8 forbids on the rejection surface.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request

from sagp.app.deps import Engines, get_engines, get_principal
from sagp.app.schemas import IngestRequest, IngestResponse
from sagp.errors import AuthError, GuardrailUnavailable, InputTooLarge, UnsupportedRequest
from sagp.rag.ingest import ingest_pdf
from sagp.rag.vectorstore import is_quarantine_name
from sagp.types import Principal

router = APIRouter()


def _resolve_under_root(raw: str, root: Path) -> Path:
    """Confine ``raw`` to ``root``: a real ``.pdf`` file, no traversal escape."""
    root = root.resolve()
    target = (root / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
    if not target.is_relative_to(root):
        raise UnsupportedRequest("path escapes the ingest root")
    if target.suffix.lower() != ".pdf":
        raise UnsupportedRequest("only .pdf documents are ingestible")
    if not target.is_file():
        raise UnsupportedRequest("no such document under the ingest root")
    return target


def run_ingest(req: IngestRequest, engines: Engines) -> IngestResponse:
    if engines.chunk_tokenizer is None:
        raise GuardrailUnavailable("ingest is not configured on this instance")
    if is_quarantine_name(req.collection):
        raise UnsupportedRequest("cannot ingest into a reserved quarantine collection")

    path = _resolve_under_root(req.path, engines.settings.data_dir)
    if path.stat().st_size > engines.settings.max_doc_bytes:
        raise InputTooLarge("document exceeds SAGP_MAX_DOC_BYTES")

    result = ingest_pdf(
        path,
        collection=req.collection,
        store=engines.store,
        embedder=engines.embedder,
        chunk_tokenizer=engines.chunk_tokenizer,
        scanner=engines.injection_scanner,  # every chunk is document-surface scanned
        policy=engines.policy,
    )
    return IngestResponse(
        doc_sha256=result.doc_sha256,
        source=result.source,
        collection=req.collection,
        chunks_indexed=result.chunks_indexed,
        chunks_suspect=result.chunks_suspect,
        chunks_quarantined=result.chunks_quarantined,
        pages_quarantined=len(result.pages_quarantined),
        pages_total=result.pages_total,
    )


@router.post("/v1/ingest", response_model=IngestResponse)
def ingest(
    req: IngestRequest,
    request: Request,
    principal: Principal = Depends(get_principal),  # C0
) -> IngestResponse:
    if not principal.has_scope("ingest"):
        raise AuthError("token lacks the ingest scope")
    return run_ingest(req, get_engines(request))
