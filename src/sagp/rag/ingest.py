"""Ingest a local PDF into the vector store (pipeline I1–I11, M8 subset).

Load → flag hidden text (quarantine the page, never index it) → token-aware chunk
→ embed → idempotent upsert. Idempotent because points are keyed by
``uuid5(doc_sha256:index)`` and the prior generation for the same ``doc_sha256``
is deleted first, so re-ingesting the same file leaves the count unchanged.

Under ``ingest_mode=raw`` (ADR-0006) the stored chunk text is the REAL text —
masking happens at retrieval, not here. The ingest-time injection scan and the
``docs_quarantine`` collection land at M12; M8 quarantines only hidden-text pages.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from tokenizers import Tokenizer

from sagp.rag.chunking import chunk_page
from sagp.rag.embeddings import BgeEmbedder
from sagp.rag.loaders import load_pdf
from sagp.rag.vectorstore import VectorStore
from sagp.types import Chunk


@dataclass
class IngestResult:
    doc_sha256: str
    source: str
    chunks_indexed: int
    pages_total: int
    pages_quarantined: list[int] = field(default_factory=list)
    quarantine_flags: dict[int, tuple[str, ...]] = field(default_factory=dict)


def build_chunk_tokenizer(tokenizer_path: Path) -> Tokenizer:
    """A tokenizer for chunking — truncation/padding OFF so long pages window fully."""
    tok = Tokenizer.from_file(str(tokenizer_path))
    tok.no_truncation()
    tok.no_padding()
    return tok


def ingest_pdf(
    path: Path,
    *,
    collection: str,
    store: VectorStore,
    embedder: BgeEmbedder,
    chunk_tokenizer: Tokenizer,
) -> IngestResult:
    data = Path(path).read_bytes()
    doc_sha256 = hashlib.sha256(data).hexdigest()
    source = Path(path).name

    pages = load_pdf(Path(path))
    chunks: list[Chunk] = []
    quarantined: list[int] = []
    flags: dict[int, tuple[str, ...]] = {}
    next_index = 0
    for page in pages:
        if page.flags:  # hidden text — quarantine, do not index
            quarantined.append(page.page)
            flags[page.page] = tuple(sorted(page.flags))
            continue
        page_chunks = chunk_page(
            page.text,
            page=page.page,
            source=source,
            doc_sha256=doc_sha256,
            tokenizer=chunk_tokenizer,
            start_index=next_index,
        )
        next_index += len(page_chunks)
        chunks.extend(page_chunks)

    store.ensure_collection(collection, dim=embedder.DIM)
    store.delete_by_doc(collection, doc_sha256)  # supersede any prior generation
    if chunks:
        vectors = embedder.embed([c.text for c in chunks], is_query=False)
        store.upsert(collection, chunks, vectors)

    return IngestResult(
        doc_sha256=doc_sha256,
        source=source,
        chunks_indexed=len(chunks),
        pages_total=len(pages),
        pages_quarantined=quarantined,
        quarantine_flags=flags,
    )
