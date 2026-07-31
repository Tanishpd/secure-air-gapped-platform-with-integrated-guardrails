"""Ingest a local PDF into the vector store (pipeline I1–I11).

Load → flag hidden text (quarantine the page, never index it) → token-aware chunk
→ **injection-scan each chunk** → embed → idempotent upsert. Idempotent because
points are keyed by ``uuid5(doc_sha256:index)`` and the prior generation for the
same ``doc_sha256`` is deleted first (on **both** the main and quarantine
collections), so re-ingesting the same file leaves the counts unchanged.

The ingest-time injection scan (M12) is the highest-value control in the design:
attacker-planted instructions inside a document are the real RAG threat, and most
demos scan only the user prompt. Every chunk is scored on the ``document`` surface
(``decide_injection`` → C3–C7 on the chunk text) and gets one of three verdicts:

* ``clean``     — indexed normally.
* ``suspect``   — indexed, tagged ``guard=suspect`` in the payload. Still
  retrievable: the assembled-context re-scan (C19) is its second line of defence.
* ``quarantined`` — **never** indexed into the retrievable collection. It is
  written to a sibling ``<collection>__quarantine`` collection that the retriever
  refuses to open, so the chunk is preserved for forensics but unreachable by
  construction rather than by a filter that could be forgotten.

Under ``ingest_mode=raw`` (ADR-0006) the stored chunk text is the REAL text —
masking happens at retrieval, not here. Passing no ``scanner`` (unit tests that
exercise chunking/idempotency only) treats every chunk as ``clean``; the ingest
route and CLI always pass one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from tokenizers import Tokenizer

from sagp.guardrails.evaluate import decide_injection
from sagp.guardrails.injection.scanner import InjectionScanner
from sagp.guardrails.policy import GuardrailsPolicy
from sagp.rag.chunking import chunk_page
from sagp.rag.embeddings import BgeEmbedder
from sagp.rag.loaders import load_pdf
from sagp.rag.vectorstore import VectorStore, quarantine_name
from sagp.types import Chunk, InjectionVerdict


@dataclass
class IngestResult:
    doc_sha256: str
    source: str
    chunks_indexed: int  # points in the retrievable collection (clean + suspect)
    pages_total: int
    chunks_suspect: int = 0  # indexed, tagged guard=suspect (subset of chunks_indexed)
    chunks_quarantined: int = 0  # injection-quarantined, in the __quarantine sibling
    pages_quarantined: list[int] = field(default_factory=list)  # hidden-text pages (never chunked)
    quarantine_flags: dict[int, tuple[str, ...]] = field(default_factory=dict)


def build_chunk_tokenizer(tokenizer_path: Path) -> Tokenizer:
    """A tokenizer for chunking — truncation/padding OFF so long pages window fully."""
    tok = Tokenizer.from_file(str(tokenizer_path))
    tok.no_truncation()
    tok.no_padding()
    return tok


def _verdict(
    chunk: Chunk,
    scanner: InjectionScanner | None,
    policy: GuardrailsPolicy | None,
) -> InjectionVerdict:
    """Score one chunk on the document surface. No scanner → treat as clean."""
    if scanner is None or policy is None:
        return InjectionVerdict.CLEAN
    return decide_injection(chunk.text, surface="document", scanner=scanner, policy=policy).verdict


def ingest_pdf(
    path: Path,
    *,
    collection: str,
    store: VectorStore,
    embedder: BgeEmbedder,
    chunk_tokenizer: Tokenizer,
    scanner: InjectionScanner | None = None,
    policy: GuardrailsPolicy | None = None,
) -> IngestResult:
    data = Path(path).read_bytes()
    doc_sha256 = hashlib.sha256(data).hexdigest()
    source = Path(path).name

    pages = load_pdf(Path(path))
    chunks: list[Chunk] = []
    quarantined_pages: list[int] = []
    flags: dict[int, tuple[str, ...]] = {}
    next_index = 0
    for page in pages:
        if page.flags:  # hidden text — quarantine the whole page, do not chunk it
            quarantined_pages.append(page.page)
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

    # Injection-scan each chunk on the document surface (I7).
    indexed: list[Chunk] = []
    indexed_guards: list[str] = []
    suspect = 0
    quarantined: list[Chunk] = []
    for chunk in chunks:
        verdict = _verdict(chunk, scanner, policy)
        if verdict is InjectionVerdict.QUARANTINED:
            quarantined.append(chunk)
        else:
            indexed.append(chunk)
            indexed_guards.append(verdict.value)
            if verdict is InjectionVerdict.SUSPECT:
                suspect += 1

    store.ensure_collection(collection, dim=embedder.DIM)
    store.delete_by_doc(collection, doc_sha256)  # supersede any prior generation
    if indexed:
        vectors = embedder.embed([c.text for c in indexed], is_query=False)
        store.upsert(collection, indexed, vectors, guards=indexed_guards)

    # The quarantine sibling: (re)write it whenever this doc quarantines a chunk,
    # OR when it already exists — so re-ingesting a now-clean document supersedes
    # a prior generation's quarantined chunks and the count stays idempotent.
    qcol = quarantine_name(collection)
    if quarantined or store.collection_exists(qcol):
        store.ensure_collection(qcol, dim=embedder.DIM)
        store.delete_by_doc(qcol, doc_sha256)
        if quarantined:
            qvectors = embedder.embed([c.text for c in quarantined], is_query=False)
            store.upsert(qcol, quarantined, qvectors, guards=["quarantined"] * len(quarantined))

    return IngestResult(
        doc_sha256=doc_sha256,
        source=source,
        chunks_indexed=len(indexed),
        pages_total=len(pages),
        chunks_suspect=suspect,
        chunks_quarantined=len(quarantined),
        pages_quarantined=quarantined_pages,
        quarantine_flags=flags,
    )
