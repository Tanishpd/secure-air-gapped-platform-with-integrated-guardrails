"""End-to-end ingest on :memory: — indexing, idempotence, quarantine, retrieval."""

from __future__ import annotations

from sagp.rag.ingest import ingest_pdf
from sagp.rag.qdrant_store import QdrantStore


def test_ingest_handbook_indexes_chunks(bge_embedder, chunk_tokenizer, sample_pdfs) -> None:  # type: ignore[no-untyped-def]
    store = QdrantStore.memory()
    r = ingest_pdf(
        sample_pdfs["handbook"],
        collection="hb",
        store=store,
        embedder=bge_embedder,
        chunk_tokenizer=chunk_tokenizer,
    )
    assert r.chunks_indexed > 0
    assert r.pages_quarantined == []
    assert store.count("hb") == r.chunks_indexed


def test_ingest_is_idempotent(bge_embedder, chunk_tokenizer, sample_pdfs) -> None:  # type: ignore[no-untyped-def]
    store = QdrantStore.memory()
    kw = {
        "collection": "hb",
        "store": store,
        "embedder": bge_embedder,
        "chunk_tokenizer": chunk_tokenizer,
    }
    r1 = ingest_pdf(sample_pdfs["handbook"], **kw)
    r2 = ingest_pdf(sample_pdfs["handbook"], **kw)  # re-ingest same file
    assert r1.doc_sha256 == r2.doc_sha256
    assert store.count("hb") == r1.chunks_indexed == r2.chunks_indexed


def test_ingest_quarantines_hidden_text_page(bge_embedder, chunk_tokenizer, sample_pdfs) -> None:  # type: ignore[no-untyped-def]
    store = QdrantStore.memory()
    r = ingest_pdf(
        sample_pdfs["poisoned"],
        collection="pa",
        store=store,
        embedder=bge_embedder,
        chunk_tokenizer=chunk_tokenizer,
    )
    assert r.pages_quarantined  # the sub-1pt payload page is withheld
    assert "PDF_TINY_FONT" in r.quarantine_flags[r.pages_quarantined[0]]
    assert store.count("pa") == r.chunks_indexed


def test_ingest_then_retrieve_grounds(bge_embedder, chunk_tokenizer, sample_pdfs) -> None:  # type: ignore[no-untyped-def]
    store = QdrantStore.memory()
    ingest_pdf(
        sample_pdfs["handbook"],
        collection="hb",
        store=store,
        embedder=bge_embedder,
        chunk_tokenizer=chunk_tokenizer,
    )
    qv = bge_embedder.embed_one("How many days of parental leave?", is_query=True)
    hits = store.query("hb", qv, limit=3)
    assert hits
    assert "parental leave" in hits[0].chunk.text.lower()
