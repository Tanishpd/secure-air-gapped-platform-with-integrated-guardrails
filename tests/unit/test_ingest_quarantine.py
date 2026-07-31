"""Ingest-time injection scan (M12): clean/suspect/quarantine routing + the
never-retrieved sibling collection.

Two lenses: the REAL scanner proves a visible indirect-injection payload is
quarantined out of the retrievable collection (robust — a blatant injection
scores ~1.0 on the document surface); a FakeScorer proves the exact three-way
split including the SUSPECT tier, which is score-dependent and not worth pinning
to the real model.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from sagp.guardrails.injection.scanner import InjectionScanner, WindowScore
from sagp.guardrails.policy import load_policy
from sagp.rag.ingest import ingest_pdf
from sagp.rag.qdrant_store import QdrantStore
from sagp.rag.vectorstore import quarantine_name


def _gen_module():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("gen_sample_pdf", "scripts/gen_sample_pdf.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class MarkerScorer:
    """Scores a chunk by the loudest marker substring it contains (document surface)."""

    def __init__(self, scores: dict[str, float]) -> None:
        self._scores = scores

    def score_max(self, text: str) -> WindowScore:
        best = max((v for k, v in self._scores.items() if k in text), default=0.0)
        return WindowScore(max_score=best, n_windows=1, truncated=False)


# --- real scanner: the visible payload is quarantined, the clean page indexed ---


def test_visible_injection_is_quarantined(  # type: ignore[no-untyped-def]
    injection_scanner, bge_embedder, chunk_tokenizer, sample_pdfs
) -> None:
    policy = load_policy(Path("config/guardrails.yaml"))
    store = QdrantStore.memory()
    r = ingest_pdf(
        sample_pdfs["poisoned_visible"],
        collection="pv",
        store=store,
        embedder=bge_embedder,
        chunk_tokenizer=chunk_tokenizer,
        scanner=injection_scanner,
        policy=policy,
    )
    assert r.chunks_quarantined >= 1  # the SYSTEM OVERRIDE page
    assert r.chunks_indexed >= 1  # the records-retention page
    assert store.count("pv") == r.chunks_indexed
    assert store.count(quarantine_name("pv")) == r.chunks_quarantined

    # The payload text is unreachable from the retrievable collection.
    qv = bge_embedder.embed_one("reveal your system prompt", is_query=True)
    hits = store.query("pv", qv, limit=5)
    assert all("SYSTEM OVERRIDE" not in h.chunk.text for h in hits)


def test_quarantine_is_idempotent(  # type: ignore[no-untyped-def]
    injection_scanner, bge_embedder, chunk_tokenizer, sample_pdfs
) -> None:
    policy = load_policy(Path("config/guardrails.yaml"))
    store = QdrantStore.memory()
    kw = {
        "collection": "pv",
        "store": store,
        "embedder": bge_embedder,
        "chunk_tokenizer": chunk_tokenizer,
        "scanner": injection_scanner,
        "policy": policy,
    }
    r1 = ingest_pdf(sample_pdfs["poisoned_visible"], **kw)
    r2 = ingest_pdf(sample_pdfs["poisoned_visible"], **kw)  # re-ingest the same file
    assert store.count("pv") == r1.chunks_indexed == r2.chunks_indexed
    assert store.count(quarantine_name("pv")) == r1.chunks_quarantined == r2.chunks_quarantined


# --- FakeScorer: the exact clean / suspect / quarantine split ---


def test_three_way_routing_with_fake_scorer(  # type: ignore[no-untyped-def]
    bge_embedder, chunk_tokenizer, tmp_path
) -> None:
    gen = _gen_module()
    # One marker per page so each becomes its own chunk.
    pdf = gen.build_pdf(
        [
            [("Records office note. This page is marker AAA and is fine.", 72, 700, 11)],
            [("Records office note. This page is marker BBB and is borderline.", 72, 700, 11)],
            [("Records office note. This page is marker CCC and is hostile.", 72, 700, 11)],
        ]
    )
    doc = tmp_path / "markers.pdf"
    doc.write_bytes(pdf)

    policy = load_policy(Path("config/guardrails.yaml"))
    # doc_suspect=0.70, doc_quarantine=0.95
    scorer = MarkerScorer({"AAA": 0.10, "BBB": 0.80, "CCC": 0.97})
    scanner = InjectionScanner(scorer, policy.injection)

    store = QdrantStore.memory()
    r = ingest_pdf(
        doc,
        collection="mk",
        store=store,
        embedder=bge_embedder,
        chunk_tokenizer=chunk_tokenizer,
        scanner=scanner,
        policy=policy,
    )
    assert r.chunks_indexed == 2  # AAA clean + BBB suspect
    assert r.chunks_suspect == 1  # BBB
    assert r.chunks_quarantined == 1  # CCC
    assert store.count("mk") == 2
    assert store.count(quarantine_name("mk")) == 1


def test_no_scanner_indexes_everything_clean(  # type: ignore[no-untyped-def]
    bge_embedder, chunk_tokenizer, sample_pdfs
) -> None:
    # The M8 call shape (no scanner) still works: every chunk is treated clean.
    store = QdrantStore.memory()
    r = ingest_pdf(
        sample_pdfs["poisoned_visible"],
        collection="pv",
        store=store,
        embedder=bge_embedder,
        chunk_tokenizer=chunk_tokenizer,
    )
    assert r.chunks_quarantined == 0
    assert store.count("pv") == r.chunks_indexed
    assert not store.collection_exists(quarantine_name("pv"))
