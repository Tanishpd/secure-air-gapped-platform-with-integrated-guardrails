"""Retriever: known-answer ranking, score ordering, and the refusal gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from sagp.guardrails.policy import load_policy
from sagp.rag.ingest import ingest_pdf
from sagp.rag.qdrant_store import QdrantStore
from sagp.rag.retriever import Retriever


@pytest.fixture(scope="module")
def retriever(bge_embedder, chunk_tokenizer, sample_pdfs):  # type: ignore[no-untyped-def]
    store = QdrantStore.memory()
    ingest_pdf(
        sample_pdfs["handbook"],
        collection="hb",
        store=store,
        embedder=bge_embedder,
        chunk_tokenizer=chunk_tokenizer,
    )
    policy = load_policy(Path("config/guardrails.yaml")).retrieval
    return Retriever(store, bge_embedder, policy, collection="hb")


def test_known_answer_ranks_first(retriever: Retriever) -> None:
    r = retriever.retrieve("How many days of parental leave am I entitled to?")
    assert r.answerable
    assert "parental leave" in r.hits[0].chunk.text.lower()


def test_hits_sorted_desc_and_above_min(retriever: Retriever) -> None:
    r = retriever.retrieve("remote work equipment policy")
    assert r.hits
    scores = [h.score for h in r.hits]
    assert scores == sorted(scores, reverse=True)
    assert all(s >= 0.35 for s in scores)


def test_unrelated_query_is_refused(retriever: Retriever) -> None:
    # Nothing in the handbook is about this; no hit clears strong_score -> refuse,
    # no LLM call (C15).
    r = retriever.retrieve("orbital mechanics of binary neutron star mergers")
    assert not r.answerable
