"""bge-small embedder: dim, L2 norm, CLS behaviour, query prefix, semantics."""

from __future__ import annotations

import numpy as np

from sagp.rag.embeddings import BgeEmbedder


def test_dim_and_l2_normalized(bge_embedder: BgeEmbedder) -> None:
    v = bge_embedder.embed(["hello world", "another sentence"], is_query=False)
    assert v.shape == (2, 384)
    assert np.allclose(np.linalg.norm(v, axis=1), 1.0, atol=1e-4)


def test_deterministic(bge_embedder: BgeEmbedder) -> None:
    a = bge_embedder.embed_one("repeatable input", is_query=False)
    b = bge_embedder.embed_one("repeatable input", is_query=False)
    assert np.allclose(a, b)


def test_query_prefix_changes_the_vector(bge_embedder: BgeEmbedder) -> None:
    q = bge_embedder.embed_one("parental leave policy", is_query=True)
    d = bge_embedder.embed_one("parental leave policy", is_query=False)
    assert not np.allclose(q, d)


def test_semantic_similarity_orders_correctly(bge_embedder: BgeEmbedder) -> None:
    v = bge_embedder.embed(
        [
            "How many days of parental leave am I entitled to?",
            "parental leave entitlement for full-time staff",
            "the cafeteria menu for next Tuesday",
        ],
        is_query=False,
    )
    related = float(v[0] @ v[1])
    unrelated = float(v[0] @ v[2])
    assert related > unrelated


def test_empty_input(bge_embedder: BgeEmbedder) -> None:
    assert bge_embedder.embed([], is_query=False).shape == (0, 384)
