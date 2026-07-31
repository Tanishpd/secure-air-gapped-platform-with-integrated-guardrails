"""QdrantStore on :memory: — upsert/query/count and idempotent delete (no model)."""

from __future__ import annotations

import numpy as np

from sagp.rag.qdrant_store import QdrantStore
from sagp.types import Chunk


def _chunks(sha: str, n: int) -> list[Chunk]:
    return [
        Chunk(doc_sha256=sha, index=i, text=f"chunk {i}", page=1, source="d.pdf", token_count=5)
        for i in range(n)
    ]


def _vecs(n: int, dim: int = 4) -> np.ndarray:
    return np.eye(n, dim, dtype=np.float32)


def test_upsert_query_count() -> None:
    st = QdrantStore.memory(embed_revision="rev1")
    st.ensure_collection("c", dim=4)
    st.upsert("c", _chunks("sha1", 3), _vecs(3))
    assert st.count("c") == 3
    hits = st.query("c", np.array([1, 0, 0, 0], dtype=np.float32), limit=2)
    assert len(hits) <= 2
    assert hits[0].chunk.doc_sha256 == "sha1"
    assert hits[0].score >= hits[-1].score  # ordered by score


def test_delete_by_doc() -> None:
    st = QdrantStore.memory()
    st.ensure_collection("c", dim=4)
    st.upsert("c", _chunks("sha1", 3), _vecs(3))
    st.upsert("c", _chunks("sha2", 2), _vecs(2))
    st.delete_by_doc("c", "sha1")
    assert st.count("c") == 2  # only sha2 remains


def test_reupsert_same_doc_leaves_count_unchanged() -> None:
    st = QdrantStore.memory()
    st.ensure_collection("c", dim=4)
    chunks, vecs = _chunks("sha1", 3), _vecs(3)
    st.upsert("c", chunks, vecs)
    st.delete_by_doc("c", "sha1")
    st.upsert("c", chunks, vecs)
    assert st.count("c") == 3  # uuid5 ids -> same points, not duplicates


def test_ensure_collection_is_idempotent() -> None:
    st = QdrantStore.memory()
    st.ensure_collection("c", dim=4)
    st.ensure_collection("c", dim=4)  # no error
    assert st.count("c") == 0
