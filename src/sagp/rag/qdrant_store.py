"""Qdrant-backed VectorStore (embedded / server / ``:memory:``).

Point ids are ``uuid5(NS, f"{doc_sha256}:{index}")`` so re-ingesting the same
document overwrites the same points (idempotent). Retrieval uses
``query_points`` (``search`` was removed in qdrant-client 1.16.0) and reads the
results from ``.points``. Deletion by document uses a ``query_filter`` on the
``doc_sha256`` payload key.
"""

from __future__ import annotations

import uuid

import numpy as np
from qdrant_client import QdrantClient, models

from sagp.rag.embeddings import BgeEmbedder
from sagp.types import Chunk, Hit

_NAMESPACE = uuid.UUID("5b3a9c1e-0d2f-4a6b-9c7d-8e1f2a3b4c5d")


def _point_id(doc_sha256: str, index: int) -> str:
    return str(uuid.uuid5(_NAMESPACE, f"{doc_sha256}:{index}"))


class QdrantStore:
    def __init__(self, client: QdrantClient, *, embed_revision: str = "") -> None:
        self._client = client
        self._embed_revision = embed_revision

    @classmethod
    def memory(cls, *, embed_revision: str = "") -> QdrantStore:
        return cls(QdrantClient(":memory:"), embed_revision=embed_revision)

    @classmethod
    def embedded(cls, path: str, *, embed_revision: str = "") -> QdrantStore:
        return cls(QdrantClient(path=path), embed_revision=embed_revision)

    def ensure_collection(self, name: str, *, dim: int) -> None:
        if not self._client.collection_exists(name):
            self._client.create_collection(
                name,
                vectors_config=models.VectorParams(size=dim, distance=models.Distance.COSINE),
            )

    def upsert(self, name: str, chunks: list[Chunk], vectors: np.ndarray) -> None:
        if not chunks:
            return
        points = [
            models.PointStruct(
                id=_point_id(c.doc_sha256, c.index),
                vector=vectors[i].tolist(),
                payload={
                    "text": c.text,
                    "page": c.page,
                    "source": c.source,
                    "doc_sha256": c.doc_sha256,
                    "index": c.index,
                    "token_count": c.token_count,
                    "embed_model": BgeEmbedder.MODEL_ID,
                    "embed_revision": self._embed_revision,
                },
            )
            for i, c in enumerate(chunks)
        ]
        self._client.upsert(name, points=points)

    def query(
        self, name: str, vector: np.ndarray, *, limit: int, score_threshold: float | None = None
    ) -> list[Hit]:
        resp = self._client.query_points(
            name,
            query=vector.tolist(),
            limit=limit,
            score_threshold=score_threshold,
            with_payload=True,
        )
        hits: list[Hit] = []
        for p in resp.points:
            pl = p.payload or {}
            chunk = Chunk(
                doc_sha256=str(pl.get("doc_sha256", "")),
                index=int(pl.get("index", 0)),
                text=str(pl.get("text", "")),
                page=int(pl.get("page", 0)),
                source=str(pl.get("source", "")),
                token_count=int(pl.get("token_count", 0)),
            )
            hits.append(Hit(chunk=chunk, score=float(p.score)))
        return hits

    def delete_by_doc(self, name: str, doc_sha256: str) -> None:
        self._client.delete(
            name,
            points_selector=models.FilterSelector(
                filter=models.Filter(
                    must=[
                        models.FieldCondition(
                            key="doc_sha256", match=models.MatchValue(value=doc_sha256)
                        )
                    ]
                )
            ),
        )

    def count(self, name: str) -> int:
        return self._client.count(name).count
