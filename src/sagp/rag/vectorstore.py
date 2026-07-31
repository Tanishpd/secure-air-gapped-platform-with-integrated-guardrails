"""The VectorStore adapter interface.

Qdrant is the only backend in this design, but the pipeline talks to this
Protocol so the embedded / server / ``:memory:`` backends are interchangeable
and tests never need a real service.
"""

from __future__ import annotations

from typing import Protocol

import numpy as np

from sagp.types import Chunk, Hit


class VectorStore(Protocol):
    def ensure_collection(self, name: str, *, dim: int) -> None: ...

    def upsert(self, name: str, chunks: list[Chunk], vectors: np.ndarray) -> None: ...

    def query(
        self, name: str, vector: np.ndarray, *, limit: int, score_threshold: float | None = None
    ) -> list[Hit]: ...

    def delete_by_doc(self, name: str, doc_sha256: str) -> None: ...

    def count(self, name: str) -> int: ...
