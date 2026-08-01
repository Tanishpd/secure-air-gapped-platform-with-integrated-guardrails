"""The VectorStore adapter interface.

Qdrant is the only backend in this design, but the pipeline talks to this
Protocol so the embedded / server / ``:memory:`` backends are interchangeable
and tests never need a real service.

Each indexed point carries a ``guard`` verdict in its payload — ``clean`` or
``suspect`` (M12). ``quarantined`` chunks never land in a retrievable collection
at all: they go to a sibling ``<name>__quarantine`` collection that the retriever
refuses to open (``is_quarantine_name``), so a poisoned chunk is stored for
forensics but is unreachable by construction, not merely by a filter.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

import numpy as np

from sagp.types import Chunk, Hit

QUARANTINE_SUFFIX = "__quarantine"


def quarantine_name(collection: str) -> str:
    """The sibling collection that holds a document's injection-quarantined chunks."""
    return f"{collection}{QUARANTINE_SUFFIX}"


def is_quarantine_name(collection: str) -> bool:
    """True if ``collection`` is a quarantine sibling — never retrieve from one."""
    return collection.endswith(QUARANTINE_SUFFIX)


class VectorStore(Protocol):
    def ensure_collection(self, name: str, *, dim: int) -> None: ...

    def upsert(
        self,
        name: str,
        chunks: list[Chunk],
        vectors: np.ndarray,
        *,
        guards: Sequence[str] | None = None,
    ) -> None: ...

    def query(
        self, name: str, vector: np.ndarray, *, limit: int, score_threshold: float | None = None
    ) -> list[Hit]: ...

    def delete_by_doc(self, name: str, doc_sha256: str) -> None: ...

    def collection_exists(self, name: str) -> bool: ...

    def count(self, name: str) -> int: ...

    def list_chunks(self, name: str, *, limit: int = 100) -> list[Chunk]: ...
