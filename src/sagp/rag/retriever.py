"""Retrieval + the deterministic refusal gate (pipeline C13–C15).

Embeds the **neutral** query (normalized, unmasked — never the masked prompt;
masked queries destroy recall), does a top-k cosine search with a ``min_score``
inclusion floor, and applies the answer-at-all gate: if no hit clears
``strong_score`` the request is refused **without an LLM call** — a cheap,
auditor-testable "insufficient context" answer rather than a hallucinated one.

Thresholds are data (``config/guardrails.yaml`` → ``retrieval``), so a decision
replays against the policy hash that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass

from sagp.guardrails.policy import RetrievalPolicy
from sagp.rag.embeddings import BgeEmbedder
from sagp.rag.vectorstore import VectorStore, is_quarantine_name
from sagp.types import Hit


@dataclass(frozen=True)
class RetrievalResult:
    hits: list[Hit]  # sorted by score desc, each >= min_score
    answerable: bool  # at least one hit >= strong_score


class Retriever:
    def __init__(
        self,
        store: VectorStore,
        embedder: BgeEmbedder,
        policy: RetrievalPolicy,
        *,
        collection: str,
    ) -> None:
        if is_quarantine_name(collection):
            # A quarantine sibling holds injection-flagged chunks and must never be
            # a retrieval source (M12). Refuse by construction, not by convention.
            raise ValueError(f"refusing to retrieve from a quarantine collection: {collection!r}")
        self._store = store
        self._embedder = embedder
        self._policy = policy
        self._collection = collection

    def retrieve(self, neutral_query: str) -> RetrievalResult:
        vector = self._embedder.embed_one(neutral_query, is_query=True)
        hits = self._store.query(
            self._collection,
            vector,
            limit=self._policy.top_k,
            score_threshold=self._policy.min_score,
        )
        answerable = any(h.score >= self._policy.strong_score for h in hits)
        return RetrievalResult(hits=hits, answerable=answerable)
