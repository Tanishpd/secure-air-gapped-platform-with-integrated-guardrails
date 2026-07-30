"""Core data types shared across the pipeline.

This module is the base of the dependency graph together with ``config`` and
``errors``: it imports **only** the standard library (no pydantic, no sagp.*),
so every other package can depend on it without creating a cycle. Types here are
plain frozen dataclasses and enums — validation and serialisation live in the
FastAPI schema layer (``app/schemas.py``), not here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Decision(StrEnum):
    """Outcome of a single guardrail stage.

    ``UNAVAILABLE`` is fail-closed (→ 503), never a silent allow. There is no
    ``ALLOW_WITH_WARNING`` — a guardrail either passes the text or stops it.
    """

    ALLOW = "allow"
    BLOCK = "block"
    UNAVAILABLE = "unavailable"


class InjectionVerdict(StrEnum):
    """Three-way verdict for injection scanning of a document chunk.

    ``suspect`` chunks are indexed and retrievable — the assembled-context
    re-scan (C19) covers them; only ``quarantined`` is withheld from retrieval.
    """

    CLEAN = "clean"
    SUSPECT = "suspect"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class TextArtifact:
    """A unit of text as it moves through normalisation.

    ``normalized`` is the canonical string every guardrail scans (invariant 7);
    ``raw`` is retained only for the egress divergence check. ``flags`` records
    what normalisation observed (e.g. ``NFKC_CHANGED``, ``ZERO_WIDTH``,
    ``TAG_CHARS``, ``BIDI_OVERRIDE``) without carrying any of the raw content.
    """

    raw: str
    normalized: str
    flags: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class Chunk:
    """A retrievable slice of an ingested document.

    Stored **raw** under ``ingest_mode=raw`` (ADR-0006); masking happens at
    retrieval, not here. ``doc_sha256`` + ``index`` are the idempotency key
    (UUIDv5 point id at upsert time).
    """

    doc_sha256: str
    index: int
    text: str
    page: int
    source: str
    token_count: int = 0


@dataclass(frozen=True, slots=True)
class Hit:
    """A retrieval result: a chunk plus its similarity score."""

    chunk: Chunk
    score: float


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Result of an injection scan over one text surface.

    Carries entity/score detail for the audit record only — none of it crosses
    the client boundary (invariant 8). ``truncated`` means the input needed more
    than ``SAGP_MAX_WINDOWS`` windows and MUST block/quarantine, never allow.
    """

    score: float
    verdict: InjectionVerdict
    truncated: bool = False
    rule_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GuardrailDecision:
    """The outcome and timing of one guardrail stage, for the audit record."""

    stage: str
    decision: Decision
    elapsed_ms: float
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller.

    Scopes are drawn from exactly three values — ``chat``, ``ingest``,
    ``pii:reveal`` — across two bearer tokens (invariant 8). There is no
    ``admin`` scope.
    """

    id: str
    scopes: frozenset[str] = field(default_factory=frozenset)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes
