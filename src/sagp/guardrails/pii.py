"""The PII guardrail (C9–C12 ingress; C17/C22b egress reuse the same engine).

Order: analyze the normalized text → BLOCK-list check → mask the MASK-list
entities into the request-scoped vault. Only entities registered in
``entities.yaml`` are acted on; anything else Presidio surfaces (URL, ORG, …) is
ignored. Per-entity thresholds are applied here, not via Presidio's single
global threshold.

**Fail closed (OQ-6).** Presidio catches a per-pattern regex timeout and returns
a *partial* result set at 200 — a silent fail-open. So every ``analyze`` runs
under a wall-clock deadline: a catastrophic-backtracking input that would hang
(or that Presidio would silently skip) trips the deadline and becomes a
``GuardrailUnavailable`` (503), never a partial result treated as success.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from sagp.errors import GuardrailUnavailable, PromptRejected
from sagp.guardrails.aliases import resolve_person_aliases
from sagp.guardrails.entities import EntitiesPolicy
from sagp.guardrails.vault import PiiVault, VaultCapacityError


@dataclass
class PiiResult:
    masked_text: str
    entity_types: dict[str, int] = field(default_factory=dict)
    blocked_entity: str | None = None


class PiiGuardrail:
    def __init__(
        self,
        analyzer: AnalyzerEngine,
        anonymizer: AnonymizerEngine,
        entities: EntitiesPolicy,
        *,
        timeout_ms: int = 3000,
    ) -> None:
        self._analyzer = analyzer
        self._anonymizer = anonymizer
        self._entities = entities
        self._timeout_s = timeout_ms / 1000.0
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pii-analyze")

    def _analyze_with_deadline(self, text: str) -> list[RecognizerResult]:
        fut = self._pool.submit(
            self._analyzer.analyze,
            text=text,
            language="en",
            entities=list(self._entities.all_entities),
            score_threshold=0.0,
        )
        try:
            return list(fut.result(timeout=self._timeout_s))
        except FuturesTimeout as exc:
            # The runaway analyze keeps running in its thread but we fail closed.
            raise GuardrailUnavailable("pii analyze exceeded deadline") from exc
        except Exception as exc:  # any analyzer error is fail-closed, never swallowed
            raise GuardrailUnavailable("pii analyze failed") from exc

    def analyze(self, text: str, *, origin: str = "prompt") -> list[RecognizerResult]:
        """Detect and filter to registered entities meeting their per-entity threshold."""
        results = self._analyze_with_deadline(text)
        is_prompt = origin == "prompt"
        kept: list[RecognizerResult] = []
        for r in results:
            if r.entity_type not in self._entities.all_entities:
                continue
            floor = (
                self._entities.ingress_threshold(r.entity_type)
                if is_prompt
                else self._entities.egress_threshold(r.entity_type)
            )
            if r.score >= floor:
                kept.append(r)
        return kept

    def first_blocked(self, results: list[RecognizerResult]) -> str | None:
        for r in results:
            if r.entity_type in self._entities.block_names:
                return r.entity_type
        return None

    def mask(
        self,
        text: str,
        results: list[RecognizerResult],
        vault: PiiVault,
        *,
        origin: str = "prompt",
        include_block: bool = False,
    ) -> str:
        names = set(self._entities.mask_names)
        if include_block:  # egress/document surfaces MASK block-tier entities (GUARDRAILS §5.1)
            names |= set(self._entities.block_names)
        mask_results = [r for r in results if r.entity_type in names]
        if not mask_results:
            return text
        person_values = [text[r.start : r.end] for r in mask_results if r.entity_type == "PERSON"]
        alias_map = resolve_person_aliases(person_values)
        operators = {
            "PERSON": OperatorConfig(
                "vault_placeholder", {"vault": vault, "origin": origin, "aliases": alias_map}
            ),
            "DEFAULT": OperatorConfig("vault_placeholder", {"vault": vault, "origin": origin}),
        }
        try:
            out = self._anonymizer.anonymize(
                text=text,
                analyzer_results=mask_results,  # type: ignore[arg-type]
                operators=operators,
            )
        except VaultCapacityError as exc:
            raise PromptRejected("vault capacity exceeded") from exc
        return out.text

    def run_input(self, text: str, vault: PiiVault) -> PiiResult:
        """C9–C12: analyze → block → mask. Raises PromptRejected / GuardrailUnavailable."""
        results = self.analyze(text, origin="prompt")
        blocked = self.first_blocked(results)
        if blocked is not None:
            # Uniform opaque rejection; the type goes to the audit record, not the client.
            raise PromptRejected(f"blocked entity: {blocked}")
        masked = self.mask(text, results, vault, origin="prompt")
        counts = Counter(r.entity_type for r in results)
        return PiiResult(masked_text=masked, entity_types=dict(counts))

    def run_egress(self, text: str, vault: PiiVault, *, origin: str = "response") -> PiiResult:
        """Mask PII leaving the box (retrieved chunks at C17, the LLM reply at C22b).

        Uses egress thresholds and masks block-tier entities too — a card or email
        the model emits, or a chunk contains, is pseudonymised, never blocked here
        (blocking retrieval/output would be DoS/data loss; §5.1). No BLOCK-list 400.
        """
        results = self.analyze(text, origin=origin)
        masked = self.mask(text, results, vault, origin=origin, include_block=True)
        counts = Counter(r.entity_type for r in results)
        return PiiResult(masked_text=masked, entity_types=dict(counts))
