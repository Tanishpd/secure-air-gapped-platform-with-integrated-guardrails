"""The guardrail entry/exit for model-bound text (invariant 3).

``InputGuardrail`` runs C2–C12 on the user message (length, normalize, injection,
neutralize, PII block/mask) and ``scan_context`` runs the C19 re-scan of the
assembled context. This module imports only guardrail-level code — the RAG and
LLM steps between input and output are orchestrated by the app route, which sits
above both. ``run_output`` (C22) lives in ``output.py``.

Every string that crosses a boundary is appended to ``scanned`` so the pipeline
can prove, per request, that the bytes sent to the model and returned to the
caller were scanned (``test_final_bytes_were_scanned``).
"""

from __future__ import annotations

from dataclasses import dataclass

from sagp.config import Settings
from sagp.errors import InputTooLarge, PromptRejected
from sagp.guardrails.evaluate import decide_injection
from sagp.guardrails.injection.scanner import InjectionScanner
from sagp.guardrails.normalize import normalize
from sagp.guardrails.pii import PiiGuardrail
from sagp.guardrails.placeholders import neutralize_placeholders
from sagp.guardrails.policy import GuardrailsPolicy
from sagp.guardrails.vault import PiiVault
from sagp.types import Hit, InjectionVerdict


@dataclass(frozen=True)
class InputResult:
    neutral: str  # normalized, unmasked — for retrieval (C13)
    masked_question: str  # PII-masked — for the LLM prompt
    entity_types: dict[str, int]
    injection_score: float
    normalize_flags: tuple[str, ...]


class InputGuardrail:
    def __init__(
        self,
        scanner: InjectionScanner,
        pii: PiiGuardrail,
        policy: GuardrailsPolicy,
        settings: Settings,
    ) -> None:
        self._scanner = scanner
        self._pii = pii
        self._policy = policy
        self._settings = settings

    def run_input(self, message: str, vault: PiiVault, *, scanned: list[str]) -> InputResult:
        """C2–C12. Raises InputTooLarge / PromptRejected / GuardrailUnavailable."""
        if len(message) > self._settings.max_input_chars:
            raise InputTooLarge("input exceeds SAGP_MAX_INPUT_CHARS")

        art = normalize(message)  # C3 (also produces the neutral text)
        scanned.append(message)
        # C3–C7: decide_injection handles tag/bidi block, heuristics, deobfuscate, classifier.
        decision = decide_injection(
            message, surface="user_prompt", scanner=self._scanner, policy=self._policy
        )
        if decision.blocked:
            raise PromptRejected("injection detected")

        neutral, _ = neutralize_placeholders(art.normalized)  # C8
        pii_res = self._pii.run_input(neutral, vault)  # C9–C12: raises on block, masks otherwise
        return InputResult(
            neutral=neutral,
            masked_question=pii_res.masked_text,
            entity_types=pii_res.entity_types,
            injection_score=decision.score,
            normalize_flags=tuple(sorted(art.flags)),
        )

    def filter_context(self, hits: list[Hit]) -> tuple[list[Hit], int]:
        """C19a — drop-and-continue: scan each masked retrieved chunk on the
        ``retrieval`` surface and keep only the CLEAN ones.

        A single poisoned chunk (indirect injection planted in a document) must
        not deny service to a legitimate query that also retrieved good chunks —
        so the flagged chunk is dropped and the rest continue, rather than
        refusing the whole request. Returns ``(kept, dropped_count)``.
        """
        kept = [
            h
            for h in hits
            if self._scanner.scan([h.chunk.text], surface="retrieval").verdict
            is InjectionVerdict.CLEAN
        ]
        return kept, len(hits) - len(kept)

    def scan_context(self, assembled: str, *, scanned: list[str]) -> bool:
        """C19b: re-scan the fully assembled masked context as one string.

        Runs after ``filter_context`` and the char-budget trim, on the exact bytes
        that will reach the model — so it catches a split-across-chunks payload
        that no single chunk tripped, and it is the scan the flagship
        ``test_final_bytes_were_scanned`` asserts on. Returns True if clean.
        """
        scanned.append(assembled)
        result = self._scanner.scan([assembled], surface="retrieval")
        return result.verdict is InjectionVerdict.CLEAN
