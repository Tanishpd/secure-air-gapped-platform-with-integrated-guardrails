"""The ONLY construction site for Presidio engines (CLAUDE.md §6).

Builds a local-only ``AnalyzerEngine`` (spaCy ``en_core_web_md``, no downloads),
swaps the stock ``EmailRecognizer`` for the ``SealedEmailRecognizer``, registers
the custom recognizers, and builds an ``AnonymizerEngine`` with the
``VaultPlaceholder`` operator that masks each detected value into the
request-scoped vault. Never construct these anywhere else, and never at import
time — the builders are ``@lru_cache`` singletons so a process loads spaCy once.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import cast

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import InAadhaarRecognizer, InPanRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.operators import Operator, OperatorType

from sagp.guardrails.recognizers import SealedEmailRecognizer, build_custom_recognizers
from sagp.guardrails.vault import PiiVault


class VaultPlaceholder(Operator):
    """Anonymizer operator: replace a detected value with a vault placeholder.

    Presidio injects ``params["entity_type"]`` per span (EngineBase). We mask
    into the request-scoped vault, origin-tagged, and return the ``<TYPE_N>``.
    """

    def operator_name(self) -> str:
        return "vault_placeholder"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize

    def validate(self, params: dict[str, object] | None = None) -> None:
        if not params or not isinstance(params.get("vault"), PiiVault):
            raise ValueError("vault_placeholder requires a PiiVault in params['vault']")

    def operate(self, text: str, params: dict[str, object] | None = None) -> str:
        params = params or {}
        vault = cast(PiiVault, params["vault"])
        entity_type = str(params.get("entity_type", "ENTITY"))
        origin = str(params.get("origin", "prompt"))
        # Alias resolution (PERSON): map a short form to its canonical value so all
        # forms share one placeholder. Unlisted values map to themselves.
        aliases = cast("dict[str, str]", params.get("aliases") or {})
        value = aliases.get(text, text)
        return vault.put(entity_type, value, origin)


@lru_cache(maxsize=2)
def build_analyzer(
    spacy_model: str = "en_core_web_md",
    tldextract_cache: Path = Path("models/tldextract"),
    recognizers_dir: Path = Path("config/recognizers"),
) -> AnalyzerEngine:
    nlp_engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": spacy_model}],
        }
    ).create_engine()

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(languages=["en"], nlp_engine=nlp_engine)
    # Swap stock EmailRecognizer for the sealed one (no PSL phone-home).
    registry.remove_recognizer("EmailRecognizer")
    registry.add_recognizer(SealedEmailRecognizer(cache_dir=tldextract_cache))
    # India recognizers are predefined but NOT loaded by languages=["en"] — without
    # this, IN_AADHAAR / IN_PAN are policy entities with no recognizer (0 recall).
    # Found by the M6 metrics gate.
    registry.add_recognizer(InAadhaarRecognizer())
    registry.add_recognizer(InPanRecognizer())
    for rec in build_custom_recognizers(recognizers_dir):
        registry.add_recognizer(rec)

    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry, supported_languages=["en"])


@lru_cache(maxsize=1)
def build_anonymizer() -> AnonymizerEngine:
    engine = AnonymizerEngine()  # type: ignore[no-untyped-call]
    engine.add_anonymizer(VaultPlaceholder)
    return engine
