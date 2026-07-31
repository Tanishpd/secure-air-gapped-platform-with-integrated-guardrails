"""Custom recognizers, and the sealed email recognizer.

``SealedEmailRecognizer`` is the fix for the tldextract phone-home the eval
caught: Presidio's stock ``EmailRecognizer.validate_result`` calls module-level
``tldextract.extract``, which fetches the Public Suffix List over HTTPS on first
use — an ``EgressViolation`` on a sealed box. We construct a private extractor
with ``suffix_list_urls=()`` (no HTTP) + the bundled snapshot, so no fetch ever
happens regardless of cache state (BLUEPRINT §5.4).

The custom pattern/deny-list recognizers (IFSC, employee id, secrets, codenames)
are built from ``config/recognizers/*.yaml`` so the detection surface is data.
"""

from __future__ import annotations

from pathlib import Path

import tldextract
import yaml
from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer.predefined_recognizers import EmailRecognizer


def _sealed_tld(cache_dir: Path) -> tldextract.TLDExtract:
    return tldextract.TLDExtract(
        suffix_list_urls=(),  # verified: empty tuple issues NO HTTP request
        cache_dir=str(cache_dir),
        fallback_to_snapshot=True,  # bundled PSL snapshot is the offline guarantee
    )


class SealedEmailRecognizer(EmailRecognizer):
    """EmailRecognizer whose TLD validation never touches the network."""

    def __init__(self, cache_dir: Path, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._tld = _sealed_tld(cache_dir)

    def validate_result(self, pattern_text: str) -> bool:
        return self._tld(pattern_text).fqdn != ""


def build_custom_recognizers(recognizers_dir: Path) -> list[PatternRecognizer]:
    """Build PatternRecognizers from every ``config/recognizers/*.yaml``."""
    out: list[PatternRecognizer] = []
    for path in sorted(recognizers_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_bytes()) or {}
        for spec in data.get("recognizers", []):
            entity = spec["entity"]
            context = spec.get("context")
            if "patterns" in spec:
                patterns = [
                    Pattern(name=p["name"], regex=p["regex"], score=float(p["score"]))
                    for p in spec["patterns"]
                ]
                out.append(
                    PatternRecognizer(supported_entity=entity, patterns=patterns, context=context)
                )
            if "deny_list" in spec:
                out.append(
                    PatternRecognizer(
                        supported_entity=entity,
                        deny_list=list(spec["deny_list"]),
                        context=context,
                    )
                )
    return out
