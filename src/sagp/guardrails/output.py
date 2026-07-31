"""Output guardrail (C22): the last check before bytes reach the caller.

* **Structural (C22a)** — strip markdown images/links (image-beacon exfiltration),
  and *suppress* the whole answer if the model echoed the nonce delimiter or a
  system-prompt marker (a zero-click exfil / prompt-leak signal). A suppressed
  answer returns the refusal text, not the model's output.
* **Egress PII (C22b)** — mask any PII the model emitted (or a retrieved chunk
  carried through), including block-tier entities, into the request vault.
* **Citation range (C22d)** — keep only ``[Sn, p.X]`` markers whose page was
  actually supplied; drop out-of-range citations.

Buffered input only — the whole reply is scanned before a byte is returned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sagp.guardrails.pii import PiiGuardrail
from sagp.guardrails.vault import PiiVault

_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_CITATION = re.compile(r"\[S(\d+),\s*p\.(\d+)\]")
_SYSTEM_MARKERS = ("<<<UNTRUSTED_DOCUMENT_", "you are a careful assistant")


@dataclass(frozen=True)
class OutputResult:
    masked_response: str
    citations: list[str] = field(default_factory=list)
    entity_types: dict[str, int] = field(default_factory=dict)
    suppressed: bool = False  # structural violation -> caller returns the refusal text


class OutputGuardrail:
    def __init__(self, pii: PiiGuardrail) -> None:
        self._pii = pii

    def run_output(
        self,
        response_raw: str,
        *,
        nonce: str,
        supplied_pages: set[int],
        vault: PiiVault,
        scanned: list[str],
    ) -> OutputResult:
        scanned.append(response_raw)

        low = response_raw.lower()
        if f"untrusted_document_{nonce}" in low or any(m in low for m in _SYSTEM_MARKERS):
            return OutputResult(
                masked_response="", suppressed=True
            )  # C22a: zero-click exfil / leak

        # C22a: strip markdown images and links (keep the link text).
        stripped = _MD_IMAGE.sub("", response_raw)
        stripped = _MD_LINK.sub(r"\1", stripped)

        # C22b: mask PII leaving the box (incl. block-tier entities).
        egress = self._pii.run_egress(stripped, vault, origin="response")

        # C22d: keep only in-range citations.
        citations = [
            f"S{s} p.{p}"
            for s, p in _CITATION.findall(egress.masked_text)
            if int(p) in supplied_pages
        ]
        return OutputResult(
            masked_response=egress.masked_text,
            citations=citations,
            entity_types=egress.entity_types,
        )
