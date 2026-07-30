"""Write-time defense-in-depth: prove an audit record carries no raw PII.

``AuditEvent`` is a closed schema of types/counts/tokens, so a raw value cannot
appear there *by construction*. ``assert_no_raw_values`` is the belt-and-braces
check that runs anyway, at write time, before a record touches the disk — if a
future field or a bug ever smuggles a raw value through, this fails loudly rather
than persisting it. The ``pii_tokens`` field (opaque HMAC hex) is excluded from
the scan; everything else in the record is scanned as text.
"""

from __future__ import annotations

import re
from typing import Any

# Deliberately conservative patterns — a false positive here fails a write, which
# is safe; a false negative would persist PII, which is not.
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_CARD_LIKE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
# Fields that are opaque hashes/tokens by construction — safe hex, never raw PII,
# and a 64-hex digest could otherwise trip the card-like regex.
_SKIP_KEYS = {
    "pii_tokens",
    "prev_hash",
    "chain_digest",
    "manifest_root_hash",
    "guardrails_config_sha256",
    "entities_config_sha256",
    "system_prompt_sha256",
}


class ScrubViolation(Exception):
    """A raw value was found in an audit record about to be written. Fail closed."""


def _scannable(record: dict[str, Any]) -> str:
    parts: list[str] = []
    for key, value in record.items():
        if key in _SKIP_KEYS:
            continue
        if isinstance(value, dict):
            parts.extend(str(k) for k in value)  # keys are TYPE names, not values
        elif isinstance(value, (list, tuple)):
            parts.extend(str(v) for v in value)
        elif value is not None:
            parts.append(str(value))
    return "\x1f".join(parts)


def assert_no_raw_values(record: dict[str, Any]) -> None:
    """Raise ``ScrubViolation`` if the record looks like it contains raw PII."""
    text = _scannable(record)
    if _EMAIL.search(text):
        raise ScrubViolation("audit record contains an email-like value")
    m = _CARD_LIKE.search(text)
    if m and sum(ch.isdigit() for ch in m.group()) >= 13:
        raise ScrubViolation("audit record contains a card-like digit run")
