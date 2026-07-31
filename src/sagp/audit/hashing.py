"""Hashing primitives for the audit spine.

Two distinct mechanisms, deliberately kept separate:

* **Chain digests** — plain SHA-256 over canonical JSON. Tamper-*evident*
  (reordering/deletion is detectable), not tamper-*proof* (an attacker with write
  access can rebuild the chain unless the head digest is exported off-box).
* **Correlation tokens** — keyed, domain-separated HMAC-SHA-256. Lets two records
  be linked on "the same email appeared" without ever storing the email
  (invariant 1). The key is the PII pepper (OQ-12); rotating it intentionally
  breaks correlation across the rotation point.

Stdlib only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import unicodedata
from typing import Any

GENESIS = "0" * 64
_UNIT_SEP = "\x1f"


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON bytes: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chain_digest(payload: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of ``payload`` (which must include prev_hash).

    ``payload`` is the record MINUS its own ``chain_digest`` field, so the digest
    binds every semantic field plus the link to the previous record.
    """
    return sha256_hex(canonical_json(payload))


def normalize_entity(entity_type: str, value: str) -> str:
    """Per-type normalization so the SAME entity yields the SAME correlation token.

    Casefold + NFKC + whitespace-collapse by default; e-mails and numeric ids
    additionally strip separators so "4111 1111" and "4111-1111" correlate.
    """
    v = unicodedata.normalize("NFKC", value).strip().casefold()
    v = " ".join(v.split())
    if entity_type in {"CREDIT_CARD", "US_SSN", "IBAN_CODE", "PHONE_NUMBER", "IN_AADHAAR"}:
        v = "".join(ch for ch in v if ch.isalnum())
    return v


def hmac_token(key: bytes, entity_type: str, value: str) -> str:
    """Domain-separated HMAC correlation token for a PII value.

    ``HMAC(key, f"entity:{type}\\x1f{normalize(type, value)}")`` — the domain
    prefix and unit separator stop a value of one type colliding with another.
    The raw ``value`` never leaves this function.
    """
    msg = f"entity:{entity_type}{_UNIT_SEP}{normalize_entity(entity_type, value)}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
