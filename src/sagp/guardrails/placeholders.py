"""Placeholder handling: ONE regex, used by both neutralize and rehydrate.

The vault masks PII into ``<TYPE_N>`` placeholders. Two dangers this module
closes, using a single shared ``PLACEHOLDER_RE`` so the two paths can never drift:

* **Neutralize (C8):** an attacker who types ``<PERSON_1>`` into the prompt could,
  after masking, collide with a real vault placeholder and get a real value
  substituted at rehydration. So user-supplied placeholder-shaped tokens are
  defanged *before* masking (angle brackets swapped for look-alikes that the
  regex does not match). Neutralize runs AFTER normalize — NFKC folds fullwidth
  ``＜`` to ``<``, so neutralizing first would be bypassable.
* **Rehydrate (C20, gated on pii:reveal):** single pass, left-to-right; an
  unknown placeholder is left VERBATIM, never mapped through a global fallback.

Property the tests pin: anything ``rehydrate`` would match, ``neutralize`` also
matches (same regex) — so after neutralize no real-looking placeholder survives.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

# TYPE is upper snake (e.g. EMAIL_ADDRESS, IN_PAN); N is the per-request ordinal.
PLACEHOLDER_RE = re.compile(r"<([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)_(\d+)>")

# Defanged brackets: mathematical angle brackets. Human-legible, regex-inert,
# and NFKC-stable (they are not folded back to ASCII ``<``/``>``).
_OPEN, _CLOSE = "⟨", "⟩"


def neutralize_placeholders(text: str) -> tuple[str, int]:
    """Defang every placeholder-shaped token in ``text``. Returns (text, count)."""
    count = 0

    def _defang(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"{_OPEN}{m.group(1)}_{m.group(2)}{_CLOSE}"

    return PLACEHOLDER_RE.sub(_defang, text), count


def rehydrate(text: str, vault: Mapping[str, str]) -> str:
    """Replace known ``<TYPE_N>`` placeholders with their vault values, one pass.

    Unknown placeholders are left exactly as-is — there is no global fallback map
    (invariant 9), so a placeholder with no vault entry can never resolve to the
    wrong value.
    """

    def _sub(m: re.Match[str]) -> str:
        return vault.get(m.group(0), m.group(0))

    return PLACEHOLDER_RE.sub(_sub, text)
