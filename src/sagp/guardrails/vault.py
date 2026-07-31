"""The pseudonym vault: request-scoped, in-memory, NEVER persisted (invariant 9).

Maps a detected PII value to a stable ``<TYPE_N>`` placeholder for the duration
of ONE request. A persistent vault would collide on ``<PERSON_1>`` across
identities and turn the placeholder scheme into a cross-request identity link,
so this object is deliberately hostile to persistence and to leakage:

* pickling raises (``__reduce__``) — it cannot be serialised into a cache, a
  queue, or a log;
* ``repr``/``str`` reveal nothing — a traceback or ``f"{vault}"`` cannot leak
  the mapping;
* the size cap (``SAGP_MAX_VAULT_ENTRIES``) raises rather than growing, so a
  vault-exhaustion input becomes a 400, not an OOM;
* ``clear()`` is called in a ``finally:`` at the end of every request.

Placeholders are per-type ordinals (``<PERSON_1>``, ``<PERSON_2>``, …); the
ordinal itself carries no information. Entries are origin-tagged so alias
resolution never links a name in the prompt to a name in a document.
"""

from __future__ import annotations

from typing import NoReturn

DEFAULT_MAX_ENTRIES = 2000


class VaultCapacityError(Exception):
    """The vault hit its entry cap — the caller turns this into a 400."""


class PiiVault:
    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self._max_entries = max_entries
        # (entity_type, origin, value) -> placeholder, and the reverse map.
        self._to_placeholder: dict[tuple[str, str, str], str] = {}
        self._to_value: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    def __reduce__(self) -> NoReturn:  # pickling is impossible, by design
        raise TypeError("PiiVault is request-scoped and must never be serialised")

    def __repr__(self) -> str:
        return f"<PiiVault entries={len(self._to_value)} (contents redacted)>"

    __str__ = __repr__

    def put(self, entity_type: str, value: str, origin: str) -> str:
        """Return a stable placeholder for (type, origin, value), minting on first sight."""
        key = (entity_type, origin, value)
        existing = self._to_placeholder.get(key)
        if existing is not None:
            return existing
        if len(self._to_value) >= self._max_entries:
            raise VaultCapacityError(
                f"vault exceeded {self._max_entries} entries (possible exhaustion attack)"
            )
        n = self._counts.get(entity_type, 0) + 1
        self._counts[entity_type] = n
        placeholder = f"<{entity_type}_{n}>"
        self._to_placeholder[key] = placeholder
        self._to_value[placeholder] = value
        return placeholder

    def get_placeholder(self, entity_type: str, value: str, origin: str) -> str | None:
        return self._to_placeholder.get((entity_type, origin, value))

    def value_for(self, placeholder: str) -> str | None:
        """Reverse lookup for rehydration. Unknown placeholder -> None (no fallback)."""
        return self._to_value.get(placeholder)

    def as_mapping(self) -> dict[str, str]:
        """A copy of {placeholder: value} for a single rehydration pass. Never logged."""
        return dict(self._to_value)

    def __len__(self) -> int:
        return len(self._to_value)

    def clear(self) -> None:
        self._to_placeholder.clear()
        self._to_value.clear()
        self._counts.clear()
