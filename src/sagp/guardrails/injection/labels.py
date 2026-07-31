"""Resolve the INJECTION class index from the checkpoint (invariant 5).

The classifier ships ``config.json`` with ``id2label`` (e.g. ``{"0":"SAFE",
"1":"INJECTION"}``). Hardcoding index 1 silently *inverts* the guard — it would
block benign traffic and admit attacks, and every downstream test would still
pass. So the index is resolved from ``id2label`` at boot, matched **casefolded**
against an alias set. An opaque positional id like ``LABEL_1`` is UNRESOLVABLE
and refuses to boot — matching it would reinstate the positional assumption this
exists to remove.
"""

from __future__ import annotations


class LabelResolutionError(Exception):
    """id2label could not be mapped to an INJECTION index — refuse to boot."""


def resolve_injection_index(
    id2label: dict[str, str] | dict[int, str],
    positive_aliases: tuple[str, ...] | list[str],
) -> int:
    """Return the index whose label casefold-matches a positive alias.

    Raises ``LabelResolutionError`` if zero or more than one index matches, or if
    a label is an opaque ``LABEL_n`` placeholder.
    """
    aliases = {a.casefold() for a in positive_aliases}
    normalized: dict[int, str] = {int(k): str(v) for k, v in id2label.items()}

    for label in normalized.values():
        if label.casefold().startswith("label_") or label.casefold().startswith("label "):
            raise LabelResolutionError(
                f"opaque positional label {label!r} in id2label={normalized} — "
                "cannot resolve INJECTION safely; refusing to boot"
            )

    matches = [idx for idx, label in normalized.items() if label.casefold() in aliases]
    if len(matches) != 1:
        raise LabelResolutionError(
            f"expected exactly one INJECTION label in id2label={normalized} "
            f"matching {sorted(aliases)}, found {matches}"
        )
    return matches[0]
