"""PERSON alias resolution (C11): map short forms to one placeholder — safely.

When Presidio finds "Alice", "alice" and "Alice Smith" in the SAME origin, they
should mask to the SAME ``<PERSON_1>`` so the LLM sees a consistent referent. But
the linking must never over-reach: the rules are longest-first, strict subset,
and **exactly one** superset. If a short form has two possible supersets
("Alice" when both "Alice Smith" and "Alice Jones" appear) it is AMBIGUOUS and
gets its own placeholder — over-mask, never cross-link two identities.

Resolution is per-origin (the caller passes prompt names and document names
separately), so a name in the prompt is never linked to a name in a document.
"""

from __future__ import annotations


def _tokens(value: str) -> frozenset[str]:
    return frozenset(t for t in value.casefold().split() if t)


def resolve_person_aliases(values: list[str]) -> dict[str, str]:
    """Map each PERSON value to its canonical (longest unambiguous) form.

    Values with no unambiguous superset map to themselves. Inputs sharing the
    same token set (case/order variants) collapse to one canonical form.
    """
    distinct = list(dict.fromkeys(values))  # preserve order, drop dups
    if len(distinct) < 2:
        return {v: v for v in distinct}

    # Group case/order variants by token set; canonical = longest, then lexical.
    groups: dict[frozenset[str], list[str]] = {}
    for v in distinct:
        groups.setdefault(_tokens(v), []).append(v)
    canonical_of_key: dict[frozenset[str], str] = {
        key: sorted(members, key=lambda s: (-len(s), s))[0] for key, members in groups.items()
    }

    keys = [k for k in groups if k]  # ignore empty token sets
    resolved_key: dict[frozenset[str], frozenset[str]] = {}
    for k in keys:
        supersets = [other for other in keys if other != k and k < other]  # strict subset
        resolved_key[k] = supersets[0] if len(supersets) == 1 else k

    out: dict[str, str] = {}
    for v in distinct:
        key = _tokens(v)
        if not key:
            out[v] = v
            continue
        out[v] = canonical_of_key[resolved_key[key]]
    return out
