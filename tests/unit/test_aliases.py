"""PERSON alias resolution: unambiguous linking; ambiguous over-masks."""

from __future__ import annotations

from sagp.guardrails.aliases import resolve_person_aliases


def test_short_form_links_to_single_superset() -> None:
    m = resolve_person_aliases(["Alice Smith", "Alice", "Smith"])
    assert m["Alice"] == "Alice Smith"
    assert m["Smith"] == "Alice Smith"
    assert m["Alice Smith"] == "Alice Smith"


def test_ambiguous_short_form_stays_itself() -> None:
    # "Alice" is a subset of two full names -> ambiguous -> its own placeholder.
    m = resolve_person_aliases(["Alice Smith", "Alice Jones", "Alice"])
    assert m["Alice"] == "Alice"  # never cross-links two identities
    assert m["Alice Smith"] == "Alice Smith"
    assert m["Alice Jones"] == "Alice Jones"


def test_case_and_order_variants_collapse() -> None:
    m = resolve_person_aliases(["Alice Smith", "smith alice", "ALICE SMITH"])
    assert len(set(m.values())) == 1  # all one canonical


def test_singleton_and_empty() -> None:
    assert resolve_person_aliases(["Alice"]) == {"Alice": "Alice"}
    assert resolve_person_aliases([]) == {}


def test_unrelated_names_are_independent() -> None:
    m = resolve_person_aliases(["Alice Smith", "Bob Jones"])
    assert m["Alice Smith"] == "Alice Smith"
    assert m["Bob Jones"] == "Bob Jones"
