"""The vault: request-scoped, unpicklable, leak-proof repr, capped (invariant 9)."""

from __future__ import annotations

import pickle

import pytest

from sagp.guardrails.vault import PiiVault, VaultCapacityError


def test_stable_placeholder_per_value() -> None:
    v = PiiVault()
    p1 = v.put("PERSON", "Alice", "prompt")
    p2 = v.put("PERSON", "Alice", "prompt")
    assert p1 == p2 == "<PERSON_1>"
    assert v.put("PERSON", "Bob", "prompt") == "<PERSON_2>"
    assert v.put("EMAIL_ADDRESS", "a@b.com", "prompt") == "<EMAIL_ADDRESS_1>"


def test_origin_separates_identical_values() -> None:
    v = PiiVault()
    a = v.put("PERSON", "Alice", "prompt")
    b = v.put("PERSON", "Alice", "doc:abc")
    assert a != b  # never cross-link a prompt name to a document name


def test_pickling_is_impossible() -> None:
    v = PiiVault()
    v.put("PERSON", "Alice", "prompt")
    with pytest.raises(TypeError):
        pickle.dumps(v)


def test_repr_and_str_leak_nothing() -> None:
    v = PiiVault()
    v.put("EMAIL_ADDRESS", "secret@example.com", "prompt")
    for rendered in (repr(v), str(v), f"{v}"):
        assert "secret@example.com" not in rendered
        assert "<EMAIL_ADDRESS_1>" not in rendered  # not even the placeholder->value hint


def test_capacity_raises_not_grows() -> None:
    v = PiiVault(max_entries=3)
    for i in range(3):
        v.put("PERSON", f"P{i}", "prompt")
    with pytest.raises(VaultCapacityError):
        v.put("PERSON", "overflow", "prompt")
    assert len(v) == 3


def test_reverse_lookup_and_clear() -> None:
    v = PiiVault()
    ph = v.put("PERSON", "Alice", "prompt")
    assert v.value_for(ph) == "Alice"
    assert v.value_for("<PERSON_99>") is None  # unknown -> None, no fallback
    v.clear()
    assert len(v) == 0
    assert v.value_for(ph) is None
