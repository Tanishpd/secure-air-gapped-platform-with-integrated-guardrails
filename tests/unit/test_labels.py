"""Label resolution: never hardcode index 1; refuse opaque/ambiguous mappings."""

from __future__ import annotations

import pytest

from sagp.guardrails.injection.labels import LabelResolutionError, resolve_injection_index

POSITIVE = ("injection", "prompt_injection", "malicious", "unsafe", "attack", "jailbreak")


def test_standard_mapping() -> None:
    assert resolve_injection_index({"0": "SAFE", "1": "INJECTION"}, POSITIVE) == 1


def test_inverted_mapping_resolves_to_zero() -> None:
    # If a checkpoint renumbered its labels, we follow id2label — not a fixed index.
    assert resolve_injection_index({"0": "INJECTION", "1": "SAFE"}, POSITIVE) == 0


def test_casefold_and_aliases() -> None:
    assert resolve_injection_index({"0": "benign", "1": "Prompt_Injection"}, POSITIVE) == 1


def test_opaque_label_refuses() -> None:
    with pytest.raises(LabelResolutionError):
        resolve_injection_index({"0": "LABEL_0", "1": "LABEL_1"}, POSITIVE)


def test_no_match_refuses() -> None:
    with pytest.raises(LabelResolutionError):
        resolve_injection_index({"0": "cat", "1": "dog"}, POSITIVE)


def test_ambiguous_multiple_matches_refuses() -> None:
    with pytest.raises(LabelResolutionError):
        resolve_injection_index({"0": "injection", "1": "malicious"}, POSITIVE)
