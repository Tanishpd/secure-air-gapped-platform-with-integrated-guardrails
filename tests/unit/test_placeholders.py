"""Placeholders: the neutralize ⊇ rehydrate property; single-pass rehydrate."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from sagp.guardrails.placeholders import PLACEHOLDER_RE, neutralize_placeholders, rehydrate


def test_neutralize_defangs_user_placeholder() -> None:
    text, n = neutralize_placeholders("email me at <EMAIL_ADDRESS_1> now")
    assert n == 1
    assert "<EMAIL_ADDRESS_1>" not in text
    assert not PLACEHOLDER_RE.search(text)  # nothing a real placeholder could collide with


def test_rehydrate_known_and_unknown() -> None:
    vault = {"<PERSON_1>": "Alice"}
    out = rehydrate("Hi <PERSON_1>, ref <PERSON_2>", vault)
    assert out == "Hi Alice, ref <PERSON_2>"  # unknown left verbatim, no global fallback


def test_rehydrate_is_single_pass() -> None:
    # A value that itself looks like a placeholder must not be re-expanded.
    vault = {"<A_1>": "<A_2>", "<A_2>": "LEAK"}
    assert rehydrate("<A_1>", vault) == "<A_2>"


# The core invariant: anything rehydrate would match, neutralize also removes —
# so after neutralize, no real-looking placeholder can survive into the prompt.
_ph = st.builds(
    lambda t, n: f"<{t}_{n}>",
    st.sampled_from(["PERSON", "EMAIL_ADDRESS", "IN_PAN"]),
    st.integers(0, 99),
)


@given(st.lists(st.one_of(_ph, st.text(max_size=20)), max_size=10))
def test_neutralize_superset_of_rehydrate(parts: list[str]) -> None:
    text = " ".join(parts)
    rehydratable = {m.group(0) for m in PLACEHOLDER_RE.finditer(text)}
    neutralized, _ = neutralize_placeholders(text)
    # Every span rehydrate could have matched is gone after neutralize.
    assert not PLACEHOLDER_RE.search(neutralized)
    # And rehydrate on the neutralized text is a no-op (nothing left to expand).
    assert rehydrate(neutralized, dict.fromkeys(rehydratable, "X")) == neutralized
