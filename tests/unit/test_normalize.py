"""Normalizer: block only tag/bidi; strip-but-never-block ZWJ/ZWNJ; fold confusables."""

from __future__ import annotations

from sagp.guardrails.normalize import (
    FLAG_BIDI_OVERRIDE,
    FLAG_HOMOGLYPH,
    FLAG_NFKC_CHANGED,
    FLAG_TAG_CHARS,
    FLAG_ZERO_WIDTH,
    has_blocking_flag,
    normalize,
)


def test_plain_ascii_unchanged() -> None:
    a = normalize("How many days of leave do I get?")
    assert a.normalized == "How many days of leave do I get?"
    assert not has_blocking_flag(a)


def test_tag_chars_flagged_and_blocking() -> None:
    smuggled = "hello" + "".join(chr(c) for c in range(0xE0041, 0xE0046))  # tag "ABCDE"
    a = normalize(smuggled)
    assert FLAG_TAG_CHARS in a.flags
    assert has_blocking_flag(a)
    assert a.normalized == "hello"  # tag chars stripped from the scan surface


def test_bidi_override_flagged_and_blocking() -> None:
    a = normalize("safe‮txet desrever")  # RLO override
    assert FLAG_BIDI_OVERRIDE in a.flags
    assert has_blocking_flag(a)


def test_hindi_zwnj_stripped_but_not_blocked() -> None:
    # Devanagari with a ZWNJ — legitimate Indic text MUST NOT block.
    hindi = "क‌ष"  # ka + ZWNJ + ssa
    a = normalize(hindi)
    assert FLAG_ZERO_WIDTH in a.flags
    assert not has_blocking_flag(a)  # never blocks (forbidden idea)
    assert "‌" not in a.normalized


def test_arabic_zwj_not_blocked() -> None:
    a = normalize("سلام‍عليكم")  # ZWJ inside
    assert not has_blocking_flag(a)


def test_soft_hyphen_stripped_not_blocked() -> None:
    a = normalize("co­operate")  # soft hyphen from PDF paste
    assert a.normalized == "cooperate"
    assert not has_blocking_flag(a)


def test_nfkc_folds_fullwidth() -> None:
    a = normalize("ｉｇｎｏｒｅ")  # fullwidth "ignore"
    assert a.normalized == "ignore"
    assert FLAG_NFKC_CHANGED in a.flags


def test_homoglyph_cyrillic_folds_to_latin() -> None:
    # "ign" + Cyrillic о (U+043E) + "re" must fold to ASCII so the scanner sees it.
    a = normalize("ignоre")
    assert a.normalized == "ignore"
    assert FLAG_HOMOGLYPH in a.flags


def test_whitespace_collapsed() -> None:
    a = normalize("a   b\t\tc\nd")
    assert a.normalized == "a b c d"
