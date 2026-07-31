"""The one shared text normalizer (pipeline stage C3 / I4).

Every guardrail scans the SAME normalized string (invariant 7): normalize once,
here, then injection detection and PII detection both run on the result. The
order is deliberate (BLUEPRINT §5.1):

  1. record + strip tag chars (U+E0000–E007F) and bidi overrides  -> BLOCK flags
  2. strip other format chars (zero-width, soft hyphen, BOM, …)    -> strip + flag
  3. NFKC                                                          -> flag if changed
  4. homoglyph fold (Cyrillic/Greek/… confusables -> Latin)        -> flag if changed
  5. collapse whitespace runs to a single space

`normalize` only *flags*; the pipeline decides. Tag chars and bidi overrides are
the only Cf that block outright (their flags → 400 at C3). Everything else —
including U+00AD / U+200C / U+200D, which are required for PDF paste and for
Indic/Arabic scripts (the stated user base) — is strip-and-flag, NEVER a block
(forbidden idea: blocking ZWJ/ZWNJ). So a Hindi or Arabic query returns 200.
"""

from __future__ import annotations

import unicodedata

from sagp.types import TextArtifact

# Flags
FLAG_TAG_CHARS = "TAG_CHARS"  # block
FLAG_BIDI_OVERRIDE = "BIDI_OVERRIDE"  # block
FLAG_ZERO_WIDTH = "ZERO_WIDTH"  # strip + flag, never block alone
FLAG_NFKC_CHANGED = "NFKC_CHANGED"
FLAG_HOMOGLYPH = "HOMOGLYPH_FOLDED"
FLAG_WHITESPACE = "WHITESPACE_COLLAPSED"

BLOCKING_FLAGS = frozenset({FLAG_TAG_CHARS, FLAG_BIDI_OVERRIDE})

# Unicode tag characters — invisible ASCII smuggling. Block outright.
_TAG_CHARS = frozenset(range(0xE0000, 0xE0080))
# Explicit bidirectional overrides/isolates — reorder rendered text. Block outright.
_BIDI_OVERRIDE = frozenset({0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069})
# Other format (Cf) chars to strip but NOT block. ZWJ/ZWNJ/soft-hyphen live here
# on purpose — they are required for legitimate Indic/Arabic text and PDF paste.
_STRIP_CF = frozenset(
    {
        0x00AD,  # soft hyphen
        0x200B,  # zero-width space
        0x200C,  # ZWNJ  (Indic/Arabic)
        0x200D,  # ZWJ   (Indic/Arabic, emoji)
        0x200E,  # LRM
        0x200F,  # RLM
        0x2060,  # word joiner
        0x2061,
        0x2062,
        0x2063,
        0x2064,
        0x180E,  # Mongolian vowel separator
        0xFEFF,  # BOM / zero-width no-break space
    }
)

# Curated confusable table: codepoints NFKC does NOT fold but that read as Latin.
# A small, explicit map — NOT unidecode (which mangles legitimate scripts).
_HOMOGLYPHS = {
    # Cyrillic -> Latin
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "һ": "h",
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    # Greek -> Latin
    "ο": "o",
    "α": "a",
    "ε": "e",
    "ρ": "p",
    "υ": "u",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Χ": "X",
}


def normalize(raw: str) -> TextArtifact:
    """Normalize ``raw`` to the canonical scan string, recording what it observed."""
    flags: set[str] = set()

    # 1 + 2: strip Cf, splitting into block-tier (tag/bidi) vs strip-and-flag.
    kept: list[str] = []
    for ch in raw:
        cp = ord(ch)
        if cp in _TAG_CHARS:
            flags.add(FLAG_TAG_CHARS)
            continue
        if cp in _BIDI_OVERRIDE:
            flags.add(FLAG_BIDI_OVERRIDE)
            continue
        if cp in _STRIP_CF:
            flags.add(FLAG_ZERO_WIDTH)
            continue
        kept.append(ch)
    text = "".join(kept)

    # 3: NFKC.
    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        flags.add(FLAG_NFKC_CHANGED)
    text = nfkc

    # 4: homoglyph fold.
    if any(ch in _HOMOGLYPHS for ch in text):
        text = "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)
        flags.add(FLAG_HOMOGLYPH)

    # 5: collapse whitespace runs to a single space.
    collapsed = " ".join(text.split())
    if collapsed != text:
        flags.add(FLAG_WHITESPACE)
    text = collapsed

    return TextArtifact(raw=raw, normalized=text, flags=frozenset(flags))


def has_blocking_flag(artifact: TextArtifact) -> bool:
    """True if normalization saw a block-tier char (tag or bidi override)."""
    return bool(artifact.flags & BLOCKING_FLAGS)
