"""Decode obfuscated payloads so the scanners see the real instruction (C5).

An attacker can hide "ignore all previous instructions" as base64, hex, rot13,
leetspeak, reversed, or space-separated text. We DECODE these to depth 2 and add
every decoded surface to the scan set — decoded payloads JOIN the scan set, they
never replace the original (BLUEPRINT §5.7). The whole thing is size-capped so a
decode bomb (base64 that expands) is bounded; the caller turns ``truncated`` into
a 400.

The output feeds both the injection scan (C6) AND — per the M0/eval fix — the
BLOCK-list scan (C10), so an encoded credential cannot slip the block list.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass, field

DEFAULT_CODECS = ("base64", "base32", "hex", "rot13", "leet", "reverse", "spaced")
DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_BYTES = 262_144
DEFAULT_MAX_CANDIDATES = 64

_B64_RE = re.compile(r"[A-Za-z0-9+/=]{12,}")
_B32_RE = re.compile(r"[A-Z2-7=]{16,}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_LEET = str.maketrans(
    {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s"}
)
_SPACED_RE = re.compile(r"(?:\b\w\b[ ]){3,}\b\w\b")


@dataclass
class DeobfuscationResult:
    candidates: list[str] = field(default_factory=list)  # decoded surfaces, excludes the original
    truncated: bool = False  # a candidate exceeded max_bytes or the candidate cap was hit


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isprintable() or ch in "\n\t " for ch in s) / len(s)


def _try_base64(s: str) -> str | None:
    best: str | None = None
    for m in _B64_RE.findall(s):
        chunk = m
        if len(chunk) % 4:
            continue
        try:
            dec = base64.b64decode(chunk, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(dec) > 0.9 and dec.strip() and dec != chunk:
            best = dec if best is None else best + "\x1f" + dec
    return best


def _try_base32(s: str) -> str | None:
    for m in _B32_RE.findall(s):
        try:
            dec = base64.b32decode(m).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(dec) > 0.9 and dec.strip():
            return dec
    return None


def _try_hex(s: str) -> str | None:
    for m in _HEX_RE.findall(s):
        try:
            dec = bytes.fromhex(m).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(dec) > 0.9 and dec.strip():
            return dec
    return None


def _try_rot13(s: str) -> str | None:
    if not any(c.isalpha() for c in s):
        return None
    dec = codecs.decode(s, "rot_13")
    return dec if dec != s else None


def _try_leet(s: str) -> str | None:
    dec = s.translate(_LEET)
    return dec if dec != s else None


def _try_reverse(s: str) -> str | None:
    return s[::-1] if s and s != s[::-1] else None


def _try_spaced(s: str) -> str | None:
    if not _SPACED_RE.search(s):
        return None
    # Join runs of single characters separated by single spaces.
    dec = re.sub(r"(?<=\b\w) (?=\w\b)", "", s)
    return dec if dec != s else None


_DECODERS = {
    "base64": _try_base64,
    "base32": _try_base32,
    "hex": _try_hex,
    "rot13": _try_rot13,
    "leet": _try_leet,
    "reverse": _try_reverse,
    "spaced": _try_spaced,
}


def expand(
    text: str,
    *,
    codecs: tuple[str, ...] = DEFAULT_CODECS,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> DeobfuscationResult:
    """BFS decode ``text`` to ``max_depth``; return new decoded surfaces."""
    result = DeobfuscationResult()
    seen = {text}
    frontier = [text]
    for _depth in range(max_depth):
        nxt: list[str] = []
        for cur in frontier:
            for name in codecs:
                decoder = _DECODERS.get(name)
                if decoder is None:
                    continue
                dec = decoder(cur)
                if not dec or dec in seen:
                    continue
                if len(dec.encode("utf-8")) > max_bytes:
                    result.truncated = True
                    continue
                seen.add(dec)
                result.candidates.append(dec)
                nxt.append(dec)
                if len(result.candidates) >= max_candidates:
                    result.truncated = True
                    return result
        frontier = nxt
        if not frontier:
            break
    return result
