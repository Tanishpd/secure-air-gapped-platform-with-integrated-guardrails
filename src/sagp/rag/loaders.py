"""PDF text extraction with hidden-text detection (pipeline I3/I4).

``pypdf`` (BSD-3) — PyMuPDF is rejected (AGPL-3.0 §13 would infect a
compliance-themed template). Each page is extracted with a ``visitor_text`` hook
that flags concealment tricks a plain text dump would miss:

* ``PDF_TINY_FONT``  — text drawn at a sub-1pt font (invisible to a human, read
  by the model).
* ``PDF_OFFPAGE_TEXT`` — text positioned outside the MediaBox.

A flagged page is quarantined by the ingest pipeline (never indexed), because a
document that hides instructions in tiny/off-page text is the malicious-author
threat this system exists to catch.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pypdf import PdfReader

FLAG_TINY_FONT = "PDF_TINY_FONT"
FLAG_OFFPAGE = "PDF_OFFPAGE_TEXT"


@dataclass(frozen=True)
class LoadedPage:
    page: int  # 1-based
    text: str
    flags: frozenset[str]


def load_pdf(path: Path) -> list[LoadedPage]:
    reader = PdfReader(str(path))
    pages: list[LoadedPage] = []
    for i, page in enumerate(reader.pages, start=1):
        flags: set[str] = set()
        mb = page.mediabox
        left, bottom, right, top = (
            float(mb.left),
            float(mb.bottom),
            float(mb.right),
            float(mb.top),
        )

        def visitor(
            text: str,
            cm: Any,
            tm: Any,
            font_dict: Any,
            font_size: Any,
            _flags: set[str] = flags,
            _box: tuple[float, float, float, float] = (left, bottom, right, top),
        ) -> None:
            if not text or not text.strip():
                return
            if font_size is not None and abs(float(font_size)) < 1.0:
                _flags.add(FLAG_TINY_FONT)
            if tm is not None:
                x, y = float(tm[4]), float(tm[5])
                bl, bb, br, bt = _box
                if not (bl <= x <= br and bb <= y <= bt):
                    _flags.add(FLAG_OFFPAGE)

        text = page.extract_text(visitor_text=visitor)
        pages.append(LoadedPage(page=i, text=text, flags=frozenset(flags)))
    return pages
