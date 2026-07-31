"""PDF loader: extract text; flag hidden (sub-1pt) text."""

from __future__ import annotations

from sagp.rag.loaders import FLAG_TINY_FONT, load_pdf


def test_handbook_extracts_and_is_clean(sample_pdfs) -> None:  # type: ignore[no-untyped-def]
    pages = load_pdf(sample_pdfs["handbook"])
    assert len(pages) == 2
    assert all(not p.flags for p in pages)  # no hidden text
    body = " ".join(p.text for p in pages).lower()
    assert "parental leave" in body


def test_poisoned_appendix_tiny_font_is_flagged(sample_pdfs) -> None:  # type: ignore[no-untyped-def]
    pages = load_pdf(sample_pdfs["poisoned"])
    assert any(FLAG_TINY_FONT in p.flags for p in pages)
