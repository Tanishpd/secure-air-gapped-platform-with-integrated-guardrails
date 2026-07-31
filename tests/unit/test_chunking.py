"""Token-aware, page-scoped chunking."""

from __future__ import annotations

from sagp.rag.chunking import MIN_TOKENS, TARGET_TOKENS, chunk_page


def test_chunks_are_page_scoped(chunk_tokenizer) -> None:  # type: ignore[no-untyped-def]
    text = " ".join(f"word{i}" for i in range(500))
    chunks = chunk_page(
        text, page=3, source="doc.pdf", doc_sha256="abc", tokenizer=chunk_tokenizer, start_index=0
    )
    assert len(chunks) >= 2
    assert all(c.page == 3 for c in chunks)
    assert all(c.doc_sha256 == "abc" for c in chunks)
    assert [c.index for c in chunks] == list(range(len(chunks)))


def test_first_chunk_hits_target(chunk_tokenizer) -> None:  # type: ignore[no-untyped-def]
    text = " ".join(f"tok{i}" for i in range(600))
    chunks = chunk_page(
        text, page=1, source="d", doc_sha256="x", tokenizer=chunk_tokenizer, start_index=0
    )
    assert chunks[0].token_count == TARGET_TOKENS


def test_chunk_text_is_a_real_substring(chunk_tokenizer) -> None:  # type: ignore[no-untyped-def]
    text = "The quick brown fox jumps over the lazy dog. " * 60
    chunks = chunk_page(
        text, page=1, source="d", doc_sha256="x", tokenizer=chunk_tokenizer, start_index=0
    )
    for c in chunks:
        assert c.text in text  # offset-mapped, not re-decoded


def test_short_page_kept_as_single_chunk(chunk_tokenizer) -> None:  # type: ignore[no-untyped-def]
    chunks = chunk_page(
        "Just a short sentence.",
        page=1,
        source="d",
        doc_sha256="x",
        tokenizer=chunk_tokenizer,
        start_index=0,
    )
    assert len(chunks) == 1
    assert chunks[0].token_count < MIN_TOKENS  # kept anyway rather than losing content


def test_empty_page_yields_no_chunks(chunk_tokenizer) -> None:  # type: ignore[no-untyped-def]
    assert (
        chunk_page(
            "   \n  ",
            page=1,
            source="d",
            doc_sha256="x",
            tokenizer=chunk_tokenizer,
            start_index=0,
        )
        == []
    )


def test_start_index_offsets_numbering(chunk_tokenizer) -> None:  # type: ignore[no-untyped-def]
    text = " ".join(f"w{i}" for i in range(400))
    chunks = chunk_page(
        text, page=2, source="d", doc_sha256="x", tokenizer=chunk_tokenizer, start_index=10
    )
    assert chunks[0].index == 10
