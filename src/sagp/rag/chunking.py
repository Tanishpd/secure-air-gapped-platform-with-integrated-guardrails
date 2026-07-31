"""Token-aware, page-first chunking.

Chunks are windowed over a page's tokens (``target``/``overlap``) and NEVER span
a page boundary, so a citation resolves to one page. Windows are mapped back to
character spans via the tokenizer offsets, so the stored text is the real
substring. A window shorter than ``min_tokens`` is dropped, unless the whole page
is that short (then it is kept as a single chunk rather than losing the content).
"""

from __future__ import annotations

from tokenizers import Tokenizer

from sagp.types import Chunk

TARGET_TOKENS = 320
OVERLAP_TOKENS = 64
MIN_TOKENS = 32


def chunk_page(
    text: str,
    *,
    page: int,
    source: str,
    doc_sha256: str,
    tokenizer: Tokenizer,
    start_index: int,
    target: int = TARGET_TOKENS,
    overlap: int = OVERLAP_TOKENS,
    min_tokens: int = MIN_TOKENS,
) -> list[Chunk]:
    """Chunk one page's text. ``tokenizer`` must have truncation disabled."""
    enc = tokenizer.encode(text, add_special_tokens=False)
    offsets = enc.offsets
    n = len(offsets)
    if n == 0 or not text.strip():
        return []

    step = max(1, target - overlap)
    chunks: list[Chunk] = []
    idx = start_index
    i = 0
    while i < n:
        window = offsets[i : i + target]
        tok_count = len(window)
        keep = tok_count >= min_tokens or (i == 0 and not chunks)
        if keep:
            start_char = window[0][0]
            end_char = window[-1][1]
            body = text[start_char:end_char].strip()
            if body:
                chunks.append(
                    Chunk(
                        doc_sha256=doc_sha256,
                        index=idx,
                        text=body,
                        page=page,
                        source=source,
                        token_count=tok_count,
                    )
                )
                idx += 1
        if i + target >= n:
            break
        i += step
    return chunks
