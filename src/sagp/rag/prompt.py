"""The SOLE builder of the final prompt string (pipeline C18).

Retrieved excerpts are UNTRUSTED DATA. Each is wrapped in a per-request nonce
delimiter — ``secrets.token_hex(8)``, minted fresh every request — so a document
cannot pre-forge a matching fence, and the excerpts go in the **user** role,
never system. No datamarking (U+2581 blows up llama3's BPE and pushes the
retrieval re-scan out of distribution).

The char budget is applied HERE, before the C19 re-scan, so the string that gets
scanned is the string that gets sent (the ``test_final_bytes_were_scanned``
invariant). Highest-scoring chunks are kept; the lowest are dropped until the
assembled context is under ``max_ctx_chars``. The assembled payload's sha256 is
recorded in the audit event.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from sagp.types import Hit


@dataclass(frozen=True)
class AssembledPrompt:
    user_payload: str  # the user-role content: wrapped context + the question
    nonce: str
    chunks_used: list[Hit]  # after the char-budget trim, highest-score first
    sha256: str


def _block(nonce: str, i: int, hit: Hit) -> str:
    open_d = f"<<<UNTRUSTED_DOCUMENT_{nonce}_S{i}>>>"
    close_d = f"<<</UNTRUSTED_DOCUMENT_{nonce}_S{i}>>>"
    return f"{open_d}\n[S{i}, p.{hit.chunk.page}] {hit.chunk.text}\n{close_d}"


def build_prompt(
    question: str,
    hits: list[Hit],
    *,
    max_ctx_chars: int,
    nonce: str | None = None,
) -> AssembledPrompt:
    """Assemble the user-role payload from the question and (budget-trimmed) hits."""
    nonce = nonce or secrets.token_hex(8)
    ordered = sorted(hits, key=lambda h: h.score, reverse=True)

    selected: list[Hit] = []
    running = 0
    for hit in ordered:
        block_len = len(_block(nonce, len(selected) + 1, hit)) + 1  # +1 for the join newline
        if selected and running + block_len > max_ctx_chars:
            break  # drop this and every lower-scoring chunk
        selected.append(hit)
        running += block_len

    blocks = [_block(nonce, i, hit) for i, hit in enumerate(selected, start=1)]
    context = "\n".join(blocks)
    payload = f"{context}\n\nQuestion: {question}" if context else f"Question: {question}"
    sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return AssembledPrompt(user_payload=payload, nonce=nonce, chunks_used=selected, sha256=sha256)
