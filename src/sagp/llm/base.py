"""LLM client contract.

Single-turn and **buffered** by design: the client returns the *complete*
generation so the output guardrail can scan it before a byte reaches the caller
(you cannot un-send a leaked token — forbidden idea: streaming). The retrieved
context lives in the ``user`` role; the system prompt is separate and is never
scanned (documented false-positive source).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

_PROMPTS_DIR = Path(__file__).parent / "prompts"
SYSTEM_RAG = "system_rag.txt"
REFUSAL = "refusal.txt"


def load_prompt(name: str) -> str:
    """Read a prompt file (``system_rag.txt`` / ``refusal.txt``)."""
    return (_PROMPTS_DIR / name).read_text(encoding="utf-8")


def prompt_sha256(name: str) -> str:
    """sha256 of a prompt file's bytes — written into every audit record so a
    decision can be replayed against the exact prompt that produced it."""
    return hashlib.sha256((_PROMPTS_DIR / name).read_bytes()).hexdigest()


@dataclass(frozen=True)
class LLMResult:
    text: str
    model: str
    prompt_eval_count: int | None = None  # exact prompt tokens, from Ollama (OQ-3)
    eval_count: int | None = None  # completion tokens
    elapsed_ms: float = 0.0


class LLMClient(Protocol):
    def generate(self, *, system: str, user: str) -> LLMResult:
        """Return the full completion for a single (system, user) turn."""
        ...
