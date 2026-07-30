"""Shared test fixtures and markers.

``needs_models`` / ``needs_ollama`` are declared in pyproject and gated here so
the fast suite (``make test``) never touches real models or a live Ollama.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture
def clean_sagp_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Strip every ``SAGP_`` variable from the environment for the test.

    ``Settings`` uses ``extra="forbid"``, so a stray ``SAGP_`` var in the real
    environment would otherwise make construction fail for the wrong reason.
    """
    import os

    for key in list(os.environ):
        if key.startswith("SAGP_"):
            monkeypatch.delenv(key, raising=False)
    yield
