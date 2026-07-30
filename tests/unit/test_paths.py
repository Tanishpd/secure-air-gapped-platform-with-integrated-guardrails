"""Paths with spaces round-trip cleanly.

The repo itself lives under a directory with spaces ("Secure Air-Gapped
Platform with Integrated Guardrails"), so every path must survive as a single
token. These tests pin that at the config layer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sagp.config import Settings

pytestmark = pytest.mark.usefixtures("clean_sagp_env")


def _settings(**env: str) -> Settings:
    import os

    for k, v in env.items():
        os.environ[k] = v
    return Settings(_env_file=None)  # type: ignore[call-arg]


def test_spaced_data_dir_round_trips() -> None:
    spaced = "/tmp/a b/sagp data"
    s = _settings(SAGP_DATA_DIR=spaced)
    assert s.data_dir == Path(spaced)
    # A single token, not split on the space.
    assert s.data_dir.name == "sagp data"
    assert str(s.data_dir) == spaced


def test_qdrant_path_derives_under_spaced_data_dir() -> None:
    s = _settings(SAGP_DATA_DIR="/tmp/a b/data")
    assert s.qdrant_path == Path("/tmp/a b/data/qdrant")
    assert s.qdrant_path.parent.name == "data"


def test_repo_root_with_spaces_is_usable() -> None:
    # This test file lives under the real spaced repo path; resolving and
    # re-joining it must not lose the space.
    here = Path(__file__).resolve()
    assert " " in str(here)  # the repo path has spaces
    rejoined = Path(str(here))
    assert rejoined == here
    assert rejoined.exists()
