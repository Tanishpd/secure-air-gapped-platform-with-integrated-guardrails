"""Settings behaviour: defaults, validation, typo-refuses-to-boot, secret masking."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sagp.config import Settings

pytestmark = pytest.mark.usefixtures("clean_sagp_env")


def _settings(**env: str) -> Settings:
    """Construct Settings from an explicit env, ignoring any on-disk .env."""
    import os

    for k, v in env.items():
        os.environ[k] = v
    return Settings(_env_file=None)  # type: ignore[call-arg]


def test_defaults() -> None:
    s = _settings()
    assert s.env == "dev"
    assert s.guard == "enforce"
    assert s.llm_model == "llama3.2:3b-instruct-q4_K_M"
    assert s.spacy_model == "en_core_web_md"
    assert s.qdrant_mode == "embedded"
    assert s.rehydrate_output is False
    assert s.max_input_chars == 8000
    assert s.max_windows == 16
    assert s.max_vault_entries == 2000
    assert s.rejection_deadline_ms == 120


def test_caps_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        _settings(SAGP_MAX_INPUT_CHARS="0")


def test_unknown_key_refuses_to_boot() -> None:
    # invariant 12: a mistyped SAGP_ key is a boot failure, not a silent default.
    with pytest.raises(ValidationError):
        _settings(SAGP_MAX_INPUT_CHAR="8000")  # missing trailing S


def test_bad_enum_refuses() -> None:
    with pytest.raises(ValidationError):
        _settings(SAGP_QDRANT_MODE="redis")
    with pytest.raises(ValidationError):
        _settings(SAGP_GUARD="off")


def test_env_override_applies() -> None:
    s = _settings(SAGP_MAX_CTX_CHARS="4096", SAGP_LLM_MODEL="llama3.2:1b")
    assert s.max_ctx_chars == 4096
    assert s.llm_model == "llama3.2:1b"


def test_secret_is_masked_in_repr() -> None:
    s = _settings(SAGP_API_TOKEN="super-secret-value")
    assert s.api_token is not None
    assert s.api_token.get_secret_value() == "super-secret-value"
    # The raw value must never appear in repr/str (audit/traceback safety).
    assert "super-secret-value" not in repr(s)
    assert "super-secret-value" not in str(s)


def test_import_sagp_has_no_side_effects() -> None:
    import sagp

    assert isinstance(sagp.__version__, str)
