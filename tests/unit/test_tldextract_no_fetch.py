"""SealedEmailRecognizer validates emails without ever fetching the PSL."""

from __future__ import annotations

from pathlib import Path

import pytest

from sagp.guardrails.recognizers import SealedEmailRecognizer


def test_sealed_extractor_is_configured_offline(tmp_path: Path) -> None:
    rec = SealedEmailRecognizer(cache_dir=tmp_path)
    # No HTTP suffix-list URLs, and the bundled snapshot is the fallback.
    assert rec._tld.suffix_list_urls == ()
    assert rec._tld.fallback_to_snapshot is True


def test_validates_good_and_bad(tmp_path: Path) -> None:
    rec = SealedEmailRecognizer(cache_dir=tmp_path)
    assert rec.validate_result("alice@example.co.uk") is True
    assert rec.validate_result("not-an-email") is False


def test_no_network_call_made(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cut every HTTP path; the sealed recognizer must still validate (snapshot only)."""

    def _boom(*_a: object, **_k: object) -> object:
        raise AssertionError("network access attempted by tldextract")

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    try:
        import requests

        monkeypatch.setattr(requests, "get", _boom)
        monkeypatch.setattr(requests.Session, "get", _boom)
    except ImportError:  # pragma: no cover
        pass

    rec = SealedEmailRecognizer(cache_dir=tmp_path)  # cold cache
    assert rec.validate_result("bob@example.com") is True  # would raise if it fetched
