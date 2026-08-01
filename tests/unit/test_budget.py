"""Projected-RSS boot refusal (invariant 11). All ESTIMATES; the check math is
what is tested, not the projections."""

from __future__ import annotations

import pytest

from sagp.errors import ConfigError
from sagp.netguard import budget

_GB = 1024**3


def test_embedded_fits_on_16gb() -> None:
    c = budget.check_rss_budget("embedded", total_bytes=16 * _GB)
    assert c.ok and c.projected_gb == budget.PROJECTED_RSS_GB["embedded"]


def test_8b_is_over_budget_on_8gb() -> None:
    c = budget.check_rss_budget("8b", total_bytes=8 * _GB)
    assert not c.ok  # 9.28 GB projected > 90% of 8 GB


def test_assert_refuses_over_budget() -> None:
    with pytest.raises(ConfigError, match="over the"):
        budget.assert_rss_budget("8b", total_bytes=8 * _GB)


def test_assert_passes_under_budget() -> None:
    c = budget.assert_rss_budget("embedded", total_bytes=16 * _GB)
    assert c.ok


def test_ceiling_is_ninety_percent() -> None:
    # A profile just over 90% of total refuses; just under passes.
    total = 10 * _GB  # ceiling = 9.0 GB
    budget.PROJECTED_RSS_GB["_test_hi"] = 9.05
    budget.PROJECTED_RSS_GB["_test_lo"] = 8.95
    try:
        assert not budget.check_rss_budget("_test_hi", total_bytes=total).ok
        assert budget.check_rss_budget("_test_lo", total_bytes=total).ok
    finally:
        del budget.PROJECTED_RSS_GB["_test_hi"]
        del budget.PROJECTED_RSS_GB["_test_lo"]


def test_unknown_profile_is_config_error() -> None:
    with pytest.raises(ConfigError, match="unknown RAM profile"):
        budget.check_rss_budget("nonsense", total_bytes=8 * _GB)
