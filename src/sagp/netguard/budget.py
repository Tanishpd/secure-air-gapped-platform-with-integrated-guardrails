"""Projected-RSS boot refusal (invariant 11).

The runtime has an 8 GB hard ceiling and runs ONE uvicorn worker. Before the app
loads its engines it sums the selected profile's **projected** RSS against the
host's total RAM and refuses to boot above a fraction of it — because macOS
compresses and swaps rather than OOM, so an over-budget config *appears* to work
while the pages it evicts are precisely the idle guardrail models (a security
property, not just slowness — see the `llama3:8b` note in the forbidden ideas).

**Every number here is an ESTIMATE / PROJECTION** (PLAN §6, BLUEPRINT §7), not a
measurement; M15 replaces them with measured RSS. Each names the profile it
assumes. The check is a pure function (inject ``total_bytes``) so it is testable
without an 8 GB host.
"""

from __future__ import annotations

from dataclasses import dataclass

from sagp.errors import ConfigError

_GB = 1024**3

# Projected total RSS per profile, in GB (ESTIMATE — see module docstring).
PROJECTED_RSS_GB: dict[str, float] = {
    "embedded": 6.75,  # default runtime backend (in-process Qdrant)
    "demo": 7.60,  # PROFILE=demo (Docker Qdrant + its VM) — fits, no margin
    "lg": 7.35,  # en_core_web_lg instead of md
    "8b": 9.28,  # llama3:8b — projects OVER an 8 GB ceiling; provisioned, not supported
}

CEILING_FRACTION = 0.90  # refuse to boot above 90% of total RAM


@dataclass(frozen=True)
class BudgetCheck:
    profile: str
    projected_gb: float
    total_gb: float
    ceiling_gb: float
    ok: bool


def check_rss_budget(
    profile: str,
    *,
    total_bytes: int,
    ceiling_fraction: float = CEILING_FRACTION,
) -> BudgetCheck:
    """Compare the profile's projected RSS to ``ceiling_fraction`` of total RAM."""
    projected = PROJECTED_RSS_GB.get(profile)
    if projected is None:
        raise ConfigError(f"unknown RAM profile {profile!r}; known: {sorted(PROJECTED_RSS_GB)}")
    total_gb = total_bytes / _GB
    ceiling_gb = total_gb * ceiling_fraction
    return BudgetCheck(profile, projected, total_gb, ceiling_gb, projected <= ceiling_gb)


def assert_rss_budget(profile: str, *, total_bytes: int | None = None) -> BudgetCheck:
    """Raise ``ConfigError`` if the profile's projection exceeds the ceiling.

    Reads total RAM from ``psutil`` when ``total_bytes`` is not injected. Called by
    the serving lifespan before any engine loads — a boot refusal, not a warning
    (invariant 6: fail closed)."""
    if total_bytes is None:
        import psutil  # type: ignore[import-untyped]

        total_bytes = psutil.virtual_memory().total
    check = check_rss_budget(profile, total_bytes=total_bytes)
    if not check.ok:
        raise ConfigError(
            f"projected RSS for profile {profile!r} is {check.projected_gb:.2f} GB, "
            f"over the {check.ceiling_gb:.2f} GB ceiling "
            f"({int(CEILING_FRACTION * 100)}% of {check.total_gb:.2f} GB). Refusing to boot "
            f"(ESTIMATE — see netguard/budget.py). Use PROFILE=embedded or a smaller model."
        )
    return check
