"""Loader for ``config/guardrails.yaml`` — thresholds/weights as data.

Loads and validates the policy, and exposes its **sha256** so the exact policy
that produced a decision is recorded in the audit event (invariant 12). Every
weight is validated ``0.0 < w <= 1.0`` at load time: a typo refuses to boot
rather than silently defaulting. Frozen models — the policy is immutable once
loaded.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class HeuristicsPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    weights: dict[str, float]
    block_rules: tuple[str, ...] = ()

    @field_validator("weights")
    @classmethod
    def _weights_in_range(cls, v: dict[str, float]) -> dict[str, float]:
        for rule, w in v.items():
            if not (0.0 < w <= 1.0):
                raise ValueError(f"heuristic weight {rule}={w} outside (0.0, 1.0]")
        return v


class DeobfuscatePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    codecs: tuple[str, ...]
    max_depth: int = Field(gt=0)
    max_bytes: int = Field(gt=0)


class GuardrailsPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: int
    heuristics: HeuristicsPolicy
    deobfuscate: DeobfuscatePolicy
    sha256: str  # of the source file bytes


def load_policy(path: Path) -> GuardrailsPolicy:
    """Load, validate, and hash ``config/guardrails.yaml``."""
    raw = path.read_bytes()
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a mapping")
    data["sha256"] = hashlib.sha256(raw).hexdigest()
    return GuardrailsPolicy(**data)
