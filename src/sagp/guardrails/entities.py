"""Loader for ``config/entities.yaml`` — the BLOCK / MASK / ALLOW policy.

Entities are data (invariant 12): which entities exist, whether presence blocks,
masks, or is merely audited, and the per-entity ingress/egress thresholds. A
threshold is a float in ``(0, 1]`` or the string ``"binary"`` (validator-forced,
threshold not applicable). The file's sha256 is exposed for the audit record.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

Threshold = float | Literal["binary"]


def _valid_threshold(v: Threshold) -> Threshold:
    if v == "binary":
        return v
    if not (0.0 < float(v) <= 1.0):
        raise ValueError(f"threshold {v} outside (0.0, 1.0]")
    return float(v)


class EntityRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    ingress: Threshold = 0.50
    egress: Threshold | None = None
    source: str | None = None

    @field_validator("ingress", "egress")
    @classmethod
    def _check(cls, v: Threshold | None) -> Threshold | None:
        return None if v is None else _valid_threshold(v)


class EntitiesPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: int
    block: tuple[EntityRule, ...]
    mask: tuple[EntityRule, ...]
    allow: tuple[EntityRule, ...]
    defaults: dict[str, float]
    sha256: str

    def _rule(self, name: str) -> EntityRule | None:
        for group in (self.block, self.mask, self.allow):
            for r in group:
                if r.name == name:
                    return r
        return None

    @property
    def block_names(self) -> frozenset[str]:
        return frozenset(r.name for r in self.block)

    @property
    def mask_names(self) -> frozenset[str]:
        return frozenset(r.name for r in self.mask)

    @property
    def allow_names(self) -> frozenset[str]:
        return frozenset(r.name for r in self.allow)

    @property
    def all_entities(self) -> frozenset[str]:
        return self.block_names | self.mask_names | self.allow_names

    def is_binary(self, name: str) -> bool:
        r = self._rule(name)
        return r is not None and r.ingress == "binary"

    def ingress_threshold(self, name: str) -> float:
        """Effective ingress score floor. 'binary' entities accept any Presidio hit."""
        r = self._rule(name)
        if r is None:
            return self.defaults["ingress"]
        return 0.0 if r.ingress == "binary" else float(r.ingress)

    def egress_threshold(self, name: str) -> float:
        r = self._rule(name)
        if r is None or r.egress is None:
            return self.defaults["egress"]
        return 0.0 if r.egress == "binary" else float(r.egress)


def load_entities(path: Path) -> EntitiesPolicy:
    raw = path.read_bytes()
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a mapping")
    data["sha256"] = hashlib.sha256(raw).hexdigest()
    return EntitiesPolicy(**data)
