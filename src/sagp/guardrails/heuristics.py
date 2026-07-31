"""Weighted heuristic rules (C4), OR'd with the classifier — never averaged (§3.5).

The rule PATTERNS are detection logic and live here in code; the WEIGHTS are data
and come from ``config/guardrails.yaml`` (invariant 12). ``scan`` reports which
rules fired, the max weight, and which block-tier rules fired (e.g.
``DELIMITER_SPOOF``); the pipeline decides — a block-tier rule or
``max(weight) >= surface_threshold`` rejects. ``TAG_CHARS`` / ``BIDI_OVERRIDE``
are block-tier too but are detected by the normalizer, not here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sagp.guardrails.policy import GuardrailsPolicy

_I = re.IGNORECASE
_IM = re.IGNORECASE | re.MULTILINE

# rule_id -> compiled pattern. Keys must match the weights in guardrails.yaml
# (weighted rules) or its block_rules (DELIMITER_SPOOF).
RULE_PATTERNS: dict[str, re.Pattern[str]] = {
    "OVERRIDE_PHRASE": re.compile(
        r"\b(?:ignore|forget|override|discard)\b[^.]{0,40}\b(?:all\s+)?"
        r"(?:previous|prior|above|earlier|preceding)\b[^.]{0,20}\binstructions?\b",
        _I,
    ),
    "DISREGARD": re.compile(r"\bdisregard\b|\bpay no attention to\b", _I),
    "SYSTEM_PROMPT_PROBE": re.compile(
        r"\b(?:repeat|print|reveal|show|expose|output|display|reproduce)\b[^.]{0,40}"
        r"\b(?:system\s+prompt|initial\s+instructions|your\s+"
        r"(?:rules|instructions|prompt|guidelines|configuration))\b",
        _I,
    ),
    "ROLE_HIJACK": re.compile(
        r"<\|im_start\|>|<\|im_end\|>|\[/?INST\]|#{2,3}\s*system\b|^\s*(?:system|assistant)\s*[:>\]]",
        _IM,
    ),
    "DAN_PERSONA": re.compile(
        r"\bDAN\b|\bdeveloper mode\b|\bdo anything now\b|"
        r"you are now[^.]{0,40}(?:no restrictions|unrestricted|jailbroken|without\s+"
        r"(?:any\s+)?(?:filter|rule|restriction))",
        _I,
    ),
    "NEW_INSTRUCTIONS": re.compile(
        r"\bnew instructions\b\s*:|\bupdated system message\b|\bthe real task is\b", _I
    ),
    "EXFIL_INTENT": re.compile(
        r"\b(?:send|post|upload|email|exfiltrate|forward|leak)\b[^.]{0,40}"
        r"(?:https?://|to\s+\S+@)",
        _I,
    ),
    "MARKDOWN_EXFIL": re.compile(
        r"!\[[^\]]*\]\(\s*https?://|\[[^\]]*\]\(\s*https?://[^)]*[{%]", _I
    ),
    "DELIMITER_SPOOF": re.compile(r"UNTRUSTED_DOCUMENT_", 0),
}


@dataclass
class HeuristicResult:
    fired: dict[str, float] = field(default_factory=dict)  # weighted rule_id -> weight
    blocked: tuple[str, ...] = ()  # block-tier rules that fired (e.g. DELIMITER_SPOOF)
    max_weight: float = 0.0

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(self.fired) + self.blocked


def scan(text: str, policy: GuardrailsPolicy) -> HeuristicResult:
    """Evaluate every heuristic against ``text`` using the policy's weights."""
    weights = policy.heuristics.weights
    block_rules = set(policy.heuristics.block_rules)
    fired: dict[str, float] = {}
    blocked: list[str] = []

    for rule_id, pattern in RULE_PATTERNS.items():
        if not pattern.search(text):
            continue
        if rule_id in block_rules:
            blocked.append(rule_id)
        if rule_id in weights:
            fired[rule_id] = weights[rule_id]

    max_weight = max(fired.values(), default=0.0)
    return HeuristicResult(fired=fired, blocked=tuple(blocked), max_weight=max_weight)
