"""AST scan: no module under src/sagp/ imports torch, transformers, or
huggingface_hub (invariant 10). huggingface_hub IS installed (via tokenizers)
but our code must never touch it — this is the rule, not that it is uninstalled."""

from __future__ import annotations

import ast
from pathlib import Path

FORBIDDEN = {"torch", "transformers", "huggingface_hub"}
SRC = Path("src/sagp")


def _top(name: str) -> str:
    return name.split(".", 1)[0]


def test_no_forbidden_runtime_imports() -> None:
    offenders: list[str] = []
    for py in SRC.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders += [
                    f"{py}: import {a.name}" for a in node.names if _top(a.name) in FORBIDDEN
                ]
            elif (
                isinstance(node, ast.ImportFrom) and node.module and _top(node.module) in FORBIDDEN
            ):
                offenders.append(f"{py}: from {node.module}")
    assert not offenders, offenders
