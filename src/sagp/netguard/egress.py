"""Egress guard exceptions.

``EgressViolation`` is defined here, **not** in ``errors.py``, and is
deliberately not a ``SagpError`` — it must never be caught by the app's
exception handler and turned into a 500 (CLAUDE.md invariant 2). The dual-layer
guard (L1 monkeypatch + L2 PEP 578 audit hook) that raises it lands at M11; this
module ships only the exception type so the rest of the tree can reference it.
"""

from __future__ import annotations


class EgressViolation(Exception):
    """Raised when in-process code attempts a non-allowlisted network egress."""
