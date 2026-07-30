"""Identifier helpers. Stdlib only; no side effects.

Request and incident ids are random UUID4 hex — an ``incident_id`` is the *only*
reference from an audit record to quarantined raw text (invariant 1), so it must
carry no information itself.
"""

from __future__ import annotations

import uuid


def new_request_id() -> str:
    return uuid.uuid4().hex


def new_incident_id() -> str:
    return uuid.uuid4().hex
