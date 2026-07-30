"""Logging filters that redact PII from console / log output.

Attached to every handler via ``config/logging.yaml`` so that even a stray
``logger.info(user_text)`` cannot leak an email or a card number into a log file.
This is a safety net for *logs* — the audit records themselves carry no raw values
by construction (see ``events.py``/``scrub.py``); this covers everything else.
"""

from __future__ import annotations

import logging
import re

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_CARD_LIKE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")


def redact(text: str) -> str:
    text = _EMAIL.sub("<EMAIL_REDACTED>", text)
    return _CARD_LIKE.sub("<NUMBER_REDACTED>", text)


class PiiRedactionFilter(logging.Filter):
    """Redact email/card-like substrings from the formatted log message."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True
