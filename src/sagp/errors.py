"""The error taxonomy and its HTTP mapping.

One root ``SagpError``; a single exception handler in ``app/main.py`` (never
``BaseHTTPMiddleware``) turns each subclass into its status code. Stdlib only —
this module is part of the dependency-graph base.

``EgressViolation`` is deliberately **not** a ``SagpError`` and lives in
``netguard.egress``: it must never be caught by a handler that would turn it
into a 500. See CLAUDE.md invariants 2 and 6.
"""

from __future__ import annotations


class SagpError(Exception):
    """Base for every error that maps to an HTTP response.

    Subclasses set ``status_code`` and ``code``. ``code`` is the machine-readable
    token in the response body; for detector rejections it is always
    ``PROMPT_REJECTED`` so the rejection surface is not a detector oracle
    (invariant 8).
    """

    status_code: int = 500
    code: str = "INTERNAL"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.code)


class PromptRejected(SagpError):
    """A detector (C3–C12) rejected the request. Uniform, opaque, deadline-padded."""

    status_code = 400
    code = "PROMPT_REJECTED"


class UnsupportedRequest(SagpError):
    """Schema/shape the API does not support (e.g. multi-turn ``messages``).

    A pre-detector error: it reveals nothing about a detector, so it is the one
    400 exempt from the uniform ``PROMPT_REJECTED`` body and the rejection
    deadline (BLUEPRINT §5.7).
    """

    status_code = 400
    code = "UNSUPPORTED"


class AuthError(SagpError):
    """Missing or invalid bearer token."""

    status_code = 401
    code = "UNAUTHORIZED"


class RateLimited(SagpError):
    """Per-principal rate limit exceeded."""

    status_code = 429
    code = "RATE_LIMITED"


class InputTooLarge(SagpError):
    """Input exceeds a size cap (``SAGP_MAX_INPUT_CHARS`` / ``SAGP_MAX_DOC_BYTES``)."""

    status_code = 413
    code = "INPUT_TOO_LARGE"


class GuardrailUnavailable(SagpError):
    """A guardrail errored, timed out, or (per OQ-6) swallowed a regex timeout.

    Fail-closed: there is exactly one failure mode and it is 503, never a
    partial result returned as 200 (invariant 6).
    """

    status_code = 503
    code = "GUARDRAIL_UNAVAILABLE"


class ConfigError(SagpError):
    """Invalid configuration detected at startup. The app refuses to boot.

    Not client-facing — raised before the server accepts requests (e.g. a
    threshold outside ``0 < t <= 1``, an unknown ``SAGP_`` key, a projected RSS
    over the 90% ceiling).
    """

    status_code = 500
    code = "CONFIG_ERROR"
