"""Correlation identifiers that link a public error to its internal log.

The trace number is the only request-specific datum exposed to clients. It
is generated from :mod:`secrets` so it cannot be guessed or enumerated, and
it is also attached to the internal log record for the same failure.
"""

from __future__ import annotations

import secrets

from sanic.request.types import Request

#: Attribute on ``request.ctx`` holding the trace number for this request.
TRACE_ATTR = "security_trace_id"

#: Response header carrying the trace number back to the caller.
TRACE_HEADER = "X-Error-Trace"

_PREFIX = "err"
_RANDOM_BYTES = 16


def generate_trace_id() -> str:
    """Return a fresh, unguessable trace number.

    The ``err-`` prefix makes the identifier self-describing in logs and
    support tickets. Generation uses :func:`secrets.token_hex` so IDs carry
    no information about the request or the underlying exception.
    """
    return f"{_PREFIX}-{secrets.token_hex(_RANDOM_BYTES)}"


def trace_id_for(request: Request | None) -> str:
    """Return the trace number for ``request``, creating one on first use.

    A single request always gets a single trace number, even if several
    handlers or fallback layers run. When ``request`` is unavailable a new
    ID is still issued so the failure remains locatable.
    """
    if request is None:
        return generate_trace_id()
    existing = getattr(request.ctx, TRACE_ATTR, None)
    if isinstance(existing, str) and existing:
        return existing
    trace_id = generate_trace_id()
    setattr(request.ctx, TRACE_ATTR, trace_id)
    return trace_id
