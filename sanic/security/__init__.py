"""Centralized public projection of sensitive exceptions.

The package separates what clients may see from what operators need:

* :class:`SafeErrorHandler` replaces Sanic's default error handler and
  routes every uncaught exception through a fixed, safe vocabulary.
* Public responses (HTML, JSON or text via content negotiation) contain only
  an error category, a generic message, an HTTP status and a trace number.
* Internal logging keeps the full cause chain after secret redaction,
  keyed by the same trace number.
* Failures of the policy itself raise :class:`SafetyPolicyError`, which
  :func:`attach_outer_guard` maps to a constant, locatable safety response.

Typical setup::

    from sanic import Sanic
    from sanic.security import SafeErrorHandler, attach_outer_guard

    app = Sanic("example", error_handler=SafeErrorHandler())
    attach_outer_guard(app)
"""

from __future__ import annotations

from sanic.security.classify import ErrorCategory, ExceptionClassifier
from sanic.security.errors import (
    ProjectionError,
    RenderingError,
    SafetyPolicyError,
)
from sanic.security.handler import SafeErrorHandler
from sanic.security.projection import (
    CauseRecord,
    InternalRecord,
    SafeProjection,
    build_projection,
)
from sanic.security.redaction import redact_text, redact_value
from sanic.security.tracing import (
    TRACE_HEADER,
    generate_trace_id,
    trace_id_for,
)

__all__ = (
    "ErrorCategory",
    "ExceptionClassifier",
    "SafetyPolicyError",
    "ProjectionError",
    "RenderingError",
    "SafeErrorHandler",
    "SafeProjection",
    "InternalRecord",
    "CauseRecord",
    "build_projection",
    "redact_text",
    "redact_value",
    "generate_trace_id",
    "trace_id_for",
    "TRACE_HEADER",
    "attach_outer_guard",
)


def _policy_failure_handler(request, exception):
    """Framework-registered handler for :class:`SafetyPolicyError`.

    It is registered directly on the error handler's lookup table, so it
    bypasses the normal projection path that just failed and emits the
    constant safety response without touching exception data.
    """
    return request.app.error_handler.safe_failure_response(
        request, exception
    )


def attach_outer_guard(app) -> None:
    """Register the outermost safety fallback on a Sanic application.

    A failure inside the projection machinery raises
    :class:`SafetyPolicyError`. Sanic's generic exception catch could
    otherwise render such an error with its debug page (which includes
    exception text). This registers a dedicated handler for
    :class:`SafetyPolicyError` directly in the error handler's lookup table,
    which is the framework's own dispatch mechanism and is not affected by
    the startup source-rewriting ("touchup") optimizations. The handler
    returns a constant body carrying only a fresh trace number.

    A defense-in-depth branch for the same exception also exists in
    :meth:`sanic.Sanic.handle_exception`, covering the case where the
    registered handler itself cannot run.
    """
    handler = app.error_handler
    if not isinstance(handler, SafeErrorHandler):
        raise TypeError(
            "attach_outer_guard requires the application to use "
            "SafeErrorHandler; got %r" % type(handler).__name__
        )

    key = (SafetyPolicyError, None)
    if key not in handler.cached_handlers:
        handler.add(SafetyPolicyError, _policy_failure_handler)
