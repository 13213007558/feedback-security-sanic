"""Error handler that projects every failure through the safe policy.

:class:`SafeErrorHandler` is a drop-in replacement for Sanic's
:class:`~sanic.handlers.ErrorHandler`. It guarantees three invariants:

1. A client only ever receives a safe category, a generic message, an HTTP
   status and a trace number -- regardless of HTML/JSON/text negotiation,
   debug mode, or whether a custom exception handler is registered.
2. The original exception's ``repr``, message and traceback never appear in
   any fallback response. They are redacted and retained in internal logs.
3. If the policy itself fails, a static, locatable safety response is still
   produced (with its own trace number) instead of a framework default that
   might echo exception data.
"""

from __future__ import annotations

import typing as t
from inspect import isawaitable

from sanic.errorpages import BaseRenderer, TextRenderer
from sanic.handlers.error import ErrorHandler
from sanic.log import error_logger
from sanic.response import HTTPResponse, json as json_response
from sanic.security.classify import ErrorCategory, ExceptionClassifier
from sanic.security.errors import (
    ProjectionError,
    SafetyPolicyError,
)
from sanic.security.projection import build_projection
from sanic.security.renderers import negotiate_mime, render
from sanic.security.tracing import (
    TRACE_HEADER,
    generate_trace_id,
    trace_id_for,
)

if t.TYPE_CHECKING:
    from sanic.request.types import Request


#: Static body used when even the safety machinery itself breaks. It contains
#: no input-derived data beyond the freshly generated trace number.
POLICY_FAILURE_STATUS = 500
POLICY_FAILURE_CATEGORY = ErrorCategory.INTERNAL_ERROR.value
POLICY_FAILURE_MESSAGE = "An internal error occurred."


class SafeErrorHandler(ErrorHandler):
    """Centralized sensitive-exception projection handler.

    Args:
        base: Kept for signature compatibility with
            :class:`~sanic.handlers.ErrorHandler`; the safe renderers ignore
            it so debug pages can never bypass the policy.
        classifier: Optional preconfigured :class:`ExceptionClassifier`.
        fallback_format: Error format override. When ``None`` the app's
            ``FALLBACK_ERROR_FORMAT`` config is used per request.
    """

    def __init__(
        self,
        base: type[BaseRenderer] = TextRenderer,
        classifier: ExceptionClassifier | None = None,
        fallback_format: str | None = None,
    ) -> None:
        super().__init__(base=base)
        self.classifier = classifier or ExceptionClassifier()
        self.fallback_format = fallback_format

    def default(
        self, request: "Request", exception: Exception
    ) -> HTTPResponse:
        """Project ``exception`` into a safe, content-negotiated response.

        This is the policy boundary. Any failure inside the projection
        machinery is normalized into :class:`ProjectionError` and propagates,
        so the outer guard can answer with the constant safety response
        instead of a framework default that might echo exception data.
        """
        try:
            projection, internal = build_projection(
                request, exception, self.classifier
            )
            self._log_internal(request, internal.format_log(), exception)
            mime = self._resolve_mime(request)
            return render(projection, mime)
        except SafetyPolicyError:
            raise
        except Exception as failure:
            raise ProjectionError(
                "Failed to build the safe error projection"
            ) from failure

    def response(self, request, exception):
        """Run a registered custom handler, enforcing the safe contract.

        Custom handlers may return their own response for business errors,
        but anything that escapes them -- an exception or a missing response
        -- is projected through :meth:`default` rather than Sanic's default
        debug-aware error pages. Async custom handlers are supported: this
        returns a coroutine in that case, mirroring Sanic's own handler
        contract so the framework's ``isawaitable`` check drives execution.
        """
        route_name = request.name if request else None
        handler = self._lookup(exception, route_name)
        if handler is None:
            return self.default(request, exception)

        outcome = handler(request, exception)
        if isawaitable(outcome):
            return self._await_custom(request, exception, handler, outcome)
        return self._consume_custom(request, exception, handler, outcome)

    async def _await_custom(self, request, exception, handler, coroutine):
        try:
            outcome = await coroutine
        except SafetyPolicyError:
            raise
        except Exception as handler_exc:
            return self._recover_custom(request, handler, handler_exc)
        return self._consume_custom(request, exception, handler, outcome)

    def _consume_custom(self, request, exception, handler, outcome):
        if outcome is not None:
            return self._ensure_trace_header(request, outcome)
        return self.default(request, exception)

    def _recover_custom(self, request, handler, handler_exc):
        error_logger.exception(
            "Custom exception handler %s failed; projecting safely",
            getattr(handler, "__name__", "<unknown>"),
        )
        try:
            return self.default(request, handler_exc)
        except SafetyPolicyError:
            raise
        except Exception as failure:
            raise ProjectionError(
                "Safe projection failed after a custom handler error"
            ) from failure

    def safe_failure_response(
        self,
        request: "Request | None",
        failure: BaseException,
    ) -> HTTPResponse:
        """Outermost fallback for failures of the policy itself.

        This performs no formatting derived from ``failure``: the body is a
        constant schema, the only dynamic value being a new trace number that
        is also logged (with the failure type only) for later diagnosis. The
        method is built to never raise; if even trace generation or JSON
        encoding fails, a bare static response is returned.
        """
        try:
            trace_id = trace_id_for(request)
        except Exception:
            trace_id = generate_trace_id()
        try:
            error_logger.error(
                "Safety policy failure trace_id=%s failure_type=%s",
                trace_id,
                type(failure).__name__,
            )
        except Exception:  # pragma: no cover - logging must never break output
            pass
        body = {
            "error": {
                "category": POLICY_FAILURE_CATEGORY,
                "message": POLICY_FAILURE_MESSAGE,
                "trace_id": trace_id,
            }
        }
        try:
            return json_response(
                body,
                status=POLICY_FAILURE_STATUS,
                headers={TRACE_HEADER: trace_id},
            )
        except Exception:  # pragma: no cover - ultimate static fallback
            return HTTPResponse(
                (
                    '{"error":{"category":"'
                    f'{POLICY_FAILURE_CATEGORY}","message":"'
                    f'{POLICY_FAILURE_MESSAGE}","trace_id":"'
                    f'{trace_id}"}}}}'
                ),
                status=POLICY_FAILURE_STATUS,
                content_type="application/json",
            )

    def _resolve_mime(self, request: "Request") -> str:
        configured = self.fallback_format
        if configured is None:
            try:
                configured = request.app.config.FALLBACK_ERROR_FORMAT
            except Exception:
                configured = "auto"
        return negotiate_mime(request, configured or "auto")

    def _ensure_trace_header(
        self,
        request: "Request",
        response: HTTPResponse,
    ) -> HTTPResponse:
        """Attach the trace header to custom-handler responses when absent."""
        try:
            trace_id = trace_id_for(request)
            if TRACE_HEADER not in response.headers:
                response.headers[TRACE_HEADER] = trace_id
        except Exception:
            # A broken custom response still travels to the client; never let
            # header bookkeeping turn into an information leak.
            pass
        return response

    def _log_internal(
        self,
        request: "Request | None",
        formatted: str,
        exception: BaseException,
    ) -> None:
        quiet = getattr(exception, "quiet", False)
        noisy = False
        try:
            noisy = getattr(request.app.config, "NOISY_EXCEPTIONS", False)
        except Exception:
            pass
        if quiet and not noisy:
            return
        try:
            error_logger.error("%s", formatted)
        except Exception:  # pragma: no cover
            error_logger.error(
                "security-error trace_id=%s (log formatting failed)",
                trace_id_for(request),
            )
