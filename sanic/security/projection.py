"""Public projection and internal cause-chain record of an exception.

A :class:`SafeProjection` is the single object that flows through rendering
and logging. Its :attr:`public` payload contains only a safe category,
generic message, status and trace number; its :attr:`internal` record keeps
the redacted exception chain for server-side logs. The two are constructed
together so there is exactly one place deciding what is safe to expose.
"""

from __future__ import annotations

import dataclasses
import traceback as _tb
import typing as t

from sanic.security.classify import ErrorCategory, ExceptionClassifier
from sanic.security.redaction import redact_text, safe_exception_message
from sanic.security.tracing import trace_id_for

if t.TYPE_CHECKING:
    from sanic.request.types import Request


@dataclasses.dataclass(frozen=True)
class CauseRecord:
    """One redacted link in the exception cause chain (logs only)."""

    type: str
    message: str
    traceback: str


@dataclasses.dataclass(frozen=True)
class InternalRecord:
    """Everything retained server-side about a failure (never serialized)."""

    trace_id: str
    path: str
    method: str
    causes: t.Tuple[CauseRecord, ...]

    def format_log(self) -> str:
        """Render the record as a multi-line, redacted log message."""
        lines = [
            f"security-error trace_id={self.trace_id} "
            f"method={self.method} path={self.path}",
        ]
        for index, cause in enumerate(self.causes):
            lines.append(
                f"  cause[{index}] {cause.type}: {cause.message}"
            )
            if cause.traceback:
                for frame_line in cause.traceback.rstrip().splitlines():
                    lines.append(f"    {frame_line}")
        return "\n".join(lines)


@dataclasses.dataclass(frozen=True)
class SafeProjection:
    """The safe, client-visible projection of one exception."""

    category: ErrorCategory
    trace_id: str
    status: int
    message: str

    def public_payload(self) -> t.Dict[str, t.Any]:
        """Plain mapping suitable for JSON serialization."""
        return {
            "error": {
                "category": self.category.value,
                "message": self.message,
                "trace_id": self.trace_id,
            }
        }

    @property
    def headers(self) -> t.Dict[str, str]:
        from sanic.security.tracing import TRACE_HEADER

        return {TRACE_HEADER: self.trace_id}


def _walk_chain(exception: BaseException) -> t.Tuple[BaseException, ...]:
    """Return the exception and its ``__cause__``/``__context__`` chain.

    Explicit ``raise ... from ...`` causes take precedence; implicit
    contexts are included only when no explicit cause exists, matching
    Python's own traceback presentation order (root first).
    """
    chain: t.List[BaseException] = []
    seen: t.Set[int] = set()
    current: BaseException | None = exception
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        if current.__cause__ is not None:
            current = current.__cause__
        elif current.__suppress_context__:
            current = None
        else:
            current = current.__context__
    return tuple(reversed(chain))


def build_projection(
    request: "Request | None",
    exception: BaseException,
    classifier: ExceptionClassifier,
) -> t.Tuple[SafeProjection, InternalRecord]:
    """Build the paired public projection and internal redacted record.

    Only the exception's type hierarchy influences the public category.
    Exception text, tracebacks and structured attributes feed the internal
    record after redaction only.
    """
    category = classifier.classify(exception)
    trace_id = trace_id_for(request)

    causes: t.List[CauseRecord] = []
    for link in _walk_chain(exception):
        raw_traceback = _tb.format_exception(
            type(link), link, link.__traceback__
        )
        causes.append(
            CauseRecord(
                type=type(link).__name__,
                message=redact_text(_message_of(link)),
                traceback=redact_text("".join(raw_traceback)),
            )
        )

    path = _safe_attr(request, "path", "<unavailable>")
    method = _safe_attr(request, "method", "<unavailable>")
    internal = InternalRecord(
        trace_id=trace_id,
        path=redact_text(path),
        method=method,
        causes=tuple(causes),
    )

    projection = SafeProjection(
        category=category,
        trace_id=trace_id,
        status=category.status,
        message=category.message,
    )
    return projection, internal


def _message_of(exception: BaseException) -> str:
    try:
        return str(exception)
    except Exception:
        return safe_exception_message(exception)


def _safe_attr(request: "Request | None", name: str, default: str) -> str:
    if request is None:
        return default
    try:
        value = getattr(request, name, default)
        return value if isinstance(value, str) and value else default
    except Exception:
        return default
