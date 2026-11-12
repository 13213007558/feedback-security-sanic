"""Render :class:`SafeProjection` objects into HTML, JSON or text.

Every renderer consumes only the already-sanitized projection. It never
receives the original exception, so there is no code path where an
exception's ``repr``, message or traceback can leak into a fallback body.
Rendering failures are converted into :class:`RenderingError` by the
calling handler rather than swallowed.
"""

from __future__ import annotations

import html as _html
import typing as t

from sanic.response import HTTPResponse, html, json, text
from sanic.security.errors import RenderingError
from sanic.security.projection import SafeProjection

JSON_MIME = "application/json"
TEXT_MIME = "text/plain"
HTML_MIME = "text/html"

#: Content negotiation preference order for the ``auto`` mode.
NEGOTIATED_MIMES: t.Tuple[str, ...] = (JSON_MIME, HTML_MIME, TEXT_MIME)


def render_json(projection: SafeProjection) -> HTTPResponse:
    """Render the projection as a JSON document."""
    return json(
        projection.public_payload(),
        status=projection.status,
        headers=projection.headers,
    )


def render_text(projection: SafeProjection) -> HTTPResponse:
    """Render the projection as a plain-text document."""
    body = (
        f"{projection.status} {projection.category.value}\n"
        f"{projection.message}\n"
        f"trace_id: {projection.trace_id}\n"
    )
    return text(
        body,
        status=projection.status,
        headers=projection.headers,
    )


def render_html(projection: SafeProjection) -> HTTPResponse:
    """Render the projection as a minimal, escaped HTML document."""
    escaped_status = _html.escape(str(projection.status))
    escaped_category = _html.escape(projection.category.value)
    escaped_message = _html.escape(projection.message)
    escaped_trace = _html.escape(projection.trace_id)
    document = (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        "<title>Error</title></head>\n"
        "<body>\n"
        f"<h1>Error {escaped_status}</h1>\n"
        f'<p data-testid="error-category">{escaped_category}</p>\n'
        f"<p>{escaped_message}</p>\n"
        f'<p>trace_id: <code>{escaped_trace}</code></p>\n'
        "</body></html>\n"
    )
    return html(
        document,
        status=projection.status,
        headers=projection.headers,
    )


_RENDERERS: t.Dict[str, t.Callable[[SafeProjection], HTTPResponse]] = {
    JSON_MIME: render_json,
    TEXT_MIME: render_text,
    HTML_MIME: render_html,
}


def negotiate_mime(request: t.Any, fallback: str) -> str:
    """Choose a response MIME type from the request and configured fallback.

    ``fallback`` mirrors Sanic's ``FALLBACK_ERROR_FORMAT`` and accepts
    ``json``, ``text``, ``html`` or ``auto``. Explicit fallback formats win
    over content negotiation; otherwise the request's ``Accept`` header is
    consulted, defaulting to JSON which is the safest machine-readable
    choice. This never raises.
    """
    explicit = {
        "json": JSON_MIME,
        "text": TEXT_MIME,
        "html": HTML_MIME,
    }
    if fallback in explicit:
        return explicit[fallback]

    try:
        match = request.accept.match(*NEGOTIATED_MIMES)
        if match and match.mime in _RENDERERS:
            return match.mime
        content_type = request.headers.getone("content-type", "")
        if JSON_MIME in content_type:
            return JSON_MIME
    except Exception:
        pass
    return JSON_MIME


def render(
    projection: SafeProjection,
    mime: str,
) -> HTTPResponse:
    """Render ``projection`` in the format identified by ``mime``.

    Unknown MIME types fall back to JSON rather than attempting any
    exception-derived rendering.
    """
    renderer = _RENDERERS.get(mime, render_json)
    try:
        return renderer(projection)
    except Exception as exc:  # pragma: no cover - defensive
        raise RenderingError("Failed to render safe error response") from exc
