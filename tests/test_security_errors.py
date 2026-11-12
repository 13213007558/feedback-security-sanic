"""Tests for the centralized sensitive-exception projection policy.

Coverage:
* Content negotiation (JSON / HTML / text, explicit fallback and "auto").
* Debug mode never leaking exception types, messages or tracebacks.
* Custom (sync and async) exception handlers and their failures.
* Failures of the policy itself producing a constant, locatable response.
* Redaction of the internal cause chain and trace-id correlation.
"""

from __future__ import annotations

import logging
import types

import pytest

from sanic import Sanic
from sanic.exceptions import BadRequest, Forbidden, NotFound
from sanic.response import json as sjson
from sanic.security import (
    ErrorCategory,
    ExceptionClassifier,
    ProjectionError,
    SafeErrorHandler,
    TRACE_HEADER,
    attach_outer_guard,
    redact_text,
    redact_value,
)
from sanic.security import renderers as renderer_module
from sanic.security.projection import build_projection

SECRET = "AKIA1234567890ABCDEF"
SECRET_TEXT = f"token={SECRET} password=hunter2"


def _make_app(name: str) -> Sanic:
    app = Sanic(name, error_handler=SafeErrorHandler())
    attach_outer_guard(app)

    @app.get("/boom")
    async def boom(request):
        raise RuntimeError(f"internal failure {SECRET_TEXT}")

    @app.get("/bad")
    async def bad(request):
        raise BadRequest(f"invalid field {SECRET_TEXT}")

    @app.get("/missing")
    async def missing(request):
        raise NotFound(f"no such resource {SECRET_TEXT}")

    return app


@pytest.mark.asyncio
async def test_json_negotiation_hides_exception_details():
    app = _make_app("sec-json")
    _, response = await app.asgi_client.get(
        "/boom", headers={"accept": "application/json"}
    )
    assert response.status == 500
    assert response.content_type == "application/json"
    body = response.json
    assert body["error"]["category"] == "internal_error"
    assert body["error"]["message"] == "An internal error occurred."
    assert body["error"]["trace_id"].startswith("err-")
    assert response.headers[TRACE_HEADER] == body["error"]["trace_id"]
    assert SECRET not in response.text
    assert "RuntimeError" not in response.text
    assert "hunter2" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "accept,suffix,content_type,marker",
    [
        ("text/html", "html", "text/html", "<html"),
        ("text/plain", "plain", "text/plain", "internal_error"),
    ],
)
async def test_html_and_text_negotiation(accept, suffix, content_type, marker):
    app = _make_app(f"sec-negotiate-{suffix}")
    _, response = await app.asgi_client.get(
        "/boom", headers={"accept": accept}
    )
    assert response.status == 500
    assert response.content_type.startswith(content_type)
    assert marker in response.text
    assert SECRET not in response.text
    assert "RuntimeError" not in response.text
    assert response.headers[TRACE_HEADER].startswith("err-")


@pytest.mark.asyncio
async def test_known_http_exception_uses_safe_category():
    app = _make_app("sec-categories")
    _, bad = await app.asgi_client.get(
        "/bad", headers={"accept": "application/json"}
    )
    assert bad.status == 400
    assert bad.json["error"]["category"] == "bad_request"
    assert SECRET not in bad.text

    _, missing = await app.asgi_client.get(
        "/missing", headers={"accept": "application/json"}
    )
    assert missing.status == 404
    assert missing.json["error"]["category"] == "not_found"
    assert SECRET not in missing.text


@pytest.mark.asyncio
async def test_method_not_allowed_uses_safe_category():
    app = Sanic("sec-method", error_handler=SafeErrorHandler())
    attach_outer_guard(app)

    @app.post("/only-post")
    async def only_post(request):
        return sjson({"ok": True})

    _, response = await app.asgi_client.get(
        "/only-post", headers={"accept": "application/json"}
    )
    assert response.status == 405
    assert response.json["error"]["category"] == "method_not_allowed"


@pytest.mark.asyncio
async def test_quiet_exception_is_safe_but_not_logged(caplog):
    app = Sanic("sec-quiet", error_handler=SafeErrorHandler())
    attach_outer_guard(app)

    @app.get("/exists")
    async def exists(request):
        return sjson({"ok": True})

    with caplog.at_level(logging.ERROR, logger="sanic.error"):
        _, response = await app.asgi_client.get(
            "/does-not-exist", headers={"accept": "application/json"}
        )

    assert response.status == 404
    assert response.json["error"]["category"] == "not_found"
    assert not any(
        "security-error" in record.message for record in caplog.records
    )


@pytest.mark.asyncio
async def test_explicit_fallback_format_overrides_accept():
    handler = SafeErrorHandler(fallback_format="text")
    app = Sanic("sec-fallback", error_handler=handler)
    attach_outer_guard(app)

    @app.get("/boom")
    async def boom(request):
        raise RuntimeError(SECRET_TEXT)

    _, response = await app.asgi_client.get(
        "/boom", headers={"accept": "application/json"}
    )
    assert response.content_type.startswith("text/plain")
    assert SECRET not in response.text


@pytest.mark.asyncio
async def test_debug_mode_does_not_leak_exception_data():
    app = Sanic("sec-debug", error_handler=SafeErrorHandler())
    app.config.DEBUG = True
    attach_outer_guard(app)

    @app.get("/boom")
    async def boom(request):
        raise RuntimeError(f"crash {SECRET_TEXT}")

    for accept in ("application/json", "text/html", "text/plain"):
        _, response = await app.asgi_client.get(
            "/boom", headers={"accept": accept}
        )
        assert SECRET not in response.text
        assert "RuntimeError" not in response.text
        assert "Traceback" not in response.text
        assert "hunter2" not in response.text
        assert response.headers[TRACE_HEADER].startswith("err-")


@pytest.mark.asyncio
async def test_trace_id_is_stable_per_request():
    app = _make_app("sec-trace-stable")

    @app.get("/twice")
    async def twice(request):
        from sanic.security import trace_id_for

        first = trace_id_for(request)
        second = trace_id_for(request)
        assert first == second
        raise RuntimeError("x")

    _, response = await app.asgi_client.get(
        "/twice", headers={"accept": "application/json"}
    )
    trace_id = response.json["error"]["trace_id"]
    assert response.headers[TRACE_HEADER] == trace_id


@pytest.mark.asyncio
async def test_custom_sync_handler_response_gets_trace_header():
    app = Sanic("sec-custom-sync", error_handler=SafeErrorHandler())
    attach_outer_guard(app)

    @app.exception(Forbidden)
    def handle_forbidden(request, exception):
        return sjson({"ok": False}, status=403)

    @app.get("/forbidden")
    async def forbidden(request):
        raise Forbidden(SECRET_TEXT)

    _, response = await app.asgi_client.get("/forbidden")
    assert response.status == 403
    assert response.headers[TRACE_HEADER].startswith("err-")
    assert SECRET not in response.text


@pytest.mark.asyncio
async def test_custom_async_handler_is_awaited():
    app = Sanic("sec-custom-async", error_handler=SafeErrorHandler())
    attach_outer_guard(app)

    @app.exception(Forbidden)
    async def handle_forbidden(request, exception):
        return sjson({"ok": False, "async": True}, status=403)

    @app.get("/forbidden")
    async def forbidden(request):
        raise Forbidden("x")

    _, response = await app.asgi_client.get("/forbidden")
    assert response.status == 403
    assert response.json["async"] is True


@pytest.mark.asyncio
async def test_failing_custom_handler_is_safely_projected():
    app = Sanic("sec-custom-fail", error_handler=SafeErrorHandler())
    attach_outer_guard(app)

    @app.exception(ValueError)
    async def broken(request, exception):
        raise RuntimeError(f"handler crash {SECRET_TEXT}")

    @app.get("/value")
    async def value(request):
        raise ValueError("origin")

    _, response = await app.asgi_client.get(
        "/value", headers={"accept": "application/json"}
    )
    assert response.status == 500
    assert response.json["error"]["category"] == "internal_error"
    assert SECRET not in response.text
    assert "RuntimeError" not in response.text
    assert "handler crash" not in response.text


@pytest.mark.asyncio
async def test_projection_failure_returns_constant_safety_response(
    caplog,
):
    app = Sanic("sec-policy-fail", error_handler=SafeErrorHandler())
    attach_outer_guard(app)

    @app.get("/fail")
    async def fail(request):
        raise ProjectionError("policy broke secret=zzz")

    with caplog.at_level(logging.ERROR, logger="sanic.error"):
        _, response = await app.asgi_client.get(
            "/fail", headers={"accept": "application/json"}
        )

    assert response.status == 500
    body = response.json
    assert body["error"] == {
        "category": "internal_error",
        "message": "An internal error occurred.",
        "trace_id": body["error"]["trace_id"],
    }
    assert body["error"]["trace_id"].startswith("err-")
    assert "ProjectionError" not in response.text
    assert "zzz" not in response.text
    assert any(
        "Safety policy failure" in record.message
        for record in caplog.records
    )


@pytest.mark.asyncio
async def test_renderer_failure_falls_back_to_safety_response():
    app = Sanic("sec-render-fail", error_handler=SafeErrorHandler())
    attach_outer_guard(app)

    @app.get("/boom")
    async def boom(request):
        raise RuntimeError("x")

    def exploding_render(projection):
        raise ValueError("renderer exploded secret=zzz")

    saved = dict(renderer_module._RENDERERS)
    try:
        for mime in list(renderer_module._RENDERERS):
            renderer_module._RENDERERS[mime] = exploding_render
        _, response = await app.asgi_client.get(
            "/boom", headers={"accept": "application/json"}
        )
    finally:
        renderer_module._RENDERERS.clear()
        renderer_module._RENDERERS.update(saved)

    assert response.status == 500
    assert response.json["error"]["category"] == "internal_error"
    assert "renderer exploded" not in response.text
    assert "zzz" not in response.text
    assert response.headers[TRACE_HEADER].startswith("err-")


def test_redaction_strips_known_secret_patterns():
    assert "hunter2" not in redact_text("password=hunter2")
    assert "tkn" not in redact_text("token: tkn")
    redacted = redact_text("postgres://u:dbpass@host/db")
    assert "dbpass" not in redacted
    # Benign text is preserved.
    assert redact_text("ordinary message") == "ordinary message"


def test_redaction_handlers_nested_structures():
    data = {
        "outer": ["password=secret123", "fine"],
        "nested": {"token": "deadbeefdeadbeefdeadbeefdeadbeef"},
    }
    cleaned = redact_value(data)
    serialized = str(cleaned)
    assert "secret123" not in serialized
    assert "deadbeefdeadbeefdeadbeefdeadbeef" not in serialized
    assert "fine" in serialized


def test_redaction_never_raises_on_bad_input():
    class BadStr:
        def __str__(self):
            raise RuntimeError("no str")

    assert redact_value(BadStr()) is not None


def test_classifier_maps_framework_and_unknown_exceptions():
    classifier = ExceptionClassifier()
    assert classifier.classify(BadRequest("x")) is ErrorCategory.BAD_REQUEST
    assert (
        classifier.classify(NotFound("x")) is ErrorCategory.NOT_FOUND
    )
    assert classifier.classify(RuntimeError("x")) is (
        ErrorCategory.INTERNAL_ERROR
    )


def test_classifier_supports_custom_registration():
    class CustomError(Exception):
        pass

    classifier = ExceptionClassifier(
        {CustomError: ErrorCategory.UNAVAILABLE}
    )
    assert classifier.classify(CustomError()) is (
        ErrorCategory.UNAVAILABLE
    )


def test_classifier_does_not_raise_on_broken_exception():
    class Weird(Exception):
        def __str__(self):
            raise RuntimeError("broken")

    classifier = ExceptionClassifier()
    assert classifier.classify(Weird()) is ErrorCategory.INTERNAL_ERROR


def test_internal_record_keeps_redacted_cause_chain():
    sanic_app = Sanic("sec-chain", error_handler=SafeErrorHandler())

    class FakeRequest:
        ctx = types.SimpleNamespace()
        path = "/pay"
        method = "POST"
        app = sanic_app

    try:
        try:
            raise ValueError("db password=dbpass123")
        except ValueError as original:
            raise RuntimeError("payment token=ptok") from original
    except RuntimeError as exc:
        projection, internal = build_projection(
            FakeRequest, exc, sanic_app.error_handler.classifier
        )

    log_text = internal.format_log()
    assert "dbpass123" not in log_text
    assert "ptok" not in log_text
    assert "ValueError" in log_text
    assert "RuntimeError" in log_text
    assert internal.trace_id == projection.trace_id
    assert SECRET not in projection.public_payload()
