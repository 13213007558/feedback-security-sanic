"""Regression tests for trusted request audit correlation.

These tests exercise the internal request key (``request.internal_id``) and
the bounded, untrusted external identifier (``request.external_id``). They
intentionally avoid live sockets so that they run in restricted CI sandboxes.
"""

import asyncio
import logging

from contextvars import ContextVar

import pytest

from sanic import Sanic, response
from sanic.log import logger
from sanic.logging.context import current_request_audit
from sanic.response import ResponseStream


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def messages_for(self, text: str) -> list[logging.LogRecord]:
        return [r for r in self.records if r.getMessage() == text]


@pytest.fixture
def capture():
    """Capture Sanic log records.

    ``Sanic(...)`` applies ``dictConfig`` which replaces handlers, so this
    fixture must be attached *after* the app is built. Tests call ``attach``
    explicitly; the handler is removed during teardown.
    """

    handler = _Capture()

    def attach():
        for name in ("sanic.root", "sanic.error", "sanic.access"):
            logging.getLogger(name).addHandler(handler)
        return handler

    handler.attach = attach  # type: ignore[attr-defined]
    yield handler

    for name in ("sanic.root", "sanic.error", "sanic.access"):
        logging.getLogger(name).removeHandler(handler)


def _internal(record) -> str:
    value = getattr(record, "internal_request_id", None)
    assert value, f"record {record!r} has no trusted internal request id"
    return value


@pytest.mark.asyncio
async def test_internal_key_is_independent_of_external_id():
    app = Sanic("correlation-independent")

    @app.get("/")
    async def handler(request):
        return response.json(
            {
                "internal": request.internal_id,
                "external": request.external_id,
            }
        )

    _, first = await app.asgi_client.get(
        "/", headers={"X-Request-ID": "abc-123"}
    )
    _, second = await app.asgi_client.get(
        "/", headers={"X-Request-ID": "abc-123"}
    )

    assert first.json["external"] == "abc-123"
    assert first.json["internal"] != first.json["external"]
    assert first.json["internal"] != second.json["internal"]


@pytest.mark.asyncio
async def test_external_id_is_bounded_and_log_safe():
    app = Sanic("correlation-bounded")
    app.config.REQUEST_ID_MAX_LENGTH = 12

    @app.get("/")
    async def handler(request):
        return response.json({"external": request.external_id})

    _, response_ = await app.asgi_client.get(
        "/",
        headers={"X-Request-ID": "A" * 5000 + "\x00\r\nforged"},
    )
    assert response_.json["external"] == "A" * 12
    assert "\r" not in response_.json["external"]
    assert "\n" not in response_.json["external"]


@pytest.mark.asyncio
async def test_external_id_absent_is_none():
    app = Sanic("correlation-absent")

    @app.get("/")
    async def handler(request):
        return response.json(
            {"external": request.external_id, "internal": request.internal_id}
        )

    _, response_ = await app.asgi_client.get("/")
    assert response_.json["external"] is None
    assert response_.json["internal"]


@pytest.mark.asyncio
async def test_middleware_and_log_records_share_internal_key(capture):
    app = Sanic("correlation-middleware")
    capture.attach()
    seen = ContextVar("seen", default=None)

    @app.on_request
    async def request_middleware(request):
        logger.info("middleware")
        seen.set(request.internal_id)

    @app.get("/")
    async def handler(request):
        logger.info("handler")
        return response.text("ok")

    _, response_ = await app.asgi_client.get(
        "/", headers={"X-Request-ID": "dup"}
    )
    assert response_.status == 200

    middleware = capture.messages_for("middleware")
    handled = capture.messages_for("handler")
    assert middleware and handled
    assert _internal(middleware[0]) == _internal(handled[0])
    assert _internal(handled[0]) == seen.get()
    assert getattr(handled[0], "external_request_id") == "dup"


@pytest.mark.asyncio
async def test_exception_log_shares_internal_key(capture):
    app = Sanic("correlation-exception")
    capture.attach()

    @app.get("/boom")
    async def handler(request):
        logger.info("before-boom")
        raise ValueError("boom")

    _, response_ = await app.asgi_client.get(
        "/boom", headers={"X-Request-ID": "dup"}
    )
    assert response_.status == 500

    before = capture.messages_for("before-boom")
    errors = [
        record
        for record in capture.records
        if "Exception occurred while handling uri" in record.getMessage()
    ]
    assert before and errors
    assert _internal(before[0]) == _internal(errors[0])


@pytest.mark.asyncio
async def test_streaming_logs_share_internal_key(capture):
    app = Sanic("correlation-stream")
    capture.attach()

    def build_stream():
        async def flow(stream):
            logger.info("stream-start")
            await asyncio.sleep(0)
            await stream.write("hello")
            logger.info("stream-end")
            await stream.write("world")

        return ResponseStream(flow)

    @app.get("/stream")
    async def handler(request):
        return build_stream()

    _, response_ = await app.asgi_client.get(
        "/stream", headers={"X-Request-ID": "S1"}
    )
    assert response_.status == 200
    assert response_.text == "helloworld"

    start = capture.messages_for("stream-start")
    end = capture.messages_for("stream-end")
    assert _internal(start[0]) == _internal(end[0])
    assert getattr(start[0], "external_request_id") == "S1"


@pytest.mark.asyncio
async def test_derived_task_shares_internal_key(capture):
    app = Sanic("correlation-task")
    capture.attach()
    done = asyncio.Event()

    @app.get("/")
    async def handler(request):
        async def derived():
            logger.info("task-start")
            await asyncio.sleep(0.05)
            logger.info("task-end")
            done.set()

        app.add_task(derived())
        logger.info("handler")
        return response.text("ok")

    _, response_ = await app.asgi_client.get(
        "/", headers={"X-Request-ID": "T1"}
    )
    assert response_.status == 200
    await asyncio.wait_for(done.wait(), 1)

    handler_record = capture.messages_for("handler")[0]
    task_start = capture.messages_for("task-start")[0]
    task_end = capture.messages_for("task-end")[0]
    assert _internal(handler_record) == _internal(task_start)
    assert _internal(handler_record) == _internal(task_end)


@pytest.mark.asyncio
async def test_interleaved_requests_do_not_share_keys(capture):
    app = Sanic("correlation-interleaved")
    capture.attach()

    @app.get("/<name>")
    async def handler(request, name):
        finished = asyncio.Event()

        async def derived():
            logger.info(f"derived-{name}-start")
            await asyncio.sleep(0.01)
            logger.info(f"derived-{name}-end")
            finished.set()

        app.add_task(derived())
        await asyncio.sleep(0.002)
        logger.info(f"handler-{name}")
        await asyncio.wait_for(finished.wait(), 1)
        return response.json({"internal": request.internal_id})

    first, second = await asyncio.gather(
        app.asgi_client.get("/one", headers={"X-Request-ID": "SAME"}),
        app.asgi_client.get("/two", headers={"X-Request-ID": "SAME"}),
    )

    assert first[1].json["internal"] != second[1].json["internal"]

    handler_one = capture.messages_for("handler-one")[0]
    handler_two = capture.messages_for("handler-two")[0]
    assert _internal(handler_one) != _internal(handler_two)
    assert getattr(handler_one, "external_request_id") == "SAME"
    assert getattr(handler_two, "external_request_id") == "SAME"

    for name, expected in (("one", handler_one), ("two", handler_two)):
        start = capture.messages_for(f"derived-{name}-start")[0]
        end = capture.messages_for(f"derived-{name}-end")[0]
        assert _internal(start) == _internal(expected)
        assert _internal(end) == _internal(expected)


@pytest.mark.asyncio
async def test_request_content_cannot_override_audit_fields(capture):
    app = Sanic("correlation-forged")
    capture.attach()

    @app.on_request
    async def middleware(request):
        logger.info(
            "forged",
            extra={
                "internal_request_id": "attacker-internal",
                "external_request_id": "attacker-external",
            },
        )

    @app.get("/")
    async def handler(request):
        logger.info("real")
        return response.json(
            {
                "internal": request.internal_id,
                "external": request.external_id,
            }
        )

    _, response_ = await app.asgi_client.get(
        "/", headers={"X-Request-ID": "client-value"}
    )

    forged = capture.messages_for("forged")[0]
    real = capture.messages_for("real")[0]
    assert getattr(forged, "internal_request_id") == response_.json["internal"]
    assert getattr(forged, "external_request_id") == "client-value"
    assert _internal(real) == response_.json["internal"]


@pytest.mark.asyncio
async def test_next_request_does_not_inherit_internal_key(capture):
    app = Sanic("correlation-no-inherit")
    capture.attach()

    @app.get("/")
    async def handler(request):
        logger.info("request-log")
        return response.json({"internal": request.internal_id})

    _, first = await app.asgi_client.get("/", headers={"X-Request-ID": "A"})
    _, second = await app.asgi_client.get("/", headers={"X-Request-ID": "B"})

    records = capture.messages_for("request-log")
    assert len(records) == 2
    assert _internal(records[0]) == first.json["internal"]
    assert _internal(records[1]) == second.json["internal"]
    assert _internal(records[0]) != _internal(records[1])

    # Outside a request lifecycle no stale audit value survives.
    assert current_request_audit() is None
    bare = logging.getLogger("sanic.root")
    record = bare.makeRecord(
        "sanic.root",
        logging.INFO,
        __file__,
        0,
        "outside",
        (),
        None,
        extra={"internal_request_id": "stale"},
    )
    for filter_ in bare.filters:
        filter_.filter(record)
    assert record.internal_request_id is None


def test_access_formatter_renders_internal_key():
    from io import StringIO

    from sanic.logging.context import audit_scope
    from sanic.logging.filter import RequestAuditFilter
    from sanic.logging.formatter import ProdAccessFormatter

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(ProdAccessFormatter())
    probe = logging.getLogger("sanic.access.formatter-probe")
    probe.handlers = [handler]
    probe.filters = [RequestAuditFilter()]
    probe.setLevel(logging.INFO)
    probe.propagate = False

    with audit_scope("internal-key", "external-key"):
        probe.info(
            "",
            extra={
                "host": "h",
                "request": "GET /",
                "status": 200,
                "byte": 2,
                "duration": "",
            },
        )

    output = stream.getvalue()
    assert "internal-key" in output


@pytest.mark.asyncio
async def test_user_defined_logger_gets_trusted_key():
    from io import StringIO

    stream = StringIO()
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "loggers": {
            "sanic.root": {"level": "INFO", "handlers": ["capture"]},
            "userapp": {
                "level": "INFO",
                "handlers": ["capture"],
                "propagate": False,
            },
        },
        "handlers": {
            "capture": {
                "class": "logging.StreamHandler",
                "stream": stream,
                "formatter": "plain",
            }
        },
        "formatters": {
            "plain": {"format": "%(message)s [%(internal_request_id)s]"}
        },
    }
    app = Sanic("correlation-user-logger", log_config=config)

    @app.get("/")
    async def handler(request):
        logging.getLogger("userapp").info(
            "user-log", extra={"internal_request_id": "FORGED"}
        )
        return response.json({"internal": request.internal_id})

    _, response_ = await app.asgi_client.get(
        "/", headers={"X-Request-ID": "EXT"}
    )

    output = stream.getvalue()
    assert "FORGED" not in output
    assert response_.json["internal"] in output
