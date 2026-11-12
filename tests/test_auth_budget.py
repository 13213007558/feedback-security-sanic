import asyncio

import pytest

from sanic import text
from sanic.auth import (
    AuthenticationBudget,
    AuthenticationBudgetExceeded,
    authentication_middleware,
)
from sanic.exceptions import ServiceUnavailable


# ---------------------------------------------------------------------------
# Budget semantics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_over_capacity_times_out_with_budget_exception():
    budget = AuthenticationBudget(capacity=1, timeout=0.1)
    holder = await budget.acquire()
    assert budget.in_flight == 1 and budget.available == 0

    with pytest.raises(AuthenticationBudgetExceeded) as exc:
        await budget.acquire()

    assert exc.value.status_code == 503
    assert isinstance(exc.value, ServiceUnavailable)
    assert exc.value.headers["Retry-After"] == "1"
    assert budget.waiting == 0
    holder.release()


@pytest.mark.asyncio
async def test_queued_request_proceeds_when_slot_is_returned():
    budget = AuthenticationBudget(capacity=1, timeout=5)
    holder = await budget.acquire()

    queued = asyncio.ensure_future(budget.acquire())
    await asyncio.sleep(0.05)
    assert budget.waiting == 1 and budget.available == 0

    holder.release()
    guard = await queued
    assert budget.in_flight == 1 and budget.waiting == 0
    guard.release()
    assert budget.in_flight == 0 and budget.available == 1


@pytest.mark.asyncio
async def test_slot_is_returned_exactly_once():
    budget = AuthenticationBudget(capacity=2, timeout=1)
    first = await budget.acquire()
    second = await budget.acquire()
    assert budget.in_flight == 2 and budget.available == 0

    first.release()
    first.release()
    first.release()
    assert budget.in_flight == 1 and budget.available == 1

    third = await budget.acquire()
    assert budget.in_flight == 2
    third.release()
    second.release()
    assert budget.in_flight == 0 and budget.available == 2

    guard = await budget.acquire()
    assert budget.in_flight == 1
    guard.release()
    assert budget.available == 2


@pytest.mark.asyncio
async def test_client_disconnect_while_queued_keeps_pool_intact():
    budget = AuthenticationBudget(capacity=1, timeout=None)
    holder = await budget.acquire()

    queued = asyncio.ensure_future(budget.acquire())
    await asyncio.sleep(0.05)
    assert budget.waiting == 1

    queued.cancel()
    with pytest.raises(asyncio.CancelledError):
        await queued
    await asyncio.sleep(0.05)
    assert budget.waiting == 0 and budget.available == 0

    holder.release()
    assert budget.available == 1
    guard = await budget.acquire()
    assert budget.in_flight == 1
    guard.release()


@pytest.mark.asyncio
async def test_shutdown_rejects_waiters_and_new_and_drains_holders():
    budget = AuthenticationBudget(capacity=1, timeout=None)
    holder = await budget.acquire()

    queued = asyncio.ensure_future(budget.acquire())
    await asyncio.sleep(0.05)
    assert budget.waiting == 1

    shutdown = asyncio.ensure_future(budget.shutdown(timeout=5))
    await asyncio.sleep(0.05)

    with pytest.raises(AuthenticationBudgetExceeded) as exc:
        await queued
    assert exc.value.status_code == 503
    assert "Retry-After" not in exc.value.headers
    assert budget.is_closed

    with pytest.raises(AuthenticationBudgetExceeded):
        await budget.acquire()

    await asyncio.sleep(0.05)
    assert not shutdown.done()
    assert budget.in_flight == 1

    holder.release()
    await shutdown
    assert budget.in_flight == 0 and budget.available == 1


@pytest.mark.asyncio
async def test_invalid_capacity_rejected():
    with pytest.raises(ValueError):
        AuthenticationBudget(capacity=0)
    with pytest.raises(ValueError):
        AuthenticationBudget(capacity=-1)


# ---------------------------------------------------------------------------
# Middleware behaviour
# ---------------------------------------------------------------------------


class FakeRequest:
    def __init__(self):
        self.ctx = type("Ctx", (), {})()


@pytest.mark.asyncio
async def test_middleware_calls_authenticator_only_with_slot():
    budget = AuthenticationBudget(capacity=1, timeout=0.05)
    calls = []

    async def authenticator(request):
        calls.append("auth")

    middleware = authentication_middleware(budget, authenticator)

    request = FakeRequest()
    await middleware(request)
    assert calls == ["auth"]
    assert request.ctx.authenticated is True
    assert budget.in_flight == 0


@pytest.mark.asyncio
async def test_middleware_rejects_before_invoking_authenticator():
    budget = AuthenticationBudget(capacity=1, timeout=0.05)
    holder = await budget.acquire()
    calls = []

    async def authenticator(request):
        calls.append("auth")

    middleware = authentication_middleware(budget, authenticator)

    with pytest.raises(AuthenticationBudgetExceeded):
        await middleware(FakeRequest())

    # The rejected request never authenticates, even after the slot
    # frees up: rejection is terminal for that request.
    holder.release()
    await asyncio.sleep(0.1)
    assert calls == []
    assert budget.available == 1


@pytest.mark.asyncio
async def test_middleware_returns_slot_when_authenticator_fails():
    budget = AuthenticationBudget(capacity=1, timeout=1)
    calls = []

    async def broken(request):
        calls.append("auth")
        raise RuntimeError("provider down")

    middleware = authentication_middleware(budget, broken)

    with pytest.raises(RuntimeError):
        await middleware(FakeRequest())

    assert calls == ["auth"]
    assert budget.in_flight == 0 and budget.available == 1


# ---------------------------------------------------------------------------
# End-to-end through the Sanic request pipeline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_503_for_over_capacity_and_handler_not_called(app):
    budget = AuthenticationBudget(capacity=1, timeout=0.1)
    events = []

    async def slow_authenticator(request):
        events.append("auth-start")
        try:
            await asyncio.sleep(0.3)
        finally:
            events.append("auth-done")

    app.on_request(authentication_middleware(budget, slow_authenticator))

    @app.get("/")
    async def handler(request):
        events.append("handler")
        return text("ok")

    loop = asyncio.get_running_loop()
    in_flight = loop.create_task(app.asgi_client.get("/"))
    loop.call_later(0.01, in_flight)
    await asyncio.sleep(0.05)
    assert budget.in_flight == 1 and budget.available == 0

    _, rejected = await app.asgi_client.get("/")
    assert rejected.status_code == 503
    assert rejected.headers["Retry-After"] == "1"
    assert events == ["auth-start"]

    _, accepted = await in_flight
    assert accepted.status_code == 200
    assert events == ["auth-start", "auth-done", "handler"]
    assert budget.in_flight == 0 and budget.available == 1


@pytest.mark.asyncio
async def test_disconnect_during_auth_returns_slot_and_request_recovers(app):
    budget = AuthenticationBudget(capacity=1, timeout=None)
    auth_started = asyncio.Event()
    auth_cancelled = asyncio.Event()
    calls = []

    async def authenticator(request):
        calls.append("auth")
        auth_started.set()
        try:
            await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            auth_cancelled.set()
            raise

    app.on_request(authentication_middleware(budget, authenticator))

    @app.get("/")
    async def handler(request):
        calls.append("handler")
        return text("ok")

    loop = asyncio.get_running_loop()
    request_task = loop.create_task(app.asgi_client.get("/"))
    loop.call_later(0.01, request_task)
    await auth_started.wait()
    assert budget.in_flight == 1

    request_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request_task
    await auth_cancelled.wait()

    # The disconnect cancels the authenticator and the guard returns
    # the slot exactly once; the handler never runs.
    assert budget.in_flight == 0 and budget.available == 1
    assert calls == ["auth"]

    _, response = await app.asgi_client.get("/")
    assert response.status_code == 200
    assert calls == ["auth", "auth", "handler"]


@pytest.mark.asyncio
async def test_event_ordering_disconnect_reject_shutdown(app):
    budget = AuthenticationBudget(capacity=1, timeout=0.1)
    handler_calls = []
    authenticator_calls = []
    auth_started = asyncio.Event()
    finish_auth = asyncio.Event()

    async def authenticator(request):
        authenticator_calls.append("auth")
        auth_started.set()
        await finish_auth.wait()

    middleware = authentication_middleware(budget, authenticator)

    async def business(request):
        handler_calls.append("handler")

    # 1. First authenticated request takes the only slot and is held.
    first = asyncio.ensure_future(middleware(FakeRequest()))
    await auth_started.wait()
    assert budget.in_flight == 1 and budget.available == 0

    # 2. Second request gets a temporary rejection; it never invokes
    #    the authenticator and must not reach the business function.
    with pytest.raises(AuthenticationBudgetExceeded) as exc:
        await middleware(FakeRequest())
    assert exc.value.status_code == 503
    assert authenticator_calls == ["auth"]
    assert handler_calls == []

    # 3. Third request queues, then the client disconnects while waiting.
    queued = asyncio.ensure_future(middleware(FakeRequest()))
    await asyncio.sleep(0.02)
    assert budget.waiting == 1
    queued.cancel()
    with pytest.raises(asyncio.CancelledError):
        await queued
    assert authenticator_calls == ["auth"]
    assert budget.waiting == 0 and budget.in_flight == 1

    # 4. Shutdown starts while the first request is still authenticating.
    shutdown = asyncio.ensure_future(budget.shutdown(timeout=5))
    await asyncio.sleep(0.02)
    assert not shutdown.done()
    with pytest.raises(AuthenticationBudgetExceeded):
        await middleware(FakeRequest())

    # 5. Authentication completes: the slot returns once, shutdown
    #    drains, and the first request proceeds into business handling.
    finish_auth.set()
    await first
    await shutdown

    assert authenticator_calls == ["auth"]
    await business(FakeRequest())
    assert handler_calls == ["handler"]
    assert budget.in_flight == 0 and budget.waiting == 0
    assert budget.is_closed


@pytest.mark.asyncio
async def test_http_reject_then_accept_ordering(app):
    budget = AuthenticationBudget(capacity=1, timeout=0.1)
    auth_started = asyncio.Event()
    finish_auth = asyncio.Event()
    protocol_events = []

    async def authenticator(request):
        protocol_events.append("auth-start")
        auth_started.set()
        await finish_auth.wait()
        protocol_events.append("auth-finish")

    app.on_request(authentication_middleware(budget, authenticator))

    @app.get("/")
    async def handler(request):
        protocol_events.append("handler")
        return text("ok")

    loop = asyncio.get_running_loop()
    first = loop.create_task(app.asgi_client.get("/"))
    loop.call_later(0.01, first)
    await auth_started.wait()

    # A concurrent request is rejected at the protocol level and never
    # reaches the authenticator or the handler.
    _, rejected = await app.asgi_client.get("/")
    assert rejected.status_code == 503
    assert rejected.headers["Retry-After"] == "1"
    assert protocol_events == ["auth-start"]

    # Releasing the held request lets it finish normally through the
    # full pipeline; a later request reuses the returned slot.
    finish_auth.set()
    _, accepted = await first
    assert accepted.status_code == 200
    assert protocol_events == ["auth-start", "auth-finish", "handler"]

    _, follow_up = await app.asgi_client.get("/")
    assert follow_up.status_code == 200
    assert budget.in_flight == 0 and budget.available == 1
