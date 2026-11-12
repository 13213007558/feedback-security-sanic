import asyncio

from unittest.mock import Mock

import pytest

from sanic import Sanic
from sanic.exceptions import (
    WebsocketAuthorizationRequired,
    WebsocketAuthorizationRevoked,
)
from sanic.server.websockets.authorization import (
    WebsocketAuthorizationManager,
    WebsocketAuthorizationMixin,
    WebsocketAuthorizationState,
)
from sanic.server.websockets.connection import WebSocketConnection


class FakeWebsocket:
    supports_synchronous_close = True

    def __init__(self):
        self.closes = []
        self.messages = []

    def end_connection(self, code=1000, reason=""):
        self.closes.append((code, reason))


@pytest.fixture
def manager():
    app = Sanic("ws_authz_manager")
    try:
        yield app.websocket_authorizations
    finally:
        Sanic._app_registry.clear()


def test_app_exposes_authorization_controls():
    app = Sanic("ws_authz_app_api")
    try:
        first = app.authorize_websocket("ops")
        second = app.authorize_websocket("ops")
        revoked = app.revoke_websocket("ops")

        assert first.generation == 1
        assert second.generation == 2
        assert revoked.generation == 3
        assert app.websocket_authorizations.snapshot() == {
            "ops": {"generation": 3, "revoked": True}
        }
    finally:
        Sanic._app_registry.clear()


def test_generations_are_monotonic_and_revocation_wins(manager):
    first = manager.issue("ops")
    second = manager.issue("ops")
    revoked = manager.revoke("ops")

    assert first.generation == 1
    assert second.generation == 2
    assert revoked.generation == 3
    assert revoked.revoked is True

    assert manager.is_current(first) is False
    assert manager.is_current(second) is False
    assert manager.is_current(revoked) is False
    assert manager.snapshot() == {
        "ops": {"generation": 3, "revoked": True}
    }


def test_connections_keep_independent_processing_state(manager):
    first_ws = FakeWebsocket()
    second_ws = FakeWebsocket()
    first = WebsocketAuthorizationState(first_ws, manager=manager)
    second = WebsocketAuthorizationState(second_ws, manager=manager)
    manager.issue("acct")
    first.bind(account="acct")
    second.bind(account="acct")

    assert first.authorization.generation == 1
    assert second.authorization.generation == 1
    assert first.authorization is not second.authorization


@pytest.mark.asyncio
async def test_admitted_action_completes_after_revocation(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    manager.issue("acct")
    state.bind(account="acct")

    async with state.protected_action() as receipt:
        assert receipt.pending
        manager.revoke("acct")
        result = "completed"
    assert result == "completed"
    assert receipt.status == "completed"
    assert receipt.finished_at is not None
    assert state.in_flight_actions == 0
    assert state.closed is False
    assert ws.closes == []


@pytest.mark.asyncio
async def test_new_protected_action_is_refused_after_revocation(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    manager.issue("acct")
    state.bind(account="acct")

    manager.revoke("acct")
    with pytest.raises(WebsocketAuthorizationRevoked) as exc_info:
        await state.admit_action()

    assert exc_info.value.close_code == 1008
    assert exc_info.value.reason == "Authorization revoked"
    assert state.refused == 1
    assert state.closed is True
    assert state.snapshot()["close_code"] == 1008
    assert state.snapshot()["close_reason"] == "Authorization revoked"
    assert state.snapshot()["close_events"] == [
        (1008, "Authorization revoked")
    ]
    assert ws.closes == [(1008, "Authorization revoked")]


@pytest.mark.asyncio
async def test_revocation_and_processing_interleave_per_connection(manager):
    control = asyncio.Event()
    order = []

    first_ws = FakeWebsocket()
    second_ws = FakeWebsocket()
    first = WebsocketAuthorizationState(first_ws, manager=manager)
    second = WebsocketAuthorizationState(second_ws, manager=manager)
    manager.issue("acct")
    first.bind(account="acct")
    second.bind(account="acct")

    async def admitted_work():
        async with first.protected_action() as receipt:
            order.append(("admitted", receipt.authorization.generation))
            control.set()
            await asyncio.sleep(0.01)
            assert receipt.pending
        order.append(("finished", receipt.status))
        return receipt

    async def revoke_while_running():
        await control.wait()
        await asyncio.sleep(0.003)
        manager.revoke("acct")
        order.append(("revoked", manager.current("acct").generation))
        await asyncio.sleep(0.008)
        with pytest.raises(WebsocketAuthorizationRevoked):
            await second.admit_action()
        order.append(("refused", second.refused))

    async def control_message_during_revoke():
        await control.wait()
        # Reading and handling a normal message is still allowed after the
        # generation changes; it simply is not a protected action.
        order.append(("control", first.authorization.generation))

    await asyncio.gather(
        admitted_work(),
        revoke_while_running(),
        control_message_during_revoke(),
    )

    assert order[:2] == [("admitted", 1), ("control", 1)]
    assert ("finished", "completed") in order
    assert first_ws.closes == []
    assert second_ws.closes == [(1008, "Authorization revoked")]
    assert first.closed is False
    assert first.refused == 0


@pytest.mark.asyncio
async def test_revalidator_renewal_keeps_connection_open(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    manager.issue("acct")
    state.bind(account="acct")

    async def revalidate(current):
        authority = manager.current("acct")
        if authority is None or authority.revoked:
            return None
        return authority

    manager.set_revalidator(revalidate)
    manager.issue("acct")

    receipt = await state.admit_action()
    assert receipt.authorization.generation == 2
    assert ws.closes == []
    state.finish_action(receipt)
    assert receipt.completed


@pytest.mark.asyncio
async def test_revalidator_rejection_fails_closed(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    manager.issue("acct")
    state.bind(account="acct")

    async def reject(current):
        return False

    manager.set_revalidator(reject)
    with pytest.raises(WebsocketAuthorizationRevoked):
        await state.admit_action()
    assert ws.closes == [(1008, "Authorization revoked")]


@pytest.mark.asyncio
async def test_unbound_connection_needs_authorization(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    with pytest.raises(WebsocketAuthorizationRequired):
        await state.admit_action()
    assert ws.closes == [(1008, "Authorization revoked")]


class FakeWebsocketWithState(WebsocketAuthorizationMixin):
    """Minimal native websocket stand-in for the framework handler path."""

    supports_synchronous_close = True

    def __init__(self, manager):
        self.authorization_state = WebsocketAuthorizationState(
            self, manager=manager
        )
        self.closes = []
        self.closes_sent = 0

    def end_connection(self, code=1000, reason=""):
        self.closes.append((code, reason))

    async def close(self, code=1000, reason=""):
        self.closes_sent += 1


@pytest.mark.asyncio
async def test_handler_refusal_closes_connection_once():
    app = Sanic("ws_authz_handler")
    manager = app.websocket_authorizations
    manager.issue("acct")

    fake_ws = FakeWebsocketWithState(manager)
    fake_ws.authorization_state.bind(account="acct")

    async def handler(request, ws):
        async with ws.protected_action():
            raise AssertionError("must not run")

    async def handshake(*args, **kwargs):
        return fake_ws

    protocol = Mock()
    protocol.websocket_handshake = handshake
    request = Mock()
    request.app = app
    request.transport = Mock()
    request.transport.get_protocol.return_value = protocol

    manager.revoke("acct")
    app.signal_router.finalize()
    try:
        await app._websocket_handler(handler, request)
    finally:
        Sanic._app_registry.clear()

    assert fake_ws.closes == [(1008, "Authorization revoked")]
    assert fake_ws.closes_sent == 0
    assert app.websocket_tasks == set()


@pytest.mark.asyncio
async def test_asgi_connection_emits_single_close():
    sent = []
    received = asyncio.Queue()

    async def send(message):
        sent.append(message)

    async def receive():
        return await received.get()

    manager = WebsocketAuthorizationManager()
    ws = WebSocketConnection(send, receive)
    ws.authorization_state.attach_manager(manager)
    manager.issue("acct")
    ws.bind_authorization(account="acct")
    manager.revoke("acct")

    with pytest.raises(WebsocketAuthorizationRevoked):
        await ws.require_authorization()

    assert sent == [
        {
            "type": "websocket.close",
            "code": 1008,
            "reason": "Authorization revoked",
        }
    ]
    with pytest.raises(WebsocketAuthorizationRevoked):
        await ws.require_authorization()
    assert len(sent) == 1
    # The second attempt is refused but the connection only closes once.
    assert ws.authorization_state.close_events == [
        (1008, "Authorization revoked")
    ]


@pytest.mark.asyncio
async def test_revocation_during_confirmation_fails_closed(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    manager.issue("acct")
    state.bind(account="acct")

    started = asyncio.Event()
    release = asyncio.Event()

    async def revalidate(current):
        started.set()
        await release.wait()
        return True

    manager.set_revalidator(revalidate)
    check = asyncio.create_task(state.admit_action())
    await started.wait()
    manager.revoke("acct")
    release.set()
    with pytest.raises(WebsocketAuthorizationRevoked):
        await check
    assert ws.closes == [(1008, "Authorization revoked")]
    assert state.refused == 1


@pytest.mark.asyncio
async def test_pending_generation_change_during_confirmation(manager):
    """A renewal during an in-flight confirmation is seen by that check."""

    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    manager.issue("acct")
    state.bind(account="acct")

    started = asyncio.Event()
    release = asyncio.Event()

    async def revalidate(current):
        started.set()
        await release.wait()
        return True

    manager.set_revalidator(revalidate)
    check = asyncio.create_task(state.admit_action())
    await started.wait()
    manager.issue("acct")
    release.set()
    receipt = await check
    # ``True`` adopts the manager's current generation, so the admission is
    # evaluated against the renewal that happened while it was running.
    assert receipt.authorization.generation == 2
    state.finish_action(receipt)
    assert ws.closes == []


def test_connection_active_flag_tracks_manager(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    manager.issue("acct")
    state.bind(account="acct")

    assert state.is_active()
    manager.issue("acct")
    assert state.is_active() is False
    manager.revoke("acct")
    assert state.is_active() is False


@pytest.mark.asyncio
async def test_protected_message_reads_then_checks(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    manager.issue("acct")
    state.bind(account="acct")

    ws.messages = ["payload"]
    seen = []

    async def recv(timeout=None):
        return ws.messages.pop(0)

    ws.recv = recv
    state.attach_request(Mock(), ws)
    async with state.protected_message() as (message, receipt):
        seen.append((message, receipt.status))
        manager.revoke("acct")
        assert receipt.pending
    assert seen == [("payload", "admitted")]
    assert receipt.status == "completed"
    assert ws.closes == []

    # After revocation the same helper refuses a new message, and the payload
    # is never yielded to application code.
    ws.messages = ["blocked"]
    with pytest.raises(WebsocketAuthorizationRevoked):
        async with state.protected_message() as result:
            raise AssertionError(f"must not yield {result}")
    assert ws.messages == []
    assert ws.closes == [(1008, "Authorization revoked")]


@pytest.mark.asyncio
async def test_concurrent_admission_on_one_connection(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    manager.issue("acct")
    state.bind(account="acct")

    first_started = asyncio.Event()
    release_first = asyncio.Event()
    calls = 0

    async def slow_revalidate(current):
        nonlocal calls
        calls += 1
        if calls == 1:
            first_started.set()
            await release_first.wait()
        return True

    manager.set_revalidator(slow_revalidate)
    one = asyncio.create_task(state.admit_action())
    await first_started.wait()
    two = asyncio.create_task(state.admit_action())
    await asyncio.sleep(0)
    # The second check is serialized behind the first, so both complete
    # against the generation that the application issues while they run.
    manager.issue("acct")
    release_first.set()

    one_receipt = await one
    two_receipt = await two
    assert one_receipt.authorization.generation == 2
    assert two_receipt.authorization.generation == 2
    assert state.admitted == 2
    assert ws.closes == []


@pytest.mark.asyncio
async def test_hook_exception_fails_closed(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    manager.issue("acct")
    state.bind(account="acct")

    async def broken(current):
        raise RuntimeError("identity service down")

    manager.set_revalidator(broken)
    with pytest.raises(WebsocketAuthorizationRevoked):
        await state.admit_action()
    assert ws.closes == [(1008, "Authorization revoked")]


@pytest.mark.asyncio
async def test_confirmed_action_generation_is_stable(manager):
    ws = FakeWebsocket()
    state = WebsocketAuthorizationState(ws, manager=manager)
    snapshot = manager.issue("acct")
    state.bind(authorization=snapshot)
    manager.issue("acct")

    with pytest.raises(WebsocketAuthorizationRevoked):
        await state.admit_action()
    assert ws.closes == [(1008, "Authorization revoked")]
