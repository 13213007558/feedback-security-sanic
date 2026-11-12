from collections.abc import Awaitable, MutableMapping
from typing import Any, Callable

from sanic.exceptions import InvalidUsage
from sanic.server.websockets.authorization import (
    WebsocketAuthorizationMixin,
    WebsocketAuthorizationState,
)


ASGIMessage = MutableMapping[str, Any]


class WebSocketConnection(WebsocketAuthorizationMixin):
    """
    This is for ASGI Connections.
    It provides an interface similar to WebsocketProtocol, but
    sends/receives over an ASGI connection.
    """

    supports_synchronous_close = False

    # TODO
    # - Implement ping/pong

    def __init__(
        self,
        send: Callable[[ASGIMessage], Awaitable[None]],
        receive: Callable[[], Awaitable[ASGIMessage]],
        subprotocols: list[str] | None = None,
    ) -> None:
        self._send = send
        self._receive = receive
        self._subprotocols = subprotocols or []
        self._close_sent = False
        self._close_code: int | None = None
        self.authorization_state = WebsocketAuthorizationState(self)

    async def send(self, data: str | bytes, *args, **kwargs) -> None:
        message: dict[str, str | bytes] = {"type": "websocket.send"}

        if isinstance(data, bytes):
            message.update({"bytes": data})
        else:
            message.update({"text": str(data)})

        await self._send(message)

    async def recv(self, *args, **kwargs) -> str | bytes | None:
        message = await self._receive()

        if message["type"] == "websocket.receive":
            try:
                return message["text"]
            except KeyError:
                try:
                    return message["bytes"]
                except KeyError:
                    raise InvalidUsage("Bad ASGI message received")
        elif message["type"] == "websocket.disconnect":
            pass

        return None

    receive = recv

    async def accept(self, subprotocols: list[str] | None = None) -> None:
        subprotocol = None
        if subprotocols:
            for subp in subprotocols:
                if subp in self.subprotocols:
                    subprotocol = subp
                    break

        await self._send(
            {
                "type": "websocket.accept",
                "subprotocol": subprotocol,
            }
        )

    async def send_close(self, code: int = 1000, reason: str = "") -> None:
        """Send one websocket close message through the ASGI channel."""

        if self._close_sent:
            return
        self._close_sent = True
        self._close_code = code
        await self._send(
            {"type": "websocket.close", "code": code, "reason": reason}
        )

    async def close(self, code: int = 1000, reason: str = "") -> None:
        # The ASGI server performs the actual close when the handler exits;
        # this method remains a no-op to preserve the pre-existing contract.
        pass

    def end_connection(self, code: int = 1000, reason: str = "") -> None:
        # Compatibility shim: ASGI servers do not close synchronously, so the
        # decision is recorded and emitted by ``send_close``.
        self.authorization_state.closed = True
        self.authorization_state.close_code = code
        self.authorization_state.close_reason = reason

    @property
    def subprotocols(self):
        return self._subprotocols

    @subprotocols.setter
    def subprotocols(self, subprotocols: list[str] | None = None):
        self._subprotocols = subprotocols or []
