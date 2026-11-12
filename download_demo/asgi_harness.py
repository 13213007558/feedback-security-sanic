from __future__ import annotations

import asyncio
from dataclasses import dataclass, field


class ClientDisconnected(Exception):
    """Raised by the harness ASGI ``send`` to mimic a closed connection."""


@dataclass
class ASGIResponse:
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    chunks: list[bytes] = field(default_factory=list)
    error: Exception | None = None
    send_calls: int = 0
    stream_started: bool = False

    @property
    def body(self) -> bytes:
        return b"".join(self.chunks)

    @property
    def byte_count(self) -> int:
        return sum(len(chunk) for chunk in self.chunks)

    @property
    def stream_byte_count(self) -> int:
        """Body bytes delivered after the 200/206 stream started."""
        if not self.stream_started or self.status not in (200, 206):
            return 0
        return self.byte_count


class ASGIClient:
    """Drives a Sanic ASGI app in-process without binding a socket."""

    def __init__(self, app) -> None:
        self._app = app

    async def startup(self) -> None:
        queue: asyncio.Queue = asyncio.Queue()
        await queue.put({"type": "lifespan.startup"})

        async def receive():
            return await queue.get()

        async def send(message):
            assert message["type"] in (
                "lifespan.startup.complete",
                "lifespan.shutdown.complete",
            ), message

        self._lifespan_queue = queue
        self._lifespan_task = asyncio.create_task(
            self._app(
                {"type": "lifespan", "asgi": {"version": "3.0"}},
                receive,
                send,
            )
        )
        await asyncio.sleep(0)

    async def shutdown(self) -> None:
        await self._lifespan_queue.put({"type": "lifespan.shutdown"})
        await self._lifespan_task

    async def request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        json_body: dict | None = None,
        disconnect_after: int | None = None,
    ) -> ASGIResponse:
        scope_headers = [
            (key.lower().encode(), value.encode())
            for key, value in (headers or {}).items()
        ]
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": scope_headers,
            "client": ("10.0.0.1", 54321),
            "server": ("testserver", 80),
        }
        response = ASGIResponse()
        request_body = b""
        if json_body is not None:
            import json

            request_body = json.dumps(json_body).encode()
            scope["headers"].append(
                (b"content-type", b"application/json")
            )

        async def receive():
            nonlocal request_body
            if request_body:
                chunk = request_body
                request_body = b""
                return {"type": "http.request", "body": chunk, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        delivered = 0
        disconnect_sent = False

        async def send(message):
            nonlocal delivered, disconnect_sent
            response.send_calls += 1
            if message["type"] == "http.response.start":
                response.status = message["status"]
                response.stream_started = message["status"] in (200, 206)
                response.headers = {
                    key.decode().lower(): value.decode()
                    for key, value in message["headers"]
                }
                return
            if message["type"] != "http.response.body":
                return
            block = message.get("body", b"")
            response.chunks.append(block)
            delivered += len(block)
            if (
                disconnect_after is not None
                and not disconnect_sent
                and delivered >= disconnect_after
                and message.get("more_body")
            ):
                disconnect_sent = True
                raise ClientDisconnected("simulated mid-transfer disconnect")
            if disconnect_sent and block:
                # The peer is gone: every further body write fails, while
                # empty EOF frames are swallowed so server cleanup completes.
                raise ClientDisconnected("write after client disconnect")

        try:
            await self._app(scope, receive, send)
        except Exception as exc:  # noqa: BLE001 - harness records all failures
            response.error = exc
        return response
