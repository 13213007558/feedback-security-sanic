from __future__ import annotations

import base64

from sanic import Sanic
from sanic.exceptions import SanicException
from sanic.request import Request
from sanic.response import json

from .file_store import FileStore
from .models import DownloadError
from .service import ClientGone, DownloadService
from .ticket_store import TicketStore

DEFAULT_TTL_SECONDS = 300


class ResponseSink:
    """Adapts a Sanic streamed response to the service's sink interface."""

    def __init__(self, request: Request) -> None:
        self._request = request
        self._response = None

    async def begin(self, status: int, headers: dict[str, str]) -> None:
        self._response = await self._request.respond(
            status=status, headers=headers
        )

    async def push(self, block: bytes) -> None:
        try:
            await self._response.send(block)
        except ClientGone:
            raise
        except Exception as exc:
            raise ClientGone(str(exc) or exc.__class__.__name__) from exc

    async def end(self) -> None:
        try:
            await self._response.eof()
        except ClientGone:
            raise
        except Exception as exc:
            raise ClientGone(str(exc) or exc.__class__.__name__) from exc


def _user(request: Request) -> str:
    user = request.headers.get("x-user")
    if not user:
        raise SanicException(
            "missing X-User header",
            status_code=401,
            quiet=True,
        )
    return user


def _identity(request: Request) -> tuple[str, str]:
    user = _user(request)
    client_id = request.headers.get("x-client-id")
    if not client_id:
        raise SanicException(
            "missing X-Client-Id header",
            status_code=401,
            quiet=True,
        )
    return user, client_id


def create_app(
    file_store: FileStore | None = None,
    ticket_store: TicketStore | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    chunk_size: int | None = None,
    app_name: str = "download-demo",
) -> Sanic:
    app = Sanic(app_name)
    app.config.FALLBACK_ERROR_FORMAT = "json"
    app.config.TOUCHUP = False
    app.config.MOTD = False
    files = file_store or FileStore()
    tickets = ticket_store or TicketStore(ttl_seconds=ttl_seconds)
    service = DownloadService(files, tickets, chunk_size=chunk_size)
    app.ctx.files = files
    app.ctx.tickets = tickets
    app.ctx.service = service

    @app.exception(DownloadError)
    async def _download_error(_: Request, exception: DownloadError):
        return json(
            {
                "error": exception.error_code,
                "message": str(exception),
            },
            status=exception.status_code,
        )

    @app.post("/files/<file_id>/tickets")
    async def create_ticket(request: Request, file_id: str):
        user = _user(request)
        ticket = await service.issue_ticket(user, file_id)
        return json(ticket.public(), status=201)

    @app.get("/tickets/<ticket_id>")
    async def get_ticket(request: Request, ticket_id: str):
        user = _user(request)
        return json(await service.ticket_status(ticket_id, user))

    @app.get("/tickets/<ticket_id>/download")
    async def download(request: Request, ticket_id: str):
        user, client_id = _identity(request)
        sink = ResponseSink(request)
        result = await service.download(
            ticket_id,
            user,
            client_id,
            request.headers.get("range"),
            sink,
        )
        if result["outcome"] == "completed":
            await sink.end()
        app.ctx.last_transfer = result

    @app.post("/admin/files/<file_id>/publish")
    async def publish(request: Request, file_id: str):
        body = request.load_json()
        if "content_base64" in body:
            content = base64.b64decode(body["content_base64"])
        else:
            raw = body["content"]
            content = raw.encode() if isinstance(raw, str) else bytes(raw)
        snapshot = files.publish(file_id, content)
        return json(
            {
                "file_id": snapshot.file_id,
                "version": snapshot.version,
                "size": snapshot.size,
                "sha256": snapshot.sha256,
            },
            status=201,
        )

    return app
