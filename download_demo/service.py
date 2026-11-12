from __future__ import annotations

import asyncio

from .file_store import FileStore
from .models import DownloadError, IdentityMismatch, Ticket
from .range_utils import parse_range
from .ticket_store import TicketStore

CHUNK_SIZE = 64 * 1024


class ClientGone(Exception):
    """Raised by the response sink when the peer stops accepting bytes."""


class DownloadService:
    def __init__(
        self,
        files: FileStore,
        tickets: TicketStore,
        chunk_size: int = CHUNK_SIZE,
    ) -> None:
        self.files = files
        self.tickets = tickets
        self.chunk_size = chunk_size
        # Test hook: an event awaited while a transfer holds the streaming
        # slot, letting tests force two transfers to overlap. None in prod.
        self.stream_gate: asyncio.Event | None = None

    async def issue_ticket(self, user: str, file_id: str) -> Ticket:
        snapshot = self.files.latest(file_id)
        return await self.tickets.issue(user, snapshot)

    async def ticket_status(self, ticket_id: str, user: str) -> dict:
        ticket = await self.tickets.get(ticket_id)
        if ticket.user != user:
            raise IdentityMismatch("ticket belongs to another user")
        return ticket.public()

    async def download(
        self,
        ticket_id: str,
        user: str,
        client_id: str,
        range_header: str | None,
        sink,
    ) -> dict:
        """Run one authorized (possibly resumed) transfer.

        ``sink`` is an async callable taking the status, headers and each
        byte chunk; raising ``ClientGone`` means the client disconnected.
        Returns a summary of what happened for the API layer.
        """
        claimed_ticket, fresh = await self.tickets.claim(
            ticket_id, user, client_id
        )

        # Validate the snapshot and the requested interval against the
        # ticket before any streaming slot is taken, so a rejected resume
        # cannot leave the ticket locked in the STREAMING state.
        snapshot = self.files.get(
            claimed_ticket.file_id, claimed_ticket.version
        )
        self.files.verify_snapshot(snapshot)
        start, end = parse_range(range_header, snapshot.size)
        if end >= snapshot.size or start < 0:
            raise DownloadError("range escaped the ticket snapshot")

        ticket, generation = await self.tickets.begin_stream(
            ticket_id, user, client_id
        )

        status = 200 if range_header is None else 206
        headers = {
            "Content-Type": "application/octet-stream",
            "Accept-Ranges": "bytes",
            "Content-Length": str(end - start + 1),
            "Content-Disposition": (
                f'attachment; filename="{ticket.file_id}-v{ticket.version}.bin"'
            ),
            "ETag": f'"{ticket.sha256}"',
            "X-Ticket-Id": ticket.ticket_id,
            "X-Ticket-Version": str(ticket.version),
            "X-Ticket-State": ticket.state.value,
        }
        if status == 206:
            headers["Content-Range"] = (
                f"bytes {start}-{end}/{snapshot.size}"
            )

        await sink.begin(status, headers)
        sent = 0
        interrupted_reason: str | None = None
        try:
            offset = start
            while offset <= end:
                block_end = min(offset + self.chunk_size - 1, end)
                block = self.files.read_range(snapshot, offset, block_end)
                # Account before the socket write: these bytes are now
                # committed to the wire, and accounting must survive a
                # disconnect raised by the following push.
                await self.tickets.record_bytes(
                    ticket_id, generation, offset, len(block)
                )
                await sink.push(block)
                sent += len(block)
                offset = block_end + 1
                if self.stream_gate is not None:
                    await self.stream_gate.wait()
        except ClientGone as exc:
            interrupted_reason = str(exc) or "client disconnected"
        except (
            ConnectionError,
            BrokenPipeError,
            asyncio.CancelledError,
        ) as exc:
            interrupted_reason = f"client disconnected: {type(exc).__name__}"

        if interrupted_reason is not None:
            await self.tickets.interrupt(
                ticket_id, generation, interrupted_reason
            )
            return {
                "outcome": "interrupted",
                "status": status,
                "bytes_sent": sent,
                "range": (start, end),
                "fresh_claim": fresh,
            }

        finished = await self.tickets.complete(ticket_id, generation)
        final_state = finished.state.value if finished else "superseded"
        return {
            "outcome": "completed",
            "status": status,
            "bytes_sent": sent,
            "range": (start, end),
            "fresh_claim": fresh,
            "final_state": final_state,
        }
