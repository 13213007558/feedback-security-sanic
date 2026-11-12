from __future__ import annotations

import asyncio
import time

from .models import (
    FileVersion,
    Ticket,
    TicketState,
    ClientConflict,
    IdentityMismatch,
    TicketNotFound,
    TicketTerminal,
)


class TicketStore:
    """Process-local ticket storage guarded by a single asyncio lock.

    The lock is held only across short state transitions, never across the
    whole file transfer. Streaming ownership is tracked separately so one
    client cannot stream the same ticket while another identity (or the same
    identity from a second client) holds it.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._tickets: dict[str, Ticket] = {}
        self._lock = asyncio.Lock()
        self._ttl_seconds = ttl_seconds
        self._streaming: dict[str, int] = {}

    async def issue(self, user: str, snapshot: FileVersion) -> Ticket:
        now = time.time()
        ticket = Ticket.create(user, snapshot, self._ttl_seconds, now)
        async with self._lock:
            self._tickets[ticket.ticket_id] = ticket
        return ticket

    async def get(self, ticket_id: str) -> Ticket:
        async with self._lock:
            return self._require(ticket_id)

    def _require(self, ticket_id: str) -> Ticket:
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise TicketNotFound(f"unknown ticket: {ticket_id}")
        return ticket

    async def claim(
        self, ticket_id: str, user: str, client_id: str
    ) -> tuple[Ticket, bool]:
        """Bind a ticket to (user, client_id).

        Returns the ticket and ``True`` when this call just created the
        binding, ``False`` when the same client re-claimed an existing
        binding (resume path).
        """
        now = time.time()
        async with self._lock:
            ticket = self._require(ticket_id)
            self._expire_if_needed(ticket, now)
            if ticket.user != user:
                raise IdentityMismatch("ticket belongs to another user")
            if ticket.state in (TicketState.CONSUMED, TicketState.EXPIRED):
                raise TicketTerminal(f"ticket is {ticket.state.value}")
            if ticket.client_id is None:
                ticket.client_id = client_id
                ticket.state = TicketState.CLAIMED
                ticket.history.append(
                    {"at": now, "event": "claimed", "client_id": client_id}
                )
                return ticket, True
            if ticket.client_id != client_id:
                raise ClientConflict(
                    "ticket is already bound to a different client"
                )
            return ticket, False

    async def begin_stream(
        self, ticket_id: str, user: str, client_id: str
    ) -> tuple[Ticket, int]:
        """Authorize one transfer and return a generation token.

        A second, concurrent transfer from any other identity is refused.
        The generation lets a later completion event ignore a stream that
        has already been superseded by a resumed one.
        """
        now = time.time()
        async with self._lock:
            ticket = self._require(ticket_id)
            self._expire_if_needed(ticket, now)
            if ticket.user != user:
                raise IdentityMismatch("ticket belongs to another user")
            if ticket.state in (TicketState.CONSUMED, TicketState.EXPIRED):
                raise TicketTerminal(f"ticket is {ticket.state.value}")
            if ticket.client_id != client_id:
                raise ClientConflict(
                    "ticket is bound to another client identity"
                )
            current = self._streaming.get(ticket_id)
            if current is not None:
                raise ClientConflict(
                    "a transfer for this ticket is already in progress"
                )
            ticket.stream_generation += 1
            generation = ticket.stream_generation
            self._streaming[ticket_id] = generation
            ticket.state = TicketState.STREAMING
            ticket.history.append(
                {
                    "at": now,
                    "event": "stream_started",
                    "generation": generation,
                }
            )
            return ticket, generation

    async def record_bytes(
        self, ticket_id: str, generation: int, start: int, length: int
    ) -> None:
        async with self._lock:
            ticket = self._require(ticket_id)
            if self._streaming.get(ticket_id) != generation:
                return
            ticket.delivered.update(range(start, start + length))

    async def interrupt(
        self, ticket_id: str, generation: int, reason: str
    ) -> None:
        now = time.time()
        async with self._lock:
            ticket = self._require(ticket_id)
            if self._streaming.get(ticket_id) != generation:
                return
            self._streaming.pop(ticket_id, None)
            self._expire_if_needed(ticket, now)
            if ticket.state not in (TicketState.CONSUMED, TicketState.EXPIRED):
                ticket.state = TicketState.INTERRUPTED
                ticket.last_error = reason
                ticket.history.append(
                    {
                        "at": now,
                        "event": "interrupted",
                        "generation": generation,
                        "reason": reason,
                        "delivered_bytes": ticket.delivered_byte_count(),
                    }
                )

    async def complete(
        self, ticket_id: str, generation: int
    ) -> Ticket | None:
        now = time.time()
        async with self._lock:
            ticket = self._require(ticket_id)
            if self._streaming.get(ticket_id) != generation:
                return None
            self._streaming.pop(ticket_id, None)
            self._expire_if_needed(ticket, now)
            if ticket.state is TicketState.EXPIRED:
                return ticket
            if ticket.is_fully_delivered():
                ticket.state = TicketState.CONSUMED
                ticket.history.append(
                    {
                        "at": now,
                        "event": "consumed",
                        "generation": generation,
                        "delivered_bytes": ticket.delivered_byte_count(),
                    }
                )
            else:
                ticket.state = TicketState.INTERRUPTED
                ticket.last_error = "stream ended before all bytes were sent"
                ticket.history.append(
                    {
                        "at": now,
                        "event": "incomplete_finish",
                        "generation": generation,
                        "delivered_bytes": ticket.delivered_byte_count(),
                    }
                )
            return ticket

    def _expire_if_needed(self, ticket: Ticket, now: float) -> None:
        if (
            ticket.state not in (TicketState.CONSUMED, TicketState.EXPIRED)
            and ticket.is_expired(now)
        ):
            ticket.state = TicketState.EXPIRED
            ticket.history.append({"at": now, "event": "expired"})
            self._streaming.pop(ticket.ticket_id, None)
