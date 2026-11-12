from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field


class TicketState(str, enum.Enum):
    ISSUED = "issued"
    CLAIMED = "claimed"
    STREAMING = "streaming"
    INTERRUPTED = "interrupted"
    CONSUMED = "consumed"
    EXPIRED = "expired"


TERMINAL_STATES = frozenset({TicketState.CONSUMED, TicketState.EXPIRED})


class DownloadError(Exception):
    """Base error carrying the HTTP status the API must return."""

    status_code = 400
    error_code = "bad_request"
    quiet = True

    def __init__(self, message: str, *, error_code: str | None = None):
        super().__init__(message)
        if error_code:
            self.error_code = error_code


class TicketNotFound(DownloadError):
    status_code = 404
    error_code = "ticket_not_found"


class IdentityMismatch(DownloadError):
    status_code = 403
    error_code = "identity_mismatch"


class ClientConflict(DownloadError):
    status_code = 409
    error_code = "client_conflict"


class TicketTerminal(DownloadError):
    status_code = 410
    error_code = "ticket_terminal"


class VersionMismatch(DownloadError):
    status_code = 410
    error_code = "version_mismatch"


class RangeNotSatisfiable(DownloadError):
    status_code = 416
    error_code = "range_not_satisfiable"


@dataclass(frozen=True)
class FileVersion:
    file_id: str
    version: int
    path: str
    size: int
    sha256: str


@dataclass
class Ticket:
    ticket_id: str
    user: str
    file_id: str
    version: int
    size: int
    sha256: str
    client_id: str | None = None
    state: TicketState = TicketState.ISSUED
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    stream_generation: int = 0
    delivered: set[int] = field(default_factory=set)
    history: list[dict] = field(default_factory=list)
    last_error: str | None = None

    @classmethod
    def create(
        cls,
        user: str,
        snapshot: FileVersion,
        ttl_seconds: int,
        now: float,
    ) -> "Ticket":
        return cls(
            ticket_id=uuid.uuid4().hex,
            user=user,
            file_id=snapshot.file_id,
            version=snapshot.version,
            size=snapshot.size,
            sha256=snapshot.sha256,
            created_at=now,
            expires_at=now + ttl_seconds,
            history=[{"at": now, "event": "issued"}],
        )

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at

    def delivered_byte_count(self) -> int:
        return len(self.delivered)

    def is_fully_delivered(self) -> bool:
        return len(self.delivered) == self.size and self.size >= 0

    def public(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "user": self.user,
            "file_id": self.file_id,
            "version": self.version,
            "size": self.size,
            "client_id": self.client_id,
            "state": self.state.value,
            "expires_at": self.expires_at,
            "delivered_bytes": self.delivered_byte_count(),
            "fully_delivered": self.is_fully_delivered(),
            "history": self.history,
            "last_error": self.last_error,
        }
