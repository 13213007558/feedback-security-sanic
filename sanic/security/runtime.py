from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any

from .policy import (
    SecurityPolicyError,
    SecurityPolicySnapshot,
    SecurityPolicyValidationError,
)


CONNECTION_GENERATION = "sanic_security_generation"
REQUEST_POLICY = "sanic_security_policy"


class PolicyNotActive(SecurityPolicyError):
    """The worker is not confirmed and cannot accept requests."""


class PolicyAuthorizationFailed(SecurityPolicyError):
    """A request cannot be admitted under the applicable snapshot."""


class StalePolicyTransaction(SecurityPolicyError):
    """A commit or rollback does not match the staged candidate."""


@dataclass(frozen=True, slots=True)
class PolicyAck:
    """A worker's response to a staged policy generation."""

    worker: str
    attempt: int
    generation: int
    fingerprint: str


def _read_ctx(conn_info: Any, name: str) -> Any:
    ctx = getattr(conn_info, "ctx", None) if conn_info is not None else None
    if ctx is None:
        return None
    return getattr(ctx, name, None)


def _write_ctx(conn_info: Any, name: str, value: Any) -> None:
    ctx = getattr(conn_info, "ctx", None) if conn_info is not None else None
    if ctx is not None:
        setattr(ctx, name, value)


class SecurityPolicyRuntime:
    """Generation-aware policy state inside one worker.

    Requests only ever observe ``active``. A candidate lives in ``pending``
    until a commit matching both the attempt and the snapshot fingerprint
    arrives, so a staged candidate can never be used for request handling.
    """

    def __init__(
        self,
        initial: SecurityPolicySnapshot,
        *,
        enabled: bool = False,
        name: str = "",
    ):
        self.name = name
        self._lock = RLock()
        self._active = initial
        self._previous: SecurityPolicySnapshot | None = None
        self._retired: dict[int, SecurityPolicySnapshot] = {
            initial.generation: initial
        }
        self._pending: tuple[int, SecurityPolicySnapshot] | None = None
        self._aborted: set[int] = set()
        self._enabled = enabled

    @property
    def active(self) -> SecurityPolicySnapshot:
        with self._lock:
            return self._active

    @property
    def generation(self) -> int:
        return self.active.generation

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    def enable(self) -> None:
        with self._lock:
            self._enabled = True

    def disable(self) -> None:
        with self._lock:
            self._enabled = False

    def stage(
        self, attempt: int, snapshot: SecurityPolicySnapshot
    ) -> PolicyAck:
        if not isinstance(snapshot, SecurityPolicySnapshot):
            raise SecurityPolicyValidationError(
                "Invalid security policy field snapshot: wrong type"
            )
        SecurityPolicySnapshot.build(snapshot.generation, snapshot.fields)
        with self._lock:
            if attempt in self._aborted:
                raise StalePolicyTransaction("Attempt was already rolled back")
            if snapshot.generation <= self._active.generation:
                raise StalePolicyTransaction(
                    "Candidate generation is not newer than active"
                )
            self._pending = (attempt, snapshot)
        return PolicyAck(
            worker=self.name,
            attempt=attempt,
            generation=snapshot.generation,
            fingerprint=snapshot.fingerprint,
        )

    def commit(self, attempt: int, generation: int, fingerprint: str) -> None:
        with self._lock:
            if self._pending is None:
                raise StalePolicyTransaction("No candidate is staged")
            staged_attempt, snapshot = self._pending
            if (
                staged_attempt != attempt
                or snapshot.generation != generation
                or snapshot.fingerprint != fingerprint
            ):
                raise StalePolicyTransaction(
                    "Commit does not match the staged candidate"
                )
            self._remember(self._active)
            self._previous = self._active
            self._active = snapshot
            self._pending = None
            self._enabled = True

    def revert_commit(self, generation: int, fingerprint: str) -> None:
        with self._lock:
            if (
                self._active.generation != generation
                or self._active.fingerprint != fingerprint
                or self._previous is None
            ):
                raise StalePolicyTransaction(
                    "Cannot revert a commit that is not active"
                )
            self._retired.pop(generation, None)
            self._active = self._previous
            self._previous = None

    def rollback(self, attempt: int, generation: int) -> None:
        with self._lock:
            self._aborted.add(attempt)
            if self._pending is None:
                return
            staged_attempt, snapshot = self._pending
            if staged_attempt != attempt or snapshot.generation != generation:
                return
            self._pending = None

    def _remember(self, snapshot: SecurityPolicySnapshot) -> None:
        """Retain the current and immediately previous generations only."""
        self._retired[snapshot.generation] = snapshot
        keep = {self._active.generation, snapshot.generation}
        for generation in set(self._retired) - keep:
            del self._retired[generation]

    def exit(self) -> None:
        with self._lock:
            self._enabled = False
            self._pending = None

    def select_for_connection(
        self, conn_info: Any, authorization: str | None
    ) -> SecurityPolicySnapshot:
        """Pick one complete snapshot for a request on this connection."""
        with self._lock:
            if not self._enabled:
                raise PolicyNotActive("Security policy is not active")
            active = self._active
            connection_generation = _read_ctx(conn_info, CONNECTION_GENERATION)
            if connection_generation is None:
                connection_generation = active.generation

            if connection_generation == active.generation:
                snapshot = active
            elif active.old_connection_policy == "pin":
                try:
                    snapshot = self._retired[connection_generation]
                except KeyError:
                    raise PolicyNotActive(
                        "Security policy generation is no longer available"
                    ) from None
            else:
                snapshot = active

            if not snapshot.authorize(authorization):
                raise PolicyAuthorizationFailed(
                    "Request rejected by the security policy"
                )
            return snapshot

    def pin_request(self, request: Any) -> SecurityPolicySnapshot:
        """Pin or reuse the snapshot for exactly this request."""
        try:
            pinned = getattr(request.ctx, REQUEST_POLICY, None)
        except AttributeError:
            pinned = None
        if pinned is not None:
            return pinned

        snapshot = self.select_for_connection(
            request.conn_info,
            request.headers.getone("authorization", None),
        )
        setattr(request.ctx, REQUEST_POLICY, snapshot)
        # Under ``pin`` this is the same generation. Under ``revalidate`` it
        # advances the connection so the next request starts from the new
        # generation rather than re-admitting on every request.
        _write_ctx(
            request.conn_info, CONNECTION_GENERATION, snapshot.generation
        )
        for cached in ("parsed_forwarded", "_remote_addr", "_scheme"):
            try:
                delattr(request, cached)
            except AttributeError:
                ...
        return snapshot


def policy_from_request(request: Any) -> SecurityPolicySnapshot | None:
    try:
        return getattr(request.ctx, REQUEST_POLICY, None)
    except AttributeError:
        return None
