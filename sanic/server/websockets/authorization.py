"""Authorization generations for long-lived websocket connections.

A websocket connection keeps the identity and permissions confirmed during
the opening handshake.  For administrative connections that stay open for
hours, that snapshot must not be treated as permanent.  This module provides
the application-facing pieces needed to re-confirm an authorization and to
refuse protected actions once a generation has been revoked.

Three concepts are deliberately separate:

``WebsocketAuthorization``
    An immutable snapshot of an account and its generation.  It is safe to
    copy between tasks and connections.

``WebsocketAuthorizationManager``
    Application-wide authority.  The application issues a new generation
    when permissions change and revokes one when access must stop.  It stores
    only per-account generations, never per-connection processing state.

``WebsocketAuthorizationState``
    Per-connection state.  Every connection owns one of these objects, even
    when several connections belong to the same account.  Admission counters,
    in-flight actions and completion receipts never cross that boundary.

The linearization point is the moment an application calls
:meth:`WebsocketAuthorizationState.admit_action` immediately before executing
a protected action.  An action admitted before revocation may finish (and
reports its outcome through a :class:`WebsocketActionReceipt`); an action
admitted afterwards is refused.  The framework does not cancel or roll back an
action that has already started.  The check is serialized per connection by a
lock, so two tasks on one connection cannot both observe a stale generation
and then admit themselves.

Messages themselves are not intercepted: authorization is attached to the
action the application decides to run, so an ordinary control message can
still be read after revocation and used to re-confirm the connection.
"""

from __future__ import annotations

import asyncio
import time

from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from inspect import isawaitable
from typing import Any

from sanic.exceptions import (
    WebsocketAuthorizationError,
    WebsocketAuthorizationRequired,
    WebsocketAuthorizationRevoked,
)


DEFAULT_CLOSE_CODE = 1008
DEFAULT_CLOSE_REASON = "Authorization revoked"



Authorizer = Callable[["WebsocketAuthorizationState"], Any]
"""Application callback invoked to re-confirm a connection's authorization.

It receives the per-connection state (which exposes ``request``,
``websocket``, ``authorization`` and ``account``).  It may return a
:class:`WebsocketAuthorization`, an ``int`` generation, ``True`` to accept the
manager's current generation, or ``False``/``None`` to refuse.  Exceptions
fail closed.
"""


@dataclass(frozen=True)
class WebsocketAuthorization:
    """An immutable authorization snapshot for one account generation."""

    account: str
    generation: int
    claims: Mapping[str, Any] = field(default_factory=dict)
    revoked: bool = False

    def is_active(self) -> bool:
        return not self.revoked


@dataclass
class WebsocketActionReceipt:
    """Tracking record for one protected action.

    ``status`` starts as ``"admitted"`` and becomes ``"completed"`` or
    ``"failed"``.  Revocation never changes the status of an admitted action;
    it only prevents new admissions.
    """

    authorization: WebsocketAuthorization
    status: str = "admitted"
    error: BaseException | None = None
    admitted_at: float = field(default_factory=time.monotonic)
    finished_at: float | None = None

    @property
    def completed(self) -> bool:
        return self.status == "completed"

    @property
    def pending(self) -> bool:
        return self.status == "admitted"

    def summary(self) -> dict[str, Any]:
        return {
            "account": self.authorization.account,
            "generation": self.authorization.generation,
            "status": self.status,
            "admitted_at": self.admitted_at,
            "finished_at": self.finished_at,
        }


class WebsocketAuthorizationManager:
    """Per-application authorization generation authority.

    Generations increase monotonically per account.  ``renew`` issues a new
    generation; ``revoke`` does the same and marks the account revoked.  A
    connection bound to an older generation is refused on its next protected
    action, while actions already admitted may finish.
    """

    def __init__(self, app: Any = None) -> None:
        self.app = app
        self.revalidator: Authorizer | None = None
        self.close_code = DEFAULT_CLOSE_CODE
        self.close_reason = DEFAULT_CLOSE_REASON
        self._authorizations: dict[str, WebsocketAuthorization] = {}

    # -- Application-facing authority ---------------------------------

    def current(self, account: str) -> WebsocketAuthorization | None:
        """Return the current generation for ``account``, if any."""

        return self._authorizations.get(account)

    def issue(
        self,
        account: str,
        *,
        generation: int | None = None,
        claims: Mapping[str, Any] | None = None,
    ) -> WebsocketAuthorization:
        """Confirm (or re-confirm) authorization for ``account``.

        Without an explicit ``generation``, a new generation is issued and
        every connection still bound to an older value becomes stale.
        """

        previous = self._authorizations.get(account)
        if generation is None:
            generation = (previous.generation + 1) if previous else 1
        authorization = WebsocketAuthorization(
            account=account,
            generation=int(generation),
            claims=dict(claims or {}),
            revoked=False,
        )
        self._authorizations[account] = authorization
        return authorization

    renew = issue

    def revoke(
        self,
        account: str,
        *,
        claims: Mapping[str, Any] | None = None,
    ) -> WebsocketAuthorization:
        """Revoke ``account`` and invalidate every bound generation.

        A new higher generation is recorded and marked revoked.  Connections
        still hold their own snapshot; each one is refused individually on its
        next protected action, so one connection cannot overwrite another
        connection's processing state.
        """

        previous = self._authorizations.get(account)
        generation = (previous.generation + 1) if previous else 1
        authorization = WebsocketAuthorization(
            account=account,
            generation=generation,
            claims=dict(claims or {}),
            revoked=True,
        )
        self._authorizations[account] = authorization
        return authorization

    def is_current(
        self, authorization: WebsocketAuthorization | None
    ) -> bool:
        if authorization is None or authorization.revoked:
            return False
        current = self._authorizations.get(authorization.account)
        if current is None:
            # No application authority has spoken for this account.  A
            # connection that was explicitly bound may use its own snapshot;
            # revocation requires an explicit manager record.
            return authorization.generation > 0
        return (
            not current.revoked
            and current.generation == authorization.generation
        )

    def set_revalidator(self, revalidator: Authorizer | None) -> None:
        """Install the application's re-confirmation hook."""

        self.revalidator = revalidator

    def make_state(
        self, connection: Any = None
    ) -> "WebsocketAuthorizationState":
        return WebsocketAuthorizationState(connection, manager=self)

    def snapshot(self) -> dict[str, dict[str, Any]]:
        """Return the current generation per account (no claims)."""

        return {
            account: {
                "generation": authorization.generation,
                "revoked": authorization.revoked,
            }
            for account, authorization in self._authorizations.items()
        }


class WebsocketAuthorizationState:
    """Per-connection authorization and processing state.

    Nothing here is shared with another connection.  Two connections for the
    same account keep independent action counters, in-flight receipts and
    close decisions even though they consult the same manager.
    """

    def __init__(
        self,
        connection: Any = None,
        *,
        manager: WebsocketAuthorizationManager | None = None,
    ) -> None:
        self.connection = connection
        self.manager = manager
        self.request: Any = None
        self.websocket: Any = None
        self.authorization: WebsocketAuthorization | None = None
        self.admitted = 0
        self.refused = 0
        self.in_flight_actions = 0
        self.completed_actions = 0
        self.failed_actions = 0
        self.in_flight: list[WebsocketActionReceipt] = []
        self.actions: list[WebsocketActionReceipt] = []
        self.closed = False
        self.close_handled = False
        self.close_events: list[tuple[int, str]] = []
        self.close_code = DEFAULT_CLOSE_CODE
        self.close_reason = DEFAULT_CLOSE_REASON
        self.refusal: str | None = None
        self._lock = asyncio.Lock()

    @property
    def account(self) -> str | None:
        return self.authorization.account if self.authorization else None

    @property
    def generation(self) -> int | None:
        return self.authorization.generation if self.authorization else None

    # -- Wiring --------------------------------------------------------

    def attach_manager(
        self, manager: WebsocketAuthorizationManager
    ) -> None:
        self.manager = manager
        self.close_code = manager.close_code
        self.close_reason = manager.close_reason

    async def _receive(self, timeout: float | None = None) -> Any:
        websocket = self.websocket or self.connection
        if websocket is None or not hasattr(websocket, "recv"):
            raise WebsocketAuthorizationRequired(
                "No websocket is attached to read protected messages"
            )
        return await websocket.recv(timeout)

    def attach_request(self, request: Any, websocket: Any = None) -> None:
        self.request = request
        self.websocket = (
            websocket if websocket is not None else self.connection
        )
        if self.manager is None:
            app_manager = getattr(
                getattr(request, "app", None),
                "websocket_authorizations",
                None,
            )
            if isinstance(app_manager, WebsocketAuthorizationManager):
                self.attach_manager(app_manager)

    def bind(
        self,
        authorization: WebsocketAuthorization | None = None,
        *,
        account: str | None = None,
        generation: int | None = None,
        claims: Mapping[str, Any] | None = None,
        manager: WebsocketAuthorizationManager | None = None,
    ) -> WebsocketAuthorization:
        """Bind this connection to an authorization snapshot.

        When only ``account`` is provided and a manager is attached, the
        manager's current generation is used.  The snapshot is copied into
        this connection; binding never mutates another connection's state.
        """

        if manager is not None:
            self.attach_manager(manager)
        if authorization is None:
            if account is None:
                raise WebsocketAuthorizationRequired(
                    "An account or authorization is required to bind"
                )
            if generation is None:
                if self.manager is None:
                    raise WebsocketAuthorizationRequired(
                        "A generation is required without a manager"
                    )
                current = self.manager.current(account)
                if current is None:
                    raise WebsocketAuthorizationRequired(
                        f"No current authorization for account {account!r}"
                    )
                authorization = WebsocketAuthorization(
                    account=current.account,
                    generation=current.generation,
                    claims=dict(current.claims),
                    revoked=current.revoked,
                )
            else:
                authorization = WebsocketAuthorization(
                    account=account,
                    generation=int(generation),
                    claims=dict(claims or {}),
                )
        else:
            authorization = WebsocketAuthorization(
                account=authorization.account,
                generation=authorization.generation,
                claims=dict(authorization.claims),
                revoked=authorization.revoked,
            )
        self.authorization = authorization
        self.refusal = None
        return authorization

    # -- Reconfirmation ------------------------------------------------

    async def _call_revalidator(self) -> Any:
        if self.manager is None or self.manager.revalidator is None:
            return None
        result = self.manager.revalidator(self)
        if isawaitable(result):
            result = await result
        return result

    async def confirm(self) -> WebsocketAuthorization:
        """Re-confirm the connection authorization.

        An explicit revoke marker is authoritative: even if a hook returns
        the same generation, a revoked manager record refuses the action.  A
        hook may issue a fresh authorization to re-admit the connection.
        """

        if self.authorization is None:
            raise WebsocketAuthorizationRequired(
                "The websocket connection has no bound authorization"
            )

        has_hook = (
            self.manager is not None
            and self.manager.revalidator is not None
        )
        hook_result = await self._call_revalidator()

        if hook_result is False:
            raise WebsocketAuthorizationRevoked(
                "The websocket authorization was not re-confirmed",
                close_code=self.close_code,
                reason=self.close_reason,
            )
        if hook_result is None and has_hook:
            # A hook that runs but returns nothing has not confirmed
            # anything, so the action fails closed.
            raise WebsocketAuthorizationRevoked(
                "The websocket authorization was not re-confirmed",
                close_code=self.close_code,
                reason=self.close_reason,
            )

        if isinstance(hook_result, WebsocketAuthorization):
            if hook_result.account != self.authorization.account:
                raise WebsocketAuthorizationRevoked(
                    "The re-confirmed authorization belongs to another "
                    "account",
                    close_code=self.close_code,
                    reason=self.close_reason,
                )
            if hook_result.revoked:
                raise WebsocketAuthorizationRevoked(
                    "The websocket authorization has been revoked",
                    close_code=self.close_code,
                    reason=self.close_reason,
                )
            self.authorization = WebsocketAuthorization(
                account=hook_result.account,
                generation=hook_result.generation,
                claims=dict(hook_result.claims),
            )
        elif isinstance(hook_result, bool):
            # ``True`` accepts the manager's current generation, which lets an
            # application confirm a renewal without building a snapshot.
            if self.manager is not None:
                current = self.manager.current(self.authorization.account)
                if current is not None:
                    if current.revoked:
                        raise WebsocketAuthorizationRevoked(
                            "The websocket authorization has been revoked",
                            close_code=self.close_code,
                            reason=self.close_reason,
                        )
                    self.authorization = current
        elif isinstance(hook_result, int):
            self.authorization = WebsocketAuthorization(
                account=self.authorization.account,
                generation=hook_result,
                claims=dict(self.authorization.claims),
            )

        if self.authorization.revoked:
            raise WebsocketAuthorizationRevoked(
                "The websocket authorization has been revoked",
                close_code=self.close_code,
                reason=self.close_reason,
            )

        if self.manager is not None:
            current = self.manager.current(self.authorization.account)
            if current is not None and (
                current.revoked
                or current.generation != self.authorization.generation
            ):
                raise WebsocketAuthorizationRevoked(
                    "The websocket authorization generation is stale",
                    close_code=self.close_code,
                    reason=self.close_reason,
                )
        return self.authorization

    def is_active(self) -> bool:
        """Whether this connection can still admit protected actions."""

        if self.authorization is None or self.authorization.revoked:
            return False
        if self.manager is None:
            return True
        current = self.manager.current(self.authorization.account)
        if current is None:
            return True
        return (
            not current.revoked
            and current.generation == self.authorization.generation
        )

    # -- Closing -------------------------------------------------------

    def _record_close(
        self, code: int | None = None, reason: str | None = None
    ) -> tuple[int, str] | None:
        code = self.close_code if code is None else code
        reason = self.close_reason if reason is None else reason
        self.closed = True
        self.close_code = code
        self.close_reason = reason
        if self.close_handled:
            return None
        self.close_handled = True
        self.close_events.append((code, reason))
        return code, reason

    async def close_connection(
        self, code: int | None = None, reason: str | None = None
    ) -> None:
        """Record and close, awaiting an asynchronous close if needed."""

        decision = self._record_close(code, reason)
        if decision is None:
            return
        code, reason = decision
        connection = self.connection
        if connection is None:
            return
        try:
            if getattr(connection, "supports_synchronous_close", True):
                end_connection = getattr(connection, "end_connection", None)
                if end_connection is not None:
                    end_connection(code, reason)
                    return
            # ASGI servers close on receiving the close event; send it once.
            send_close = getattr(connection, "send_close", None)
            if send_close is not None:
                result = send_close(code, reason)
            else:
                result = connection.close(  # type: ignore[union-attr]
                    code, reason
                )
            if isawaitable(result):
                await result
        except Exception:
            # The close decision is already recorded; a transport that is
            # already gone must not mask the original refusal.
            ...

    async def _refuse(self, error: Exception) -> None:
        self.refused += 1
        self.refusal = str(error)
        await self.close_connection(
            getattr(error, "close_code", None) or self.close_code,
            getattr(error, "reason", None) or self.close_reason,
        )
        raise error

    # -- Protected actions ---------------------------------------------

    async def admit_action(self) -> WebsocketActionReceipt:
        """Check the authorization generation and admit one protected action.

        Call this immediately before executing an admin action.  If it raises,
        the action must not run and the connection has been closed.
        """

        async with self._lock:
            try:
                authorization = await self.confirm()
            except WebsocketAuthorizationError as error:
                await self._refuse(error)
                raise
            except Exception as error:
                wrapped = WebsocketAuthorizationRevoked(
                    "The websocket authorization could not be re-confirmed",
                    close_code=self.close_code,
                    reason=self.close_reason,
                )
                await self._refuse(wrapped)
                raise wrapped from error
            receipt = WebsocketActionReceipt(authorization=authorization)
            self.admitted += 1
            self.in_flight_actions += 1
            self.in_flight.append(receipt)
            self.actions.append(receipt)
            return receipt

    def finish_action(
        self,
        receipt: WebsocketActionReceipt,
        *,
        error: BaseException | None = None,
    ) -> None:
        """Mark an admitted action as completed or failed.

        Revocation never changes this record; it only prevents new
        admissions.  Calling it more than once is a no-op.
        """

        if receipt.status != "admitted":
            return
        receipt.status = "failed" if error is not None else "completed"
        receipt.error = error
        receipt.finished_at = time.monotonic()
        self.in_flight_actions = max(0, self.in_flight_actions - 1)
        if receipt in self.in_flight:
            self.in_flight.remove(receipt)
        if error is not None:
            self.failed_actions += 1
        else:
            self.completed_actions += 1

    def protected_action(self) -> "ProtectedAction":
        """Return an async context manager for one protected action."""

        return ProtectedAction(self)

    @asynccontextmanager
    async def protected_message(
        self, timeout: float | None = None
    ) -> AsyncIterator[tuple[Any, WebsocketActionReceipt]]:
        """Read one message, check the generation, then hand it to the app.

        The payload is read first so ordinary control messages keep working
        after revocation; the authorization check happens before the payload
        is yielded, which is the linearization point for a protected message.
        On refusal the connection is closed and the payload is never yielded.
        """

        message = await self._receive(timeout)
        receipt = await self.admit_action()
        try:
            yield message, receipt
        except BaseException as error:
            self.finish_action(receipt, error=error)
            raise
        else:
            self.finish_action(receipt)

    def snapshot(self) -> dict[str, Any]:
        """Return a per-connection status summary for operational checks."""

        return {
            "account": self.account,
            "generation": self.generation,
            "admitted": self.admitted,
            "refused": self.refused,
            "in_flight": self.in_flight_actions,
            "completed": self.completed_actions,
            "failed": self.failed_actions,
            "closed": self.closed,
            "active": self.is_active(),
            "close_code": (
                self.close_events[-1][0] if self.close_events else None
            ),
            "close_reason": (
                self.close_events[-1][1] if self.close_events else None
            ),
            "close_events": list(self.close_events),
            "refusal": self.refusal,
        }


class ProtectedAction:
    """Async context manager that admits and tracks one protected action.

    The action is admitted on entry.  On exit the receipt records
    ``completed`` or ``failed``; a revocation during execution does not
    cancel the action.
    """

    def __init__(self, state: WebsocketAuthorizationState) -> None:
        self.state = state
        self.receipt: WebsocketActionReceipt | None = None

    async def __aenter__(self) -> WebsocketActionReceipt:
        self.receipt = await self.state.admit_action()
        return self.receipt

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        assert self.receipt is not None
        self.state.finish_action(
            self.receipt, error=exc if exc_type is not None else None
        )
        return False


class WebsocketAuthorizationMixin:
    """Convenience methods shared by native and ASGI websocket objects."""

    authorization_state: WebsocketAuthorizationState

    @property
    def authorization(self) -> WebsocketAuthorization | None:
        return self.authorization_state.authorization

    @property
    def authorization_generation(self) -> int | None:
        return self.authorization_state.generation

    def bind_authorization(
        self,
        authorization: WebsocketAuthorization | None = None,
        *,
        account: str | None = None,
        generation: int | None = None,
        claims: Mapping[str, Any] | None = None,
        manager: WebsocketAuthorizationManager | None = None,
    ) -> WebsocketAuthorization:
        """Bind this connection to an authorization snapshot."""

        return self.authorization_state.bind(
            authorization,
            account=account,
            generation=generation,
            claims=claims,
            manager=manager,
        )

    async def confirm_authorization(self) -> WebsocketAuthorization:
        """Re-confirm this connection without admitting an action."""

        return await self.authorization_state.confirm()

    async def admit_action(self) -> WebsocketActionReceipt:
        """Admit one protected action, leaving the receipt pending."""

        return await self.authorization_state.admit_action()

    async def require_authorization(self) -> WebsocketActionReceipt:
        """Admit one protected action or refuse and close the connection.

        The returned receipt stays ``pending`` until the caller records the
        outcome with :meth:`finish_action` or uses
        :meth:`protected_action`.
        """

        return await self.authorization_state.admit_action()

    def finish_action(
        self,
        receipt: WebsocketActionReceipt,
        *,
        error: BaseException | None = None,
    ) -> None:
        """Record whether an admitted action completed or failed."""

        self.authorization_state.finish_action(receipt, error=error)

    def protected_action(self) -> ProtectedAction:
        """Context manager that admits and tracks one protected action."""

        return self.authorization_state.protected_action()

    def protected_message(self, timeout: float | None = None):
        """Read a message and check authorization before yielding it."""

        return self.authorization_state.protected_message(timeout)

    @property
    def authorization_active(self) -> bool:
        """Whether this connection can still admit protected actions."""

        return self.authorization_state.is_active()

    def authorization_snapshot(self) -> dict[str, Any]:
        """Return this connection's own status summary."""

        return self.authorization_state.snapshot()
