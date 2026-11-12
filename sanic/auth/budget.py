from __future__ import annotations

import asyncio
import math

from collections import deque
from contextlib import suppress
from types import TracebackType
from typing import Any, Awaitable, Callable, Optional

from sanic.exceptions import ServiceUnavailable


class AuthenticationBudgetExceeded(ServiceUnavailable):
    """503 raised when the authentication wait budget is exhausted.

    The exception is temporary by design: the request never acquired a
    wait slot, so it must not continue into the business handler. When
    the rejection is caused by a finite timeout, a ``Retry-After``
    header carrying that budget (rounded up to whole seconds) is
    attached to the response.

    Args:
        budget (Optional[float]): The wait budget in seconds that was
            exceeded. ``None`` indicates a shutdown with no configured
            timeout, in which case no ``Retry-After`` header is sent.
    """

    quiet = True

    def __init__(self, budget: Optional[float] = None) -> None:
        headers = None
        if budget is not None:
            retry_after = max(1, int(math.ceil(budget)))
            headers = {"Retry-After": str(retry_after)}
        super().__init__(
            "Authentication wait budget exceeded; try again later.",
            headers=headers,
        )
        self.budget = budget


class AuthenticationBudget:
    """Independent wait budget for the authentication stage of requests.

    A bounded pool of wait slots limits how many requests may wait on
    the authentication provider at the same time. Every request takes
    a slot before invoking the provider and gets it back exactly once
    when authentication finishes, the client disconnects, or the server
    shuts down. Requests that cannot obtain a slot within ``timeout``
    seconds fail immediately with
    :class:`AuthenticationBudgetExceeded` instead of piling up behind a
    slow provider.

    The slot pool is driven explicitly with a waiter queue rather than
    a plain semaphore so that timeouts, client disconnects and shutdown
    can reject a queued request without ever corrupting the slot count.

    Args:
        capacity (int): Maximum number of concurrent authentication
            waits. Must be greater than zero.
        timeout (Optional[float]): Maximum time, in seconds, a request
            may wait for a free slot. ``None`` means wait indefinitely
            (unless the budget is shut down).
    """

    __slots__ = (
        "_capacity",
        "_timeout",
        "_value",
        "_in_flight",
        "_waiting",
        "_closed",
        "_waiters",
        "_drain",
    )

    def __init__(self, capacity: int, timeout: Optional[float] = None) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be greater than zero")
        self._capacity = capacity
        self._timeout = timeout
        self._value = capacity
        self._in_flight = 0
        self._waiting = 0
        self._closed = False
        self._waiters: deque[asyncio.Future[None]] = deque()
        self._drain: Optional[asyncio.Future[None]] = None

    @property
    def capacity(self) -> int:
        """Maximum number of concurrent authentication waits."""
        return self._capacity

    @property
    def timeout(self) -> Optional[float]:
        """Maximum slot acquisition time in seconds."""
        return self._timeout

    @property
    def in_flight(self) -> int:
        """Number of requests currently holding a wait slot."""
        return self._in_flight

    @property
    def waiting(self) -> int:
        """Number of requests currently queued for a wait slot."""
        return self._waiting

    @property
    def available(self) -> int:
        """Number of wait slots immediately available."""
        return self._value

    @property
    def is_closed(self) -> bool:
        """Whether the budget has been shut down."""
        return self._closed

    async def acquire(self) -> AuthenticationGuard:
        """Acquire a wait slot.

        Returns an :class:`AuthenticationGuard` whose context manager
        releases the slot exactly once. If no slot becomes available
        within the timeout, the client disconnects while queued, or the
        budget is shut down before a slot is granted,
        :class:`AuthenticationBudgetExceeded` is raised (a client
        disconnect instead surfaces ``asyncio.CancelledError``).

        Returns:
            AuthenticationGuard: A guard for the acquired slot.

        Raises:
            AuthenticationBudgetExceeded: If the wait budget or the
                timeout is exhausted, or the budget is closed.
        """
        if self._closed:
            raise AuthenticationBudgetExceeded(self._timeout)

        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[None] = loop.create_future()
        self._waiters.append(waiter)
        self._waiting += 1

        timer: Optional[asyncio.TimerHandle] = None
        if self._timeout is not None:

            def on_timeout() -> None:
                if not waiter.done():
                    waiter.set_exception(
                        AuthenticationBudgetExceeded(self._timeout)
                    )

            timer = loop.call_later(self._timeout, on_timeout)

        self._pump()

        try:
            await waiter
        except BaseException:
            with suppress(ValueError):
                self._waiters.remove(waiter)
            # A slot may have been granted in the same loop step before
            # a cancellation landed. Hand it back so it is never lost.
            if (
                not waiter.cancelled()
                and waiter.done()
                and waiter.exception() is None
            ):
                self._return_slot()
            raise
        finally:
            if timer is not None:
                timer.cancel()
            self._waiting -= 1

        if self._closed:
            # The slot was granted while shutdown was in progress.
            self._return_slot()
            raise AuthenticationBudgetExceeded(self._timeout)

        self._in_flight += 1
        return AuthenticationGuard(self)

    async def shutdown(self, timeout: Optional[float] = None) -> None:
        """Close the budget and wait for held slots to be returned.

        Queued requests are rejected immediately and new acquisitions
        are rejected as well. Requests already holding a slot keep
        running until they finish and return their slots.

        Args:
            timeout (Optional[float]): Maximum time to wait for in
                flight requests to drain. ``None`` waits until every
                held slot is returned.
        """
        self._closed = True
        for queued in tuple(self._waiters):
            if not queued.done():
                queued.set_exception(
                    AuthenticationBudgetExceeded(self._timeout)
                )

        if not self._in_flight:
            return

        drain: asyncio.Future[None] = (
            asyncio.get_running_loop().create_future()
        )
        self._drain = drain
        try:
            await asyncio.wait_for(asyncio.shield(drain), timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass

    def _pump(self) -> None:
        """Hand free slots to queued requests in FIFO order."""
        while self._value > 0 and self._waiters:
            queued = self._waiters.popleft()
            if queued.done():
                continue
            self._value -= 1
            queued.set_result(None)

    def _return_slot(self) -> None:
        self._value += 1
        self._pump()

    def _release(self) -> None:
        if self._in_flight == 0:
            return
        self._in_flight -= 1
        self._return_slot()
        if self._in_flight == 0 and self._drain is not None:
            drain = self._drain
            self._drain = None
            if not drain.done():
                drain.set_result(None)


class AuthenticationGuard:
    """Context manager that returns an acquired wait slot exactly once."""

    __slots__ = ("_budget", "_released")

    def __init__(self, budget: AuthenticationBudget) -> None:
        self._budget = budget
        self._released = False

    @property
    def budget(self) -> AuthenticationBudget:
        """The budget this guard draws its slot from."""
        return self._budget

    def release(self) -> None:
        """Return the slot; safe to call more than once."""
        if self._released:
            return
        self._released = True
        self._budget._release()

    def __enter__(self) -> "AuthenticationGuard":
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.release()


AuthenticationHandler = Callable[..., Awaitable[Any]]


def authentication_middleware(
    budget: AuthenticationBudget,
    authenticator: AuthenticationHandler,
) -> Callable[..., Awaitable[None]]:
    """Build a Sanic request middleware guarding an authenticator.

    The middleware takes one slot from ``budget`` before calling
    ``authenticator`` and always returns the slot afterwards, including
    when the client disconnects while authentication is running. When
    the budget rejects the request, the middleware raises before the
    authenticator (and therefore any business handler) runs.

    Args:
        budget (AuthenticationBudget): The wait budget to draw slots
            from.
        authenticator (AuthenticationHandler): Coroutine function
            performing the actual authentication, e.g. a call to a
            slow external provider.

    Returns:
        Callable: A Sanic request middleware coroutine.
    """

    async def middleware(request: Any, *args: Any, **kwargs: Any) -> None:
        guard = await budget.acquire()
        with guard:
            result = authenticator(request, *args, **kwargs)
            if asyncio.iscoroutine(result):
                await result
        request.ctx.authenticated = True

    return middleware
