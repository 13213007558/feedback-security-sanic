"""Employee-authorization gateway driven by Sanic route metadata.

The gateway watches every route registration on an application (including
blueprints, blueprint copies, blueprint groups, static routes and delayed
registrations) and, once the application has finished registering routes,
builds a final, auditable mapping of which endpoints require an employee
identity.

Usage::

    app = Sanic("gateway_example")
    gateway = EmployeeAuthGateway(app)

    @app.get("/payroll", ctx_requires_employee=True)
    async def payroll(request):
        ...

Routes declare the requirement through route metadata, either with the
``ctx_requires_employee=True`` keyword (stored on ``route.ctx``) or with
the :func:`employee_required` decorator on the handler.

Lifecycle rules:

* :meth:`EmployeeAuthGateway.finalize` (also wired to the
  ``after_server_start`` listener) seals the mapping. Conflicting
  definitions for the same effective endpoint raise
  :class:`AuthMappingConflictError` at that point, refusing startup.
* Authorization decisions at request time follow the route that the
  router actually matched (including its version and host restrictions),
  never a re-derived path lookup.
* After the mapping is sealed, any further route registration raises
  :class:`GatewaySealedError`. To intentionally change routes, call
  :meth:`EmployeeAuthGateway.invalidate` (or use
  :meth:`EmployeeAuthGateway.amend`) and finalize again. While the
  mapping is not finalized, requests fail closed with HTTP 500.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from inspect import isawaitable
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    Union,
)

from sanic_routing.route import Route

from sanic.exceptions import ServerError, Unauthorized


if TYPE_CHECKING:
    from sanic import Sanic
    from sanic.request import Request


DEFAULT_CTX_KEY = "requires_employee"
DEFAULT_IDENTITY_HEADER = "x-employee-id"
HANDLER_FLAG = "__employee_required__"
MIDDLEWARE_PRIORITY = 10_000

Verifier = Callable[["Request"], Union[bool, Awaitable[bool]]]


class GatewayError(RuntimeError):
    """Base error for gateway lifecycle problems."""


class AuthMappingConflictError(GatewayError):
    """Two definitions of the same effective endpoint disagree about
    whether an employee identity is required. Raised at finalization so
    the application refuses to start with an ambiguous mapping."""


class GatewaySealedError(GatewayError):
    """A route registration was attempted after the authorization
    mapping had been sealed."""


class GatewayNotFinalizedError(ServerError):
    """Fail-closed error (HTTP 500) raised when a request arrives but
    the authorization mapping has not been finalized."""


@dataclass(frozen=True)
class AuthEntry:
    """One row of the final, auditable authorization mapping."""

    route_name: str
    method: str
    path: str
    host: Optional[str]
    version: Optional[Union[int, str, float]]
    requires_employee: bool


def employee_required(handler):
    """Mark a route handler as requiring an employee identity.

    This is an alternative to passing ``ctx_requires_employee=True`` to
    the route decorator; the gateway honors both.
    """

    setattr(handler, HANDLER_FLAG, True)
    return handler


class EmployeeAuthGateway:
    """Builds and enforces the employee-authorization mapping of an app."""

    def __init__(
        self,
        app: "Sanic",
        *,
        verifier: Optional[Verifier] = None,
        identity_header: str = DEFAULT_IDENTITY_HEADER,
        ctx_key: str = DEFAULT_CTX_KEY,
    ) -> None:
        self.app = app
        self.ctx_key = ctx_key
        self.identity_header = identity_header
        self._verifier = verifier or self._default_verifier
        self._registrations: List[
            Tuple[Tuple[Route, ...], Dict[str, Any]]
        ] = []
        self._mapping: Optional[Tuple[AuthEntry, ...]] = None
        self._decisions: Optional[Dict[int, bool]] = None
        self._sealed = False
        self._ever_sealed = False

        self._wrap_router(app)
        app.register_middleware(
            self._enforce, attach_to="request", priority=MIDDLEWARE_PRIORITY
        )
        app.after_server_start(self._finalize_on_startup)

    @property
    def sealed(self) -> bool:
        """Whether the mapping has been finalized and sealed."""

        return self._sealed

    @property
    def mapping(self) -> Tuple[AuthEntry, ...]:
        """The final, immutable authorization mapping.

        Raises:
            GatewayError: If the mapping has not been finalized yet.
        """

        if self._mapping is None:
            raise GatewayError(
                "The authorization mapping has not been finalized. "
                "Call gateway.finalize() after all routes are registered."
            )
        return self._mapping

    def report(self) -> str:
        """Render the final mapping as a human-reviewable table."""

        lines = [
            "Employee authorization mapping "
            f"({len(self.mapping)} entries, sealed={self._sealed}):"
        ]
        for entry in self.mapping:
            host = entry.host or "*"
            version = "-" if entry.version is None else str(entry.version)
            policy = "EMPLOYEE" if entry.requires_employee else "public"
            lines.append(
                f"  {entry.method:<7} {entry.path} "
                f"(host={host}, version={version}) "
                f"-> {policy} [{entry.route_name}]"
            )
        return "\n".join(lines)

    def finalize(self) -> Tuple[AuthEntry, ...]:
        """Build and seal the final authorization mapping.

        Considers every route registration observed so far (including
        definitions later replaced through route overwrites) plus the
        router's current state. Idempotent while sealed.

        Raises:
            AuthMappingConflictError: If two definitions of the same
                effective endpoint (method, path, host) disagree on the
                employee requirement.
        """

        if self._sealed:
            return self.mapping

        decisions_by_key: Dict[
            Tuple[str, str, Optional[str]], Tuple[bool, str]
        ] = {}
        conflicts: List[str] = []

        def consider(route: Route) -> None:
            decision = self._decision_of(route)
            host = route.requirements.get("host")
            for method in sorted(route.methods or {"GET"}):
                key = (method, route.path, host)
                existing = decisions_by_key.get(key)
                if existing is None:
                    decisions_by_key[key] = (decision, route.name)
                elif existing[0] != decision:
                    conflicts.append(
                        f"  {method} /{route.path.lstrip('/')} "
                        f"(host={host or '*'}): '{existing[1]}' "
                        f"requires_employee={existing[0]} vs "
                        f"'{route.name}' requires_employee={decision}"
                    )

        for routes, _meta in self._registrations:
            for route in routes:
                consider(route)
        for route in self.app.router.routes:
            consider(route)

        if conflicts:
            raise AuthMappingConflictError(
                "Conflicting employee-authorization definitions "
                "detected; refusing to finalize:\n" + "\n".join(conflicts)
            )

        declared: Dict[int, Dict[str, Any]] = {}
        for routes, meta in self._registrations:
            for route in routes:
                declared[id(route)] = meta

        entries: List[AuthEntry] = []
        decisions: Dict[int, bool] = {}
        for route in self.app.router.routes:
            meta = declared.get(id(route), {})
            host = route.requirements.get("host")
            decision = self._decision_of(route)
            decisions[id(route)] = decision
            for method in sorted(route.methods or {"GET"}):
                entries.append(
                    AuthEntry(
                        route_name=route.name,
                        method=method,
                        path="/" + route.path.lstrip("/"),
                        host=host,
                        version=meta.get("version"),
                        requires_employee=decision,
                    )
                )
        entries.sort(
            key=lambda entry: (
                entry.path,
                entry.method,
                entry.host or "",
                entry.route_name,
            )
        )
        self._mapping = tuple(entries)
        self._decisions = decisions
        self._sealed = True
        self._ever_sealed = True
        return self._mapping

    def invalidate(self) -> None:
        """Explicitly invalidate the sealed mapping.

        After invalidation, requests fail closed until
        :meth:`finalize` is called again, and route registration is
        permitted once more.
        """

        self._mapping = None
        self._decisions = None
        self._sealed = False

    @contextmanager
    def amend(self) -> Iterator[None]:
        """Explicitly reopen the app for route changes, then reseal.

        Example:
            ```python
            with gateway.amend():
                app.add_route(handler, "/new-endpoint")
            ```
        """

        self.invalidate()
        with self.app.amend():
            yield
        self.finalize()

    async def _finalize_on_startup(self, app) -> None:
        if self._ever_sealed:
            # Startup finalization happens once. After an explicit
            # invalidate(), only an explicit finalize() may reseal the
            # mapping; refired startup events must not silently do it.
            return
        self.finalize()

    def _default_verifier(self, request: "Request") -> bool:
        return bool(request.headers.get(self.identity_header))

    def _decision_of(self, route: Route) -> bool:
        if getattr(route.ctx, self.ctx_key, False):
            return True
        return bool(getattr(route.handler, HANDLER_FLAG, False))

    def _wrap_router(self, app: "Sanic") -> None:
        original_add = app.router.add
        gateway = self

        @wraps(original_add)
        def guarded_add(*args, **kwargs):
            if gateway._sealed:
                raise GatewaySealedError(
                    "Route registration after the authorization mapping "
                    "has been sealed is rejected. Call "
                    "gateway.invalidate() (or use gateway.amend()) and "
                    "finalize again to apply changes explicitly."
                )
            routes = original_add(*args, **kwargs)
            normalized = (
                list(routes) if isinstance(routes, (list, tuple)) else [routes]
            )
            gateway._registrations.append(
                (
                    tuple(normalized),
                    {
                        "version": kwargs.get("version"),
                        "host": kwargs.get("host"),
                        "overwrite": kwargs.get("overwrite", False),
                    },
                )
            )
            return routes

        app.router.add = guarded_add  # type: ignore[method-assign]

    async def _enforce(self, request: "Request") -> None:
        decisions = self._decisions
        if decisions is None:
            raise GatewayNotFinalizedError(
                "The employee-authorization mapping has not been "
                "finalized; refusing to serve requests (fail-closed)."
            )
        route = request.route
        if route is None:
            # No route matched (for example while handling a 404); there
            # is no protected endpoint to enforce.
            return
        required = decisions.get(id(route))
        if required is None:
            raise GatewayNotFinalizedError(
                "The matched route is not present in the sealed "
                "authorization mapping; refusing to serve (fail-closed)."
            )
        if not required:
            return
        verdict = self._verifier(request)
        if isawaitable(verdict):
            verdict = await verdict
        if not verdict:
            raise Unauthorized(
                "An employee identity is required for this endpoint."
            )
