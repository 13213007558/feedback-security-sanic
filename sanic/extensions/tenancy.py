"""Request-scoped borrowing for tenant-aware application objects.

A common Sanic extension pattern caches tenant objects on ``app.ctx`` and
binds the "current" tenant on a shared resource while a request is handled.
That is unsafe as soon as a handler awaits: another request can run, bind a
different tenant on the same shared object, and the first request can then
read or write with the wrong identity.

This module separates the two concerns:

* Things that are safe to share between concurrent requests:
  - the physical backing resource (connection, pool, client, etc.);
  - the immutable tenant catalog kept on ``app.ctx``;
  - read-only tenant metadata/attributes;
  - the lease bookkeeping (reference counts) on the manager.

* Things that must be frozen for the lifetime of one request:
  - the tenant id and authorization snapshot;
  - the cache generation the snapshot was taken from;
  - the request-owned :class:`TenantLease` handle;
  - all operation state derived from that identity.

A lease never consults a shared mutable "active tenant" field to decide who
it is.  It captures an immutable :class:`TenantIdentity` at borrow time and
passes it explicitly to every operation.  Releasing a lease only removes its
own lease id from the bookkeeping.  If another request still holds an
authorization on the same resource, the authorization stays in use and the
resource's visible binding falls back to that other request, never to
``None``.

Typical usage::

    from sanic.extensions.tenancy import SharedTenantResource, setup_tenancy

    resource = SharedTenantResource("primary-db")
    setup_tenancy(
        app,
        resource,
        {"alpha": "token-alpha", "beta": "token-beta"},
    )

    @app.get("/whoami")
    async def whoami(request):
        lease = request.ctx.tenant_lease
        await lease.execute("read-profile")
        return text(f"{lease.tenant_id}:{lease.authorization}")

The resource may also be borrowed explicitly, which is useful when the
tenant is not selected by a header::

    lease = request.app.ctx.tenants.borrow(request, "alpha")
    async with lease:
        await lease.execute("read-profile")
"""

from __future__ import annotations

import asyncio

from collections.abc import Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from itertools import count
from types import MappingProxyType
from typing import Any

from sanic.exceptions import SanicException, Unauthorized


DEFAULT_TENANT_HEADER = "X-Tenant-ID"
DEFAULT_LEASE_ATTRIBUTE = "tenant_lease"


class TenantBindingError(SanicException):
    """Raised when a request tries to hold incompatible tenant identities."""


class LeaseReleased(SanicException):
    """Raised when an operation is attempted through a returned lease."""


@dataclass(frozen=True, slots=True)
class TenantIdentity:
    """An immutable snapshot of one tenant's identity.

    ``authorization`` is intentionally opaque: this module does not validate
    or parse tokens, it only freezes the value the authorization layer or
    cache resolved at borrow time.

    Attributes are exposed as a read-only mapping so that metadata shared
    through ``app.ctx`` cannot be mutated through a lease.
    """

    tenant_id: str
    authorization: str
    generation: int = 1
    attributes: Mapping[str, Any] = field(
        default_factory=dict, compare=False, hash=False
    )

    def __post_init__(self) -> None:
        attributes = dict(self.attributes)
        object.__setattr__(self, "attributes", MappingProxyType(attributes))


class TenantCache:
    """Immutable-per-generation tenant catalog stored on ``app.ctx``.

    The cache object itself is shared by all requests, but callers only ever
    receive :class:`TenantIdentity` snapshots.  Rotating an authorization
    creates a new generation; existing snapshots and leases are unaffected.
    """

    def __init__(
        self,
        tenants: Mapping[str, str | Mapping[str, Any]] | None = None,
    ) -> None:
        self._records: dict[str, TenantIdentity] = {}
        for tenant_id, seed in (tenants or {}).items():
            self.add(tenant_id, seed)

    def add(
        self,
        tenant_id: str,
        authorization: str | Mapping[str, Any],
        *,
        attributes: Mapping[str, Any] | None = None,
    ) -> TenantIdentity:
        """Add a tenant, or replace it with a fresh generation.

        ``authorization`` may be either the opaque token itself, or a mapping
        containing ``authorization`` and optional ``attributes``.  The latter
        form keeps call sites self-documenting.
        """
        if isinstance(authorization, Mapping):
            attributes = authorization.get("attributes", attributes)
            value = authorization["authorization"]
        else:
            value = authorization

        if not tenant_id:
            raise ValueError("A tenant id is required.")
        if not isinstance(value, str) or not value:
            raise ValueError("A tenant authorization token is required.")

        current = self._records.get(tenant_id)
        generation = 1 if current is None else current.generation + 1
        identity = TenantIdentity(
            tenant_id=tenant_id,
            authorization=value,
            generation=generation,
            attributes=attributes or {},
        )
        self._records[tenant_id] = identity
        return identity

    def snapshot(self, tenant_id: str) -> TenantIdentity:
        """Return the current immutable snapshot for ``tenant_id``."""
        try:
            return self._records[tenant_id]
        except KeyError:
            # Do not distinguish "unknown tenant" from "invalid credentials"
            # on the wire, and do not echo client-supplied input in the
            # response body; both cases are simply unauthorized.
            raise Unauthorized("Unknown tenant.") from None

    def rotate_authorization(
        self, tenant_id: str, authorization: str
    ) -> TenantIdentity:
        """Install a new authorization; existing leases keep their snapshot."""
        current = self.snapshot(tenant_id)
        return self.add(
            tenant_id,
            authorization,
            attributes=current.attributes,
        )

    def current(self, tenant_id: str) -> TenantIdentity:
        """Alias for :meth:`snapshot` with intent-revealing naming."""
        return self.snapshot(tenant_id)

    def __contains__(self, tenant_id: object) -> bool:
        return tenant_id in self._records

    def __len__(self) -> int:
        return len(self._records)

    @property
    def tenant_ids(self) -> tuple[str, ...]:
        return tuple(self._records)


class SharedTenantResource:
    """A physical resource shared by all tenants and all requests.

    The resource may have a legacy mutable ``active_identity`` binding.  The
    lease manager updates that binding for observability/backwards
    compatibility, but lease operations never trust it: they always pass the
    request's frozen identity explicitly.  Tests can therefore prove that a
    shared binding changed by another request does not affect an in-flight
    lease.

    ``connection_id`` is deliberately stable across tenants: the point of
    the contract is that the expensive physical resource is shared while the
    identity is sliced per request.
    """

    def __init__(
        self, name: str = "tenant-resource", connection_id: str | None = None
    ) -> None:
        self.name = name
        self.connection_id = connection_id or f"{name}:shared"
        self._active: TenantIdentity | None = None
        self._active_lease_id: int | None = None
        self.operations: list[tuple[str, str, str, int]] = []
        self.binding_events: list[tuple[str, int | None, str | None]] = []

    @property
    def active_identity(self) -> TenantIdentity | None:
        """Legacy mutable binding; never use it for authorization."""
        return self._active

    @property
    def active_lease_id(self) -> int | None:
        return self._active_lease_id

    def _bind(self, lease_id: int, identity: TenantIdentity) -> None:
        self._active = identity
        self._active_lease_id = lease_id
        self.binding_events.append(("bind", lease_id, identity.tenant_id))

    def _rebind(
        self,
        previous_lease_id: int,
        replacement_lease_id: int | None,
        replacement: TenantIdentity | None,
    ) -> None:
        if self._active_lease_id != previous_lease_id:
            # Another request owns the visible binding now.  Returning the
            # old lease must not touch it at all.
            self.binding_events.append(
                (
                    "leave",
                    previous_lease_id,
                    self._active.tenant_id if self._active else None,
                )
            )
            return
        self._active = replacement
        self._active_lease_id = replacement_lease_id
        self.binding_events.append(
            (
                "restore" if replacement is not None else "clear",
                replacement_lease_id,
                replacement.tenant_id if replacement is not None else None,
            )
        )

    async def execute(
        self,
        identity: TenantIdentity,
        operation: str,
        *,
        delay: float = 0.0,
    ) -> Any:
        """Run one operation with an explicit frozen identity.

        This method is the only supported way to work through a lease.
        ``identity`` is never looked up from ``active_identity``.
        """
        self.operations.append(
            (
                identity.tenant_id,
                identity.authorization,
                operation,
                identity.generation,
            )
        )
        if delay:
            await asyncio.sleep(delay)
        return {
            "tenant_id": identity.tenant_id,
            "authorization": identity.authorization,
            "generation": identity.generation,
            "operation": operation,
            "connection_id": self.connection_id,
        }

    def operations_for(
        self, tenant_id: str
    ) -> list[tuple[str, str, str, int]]:
        return [op for op in self.operations if op[0] == tenant_id]


class TenantLease:
    """A request-owned handle to a shared resource with a frozen identity.

    Leases are created by :class:`TenantLeaseManager` and must be returned
    exactly once.  Use either::

        lease = manager.borrow(request, "alpha")
        ...
        manager.release(lease)

    or the async context manager form::

        async with manager.borrow(request, "alpha") as lease:
            ...

    The context variable :meth:`current` is set while the lease is active.
    Tasks created from the handler inherit that snapshot, so a delayed
    callback cannot accidentally pick up another request's identity.  A task
    that outlives the request still sees the (now released) lease object and
    operations fail closed instead of falling back to shared state.
    """

    __slots__ = (
        "manager",
        "identity",
        "request",
        "resource",
        "lease_id",
        "_token",
        "_released",
    )

    def __init__(
        self,
        manager: TenantLeaseManager,
        identity: TenantIdentity,
        request: Any,
        resource: SharedTenantResource,
        lease_id: int,
    ) -> None:
        self.manager = manager
        self.identity = identity
        self.request = request
        self.resource = resource
        self.lease_id = lease_id
        self._token: Token | None = None
        self._released = False

    @property
    def tenant_id(self) -> str:
        return self.identity.tenant_id

    @property
    def authorization(self) -> str:
        return self.identity.authorization

    @property
    def generation(self) -> int:
        return self.identity.generation

    @property
    def active(self) -> bool:
        return not self._released

    def _ensure_active(self) -> None:
        if self._released or self.manager.is_released(self.lease_id):
            raise LeaseReleased(
                "This tenant lease has already been returned to the pool."
            )

    async def execute(self, operation: str, *, delay: float = 0.0) -> Any:
        """Execute an operation using this lease's frozen identity."""
        self._ensure_active()
        return await self.resource.execute(
            self.identity, operation, delay=delay
        )

    def __repr__(self) -> str:
        state = "active" if self.active else "released"
        return (
            f"<TenantLease {self.identity.tenant_id} "
            f"gen={self.identity.generation} {state}>"
        )

    def __enter__(self) -> TenantLease:
        self._ensure_active()
        if _current_lease.get() is not self:
            self._token = _current_lease.set(self)
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    async def __aenter__(self) -> TenantLease:
        return self.__enter__()

    async def __aexit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        self.manager.release(self)

    @classmethod
    def current(cls) -> TenantLease | None:
        """Return the lease active in this context, if any.

        A lease that has already been returned is still exposed here so that
        delayed tasks can discover *which* tenant they belonged to.  Using
        :meth:`execute` on it fails closed with :class:`LeaseReleased`; use
        :meth:`current_identity` when only the frozen snapshot is needed.
        """
        return _current_lease.get()

    @classmethod
    def current_identity(cls) -> TenantIdentity | None:
        """Return the frozen identity of this context, even after release."""
        lease = cls.current()
        return lease.identity if lease else None


_current_lease: ContextVar[TenantLease | None] = ContextVar(
    "sanic_tenant_lease", default=None
)


class TenantLeaseManager:
    """Create, track and return request-level leases.

    Authorization bookkeeping is keyed by ``(tenant_id, authorization)`` and
    stores the set of lease ids currently using it.  Releasing a lease removes
    only that lease's id.  Consequently the last-lease-wins rule is scoped to
    the exact authorization snapshot: returning request A can never clear an
    authorization that request B is still using.
    """

    def __init__(
        self,
        cache: TenantCache,
        resource: SharedTenantResource,
    ) -> None:
        self.cache = cache
        self.resource = resource
        self._ids = count(1)
        self._leases: dict[int, TenantLease] = {}
        self._authorizations: dict[tuple[str, str], set[int]] = {}
        self._bindings: list[tuple[int, TenantIdentity]] = []

    def borrow(self, request: Any, tenant_id: str) -> TenantLease:
        """Borrow the current snapshot of ``tenant_id`` for ``request``.

        A request may hold at most one tenant identity.  Re-borrowing the same
        identity returns the existing lease, which makes idempotent middleware
        safe.  Borrowing a different identity while the first lease is active
        raises :class:`TenantBindingError`; a single request must never mix
        tenants.
        """
        existing = getattr(request.ctx, "tenant_lease", None)
        if isinstance(existing, TenantLease) and existing.request is request:
            if not existing.active:
                raise TenantBindingError(
                    "Cannot borrow a tenant after the request lease was "
                    "already returned."
                )
            if existing.tenant_id != tenant_id:
                raise TenantBindingError(
                    "A request cannot mix tenant identities: "
                    f"{existing.tenant_id!r} vs {tenant_id!r}."
                )
            return existing

        identity = self.cache.snapshot(tenant_id)
        lease_id = next(self._ids)
        lease = TenantLease(self, identity, request, self.resource, lease_id)
        self._leases[lease_id] = lease
        self._authorizations.setdefault(
            (identity.tenant_id, identity.authorization), set()
        ).add(lease_id)
        self._bindings.append((lease_id, identity))
        self.resource._bind(lease_id, identity)

        request.add_finalizer(lambda: self.release(lease))
        request.ctx.tenant_lease = lease
        request.ctx.tenant = lease

        # Do not overwrite a lease already active in an outer context.  The
        # request handler runs in its own task, so normally this is empty.
        if _current_lease.get() is None:
            lease._token = _current_lease.set(lease)
        return lease

    def release(self, lease: TenantLease) -> None:
        """Return ``lease``.  This operation is idempotent and synchronous."""
        if lease.lease_id not in self._leases:
            lease._released = True
            return

        lease._released = True
        del self._leases[lease.lease_id]

        key = (lease.identity.tenant_id, lease.identity.authorization)
        in_use = self._authorizations.get(key)
        if in_use is not None:
            in_use.discard(lease.lease_id)
            if not in_use:
                del self._authorizations[key]

        replacement: tuple[int, TenantIdentity] | None = None
        for index, (lease_id, identity) in enumerate(self._bindings):
            if lease_id == lease.lease_id:
                del self._bindings[index]
                break
        if self._bindings:
            replacement = self._bindings[-1]

        self.resource._rebind(
            lease.lease_id,
            replacement[0] if replacement else None,
            replacement[1] if replacement else None,
        )

        token = lease._token
        lease._token = None
        if token is not None:
            try:
                _current_lease.reset(token)
            except (RuntimeError, ValueError):
                # The release ran in another context (for example a
                # cancellation finalizer in a different task).  The lease
                # object itself is already marked released, so stale copies
                # fail closed in that context.
                ...

    def is_released(self, lease_id: int) -> bool:
        return lease_id not in self._leases

    def authorization_in_use(
        self, tenant_id: str, authorization: str | None = None
    ) -> bool:
        """Whether an authorization is still held by at least one lease."""
        if authorization is None:
            return self.tenant_in_use(tenant_id)
        return bool(self._authorizations.get((tenant_id, authorization)))

    def tenant_in_use(self, tenant_id: str) -> bool:
        """Whether any authorization of ``tenant_id`` is actively borrowed."""
        return any(
            lease.tenant_id == tenant_id for lease in self._leases.values()
        )

    def active_count(self) -> int:
        return len(self._leases)

    def active_leases(self) -> tuple[TenantLease, ...]:
        return tuple(self._leases.values())

    def active_authorizations(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._authorizations)

    def resource_binding(self) -> tuple[str | None, int | None]:
        """The legacy visible binding as ``(tenant_id, lease_id)``."""
        identity = self.resource.active_identity
        return (
            identity.tenant_id if identity is not None else None,
            self.resource.active_lease_id,
        )


def setup_tenancy(
    app: Any,
    resource: SharedTenantResource,
    tenants: Mapping[str, str | Mapping[str, Any]],
    *,
    header: str = DEFAULT_TENANT_HEADER,
    required: bool = True,
    auto: bool = True,
    lease_attribute: str = DEFAULT_LEASE_ATTRIBUTE,
) -> TenantLeaseManager:
    """Install the tenant cache and request-level lease contract on ``app``.

    The tenant catalog is stored on ``app.ctx.tenant_cache`` and the manager
    on ``app.ctx.tenants``.  With ``auto=True`` a request middleware reads
    ``header`` and borrows the matching lease before the handler runs.

    Missing or unknown tenants are answered with ``401 Unauthorized``
    rather than a route-specific error, and the response does not echo
    client-supplied tenant data.  Set ``required=False`` to allow requests
    without the header to proceed unbound.

    Args:
        app: The Sanic application.
        resource: The single physical resource shared by all tenants.
        tenants: Mapping of tenant id to authorization token (or mapping with
            ``authorization``/``attributes`` keys).
        header: Header used by the automatic borrow middleware.
        required: Whether the header is mandatory.
        auto: Whether to install the borrow middleware.
        lease_attribute: Name used on ``request.ctx`` for the lease.

    Returns:
        TenantLeaseManager: The installed manager.
    """
    cache = TenantCache(tenants)
    manager = TenantLeaseManager(cache, resource)
    app.ctx.tenant_cache = cache
    app.ctx.tenants = manager
    app.ctx.tenant_resource = resource

    if auto:

        @app.on_request
        async def _borrow_tenant(request: Any) -> None:
            tenant_id = request.headers.getone(header, None)
            if not tenant_id:
                if required:
                    raise Unauthorized(f"Missing {header} header.")
                return
            lease = manager.borrow(request, tenant_id)
            setattr(request.ctx, lease_attribute, lease)
            request.ctx.tenant = lease

    return manager


__all__ = (
    "DEFAULT_LEASE_ATTRIBUTE",
    "DEFAULT_TENANT_HEADER",
    "LeaseReleased",
    "SharedTenantResource",
    "TenantBindingError",
    "TenantCache",
    "TenantIdentity",
    "TenantLease",
    "TenantLeaseManager",
    "setup_tenancy",
)
