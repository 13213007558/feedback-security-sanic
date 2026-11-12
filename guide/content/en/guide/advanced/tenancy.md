# Tenant Leases

A common extension pattern caches tenant objects on `app.ctx` and writes the
"current" tenant onto a shared resource while a request is handled. That is
safe only until the handler awaits. While it is suspended, another request can
run, overwrite the shared binding, and the first request can then act with the
wrong identity — reading another tenant's data, or worse, writing it.

Sanic ships a first-party borrow contract for exactly this case in
`sanic.extensions.tenancy`.

## What is shared and what is frozen

Share across requests:

- the physical resource: connection, pool, client, file handle;
- the tenant catalog on `app.ctx`, including immutable snapshots and
  generation numbers;
- read-only tenant metadata;
- the manager's lease and authorization bookkeeping.

Freeze per request:

- tenant id, opaque authorization value, and cache generation;
- the `TenantLease` handle itself, stored on `request.ctx`;
- every operation derived from that identity;
- the authorization snapshot, which must not change even if the cache rotates
  the tenant's credentials while the request is in flight.

The shared physical resource is never asked "who am I?" at operation time.
Each authorized operation receives the request's frozen `TenantIdentity`
explicitly.

## Setup

```python
from sanic import Sanic, text
from sanic.extensions.tenancy import SharedTenantResource, setup_tenancy

app = Sanic("MyApp")
resource = SharedTenantResource("primary-db")

manager = setup_tenancy(
    app,
    resource,
    {
        "alpha": "token-alpha",
        "beta": "token-beta",
    },
)
```

`setup_tenancy` stores the catalog on `app.ctx.tenant_cache`, the manager on
`app.ctx.tenants`, and the resource on `app.ctx.tenant_resource`. It also
installs request middleware that borrows the tenant from the `X-Tenant-ID`
header (configurable with `header=`). Missing and unknown tenants both get `401
Unauthorized`; the response does not echo the client-supplied value.

If tenants are selected some other way (a path parameter, a claim, unit of
work), disable the automatic middleware and borrow explicitly:

```python
lease = request.app.ctx.tenants.borrow(request, "alpha")
try:
    ...
finally:
    lease.close()
```

## Using a lease

```python
@app.get("/whoami")
async def whoami(request):
    lease = request.ctx.tenant_lease
    profile = await lease.execute("read-profile")
    return text(f"{profile['tenant_id']}:{profile['generation']}")
```

`lease.tenant_id`, `lease.authorization` and `lease.generation` are read-only
snapshot accessors. `TenantLease.current()` returns the lease bound to the
current context, and `TenantLease.current_identity()` returns the frozen
identity even after the lease has been returned.

A lease can also be used as a context manager:

```python
async with request.app.ctx.tenants.borrow(request, "alpha") as lease:
    await lease.execute("read-profile")
```

A single request may hold only one tenant identity. Borrowing the same tenant
again returns the same lease. Borrowing a different tenant while the first
lease is active raises `TenantBindingError` rather than silently mixing
tenants.

## Streaming

Streaming handlers keep the same lease for every chunk. The returned lease is
frozen before the first `await`, so chunk two cannot observe a binding changed
by another request between chunk one and chunk two.

```python
@app.get("/stream")
async def stream(request):
    lease = request.ctx.tenant_lease
    response = await request.respond(content_type="text/csv")
    async for row in cursor:
        await response.send(f"{lease.tenant_id},{row}\n")
    await response.eof()
```

## Cancellation

Leases are returned through `Request.add_finalizer`, which runs after the
response is sent, after an exception, and when the request task is cancelled.
A delayed task that outlives the request still inherits the frozen identity
through the context variable, but an operation through the already-returned
lease fails closed with `LeaseReleased` instead of falling back to shared
state.

If you must run cleanup from a background task, capture the lease's identity
explicitly before the request ends. Do not re-read a shared "current tenant"
binding from the background task.

## Returning authorizations safely

Authorization bookkeeping is reference counted per exact
`(tenant_id, authorization)` pair. Releasing a lease removes only that lease's
own entry:

- if another request still holds the same authorization, it stays in use and
  the shared resource's visible binding falls back to that request;
- if no other request holds it, the authorization is dropped and the binding
  is cleared;
- releasing a lease never clears an authorization that another request is
  still using.

Rotating a tenant's authorization creates a new cache generation. In-flight
leases keep the token and generation they captured; new requests see the new
one.

## Failure behavior

- Unknown or missing tenant: `401 Unauthorized`, no lease created.
- Mixing tenants in one request: `TenantBindingError` (server error), and the
  lease is still returned.
- Operation on a released lease: `LeaseReleased`.
- Operation after another request changed the shared binding: unaffected;
  the operation uses the lease's frozen identity.
