import asyncio

from types import SimpleNamespace

import pytest

from sanic import Sanic, text
from sanic.extensions.tenancy import (
    LeaseReleased,
    SharedTenantResource,
    TenantBindingError,
    TenantCache,
    TenantIdentity,
    TenantLease,
    setup_tenancy,
)


ALPHA_TOKEN = "token-alpha"
BETA_TOKEN = "token-beta"
TENANTS = {"alpha": ALPHA_TOKEN, "beta": BETA_TOKEN}


class Barrier:
    """Deterministic interleaving point for two concurrent requests."""

    def __init__(self, slots):
        self.started = {slot: asyncio.Event() for slot in slots}
        self.release = {slot: asyncio.Event() for slot in slots}

    async def wait_started(self, slot, timeout=5):
        return await asyncio.wait_for(self.started[slot].wait(), timeout)


def make_app(name="tenancy", *, tenants=None, required=True):
    app = Sanic(name)
    resource = SharedTenantResource("primary-db")
    manager = setup_tenancy(
        app,
        resource,
        tenants or TENANTS,
        required=required,
    )
    return app, manager, resource


@pytest.mark.asyncio
async def test_shared_resource_and_frozen_identity_interleave():
    app, manager, resource = make_app("tenancy-interleave")
    barrier = Barrier(("alpha", "beta"))

    @app.get("/whoami")
    async def whoami(request):
        lease = request.ctx.tenant_lease
        tenant_id = lease.tenant_id
        await lease.execute(f"{tenant_id}:first")
        barrier.started[tenant_id].set()
        await barrier.release[tenant_id].wait()
        result = await lease.execute(f"{tenant_id}:second")
        return text(
            f"{result['tenant_id']}:{result['authorization']}:"
            f"{result['generation']}"
        )

    async def call(tenant_id):
        _, response = await app.asgi_client.get(
            "/whoami", headers={"X-Tenant-ID": tenant_id}
        )
        return response.text

    alpha = asyncio.create_task(call("alpha"))
    await barrier.wait_started("alpha")
    beta = asyncio.create_task(call("beta"))
    await barrier.wait_started("beta")

    # Both requests share one physical resource and both authorizations are
    # tracked independently while the handlers are suspended.
    assert resource.connection_id == "primary-db:shared"
    assert manager.active_count() == 2
    assert manager.active_authorizations() == (
        ("alpha", ALPHA_TOKEN),
        ("beta", BETA_TOKEN),
    )

    # Intentionally return alpha first while beta is still in flight.
    barrier.release["alpha"].set()
    assert await alpha == f"alpha:{ALPHA_TOKEN}:1"
    assert manager.authorization_in_use("alpha", ALPHA_TOKEN) is False
    assert manager.authorization_in_use("beta", BETA_TOKEN) is True
    binding = manager.resource_binding()
    assert binding[0] == "beta"
    assert binding[1] is not None

    barrier.release["beta"].set()
    assert await beta == f"beta:{BETA_TOKEN}:1"

    assert manager.active_count() == 0
    assert manager.resource_binding() == (None, None)
    assert resource.operations_for("alpha") == [
        ("alpha", ALPHA_TOKEN, "alpha:first", 1),
        ("alpha", ALPHA_TOKEN, "alpha:second", 1),
    ]
    assert resource.operations_for("beta") == [
        ("beta", BETA_TOKEN, "beta:first", 1),
        ("beta", BETA_TOKEN, "beta:second", 1),
    ]


@pytest.mark.asyncio
async def test_other_request_mutating_shared_binding_does_not_affect_lease():
    app, manager, resource = make_app("tenancy-binding")
    started = asyncio.Event()
    release = asyncio.Event()
    seen = {}

    @app.get("/alpha")
    async def alpha_handler(request):
        lease = request.ctx.tenant_lease
        seen["alpha_lease"] = lease
        await lease.execute("alpha:before")
        started.set()
        await release.wait()
        return text((await lease.execute("alpha:after"))["authorization"])

    @app.get("/beta")
    async def beta_handler(request):
        lease = request.ctx.tenant_lease
        # Directly mutate the legacy shared binding, simulating an extension
        # that writes the "current" tenant onto the shared object.
        resource._bind(999, lease.identity)
        return text("beta")

    alpha_task = asyncio.create_task(
        app.asgi_client.get("/alpha", headers={"X-Tenant-ID": "alpha"})
    )
    await asyncio.wait_for(started.wait(), 5)

    _, beta_response = await app.asgi_client.get(
        "/beta", headers={"X-Tenant-ID": "beta"}
    )
    assert beta_response.text == "beta"
    assert resource.active_identity.tenant_id == "beta"

    release.set()
    _, alpha_response = await alpha_task
    assert alpha_response.text == ALPHA_TOKEN
    assert seen["alpha_lease"].tenant_id == "alpha"
    assert manager.active_count() == 0


@pytest.mark.asyncio
async def test_same_tenant_authorization_survives_other_lease_release():
    app, manager, resource = make_app("tenancy-refcount")
    barrier = Barrier(("one", "two"))
    leases = {}

    @app.get("/hold/<slot>")
    async def hold(request, slot):
        lease = request.ctx.tenant_lease
        leases[slot] = lease
        await lease.execute(f"{slot}:first")
        barrier.started[slot].set()
        await barrier.release[slot].wait()
        return text((await lease.execute(f"{slot}:second"))["authorization"])

    async def call(slot):
        _, response = await app.asgi_client.get(
            f"/hold/{slot}", headers={"X-Tenant-ID": "alpha"}
        )
        return response.text

    one = asyncio.create_task(call("one"))
    await barrier.wait_started("one")
    two = asyncio.create_task(call("two"))
    await barrier.wait_started("two")

    assert manager.active_count() == 2
    assert manager.authorization_in_use("alpha", ALPHA_TOKEN) is True

    barrier.release["one"].set()
    assert await one == ALPHA_TOKEN
    # Releasing request one must not clear the authorization request two is
    # still using, and the shared binding must remain on alpha.
    assert manager.authorization_in_use("alpha", ALPHA_TOKEN) is True
    assert manager.resource_binding()[0] == "alpha"
    assert manager.resource_binding()[1] == leases["two"].lease_id

    barrier.release["two"].set()
    assert await two == ALPHA_TOKEN
    assert manager.authorization_in_use("alpha", ALPHA_TOKEN) is False
    assert manager.resource_binding() == (None, None)


@pytest.mark.asyncio
async def test_streaming_responses_keep_identity_across_chunks():
    app, manager, resource = make_app("tenancy-stream")
    barrier = Barrier(("alpha", "beta"))

    @app.get("/stream/<tenant_id>")
    async def stream(request, tenant_id):
        lease = request.ctx.tenant_lease
        response = await request.respond(content_type="text/plain")
        first = await lease.execute(f"{tenant_id}:chunk-1")
        await response.send(f"{tenant_id}:{first['authorization']};")
        barrier.started[tenant_id].set()
        await barrier.release[tenant_id].wait()
        second = await lease.execute(f"{tenant_id}:chunk-2")
        await response.send(f"{tenant_id}:{second['authorization']};")
        await response.eof()

    async def call(tenant_id):
        _, response = await app.asgi_client.get(
            f"/stream/{tenant_id}",
            headers={"X-Tenant-ID": tenant_id},
        )
        return response.text

    alpha = asyncio.create_task(call("alpha"))
    await barrier.wait_started("alpha")
    beta = asyncio.create_task(call("beta"))
    await barrier.wait_started("beta")

    barrier.release["alpha"].set()
    barrier.release["beta"].set()

    assert await alpha == f"alpha:{ALPHA_TOKEN};alpha:{ALPHA_TOKEN};"
    assert await beta == f"beta:{BETA_TOKEN};beta:{BETA_TOKEN};"
    assert manager.active_count() == 0


@pytest.mark.asyncio
async def test_cancelled_request_returns_lease_and_late_use_fails():
    app, manager, resource = make_app("tenancy-cancel")
    started = asyncio.Event()
    held = {}

    @app.get("/hold")
    async def hold(request):
        lease = request.ctx.tenant_lease
        held["lease"] = lease
        started.set()
        await asyncio.sleep(10)
        return text("never")

    task = asyncio.create_task(
        app.asgi_client.get("/hold", headers={"X-Tenant-ID": "alpha"})
    )
    await asyncio.wait_for(started.wait(), 5)
    assert manager.active_count() == 1

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0)

    assert manager.active_count() == 0
    assert manager.resource_binding() == (None, None)
    with pytest.raises(LeaseReleased):
        await held["lease"].execute("too-late")


@pytest.mark.asyncio
async def test_generation_rotation_does_not_rewrite_inflight_lease():
    app, manager, resource = make_app("tenancy-rotation")
    started = asyncio.Event()
    release = asyncio.Event()
    seen = {}

    @app.get("/hold")
    async def hold(request):
        lease = request.ctx.tenant_lease
        seen["lease"] = lease
        await lease.execute("before-rotation")
        started.set()
        await release.wait()
        return text((await lease.execute("after-rotation"))["authorization"])

    @app.get("/fresh")
    async def fresh(request):
        return text(
            (await request.ctx.tenant_lease.execute("fresh"))["authorization"]
        )

    holder = asyncio.create_task(
        app.asgi_client.get("/hold", headers={"X-Tenant-ID": "alpha"})
    )
    await asyncio.wait_for(started.wait(), 5)

    new_snapshot = manager.cache.rotate_authorization("alpha", "token-new")
    assert new_snapshot.generation == 2
    assert seen["lease"].generation == 1
    assert seen["lease"].authorization == ALPHA_TOKEN

    release.set()
    _, response = await holder
    assert response.text == ALPHA_TOKEN

    # After the old lease is returned, a new request sees the new generation.
    _, fresh_response = await app.asgi_client.get(
        "/fresh", headers={"X-Tenant-ID": "alpha"}
    )
    assert fresh_response.text == "token-new"
    assert manager.authorization_in_use("alpha", ALPHA_TOKEN) is False
    assert manager.authorization_in_use("alpha", "token-new") is False


@pytest.mark.asyncio
@pytest.mark.parametrize("headers", ({}, {"X-Tenant-ID": "unknown"}))
async def test_missing_or_unknown_tenant_is_unauthorized(headers):
    app, manager, resource = make_app("tenancy-auth")

    @app.get("/")
    async def handler(request):
        return text("unreachable")

    _, response = await app.asgi_client.get("/", headers=headers)
    assert response.status == 401
    assert manager.active_count() == 0
    assert resource.operations == []


@pytest.mark.asyncio
async def test_request_cannot_mix_tenants_and_error_path_returns_lease():
    app, manager, resource = make_app("tenancy-mixed", required=False)

    @app.get("/")
    async def handler(request):
        manager.borrow(request, "alpha")
        manager.borrow(request, "beta")
        return text("unreachable")

    _, response = await app.asgi_client.get(
        "/", headers={"X-Tenant-ID": "alpha"}
    )
    assert response.status == 500
    assert manager.active_count() == 0
    assert manager.resource_binding() == (None, None)


@pytest.mark.asyncio
async def test_task_outliving_request_keeps_frozen_identity_and_fails_closed():
    app, manager, resource = make_app("tenancy-delayed")
    recorded = {}

    @app.get("/spawn")
    async def spawn(request):
        lease = request.ctx.tenant_lease

        async def delayed():
            await asyncio.sleep(0.05)
            recorded["identity"] = TenantLease.current_identity()
            try:
                recorded["result"] = await lease.execute("delayed")
            except LeaseReleased as e:
                recorded["error"] = e

        asyncio.create_task(delayed())
        return text("ok")

    _, response = await app.asgi_client.get(
        "/spawn", headers={"X-Tenant-ID": "alpha"}
    )
    assert response.status == 200
    await asyncio.sleep(0.1)

    # The delayed task inherited the request's context snapshot, so it still
    # knows which tenant it belongs to...
    assert recorded["identity"].tenant_id == "alpha"
    assert recorded["identity"].authorization == ALPHA_TOKEN
    # ...but the lease itself was returned, so operations fail closed instead
    # of falling back to the shared binding.
    assert "error" in recorded
    assert "result" not in recorded
    assert manager.active_count() == 0


def test_request_finalizers_run_in_lifo_order():
    from sanic.request.types import Request

    events = []
    request = Request(b"/", {}, None, "GET", None, None)
    request.add_finalizer(lambda: events.append("first"))
    request.add_finalizer(lambda: events.append("second"))

    async def run():
        await request.run_finalizers()

    asyncio.run(run())
    assert events == ["second", "first"]
    assert request.clear_finalizers() == []


def test_identity_is_immutable_and_attributes_are_read_only():
    identity = TenantIdentity(
        tenant_id="alpha",
        authorization=ALPHA_TOKEN,
        attributes={"region": "eu"},
    )
    with pytest.raises(Exception):
        identity.tenant_id = "beta"
    with pytest.raises(TypeError):
        identity.attributes["region"] = "us"


def test_cache_snapshot_is_stable_until_rotation():
    cache = TenantCache(TENANTS)
    alpha = cache.snapshot("alpha")
    assert alpha.authorization == ALPHA_TOKEN
    assert alpha.generation == 1
    rotated = cache.rotate_authorization("alpha", "token-new")
    assert alpha.authorization == ALPHA_TOKEN
    assert rotated.authorization == "token-new"
    assert rotated.generation == 2


def test_manager_borrow_is_idempotent_and_release_is_safe():
    app, manager, resource = make_app("tenancy-manager")

    request = SimpleNamespace(
        ctx=SimpleNamespace(),
        add_finalizer=lambda callback: None,
    )
    lease = manager.borrow(request, "alpha")
    again = manager.borrow(request, "alpha")
    assert again is lease
    with pytest.raises(TenantBindingError):
        manager.borrow(request, "beta")

    manager.release(lease)
    manager.release(lease)
    assert manager.active_count() == 0
    assert manager.resource_binding() == (None, None)
