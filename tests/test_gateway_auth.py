import dataclasses

from types import SimpleNamespace

import pytest

from sanic import Blueprint, Sanic
from sanic.gateway import (
    AuthMappingConflictError,
    EmployeeAuthGateway,
    GatewayError,
    GatewayNotFinalizedError,
    GatewaySealedError,
    employee_required,
)
from sanic.response import text


EMPLOYEE = {"X-Employee-Id": "emp-42"}


def build_employee_app(name="gw_app"):
    app = Sanic(name)
    gateway = EmployeeAuthGateway(app)

    bp = Blueprint("accounts", url_prefix="/accounts")

    @bp.get("/profile", ctx_requires_employee=True)
    async def profile(request):
        return text("profile")

    @bp.get("/status")
    async def status(request):
        return text("ok")

    bp_copy = bp.copy("accounts_copy", url_prefix="/accounts_v2", version=2)
    group = Blueprint.group(bp, bp_copy, url_prefix="/api")
    app.blueprint(group)

    @app.get("/delayed", apply=False, ctx_requires_employee=True)
    async def delayed(request):
        return text("delayed")

    future = next(f for f in app._future_routes if f.uri == "/delayed")
    app._apply_route(future)

    return app, gateway


def mapping_index(gateway):
    return {
        (entry.method, entry.path, entry.host): entry
        for entry in gateway.mapping
    }


def test_final_mapping_after_copy_group_and_delayed_registration():
    app, gateway = build_employee_app()
    mapping = gateway.finalize()

    assert gateway.sealed
    assert isinstance(mapping, tuple)
    index = mapping_index(gateway)

    employee_paths = {
        ("GET", "/api/accounts/profile", None),
        ("GET", "/v2/api/accounts_v2/profile", None),
        ("GET", "/delayed", None),
    }
    public_paths = {
        ("GET", "/api/accounts/status", None),
        ("GET", "/v2/api/accounts_v2/status", None),
    }
    assert set(index) == employee_paths | public_paths
    for key in employee_paths:
        assert index[key].requires_employee is True
    for key in public_paths:
        assert index[key].requires_employee is False

    versioned = index[("GET", "/v2/api/accounts_v2/profile", None)]
    assert versioned.version == 2
    assert versioned.route_name.endswith("accounts_copy.profile")


def test_mapping_is_immutable_and_finalize_idempotent():
    _, gateway = build_employee_app("gw_immutable")

    with pytest.raises(GatewayError):
        _ = gateway.mapping

    first = gateway.finalize()
    second = gateway.finalize()
    assert first is second

    entry = first[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.requires_employee = False

    report = gateway.report()
    assert "/api/accounts/profile" in report
    assert "EMPLOYEE" in report
    assert "public" in report


@pytest.mark.asyncio
async def test_requests_follow_mapping_for_copy_group_and_delayed():
    app, gateway = build_employee_app("gw_requests")
    gateway.finalize()

    _, response = await app.asgi_client.get("/api/accounts/profile")
    assert response.status_code == 401
    _, response = await app.asgi_client.get(
        "/api/accounts/profile", headers=EMPLOYEE
    )
    assert response.status_code == 200
    assert response.text == "profile"

    _, response = await app.asgi_client.get("/api/accounts/status")
    assert response.status_code == 200

    _, response = await app.asgi_client.get("/v2/api/accounts_v2/profile")
    assert response.status_code == 401
    _, response = await app.asgi_client.get(
        "/v2/api/accounts_v2/profile", headers=EMPLOYEE
    )
    assert response.status_code == 200

    _, response = await app.asgi_client.get("/delayed")
    assert response.status_code == 401
    _, response = await app.asgi_client.get("/delayed", headers=EMPLOYEE)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_overlapping_path_with_different_methods():
    app = Sanic("gw_methods")
    gateway = EmployeeAuthGateway(app)

    @app.get("/resource")
    async def get_resource(request):
        return text("read")

    @app.post("/resource", ctx_requires_employee=True)
    async def post_resource(request):
        return text("write")

    gateway.finalize()
    index = mapping_index(gateway)
    assert index[("GET", "/resource", None)].requires_employee is False
    assert index[("POST", "/resource", None)].requires_employee is True

    _, response = await app.asgi_client.get("/resource")
    assert response.status_code == 200

    _, response = await app.asgi_client.post("/resource")
    assert response.status_code == 401

    _, response = await app.asgi_client.post("/resource", headers=EMPLOYEE)
    assert response.status_code == 200
    assert response.text == "write"


@pytest.mark.asyncio
async def test_decisions_follow_version_and_host_restrictions():
    app = Sanic("gw_version_host")
    gateway = EmployeeAuthGateway(app)

    @app.get("/thing", version=1)
    async def thing_v1(request):
        return text("v1")

    @app.get("/thing", version=2, ctx_requires_employee=True)
    async def thing_v2(request):
        return text("v2")

    @app.get(
        "/internal",
        host="internal.example.com",
        ctx_requires_employee=True,
    )
    async def internal(request):
        return text("internal")

    gateway.finalize()
    index = mapping_index(gateway)
    assert index[("GET", "/v1/thing", None)].requires_employee is False
    assert index[("GET", "/v2/thing", None)].requires_employee is True
    host_entry = index[("GET", "/internal", "internal.example.com")]
    assert host_entry.requires_employee is True

    _, response = await app.asgi_client.get("/v1/thing")
    assert response.status_code == 200
    _, response = await app.asgi_client.get("/v2/thing")
    assert response.status_code == 401
    _, response = await app.asgi_client.get("/v2/thing", headers=EMPLOYEE)
    assert response.status_code == 200

    host = {"host": "internal.example.com"}
    _, response = await app.asgi_client.get("/internal", headers=host)
    assert response.status_code == 401
    _, response = await app.asgi_client.get(
        "/internal", headers={**host, **EMPLOYEE}
    )
    assert response.status_code == 200
    _, response = await app.asgi_client.get(
        "/internal", headers={"host": "other.example.com"}
    )
    assert response.status_code == 404


def test_conflicting_definitions_rejected_at_finalize():
    app = Sanic("gw_conflict")
    gateway = EmployeeAuthGateway(app)

    @app.get("/api/thing", ctx_requires_employee=True)
    async def thing(request):
        return text("secret")

    bp = Blueprint("public_api", url_prefix="/api")

    @bp.get("/thing")
    async def thing_public(request):
        return text("public")

    overwrite = bp.copy("public_api_copy", allow_route_overwrite=True)
    app.blueprint(overwrite)

    with pytest.raises(AuthMappingConflictError) as excinfo:
        gateway.finalize()

    message = str(excinfo.value)
    assert "/api/thing" in message
    assert "requires_employee=True" in message
    assert "requires_employee=False" in message
    assert not gateway.sealed


@pytest.mark.asyncio
async def test_conflict_leaves_gateway_fail_closed():
    app = Sanic("gw_conflict_closed")
    gateway = EmployeeAuthGateway(app)

    @app.get("/api/thing", ctx_requires_employee=True)
    async def thing(request):
        return text("secret")

    bp = Blueprint("public_api", url_prefix="/api")

    @bp.get("/thing")
    async def thing_public(request):
        return text("public")

    overwrite = bp.copy("public_api_copy", allow_route_overwrite=True)
    app.blueprint(overwrite)

    with pytest.raises(AuthMappingConflictError):
        gateway.finalize()

    # A conflicting application must not start: the startup listener
    # keeps raising the conflict instead of serving requests.
    with pytest.raises(AuthMappingConflictError):
        await app.asgi_client.get("/api/thing", headers=EMPLOYEE)


def test_consistent_overwrite_is_not_a_conflict():
    app = Sanic("gw_consistent")
    gateway = EmployeeAuthGateway(app)

    @app.get("/api/thing", ctx_requires_employee=True)
    async def thing(request):
        return text("secret")

    bp = Blueprint("same_api", url_prefix="/api")

    @bp.get("/thing", ctx_requires_employee=True)
    async def thing_same(request):
        return text("secret too")

    overwrite = bp.copy("same_api_copy", allow_route_overwrite=True)
    app.blueprint(overwrite)

    mapping = gateway.finalize()
    assert len(mapping) == 1
    assert mapping[0].requires_employee is True


@pytest.mark.asyncio
async def test_registration_after_seal_is_rejected():
    app = Sanic("gw_sealed")
    gateway = EmployeeAuthGateway(app)

    @app.get("/a")
    async def a(request):
        return text("a")

    gateway.finalize()

    with pytest.raises(GatewaySealedError):

        @app.get("/b")
        async def b(request):
            return text("b")

    _, response = await app.asgi_client.get("/a")
    assert response.status_code == 200

    with pytest.raises(GatewaySealedError):

        @app.get("/c")
        async def c(request):
            return text("c")


@pytest.mark.asyncio
async def test_explicit_invalidation_then_refinalize():
    app = Sanic("gw_invalidate")
    gateway = EmployeeAuthGateway(app)

    @app.get("/a")
    async def a(request):
        return text("a")

    gateway.finalize()
    gateway.invalidate()
    assert not gateway.sealed

    _, response = await app.asgi_client.get("/a")
    assert response.status_code == 500

    @app.get("/b", ctx_requires_employee=True)
    async def b(request):
        return text("b")

    gateway.finalize()
    index = mapping_index(gateway)
    assert set(index) == {
        ("GET", "/a", None),
        ("GET", "/b", None),
    }

    _, response = await app.asgi_client.get("/a")
    assert response.status_code == 200
    _, response = await app.asgi_client.get("/b")
    assert response.status_code == 401
    _, response = await app.asgi_client.get("/b", headers=EMPLOYEE)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_amend_context_manager_reseals():
    app = Sanic("gw_amend")
    gateway = EmployeeAuthGateway(app)

    @app.get("/a")
    async def a(request):
        return text("a")

    gateway.finalize()

    with gateway.amend():

        @app.get("/new", ctx_requires_employee=True)
        async def new(request):
            return text("new")

    assert gateway.sealed
    assert ("GET", "/new", None) in mapping_index(gateway)

    _, response = await app.asgi_client.get("/new")
    assert response.status_code == 401
    _, response = await app.asgi_client.get("/new", headers=EMPLOYEE)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_fail_closed_before_finalize():
    app = Sanic("gw_unfinalized")
    gateway = EmployeeAuthGateway(app)

    @app.get("/a")
    async def a(request):
        return text("a")

    request = SimpleNamespace(route=app.router.routes[0], headers={})
    with pytest.raises(GatewayNotFinalizedError):
        await gateway._enforce(request)


@pytest.mark.asyncio
async def test_handler_decorator_and_custom_async_verifier():
    app = Sanic("gw_custom")

    async def verifier(request):
        return request.headers.get("x-employee-id") == "emp-42"

    gateway = EmployeeAuthGateway(app, verifier=verifier)

    @app.get("/decorated")
    @employee_required
    async def decorated(request):
        return text("decorated")

    gateway.finalize()
    index = mapping_index(gateway)
    assert index[("GET", "/decorated", None)].requires_employee is True

    _, response = await app.asgi_client.get("/decorated")
    assert response.status_code == 401
    _, response = await app.asgi_client.get(
        "/decorated", headers={"x-employee-id": "intruder"}
    )
    assert response.status_code == 401
    _, response = await app.asgi_client.get("/decorated", headers=EMPLOYEE)
    assert response.status_code == 200


def test_startup_listener_finalizes():
    app = Sanic("gw_listener")
    gateway = EmployeeAuthGateway(app)

    @app.get("/a")
    async def a(request):
        return text("a")

    listeners = [
        future.listener
        for future in app._future_listeners
        if future.event == "after_server_start"
    ]
    assert gateway._finalize_on_startup in listeners

    assert not gateway.sealed
    gateway.finalize()
    assert gateway.sealed
