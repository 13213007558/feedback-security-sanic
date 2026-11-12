"""Contract tests: request-method semantics vs. the handlers that run.

The application under test enforces authentication in a *request* middleware
(a pre-handler policy) with two distinct scopes:

* a read scope for safe methods, and
* a write scope for state-changing methods.

The tests pin down, through the real router and the in-process ASGI client,
that the method the policy sees is the same semantic action the dispatched
handler performs. They cover framework-generated responses (auto HEAD,
OPTIONS and 405), several methods sharing one path, and versioned routes.

A deliberately wrong policy is included as a control: it treats every method
other than POST as a read. That policy silently lets PUT/PATCH/DELETE mutate
state with only read credentials, which the correct policy must reject.

Framework-generated responses are never judged by status code alone. Every
case also asserts on recorded side effects so that "the business handler ran"
and "the framework answered without running business code" are distinguishable.
"""

import asyncio

import pytest

from sanic import Sanic, text
from sanic.constants import SAFE_HTTP_METHODS
from sanic.exceptions import Forbidden, MethodNotAllowed, Unauthorized


READ_TOKEN = "read-scope-token"
WRITE_TOKEN = "write-scope-token"

# Methods that change server state. Everything else is treated as a read.
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
READ_METHODS = frozenset(SAFE_HTTP_METHODS)


class CallLog:
    """Records both business-code invocation and real state mutations."""

    def __init__(self):
        self.invocations = []
        self.mutations = []
        self.policy_decisions = []

    def reset(self):
        self.invocations.clear()
        self.mutations.clear()
        self.policy_decisions.clear()


def correct_policy(method):
    """Classify the request by HTTP semantics."""
    return "write" if method in WRITE_METHODS else "read"


def broken_only_post_policy(method):
    """Control policy: only POST is considered state-changing.

    PUT, PATCH and DELETE are mislabelled as reads, so a read-only token is
    wrongly accepted for genuine state changes.
    """
    return "write" if method == "POST" else "read"


def _build_app(policy):
    app = Sanic(f"contract-{policy.__name__}")
    calls = CallLog()
    app.ctx.calls = calls

    def enforce(request):
        required_scope = policy(request.method)
        token = request.headers.get("X-Auth")
        calls.policy_decisions.append((request.method, required_scope))
        if token is None:
            raise Unauthorized("authentication required")
        if required_scope == "write" and token != WRITE_TOKEN:
            raise Forbidden("write scope required")
        if required_scope == "read" and token not in (
            READ_TOKEN,
            WRITE_TOKEN,
        ):
            raise Forbidden("read scope required")

    app.register_middleware(enforce, "request")

    async def read_handler(request):
        calls.invocations.append(("read", request.path, request.method))
        return text("representation")

    async def write_handler(request):
        calls.invocations.append(("write", request.path, request.method))
        calls.mutations.append((request.path, request.method))
        return text("accepted")

    async def options_handler(request):
        calls.invocations.append(("options", request.path, request.method))
        return text("", headers={"Allow": "GET, HEAD, OPTIONS"})

    # Same path, multiple methods; HEAD is served by the read handler so that
    # an automatic HEAD never triggers a mutation.
    app.add_route(
        read_handler,
        "/resource",
        methods=["GET", "HEAD"],
        name="resource.read",
    )
    app.add_route(
        write_handler,
        "/resource",
        methods=["POST", "PUT", "PATCH", "DELETE"],
        name="resource.write",
    )

    # A path with an explicit, business-defined OPTIONS handler.
    app.add_route(
        read_handler, "/described", methods=["GET"], name="described.read"
    )
    app.add_route(
        options_handler,
        "/described",
        methods=["OPTIONS"],
        name="described.options",
    )

    # Versioned routes: each version exposes a read and a write action.
    for version in (1, 2):
        app.add_route(
            read_handler,
            "/items",
            methods=["GET", "HEAD"],
            version=version,
            name=f"v{version}.items.read",
        )
        app.add_route(
            write_handler,
            "/items",
            methods=["POST"],
            version=version,
            name=f"v{version}.items.write",
        )

    return app


@pytest.fixture
def make_app():
    def _make(policy=correct_policy):
        return _build_app(policy)

    return _make


def request_response(app, method, path, token=None):
    """Synchronous wrapper around the in-process ASGI test client."""
    headers = {} if token is None else {"X-Auth": token}

    async def _run():
        client = app.asgi_client
        result = await getattr(client, method)(path, headers=headers)
        if isinstance(result, tuple):
            return result
        return None, result

    return asyncio.run(_run())


# --------------------------------------------------------------------------- #
# 1. Routing contract: method -> concrete handler, independent of auth.
# --------------------------------------------------------------------------- #


def test_router_maps_each_method_to_a_concrete_handler(make_app):
    app = make_app()
    app.router.finalize()

    expected = {
        "GET": "read_handler",
        "HEAD": "read_handler",
        "POST": "write_handler",
        "PUT": "write_handler",
        "PATCH": "write_handler",
        "DELETE": "write_handler",
    }
    for method, handler_name in expected.items():
        route, handler, _ = app.router.get("/resource", method, None)
        assert handler.__name__ == handler_name
        assert method in route.methods


def test_router_resolves_versioned_routes_independently(make_app):
    app = make_app()
    app.router.finalize()

    for version in (1, 2):
        prefix = f"/v{version}/items"
        read_route, read_handler, _ = app.router.get(prefix, "GET", None)
        write_route, write_handler, _ = app.router.get(prefix, "POST", None)
        assert read_handler.__name__ == "read_handler"
        assert write_handler.__name__ == "write_handler"
        assert read_route is not write_route
        assert read_route.path == write_route.path == f"v{version}/items"


def test_router_reports_allowed_methods_for_unregistered_method(make_app):
    app = make_app()
    app.router.finalize()

    with pytest.raises(MethodNotAllowed) as exc_info:
        app.router.get("/resource", "OPTIONS", None)

    error = exc_info.value
    assert error.status_code == 405
    assert set(error.allowed_methods) == {
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }


# --------------------------------------------------------------------------- #
# 2. Framework-generated responses do not execute business code.
# --------------------------------------------------------------------------- #


def test_framework_405_runs_policy_but_not_business_handler(make_app):
    app = make_app()
    _, response = request_response(
        app, "options", "/resource", token=READ_TOKEN
    )

    assert response.status_code == 405
    # The framework answer still went through the pre-handler policy, and the
    # policy observed the real method rather than a mapped one.
    assert app.ctx.calls.policy_decisions == [("OPTIONS", "read")]
    # The distinguishing assertion: no business code ran and nothing mutated.
    assert app.ctx.calls.invocations == []
    assert app.ctx.calls.mutations == []


def test_framework_405_is_distinguishable_from_a_real_handler(make_app):
    app = make_app()

    # Framework-generated OPTIONS on /resource (no OPTIONS route): the router
    # answers 405 itself, so no business code runs.
    _, framework_response = request_response(
        app, "options", "/resource", token=READ_TOKEN
    )
    assert framework_response.status_code == 405
    framework_invocations = list(app.ctx.calls.invocations)
    assert framework_invocations == []

    # Business-defined OPTIONS on /described (explicit OPTIONS route): the
    # same method now reaches a handler and returns 200.
    _, explicit_response = request_response(
        app, "options", "/described", token=READ_TOKEN
    )
    assert explicit_response.status_code == 200
    assert ("options", "/described", "OPTIONS") in app.ctx.calls.invocations
    assert app.ctx.calls.mutations == []


def test_status_code_alone_cannot_prove_handler_execution(make_app):
    """Two requests share a status code but only one runs business code."""
    app = make_app()

    # Authenticated GET is denied by no one and runs the read handler (200).
    _, allowed = request_response(
        app, "get", "/resource", token=READ_TOKEN
    )
    assert allowed.status_code == 200
    assert ("read", "/resource", "GET") in app.ctx.calls.invocations

    app.ctx.calls.reset()

    # Explicit OPTIONS handler also yields 200, but is a different handler and
    # must never be confused with a read of the resource.
    _, options_response = request_response(
        app, "options", "/described", token=READ_TOKEN
    )
    assert options_response.status_code == 200
    assert app.ctx.calls.invocations == [
        ("options", "/described", "OPTIONS")
    ]
    assert app.ctx.calls.mutations == []


def test_auto_head_serves_read_handler_without_mutation(make_app):
    app = make_app()
    _, response = request_response(app, "head", "/resource", token=READ_TOKEN)

    assert response.status_code == 200
    # HEAD reuses the read handler, never the write handler.
    assert app.ctx.calls.invocations == [
        ("read", "/resource", "HEAD")
    ]
    assert app.ctx.calls.mutations == []


# --------------------------------------------------------------------------- #
# 3. Correct policy: the pre-handler decision matches the executed action.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "method,path,token",
    [
        ("get", "/resource", READ_TOKEN),
        ("head", "/resource", READ_TOKEN),
        ("options", "/described", READ_TOKEN),
        ("post", "/resource", WRITE_TOKEN),
        ("put", "/resource", WRITE_TOKEN),
        ("patch", "/resource", WRITE_TOKEN),
        ("delete", "/resource", WRITE_TOKEN),
        ("get", "/v1/items", READ_TOKEN),
        ("head", "/v2/items", READ_TOKEN),
        ("post", "/v2/items", WRITE_TOKEN),
    ],
)
def test_correct_policy_allows_matching_scope(make_app, method, path, token):
    app = make_app()
    _, response = request_response(app, method, path, token=token)

    assert response.status_code == 200
    assert app.ctx.calls.policy_decisions == [
        (method.upper(), correct_policy(method.upper()))
    ]


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/resource"),
        ("put", "/resource"),
        ("patch", "/resource"),
        ("delete", "/resource"),
        ("post", "/v1/items"),
    ],
)
def test_correct_policy_rejects_write_with_read_token(
    make_app, method, path
):
    app = make_app()
    _, response = request_response(app, method, path, token=READ_TOKEN)

    assert response.status_code == 403
    assert app.ctx.calls.policy_decisions == [(method.upper(), "write")]
    # Rejection happens before the handler, so state is untouched.
    assert app.ctx.calls.invocations == []
    assert app.ctx.calls.mutations == []


@pytest.mark.parametrize(
    "method,path",
    [("get", "/resource"), ("head", "/resource"), ("get", "/v1/items")]
)
def test_correct_policy_requires_authentication(make_app, method, path):
    app = make_app()
    _, response = request_response(app, method, path)

    assert response.status_code == 401
    assert app.ctx.calls.invocations == []
    assert app.ctx.calls.mutations == []


def test_write_token_satisfies_read_scope(make_app):
    app = make_app()
    _, response = request_response(
        app, "get", "/resource", token=WRITE_TOKEN
    )

    assert response.status_code == 200
    assert app.ctx.calls.invocations == [("read", "/resource", "GET")]
    assert app.ctx.calls.mutations == []


def test_only_write_methods_record_mutations(make_app):
    app = make_app()
    for method in ("get", "head"):
        request_response(app, method, "/resource", token=READ_TOKEN)
    for method in ("post", "put", "patch", "delete"):
        request_response(app, method, "/resource", token=WRITE_TOKEN)

    mutated_methods = {method for _, method in app.ctx.calls.mutations}
    assert mutated_methods == {"POST", "PUT", "PATCH", "DELETE"}
    assert all(
        invocation[0] == "read"
        for invocation in app.ctx.calls.invocations
        if invocation[2] in READ_METHODS
    )


# --------------------------------------------------------------------------- #
# 4. Control: the broken policy mistakes state changes for reads.
# --------------------------------------------------------------------------- #


def test_broken_policy_blocks_post_but_admits_other_writes_as_reads(make_app):
    app = make_app(broken_only_post_policy)

    # POST is still recognized as a write.
    _, post_response = request_response(
        app, "post", "/resource", token=READ_TOKEN
    )
    assert post_response.status_code == 403

    # The vulnerability: PUT/PATCH/DELETE pass with a read-only token and
    # actually mutate state.
    leaked = {}
    for method in ("put", "patch", "delete"):
        app.ctx.calls.reset()
        _, response = request_response(
            app, method, "/resource", token=READ_TOKEN
        )
        leaked[method] = response.status_code

    assert leaked == {"put": 200, "patch": 200, "delete": 200}
    # Re-run one to assert the side effect the correct policy would prevent.
    app.ctx.calls.reset()
    request_response(app, "delete", "/resource", token=READ_TOKEN)
    assert app.ctx.calls.mutations == [("/resource", "DELETE")]


def test_broken_policy_decision_diverges_from_handler_action(make_app):
    correct_app = make_app(correct_policy)
    broken_app = make_app(broken_only_post_policy)

    request_response(
        correct_app, "delete", "/resource", token=READ_TOKEN
    )
    request_response(
        broken_app, "delete", "/resource", token=READ_TOKEN
    )

    # Both policies see the identical method; only the classification differs.
    assert correct_app.ctx.calls.policy_decisions == [("DELETE", "write")]
    assert broken_app.ctx.calls.policy_decisions == [("DELETE", "read")]
    # The correct policy blocks the mutation; the broken one allows it.
    assert correct_app.ctx.calls.mutations == []
    assert broken_app.ctx.calls.mutations == [("/resource", "DELETE")]


def test_broken_policy_still_protects_reads(make_app):
    app = make_app(broken_only_post_policy)
    _, response = request_response(app, "get", "/resource")

    assert response.status_code == 401
    assert app.ctx.calls.invocations == []
