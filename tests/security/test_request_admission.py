from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sanic.security import (
    PolicyAuthorizationFailed,
    PolicyNotActive,
    SecurityPolicyRuntime,
    SecurityPolicySnapshot,
    fields_from_config,
)


def base():
    from sanic.config import Config

    return SecurityPolicySnapshot.build(1, fields_from_config(Config()))


def fake_request(conn_info, headers=None):
    request = SimpleNamespace(
        conn_info=conn_info,
        ctx=SimpleNamespace(),
        headers=Mock(),
    )
    values = {key.lower(): value for key, value in (headers or {}).items()}

    def getone(name, default=None):
        return values.get(name.lower(), default)

    def getall(name, default=None):
        value = values.get(name.lower(), default)
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    request.headers.getone.side_effect = getone
    request.headers.getall.side_effect = getall
    return request


def client_ip(request, runtime):
    runtime.pin_request(request)
    policy = request.ctx.sanic_security_policy
    config = policy.forwarded_config
    from sanic.headers import parse_xforwarded

    forwarded = parse_xforwarded(request.headers, config) or {}
    return forwarded.get("for")


def test_mixed_proxy_fields_are_impossible_within_one_request():
    runtime = SecurityPolicyRuntime(base(), enabled=True, name="w1")
    conn = SimpleNamespace(ctx=SimpleNamespace())
    old = fake_request(conn, {"X-Forwarded-For": "198.51.100.7, 203.0.113.9"})
    old_policy = runtime.pin_request(old)
    assert old_policy.fields["PROXIES_COUNT"] is None
    assert old_policy.fields["REAL_IP_HEADER"] is None
    # Generation 1 trusts no proxy header, so this must not be spoofable.
    assert client_ip(old, runtime) is None

    target = old_policy.updated(
        2,
        {
            "PROXIES_COUNT": 2,
            "REAL_IP_HEADER": "X-Real-IP",
            "FORWARDED_FOR_HEADER": "X-Forwarded-For",
        },
    )
    runtime.stage(1, target)
    runtime.commit(1, target.generation, target.fingerprint)

    # Same connection is explicit old generation: every field comes from
    # generation 1, even though generation 2 exists.
    same = fake_request(
        conn,
        {
            "X-Forwarded-For": "198.51.100.7, 203.0.113.9",
            "X-Real-IP": "192.0.2.44",
        },
    )
    pinned = runtime.pin_request(same)
    assert pinned.generation == 1
    assert pinned.fields["PROXIES_COUNT"] is None
    assert pinned.fields["REAL_IP_HEADER"] is None
    assert client_ip(same, runtime) is None

    # A brand-new connection gets the whole generation 2 policy.
    fresh = fake_request(
        SimpleNamespace(ctx=SimpleNamespace()),
        {
            "X-Forwarded-For": "198.51.100.7, 203.0.113.9",
            "X-Real-IP": "192.0.2.44",
        },
    )
    new_policy = runtime.pin_request(fresh)
    assert new_policy.generation == 2
    assert client_ip(fresh, runtime) == "192.0.2.44"


def test_staged_generation_is_not_used_by_requests():
    runtime = SecurityPolicyRuntime(base(), enabled=True, name="w1")
    conn = SimpleNamespace(ctx=SimpleNamespace())
    request = fake_request(conn, {"X-Real-IP": "192.0.2.44"})
    target = base().updated(2, {"REAL_IP_HEADER": "X-Real-IP"})
    runtime.stage(1, target)

    assert runtime.pin_request(request).generation == 1
    assert client_ip(request, runtime) is None


def test_auth_required_uses_snapshot_fields_only():
    runtime = SecurityPolicyRuntime(base(), enabled=True, name="w1")
    target = base().updated(
        2,
        {
            "AUTH_REQUIRED": True,
            "AUTH_SCHEMES": ("Bearer",),
            "AUTH_TOKEN": "generation-two",
        },
    )
    conn = SimpleNamespace(ctx=SimpleNamespace())
    runtime.pin_request(fake_request(conn, {}))
    assert conn.ctx.sanic_security_generation == 1

    runtime.stage(1, target)
    runtime.commit(1, target.generation, target.fingerprint)

    old = fake_request(conn, {})
    runtime.pin_request(old)
    assert conn.ctx.sanic_security_generation == 1
    old = fake_request(conn, {"Authorization": "Bearer generation-one"})
    old_policy = runtime.pin_request(old)
    assert old_policy.generation == 1
    assert not old_policy.auth_required

    # A connection explicitly on the new generation must present the new
    # token; the old token is not silently accepted.
    with pytest.raises(PolicyAuthorizationFailed):
        runtime.pin_request(
            fake_request(
                SimpleNamespace(ctx=SimpleNamespace()),
                {"Authorization": "Bearer generation-one"},
            )
        )
    assert (
        runtime.pin_request(
            fake_request(
                SimpleNamespace(ctx=SimpleNamespace()),
                {"Authorization": "Bearer generation-two"},
            )
        ).generation
        == 2
    )


def test_inactive_worker_rejects_admission():
    runtime = SecurityPolicyRuntime(base(), enabled=False, name="w1")
    with pytest.raises(PolicyNotActive):
        runtime.pin_request(
            fake_request(SimpleNamespace(ctx=SimpleNamespace()))
        )
    runtime.enable()
    assert (
        runtime.pin_request(
            fake_request(SimpleNamespace(ctx=SimpleNamespace()))
        ).generation
        == 1
    )


def test_retired_generation_with_revalidate_policy_moves_forward():
    runtime = SecurityPolicyRuntime(base(), enabled=True, name="w1")
    conn = SimpleNamespace(ctx=SimpleNamespace())
    fake_request(conn)
    runtime.pin_request(fake_request(conn))
    target = base().updated(2, {"OLD_CONNECTION_POLICY": "revalidate"})
    runtime.stage(1, target)
    runtime.commit(1, target.generation, target.fingerprint)

    assert runtime.pin_request(fake_request(conn)).generation == 2


@pytest.mark.asyncio
async def test_request_entry_pins_before_handlers(app):
    from sanic.response import json

    app.config.SECURITY_POLICY_ENABLED = True
    app.config.SECURITY_AUTH_REQUIRED = True
    app.config.SECURITY_AUTH_TOKEN = "topsecret"
    app.config.REAL_IP_HEADER = "X-Real-IP"
    app._setup_security_policy()
    seen = {}

    @app.get("/")
    async def handler(request):
        seen["generation"] = request.security_policy.generation
        return json({"generation": request.security_policy.generation})

    _, response = await app.asgi_client.get(
        "/", headers={"Authorization": "Bearer topsecret"}
    )
    assert response.status == 200
    assert response.json == {"generation": 0}
    assert seen["generation"] == 0

    _, unauthorized = await app.asgi_client.get("/")
    assert unauthorized.status == 401
