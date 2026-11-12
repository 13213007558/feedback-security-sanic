from __future__ import annotations

import asyncio
import ssl

from unittest.mock import MagicMock

import pytest

from sanic import Sanic, text
from sanic.asgi import ASGIApp
from sanic.auth import (
    CertifiedIdentityError,
    IdentityClaim,
    IdentitySource,
    VerifiedIdentity,
    get_identity,
    require_verified_identity,
)
from sanic.exceptions import Unauthorized
from sanic.request import Request
from sanic.server import ConnInfo


class FakeTransport:
    """Stand-in for a native asyncio transport and its TLS extra info."""

    def __init__(self, ssl_object=None, peer=("127.0.0.1", 1234)):
        self._ssl_object = ssl_object
        self.peername = peer
        self.scope = None

    def get_extra_info(self, name, default=None):
        if name == "ssl_object":
            return self._ssl_object
        if name == "sockname":
            return ("127.0.0.1", 8443)
        if name == "peername":
            return self.peername
        return default

    def get_protocol(self):  # pragma: no cover - not used here
        raise NotImplementedError


def make_native_request(app, transport, path=b"/protected", headers=None):
    request = Request(path, headers or {}, "1.1", "GET", transport, app)
    request.conn_info = ConnInfo(transport)
    return request


def make_ssl_object(verified=True):
    ssl_object = MagicMock(spec=ssl.SSLObject)
    ssl_object.getpeercert.return_value = (
        {"subject": ((("commonName", "client.example"),),)}
        if verified
        else {}
    )
    return ssl_object


def asgi_scope(headers=None, extensions=None):
    headers = headers if headers is not None else [
        (b"host", b"mockserver"),
        (b"x-client-cert", b"CN=client.example"),
    ]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/protected",
        "raw_path": b"/protected",
        "query_string": b"",
        "headers": headers,
        "server": ("mockserver", 443),
        "client": ("127.0.0.1", 1234),
        "root_path": "",
    }
    if extensions is not None:
        scope["extensions"] = extensions
    return scope


async def make_asgi_request(app, scope, headers=None):
    messages = asyncio.Queue()
    await messages.put(
        {"type": "http.request", "body": b"", "more_body": False}
    )
    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    app.asgi = True
    await app._startup()
    asgi_app = await ASGIApp.create(app, scope, messages.get, send)
    return asgi_app.request, asgi_app


def make_app():
    app = Sanic("client-identity")

    @app.get("/identity")
    async def identity(request):
        value = get_identity(request)
        if value is None:
            kind = "none"
        elif isinstance(value, VerifiedIdentity):
            kind = "verified"
        else:
            kind = "claim"
        return text(f"{kind}:{getattr(value, 'subject', '')}")

    @app.get("/protected")
    @require_verified_identity
    async def protected(request):
        value = request.ctx.client_identity
        return text(f"{value.source.value}:{value.subject}:{value.dn}")

    return app


@pytest.mark.asyncio
async def test_native_tls_verified_identity():
    app = make_app()
    ssl_object = make_ssl_object()
    request = make_native_request(app, FakeTransport(ssl_object))

    value = get_identity(request)

    assert isinstance(value, VerifiedIdentity)
    assert value.source is IdentitySource.TLS
    assert value.subject == "CN=client.example"
    assert value.certificate is ssl_object


@pytest.mark.asyncio
async def test_native_missing_tls_metadata_leaves_only_a_header_claim():
    app = make_app()
    request = make_native_request(
        app,
        FakeTransport(),
        headers={"X-Client-Cert": "CN=client.example"},
    )

    value = get_identity(request)

    assert isinstance(value, IdentityClaim)
    assert value.source is IdentitySource.REQUEST_HEADER
    assert value.subject == "CN=client.example"


@pytest.mark.asyncio
async def test_native_unverified_peer_certificate_is_not_verified():
    app = make_app()
    request = make_native_request(
        app, FakeTransport(make_ssl_object(verified=False))
    )

    assert get_identity(request) is None


@pytest.mark.asyncio
async def test_native_conn_info_can_supply_verified_ssl_object():
    app = make_app()
    request = make_native_request(app, FakeTransport())
    request.conn_info.peer_cert = make_ssl_object()

    value = get_identity(request)

    assert isinstance(value, VerifiedIdentity)
    assert value.subject == "CN=client.example"


@pytest.mark.asyncio
async def test_asgi_scope_without_tls_extension_does_not_trust_header():
    app = make_app()
    request, _ = await make_asgi_request(app, asgi_scope(extensions={}))

    value = get_identity(request)

    assert isinstance(value, IdentityClaim)
    assert value.subject == "CN=client.example"


@pytest.mark.asyncio
async def test_asgi_scope_without_tls_extension_and_no_header_is_absent():
    app = make_app()
    request, _ = await make_asgi_request(
        app, asgi_scope(headers=[(b"host", b"mockserver")], extensions={})
    )

    assert get_identity(request) is None


@pytest.mark.asyncio
async def test_asgi_tls_extension_yields_verified_identity():
    app = make_app()
    ssl_object = make_ssl_object()
    request, _ = await make_asgi_request(
        app,
        asgi_scope(
            headers=[
                (b"host", b"mockserver"),
                (b"x-client-cert", b"CN=spoofed"),
            ],
            extensions={"tls": {"client_cert": ssl_object}},
        ),
    )

    value = get_identity(request)

    assert isinstance(value, VerifiedIdentity)
    assert value.source is IdentitySource.TLS
    assert value.subject == "CN=client.example"
    assert value.certificate is ssl_object


@pytest.mark.asyncio
async def test_asgi_tls_extension_unverified_certificate_is_not_verified():
    app = make_app()
    request, _ = await make_asgi_request(
        app,
        asgi_scope(
            headers=[(b"host", b"mockserver")],
            extensions={
                "tls": {"client_cert": make_ssl_object(verified=False)}
            },
        ),
    )

    assert get_identity(request) is None


@pytest.mark.asyncio
async def test_identity_header_cannot_masquerade_as_tls_extension():
    app = make_app()
    request, _ = await make_asgi_request(
        app,
        asgi_scope(
            headers=[
                (b"host", b"mockserver"),
                (b"x-client-cert", b"CN=spoof"),
            ],
            extensions={},
        ),
    )

    assert isinstance(get_identity(request), IdentityClaim)


@pytest.mark.asyncio
async def test_trusted_proxy_with_secret_and_success_is_verified():
    app = make_app()
    app.config.FORWARDED_SECRET = "proxy-secret"
    request = make_native_request(
        app,
        FakeTransport(),
        headers={
            "Forwarded": "for=10.0.0.1;by=proxy-secret",
            "X-Client-Verify": "SUCCESS",
            "X-Client-DN": "CN=client.example",
        },
    )

    value = get_identity(request)

    assert isinstance(value, VerifiedIdentity)
    assert value.source is IdentitySource.TRUSTED_PROXY
    assert value.subject == "CN=client.example"


@pytest.mark.asyncio
async def test_proxy_headers_without_secret_stay_claims():
    app = make_app()
    app.config.PROXIES_COUNT = 1
    request = make_native_request(
        app,
        FakeTransport(),
        headers={
            "X-Client-Verify": "SUCCESS",
            "X-Client-DN": "CN=client.example",
        },
    )

    assert isinstance(get_identity(request), IdentityClaim)


@pytest.mark.asyncio
async def test_proxy_with_wrong_secret_stays_a_claim():
    app = make_app()
    app.config.FORWARDED_SECRET = "proxy-secret"
    request = make_native_request(
        app,
        FakeTransport(),
        headers={
            "Forwarded": "for=10.0.0.1;by=wrong-secret",
            "X-Client-Verify": "SUCCESS",
            "X-Client-DN": "CN=client.example",
        },
    )

    assert isinstance(get_identity(request), IdentityClaim)


@pytest.mark.asyncio
async def test_proxy_failed_verification_stays_a_claim():
    app = make_app()
    app.config.FORWARDED_SECRET = "proxy-secret"
    request = make_native_request(
        app,
        FakeTransport(),
        headers={
            "Forwarded": "for=10.0.0.1;by=proxy-secret",
            "X-Client-Verify": "FAILED",
            "X-Client-DN": "CN=client.example",
        },
    )

    assert isinstance(get_identity(request), IdentityClaim)


@pytest.mark.asyncio
async def test_guard_rejects_absent_identity():
    app = make_app()
    request = make_native_request(app, FakeTransport())

    with pytest.raises(Unauthorized) as exc:
        await require_verified_identity(lambda request: text("no"))(request)

    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_guard_rejects_header_claim_with_403():
    app = make_app()
    request = make_native_request(
        app, FakeTransport(), headers={"X-Client-Cert": "CN=spoof"}
    )

    with pytest.raises(CertifiedIdentityError) as exc:
        await require_verified_identity(lambda request: text("no"))(request)

    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_guard_exposes_verified_identity_to_handler():
    app = make_app()
    request = make_native_request(app, FakeTransport(make_ssl_object()))

    async def handler(request):
        return text(request.ctx.client_identity.source.value)

    response = await require_verified_identity(handler)(request)

    assert response.body == b"tls"


@pytest.mark.asyncio
async def test_protected_route_returns_401_via_asgi_entry():
    app = make_app()
    _, asgi_app = await make_asgi_request(
        app, asgi_scope(headers=[(b"host", b"mockserver")])
    )

    await asgi_app()

    assert asgi_app.response is not None
    assert asgi_app.response.status == 401


def real_tls_peer_certificate(tmp_path, verify_mode):
    """Produce a real handshake result without any network socket.

    ``MemoryBIO`` keeps the OpenSSL verification path but avoids binding a
    port and avoids needing a certificate authority service.
    """
    import subprocess

    cert = str(tmp_path / "client-cert.pem")
    key = str(tmp_path / "client-key.pem")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=client.example",
            "-keyout",
            key,
            "-out",
            cert,
        ],
        check=True,
        capture_output=True,
    )

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    server_context.verify_mode = verify_mode
    server_context.load_verify_locations(cert)

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_cert_chain(cert, key)
    client_context.load_verify_locations(cert)
    client_context.check_hostname = False

    client_out, client_in = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(
        client_in, client_out, server_side=False
    )
    server = server_context.wrap_bio(
        server_in, server_out, server_side=True
    )

    for _ in range(30):
        progressed = False
        try:
            client.do_handshake()
            progressed = True
        except ssl.SSLWantReadError:
            pass
        data = client_out.read()
        if data:
            server_in.write(data)
            progressed = True
        try:
            server.do_handshake()
            progressed = True
        except ssl.SSLWantReadError:
            pass
        data = server_out.read()
        if data:
            client_in.write(data)
            progressed = True
        if not progressed:
            break

    return server


@pytest.mark.asyncio
async def test_real_verified_handshake_yields_verified_identity(tmp_path):
    app = make_app()
    peer = real_tls_peer_certificate(tmp_path, ssl.CERT_REQUIRED)
    transport = FakeTransport()
    request = make_native_request(app, transport)
    request.conn_info.peer_cert = peer

    value = get_identity(request)

    assert isinstance(value, VerifiedIdentity)
    assert value.subject == "CN=client.example"
    assert value.source is IdentitySource.TLS


@pytest.mark.asyncio
async def test_real_unverified_handshake_yields_no_identity(tmp_path):
    app = make_app()
    peer = real_tls_peer_certificate(tmp_path, ssl.CERT_NONE)
    transport = FakeTransport()
    request = make_native_request(
        app, transport, headers={"X-Client-Cert": "CN=client.example"}
    )
    request.conn_info.peer_cert = peer

    value = get_identity(request)

    assert isinstance(value, IdentityClaim)
    assert value.source is IdentitySource.REQUEST_HEADER


@pytest.mark.asyncio
async def test_conn_info_records_peer_cert_without_changing_cert_semantics():
    ssl_object = make_ssl_object()
    ssl_object.context.sanic = {"creator": "test"}
    transport = FakeTransport(ssl_object)

    info = ConnInfo(transport)

    assert info.peer_cert is ssl_object
    assert info.cert == {"creator": "test"}
    assert info.cert is not ssl_object.context.sanic


@pytest.mark.asyncio
async def test_malformed_client_cert_metadata_is_not_verified():
    app = make_app()
    ssl_object = MagicMock(spec=ssl.SSLObject)
    ssl_object.getpeercert.side_effect = ValueError("bad certificate")
    request, _ = await make_asgi_request(
        app,
        asgi_scope(
            headers=[
                (b"host", b"mockserver"),
                (b"x-client-cert", b"CN=spoof"),
            ],
            extensions={"tls": {"client_cert": ssl_object}},
        ),
    )

    value = get_identity(request)

    assert isinstance(value, IdentityClaim)
    assert value.source is IdentitySource.REQUEST_HEADER
