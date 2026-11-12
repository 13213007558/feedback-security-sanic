# Client certificates

When a service authorizes requests by client certificate, it must distinguish
an identity that the TLS stack actually verified from one that a request
merely claims. Sanic's native server and its ASGI entry point learn about
TLS from different places, so this guide describes the contract that covers
both and the parts that only the deployment can guarantee.

## Where certificate data comes from

.. column::

    **Native server (`app.run`, `create_server`, HTTP/3)**

    Sanic terminates TLS itself. `ConnInfo` reads `ssl_object` from the
    transport while the connection is established and keeps it as
    `request.conn_info.peer_cert`. The peer certificate subject is available
    only after OpenSSL completed the handshake.

.. column::

    **ASGI server (uvicorn, hypercorn, etc.)**

    The outer server owns the socket. Sanic sees a synthetic transport whose
    `get_extra_info` returns only `peername` and the scheme. Certificate
    data can therefore arrive only through the ASGI `tls` extension on the
    `scope`, whose `client_cert` value is an `ssl.SSLObject`.

In both cases `request.conn_info.cert` is **not** the client certificate. It
is a copy of Sanic's own server-side `SSLContext.sanic` metadata (certificate
path, SNI names, creator), and it is empty under ASGI unless the outer server
chooses to expose it.

## The identity contract

`sanic.auth.get_identity(request)` returns one of three values:

- `VerifiedIdentity`: the certificate was verified by Sanic's TLS transport,
  by the ASGI server through the `tls` extension, or by a reverse proxy that
  proved itself with `FORWARDED_SECRET`. It carries `subject`, `source`
  (`tls`, `trusted_proxy`) and the raw `certificate`.
- `IdentityClaim`: identity information appears only in request headers, or a
  trusted proxy reported that verification did not succeed. It carries
  `subject` and never authorizes anything by itself.
- `None`: no certificate identity information reached the application.

```python
from sanic.auth import VerifiedIdentity, get_identity

@app.get("/whoami")
async def whoami(request):
    identity = get_identity(request)
    if isinstance(identity, VerifiedIdentity):
        return text(f"{identity.source.value}:{identity.subject}")
    return text("unverified", status=401)
```

Applying `@require_verified_identity` under the route decorator rejects
requests without a verified source: 401 when nothing was presented, 403 when
a header claim could not be confirmed. The verified value is also exposed as
`request.ctx.client_identity`.

```python
from sanic.auth import require_verified_identity

@app.get("/admin")
@require_verified_identity
async def admin(request):
    return text(request.ctx.client_identity.subject)
```

## Verification is not just a header

A certificate subject header is attacker-controlled. Sanic's own TLS path
calls `ssl.SSLObject.getpeercert()`, which returns an empty mapping unless
OpenSSL verified the chain under the connection's verify mode. That means:

- `CERT_NONE` with a client certificate that was never validated yields no
  `VerifiedIdentity`, even though the handshake succeeded.
- ASGI servers must be configured to verify client certificates and to emit
  the `tls` extension; Sanic cannot inspect the outer server's SSL context.
- A header named `X-Client-Cert` is always an `IdentityClaim`, regardless of
  its value or spelling.

For a trusted proxy, `FORWARDED_SECRET` must be configured and the `Forwarded`
header must carry the same secret as `by` or `secret`. Only then do
`X-Client-Verify: SUCCESS` and `X-Client-DN` become a `VerifiedIdentity`.

## Guarantees that stay outside Sanic

The native path depends on the `ssl.SSLContext` passed to `app.run`: its
`verify_mode`, `load_verify_locations` and any chain policy are the actual
verification decision. Sanic only reports what the context produced.

The ASGI path depends entirely on the outer server. It must terminate TLS,
verify the client chain, and populate `scope["extensions"]["tls"]["client_cert"]`.
If any of those steps is missing, the request is treated as unverified. Sanic
does not read certificate headers as a fallback on that path.

Proxy attestations depend on the secret being shared with a proxy that strips
client-supplied copies of these headers. Sanic cannot enforce that; it only
requires proof of the secret on every request.
