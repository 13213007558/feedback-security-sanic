from __future__ import annotations

import ssl

from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from inspect import isawaitable
from typing import TYPE_CHECKING, Any, Callable

from sanic.exceptions import Forbidden, Unauthorized


if TYPE_CHECKING:
    from sanic.request import Request


CERT_HEADER_VARIABLE = "X-Client-Cert"
"""Header a client or proxy may use to assert a certificate identity."""

VERIFY_HEADER_VARIABLE = "X-Client-Verify"
"""Proxy header that states the result of certificate verification."""

DN_HEADER_VARIABLE = "X-Client-DN"
"""Proxy header carrying the verified certificate subject."""

VERIFIED_MARKER = "SUCCESS"
"""Value of ``X-Client-Verify`` that means the proxy verified the chain."""


class IdentitySource(Enum):
    """Where a request's identity information came from."""

    TLS = "tls"
    TRUSTED_PROXY = "trusted_proxy"
    REQUEST_HEADER = "request_header"


class CertifiedIdentityError(Forbidden):
    """403 when identity data exists but its verification cannot be trusted."""

    status_code = 403
    quiet = True


@dataclass(frozen=True)
class VerifiedIdentity:
    """An identity authenticated by the transport or a trusted proxy."""

    subject: str
    source: IdentitySource
    certificate: Any = field(default=None, repr=False, compare=False)

    @property
    def dn(self) -> str:
        """Alias for :attr:`subject`."""
        return self.subject


@dataclass(frozen=True)
class IdentityClaim:
    """An identity merely asserted by an untrusted request header."""

    subject: str
    source: IdentitySource = IdentitySource.REQUEST_HEADER
    certificate: Any = field(default=None, repr=False, compare=False)

    @property
    def dn(self) -> str:
        """Alias for :attr:`subject`."""
        return self.subject


def _normalize(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return " ".join(str(value).split())


_DN_SHORT_NAMES = {
    "commonName": "CN",
    "countryName": "C",
    "localityName": "L",
    "stateOrProvinceName": "ST",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "emailAddress": "emailAddress",
    "serialNumber": "serialNumber",
    "domainComponent": "DC",
    "userId": "UID",
}


def _subject_from_ssl_object(ssl_object: Any) -> str:
    """Return the verified subject of a peer ``ssl.SSLObject``.

    ``getpeercert()`` returns an empty mapping unless OpenSSL verified the
    chain under the context's verify mode.  A non-empty result is therefore
    evidence of verification, not merely of a certificate being presented.
    """
    try:
        certificate = ssl_object.getpeercert()
    except (AttributeError, ssl.SSLError, ValueError):
        return ""
    if not certificate:
        return ""
    subject = certificate.get("subject")
    if subject:
        return _normalize(
            "/".join(
                f"{_DN_SHORT_NAMES.get(key, key)}={value}"
                for item in subject
                for key, value in item
            )
        )
    return _normalize(certificate.get("subjectAltName", ""))


def _verified_from_ssl_object(ssl_object: Any) -> VerifiedIdentity | None:
    if ssl_object is None:
        return None
    subject = _subject_from_ssl_object(ssl_object)
    if not subject:
        return None
    return VerifiedIdentity(
        subject=subject,
        source=IdentitySource.TLS,
        certificate=ssl_object,
    )


def _identity_from_tls(request: "Request") -> VerifiedIdentity | None:
    """Identity verified by Sanic's own asyncio TLS transport."""
    conn_info = request.conn_info
    if conn_info is None:
        return None
    ssl_object = conn_info.peer_cert
    if ssl_object is None and request.transport is not None:
        ssl_object = request.transport.get_extra_info("ssl_object")
    return _verified_from_ssl_object(ssl_object)


def _scope_extensions(request: "Request") -> dict[str, Any]:
    try:
        scope = request.transport.scope
    except (AttributeError, NotImplementedError):
        return {}
    if not isinstance(scope, dict):
        return {}
    extensions = scope.get("extensions") or {}
    return extensions if isinstance(extensions, dict) else {}


def _identity_from_asgi_extension(
    request: "Request",
) -> VerifiedIdentity | None:
    """Identity verified by the ASGI server's TLS extension.

    The extension is populated only when the outer ASGI server performed
    the TLS handshake and chose to expose the peer certificate.  Its
    ``client_cert`` is an ``ssl.SSLObject`` whose verification result is
    still decided by that server's SSL context.
    """
    tls = _scope_extensions(request).get("tls")
    if not isinstance(tls, dict):
        return None
    return _verified_from_ssl_object(tls.get("client_cert"))


def _proxy_headers_trusted(request: "Request") -> bool:
    """Whether proxy-supplied identity headers may be trusted.

    Certificate identity headers are only an attestation when the request
    proves it came from a proxy configured with ``FORWARDED_SECRET``.  Proxy
    address settings such as ``PROXIES_COUNT`` alone cannot authenticate
    these headers, so they are not sufficient here.
    """
    secret = request.app.config.get("FORWARDED_SECRET")
    if not secret:
        return False
    forwarded = request.forwarded
    return secret in (forwarded.get("by"), forwarded.get("secret"))


def _identity_from_trusted_proxy(
    request: "Request",
) -> VerifiedIdentity | IdentityClaim | None:
    """Identity attested by an explicitly trusted reverse proxy."""
    if not _proxy_headers_trusted(request):
        return None

    verdict = _normalize(
        request.headers.getone(VERIFY_HEADER_VARIABLE, None)
    )
    subject = _normalize(request.headers.getone(DN_HEADER_VARIABLE, None))

    if verdict == VERIFIED_MARKER and subject:
        return VerifiedIdentity(
            subject=subject,
            source=IdentitySource.TRUSTED_PROXY,
            certificate=request.headers.getone(
                CERT_HEADER_VARIABLE, None
            ),
        )

    if verdict or subject:
        return IdentityClaim(
            subject=subject,
            source=IdentitySource.TRUSTED_PROXY,
        )
    return None


def _identity_from_claim(request: "Request") -> IdentityClaim | None:
    subject = _normalize(
        request.headers.getone(DN_HEADER_VARIABLE, None)
        or request.headers.getone(CERT_HEADER_VARIABLE, None)
    )
    if not subject:
        return None
    return IdentityClaim(subject=subject)


def get_identity(
    request: "Request",
) -> VerifiedIdentity | IdentityClaim | None:
    """Return the request identity together with its trust level.

    Returns:
        - ``VerifiedIdentity`` when the peer certificate was verified by
          Sanic's TLS transport, by the ASGI server through the ``tls``
          extension, or by an explicitly trusted reverse proxy.
        - ``IdentityClaim`` when certificate identity information appears
          only in request headers, or when a trusted proxy reports that
          verification did not succeed.  Never authorize based on this.
        - ``None`` when no certificate identity information is present.
    """
    ctx = request.ctx
    if getattr(ctx, "_sanic_identity_checked", False):
        return ctx._sanic_identity

    identity = (
        _identity_from_tls(request)
        or _identity_from_asgi_extension(request)
        or _identity_from_trusted_proxy(request)
        or _identity_from_claim(request)
    )
    ctx._sanic_identity = identity
    ctx._sanic_identity_checked = True
    return identity


def require_verified_identity(
    handler: Callable[..., Any],
) -> Callable[..., Any]:
    """Reject requests without a server-verified client certificate.

    Use as a route decorator, applied *before* the route decorator so that
    Sanic registers the wrapped callable::

        @app.get("/protected")
        @require_verified_identity
        async def protected(request):
            return text(request.ctx.client_identity.subject)

    A header-only :class:`IdentityClaim` is rejected with 403 because its
    verification source cannot be confirmed.  No identity information at
    all is rejected with 401.  The verified value is also stored on
    ``request.ctx.client_identity``.
    """

    @wraps(handler)
    async def wrapped(request: "Request", *args, **kwargs):
        identity = get_identity(request)
        if not isinstance(identity, VerifiedIdentity):
            if isinstance(identity, IdentityClaim):
                raise CertifiedIdentityError(
                    "Client certificate identity could not be verified",
                )
            raise Unauthorized(
                "Client certificate required",
                scheme="Mutual-TLS",
                realm="client-certificate",
            )
        request.ctx.client_identity = identity
        result = handler(request, *args, **kwargs)
        if isawaitable(result):
            result = await result
        return result

    return wrapped


verified_identity = require_verified_identity
"""Alias identifying the contract by the value it guarantees."""
