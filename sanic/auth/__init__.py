"""Client certificate identity helpers.

This package defines one contract for applications that authorize requests
from a client certificate.  It keeps "the server verified this identity"
distinct from "a request header merely claims this identity", because
Sanic's native server and ASGI deployment entry points learn about TLS in
different ways.
"""

from sanic.auth.identity import (
    CERT_HEADER_VARIABLE,
    DN_HEADER_VARIABLE,
    VERIFIED_MARKER,
    VERIFY_HEADER_VARIABLE,
    CertifiedIdentityError,
    IdentityClaim,
    IdentitySource,
    VerifiedIdentity,
    get_identity,
    require_verified_identity,
    verified_identity,
)


__all__ = (
    "CERT_HEADER_VARIABLE",
    "DN_HEADER_VARIABLE",
    "VERIFIED_MARKER",
    "VERIFY_HEADER_VARIABLE",
    "CertifiedIdentityError",
    "IdentityClaim",
    "IdentitySource",
    "VerifiedIdentity",
    "get_identity",
    "require_verified_identity",
    "verified_identity",
)
