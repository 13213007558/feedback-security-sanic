from __future__ import annotations

import hashlib
import hmac
import json

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType, SimpleNamespace
from typing import Any

from sanic.headers import parse_credentials


PROXY_FIELDS = (
    "FORWARDED_FOR_HEADER",
    "FORWARDED_SECRET",
    "PROXIES_COUNT",
    "REAL_IP_HEADER",
)
AUTH_FIELDS = (
    "AUTH_REQUIRED",
    "AUTH_SCHEMES",
    "AUTH_TOKEN",
)
POLICY_FIELDS = (*PROXY_FIELDS, *AUTH_FIELDS, "OLD_CONNECTION_POLICY")
OLD_CONNECTION_POLICIES = ("pin", "revalidate")

CONFIG_KEYS = {
    "FORWARDED_FOR_HEADER": "FORWARDED_FOR_HEADER",
    "FORWARDED_SECRET": "FORWARDED_SECRET",
    "PROXIES_COUNT": "PROXIES_COUNT",
    "REAL_IP_HEADER": "REAL_IP_HEADER",
    "AUTH_REQUIRED": "SECURITY_AUTH_REQUIRED",
    "AUTH_SCHEMES": "SECURITY_AUTH_SCHEMES",
    "AUTH_TOKEN": "SECURITY_AUTH_TOKEN",
    "OLD_CONNECTION_POLICY": "SECURITY_OLD_CONNECTION_POLICY",
}

DEFAULT_POLICY_FIELDS = {
    "FORWARDED_FOR_HEADER": "X-Forwarded-For",
    "FORWARDED_SECRET": None,
    "PROXIES_COUNT": None,
    "REAL_IP_HEADER": None,
    "AUTH_REQUIRED": False,
    "AUTH_SCHEMES": ("Bearer", "Token"),
    "AUTH_TOKEN": None,
    "OLD_CONNECTION_POLICY": "pin",
}


class SecurityPolicyError(Exception):
    """Base class for security policy failures."""


class SecurityPolicyValidationError(SecurityPolicyError, ValueError):
    """A candidate policy snapshot failed validation.

    Messages identify the offending field only. Values, especially secrets,
    are never included so that the exception is safe to log.
    """


def _reject(field_name: str, reason: str) -> SecurityPolicyValidationError:
    return SecurityPolicyValidationError(
        f"Invalid security policy field {field_name}: {reason}"
    )


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_optional_string(field_name: str, value: Any) -> None:
    if value is not None and not _is_nonempty_str(value):
        raise _reject(field_name, "must be a non-empty string or None")


def _validate_headers(field_name: str, value: Any) -> None:
    if not _is_nonempty_str(value):
        raise _reject(field_name, "must be a non-empty header name")


def _validate_schemes(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [part for part in value.split(",") if part.strip()]
    if not isinstance(value, Sequence):
        raise _reject("AUTH_SCHEMES", "must be a sequence of scheme names")
    schemes: list[str] = []
    seen: set[str] = set()
    for scheme in value:
        if not _is_nonempty_str(scheme) or " " in scheme.strip():
            raise _reject("AUTH_SCHEMES", "contains an invalid scheme name")
        normalized = scheme.strip().lower()
        if normalized in seen:
            raise _reject("AUTH_SCHEMES", "contains a duplicate scheme")
        seen.add(normalized)
        schemes.append(scheme.strip())
    if not schemes:
        raise _reject("AUTH_SCHEMES", "must contain at least one scheme")
    return tuple(schemes)


def _canonicalize(fields: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(fields, Mapping):
        raise _reject("snapshot", "fields must be a mapping")
    unknown = sorted(set(fields) - set(POLICY_FIELDS))
    if unknown:
        raise SecurityPolicyValidationError(
            "Unknown security policy fields: " + ", ".join(unknown)
        )
    missing = sorted(set(POLICY_FIELDS) - set(fields))
    if missing:
        raise SecurityPolicyValidationError(
            "Missing security policy fields: " + ", ".join(missing)
        )

    _validate_headers("FORWARDED_FOR_HEADER", fields["FORWARDED_FOR_HEADER"])
    _validate_optional_string("FORWARDED_SECRET", fields["FORWARDED_SECRET"])
    _validate_optional_string("REAL_IP_HEADER", fields["REAL_IP_HEADER"])

    proxies_count = fields["PROXIES_COUNT"]
    if proxies_count is not None:
        if isinstance(proxies_count, bool) or not isinstance(
            proxies_count, int
        ):
            raise _reject("PROXIES_COUNT", "must be an integer or None")
        if proxies_count < 0:
            raise _reject("PROXIES_COUNT", "cannot be negative")

    auth_required = fields["AUTH_REQUIRED"]
    if not isinstance(auth_required, bool):
        raise _reject("AUTH_REQUIRED", "must be a boolean")

    schemes = _validate_schemes(fields["AUTH_SCHEMES"])

    auth_token = fields["AUTH_TOKEN"]
    _validate_optional_string("AUTH_TOKEN", auth_token)
    if auth_required and auth_token is None:
        raise _reject("AUTH_TOKEN", "is required when AUTH_REQUIRED is true")

    old_policy = fields["OLD_CONNECTION_POLICY"]
    if not isinstance(old_policy, str):
        raise _reject("OLD_CONNECTION_POLICY", "must be a string")
    old_policy = old_policy.strip().lower()
    if old_policy not in OLD_CONNECTION_POLICIES:
        raise _reject("OLD_CONNECTION_POLICY", "must be 'pin' or 'revalidate'")

    return {
        "FORWARDED_FOR_HEADER": fields["FORWARDED_FOR_HEADER"].strip(),
        "FORWARDED_SECRET": fields["FORWARDED_SECRET"],
        "PROXIES_COUNT": proxies_count,
        "REAL_IP_HEADER": (
            fields["REAL_IP_HEADER"].strip()
            if fields["REAL_IP_HEADER"] is not None
            else None
        ),
        "AUTH_REQUIRED": auth_required,
        "AUTH_SCHEMES": schemes,
        "AUTH_TOKEN": auth_token,
        "OLD_CONNECTION_POLICY": old_policy,
    }


def _fingerprint(fields: Mapping[str, Any]) -> str:
    payload = {
        key: list(value) if isinstance(value, tuple) else value
        for key, value in fields.items()
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def fields_from_config(config: Any) -> dict[str, Any]:
    """Read a complete policy from an app config-like object."""
    fields: dict[str, Any] = {}
    for name in POLICY_FIELDS:
        config_key = CONFIG_KEYS[name]
        fields[name] = getattr(config, config_key, DEFAULT_POLICY_FIELDS[name])
    return fields


@dataclass(frozen=True, slots=True, repr=False)
class SecurityPolicySnapshot:
    """An immutable, generation-tagged security policy.

    Every request resolves exactly one snapshot and keeps a reference to it
    for its whole lifecycle. Proxy parsing and authentication use only fields
    from that snapshot, which makes mixed-generation requests impossible.
    """

    generation: int
    _fields: Mapping[str, Any] = field(repr=False)
    fingerprint: str = field(repr=False)

    @classmethod
    def build(
        cls, generation: int, fields: Mapping[str, Any]
    ) -> SecurityPolicySnapshot:
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise _reject("generation", "must be an integer")
        if generation < 0:
            raise _reject("generation", "cannot be negative")
        canonical = _canonicalize(fields)
        return cls(
            generation,
            MappingProxyType(canonical),
            _fingerprint(canonical),
        )

    def updated(
        self, generation: int, changes: Mapping[str, Any]
    ) -> SecurityPolicySnapshot:
        return self.build(generation, {**self._fields, **changes})

    @property
    def fields(self) -> Mapping[str, Any]:
        return self._fields

    @property
    def forwarded_config(self) -> SimpleNamespace:
        """Config adapter for Sanic's forwarded-header parsers."""
        return SimpleNamespace(
            **{name: self._fields[name] for name in PROXY_FIELDS}
        )

    @property
    def old_connection_policy(self) -> str:
        return str(self._fields["OLD_CONNECTION_POLICY"])

    @property
    def auth_required(self) -> bool:
        return bool(self._fields["AUTH_REQUIRED"])

    def authorize(self, authorization: str | None) -> bool:
        if not self.auth_required:
            return True
        if not authorization:
            return False
        schemes = tuple(str(s) for s in self._fields["AUTH_SCHEMES"])
        _, token = parse_credentials(authorization, prefixes=schemes)
        expected = self._fields["AUTH_TOKEN"]
        if token is None or expected is None:
            return False
        return hmac.compare_digest(str(token), str(expected))

    def public(self) -> dict[str, Any]:
        """Generation only; policy contents never leave the process."""
        return {"generation": self.generation}

    def __repr__(self) -> str:
        return (
            f"SecurityPolicySnapshot(generation={self.generation}, "
            "fields=<redacted>)"
        )
