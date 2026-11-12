import pytest

from sanic.security import (
    POLICY_FIELDS,
    SecurityPolicySnapshot,
    SecurityPolicyValidationError,
    fields_from_config,
)


def policy_fields(**changes):
    from sanic.config import Config

    fields = fields_from_config(Config())
    fields.update(changes)
    return fields


def make(generation=1, **changes):
    return SecurityPolicySnapshot.build(generation, policy_fields(**changes))


def test_snapshot_is_immutable_and_redacted():
    snapshot = make(FORWARDED_SECRET="proxy-secret", AUTH_TOKEN="token")
    assert snapshot.generation == 1
    assert "proxy-secret" not in repr(snapshot)
    assert "token" not in repr(snapshot)
    with pytest.raises(TypeError):
        snapshot.fields["REAL_IP_HEADER"] = "x"  # type: ignore
    assert snapshot.public() == {"generation": 1}


def test_fingerprint_is_stable_and_covers_every_field():
    first = make()
    second = make()
    assert first.fingerprint == second.fingerprint
    current = dict(first.fields)
    for name in POLICY_FIELDS:
        alternate = _alternate(name)
        if alternate == current[name]:
            continue
        if name == "AUTH_REQUIRED":
            # Turning auth on requires a token; supply one explicitly.
            changed = make(**{name: alternate, "AUTH_TOKEN": "required-token"})
        else:
            changed = make(**{name: alternate})
        assert changed.fingerprint != first.fingerprint


def _alternate(name):
    return {
        "FORWARDED_FOR_HEADER": "X-Forwarded-For-Chain",
        "FORWARDED_SECRET": "other-secret",
        "PROXIES_COUNT": 1,
        "REAL_IP_HEADER": "CF-Connecting-IP",
        "AUTH_REQUIRED": True,
        "AUTH_SCHEMES": ("Bearer",),
        "AUTH_TOKEN": "another-token",
        "OLD_CONNECTION_POLICY": "revalidate",
    }[name]


@pytest.mark.parametrize(
    "changes,field",
    (
        ({"PROXIES_COUNT": -1}, "PROXIES_COUNT"),
        ({"PROXIES_COUNT": "1"}, "PROXIES_COUNT"),
        ({"AUTH_REQUIRED": "yes"}, "AUTH_REQUIRED"),
        ({"AUTH_REQUIRED": True}, "AUTH_TOKEN"),
        ({"AUTH_SCHEMES": ()}, "AUTH_SCHEMES"),
        ({"AUTH_SCHEMES": ("Bearer", "bearer")}, "AUTH_SCHEMES"),
        ({"OLD_CONNECTION_POLICY": "reload"}, "OLD_CONNECTION_POLICY"),
        ({"REAL_IP_HEADER": ""}, "REAL_IP_HEADER"),
    ),
)
def test_invalid_candidates_are_rejected_without_values(changes, field):
    with pytest.raises(SecurityPolicyValidationError, match=field) as exc:
        make(**changes)
    for value in changes.values():
        if isinstance(value, str) and value:
            assert value not in str(exc.value)


def test_unknown_and_missing_fields_are_rejected():
    fields = policy_fields()
    del fields["REAL_IP_HEADER"]
    with pytest.raises(SecurityPolicyValidationError, match="Missing"):
        SecurityPolicySnapshot.build(1, fields)

    fields["EXTRA"] = "value"
    with pytest.raises(SecurityPolicyValidationError, match="Unknown"):
        SecurityPolicySnapshot.build(1, fields)


def test_generation_must_be_non_negative_int():
    fields = policy_fields()
    with pytest.raises(SecurityPolicyValidationError, match="generation"):
        SecurityPolicySnapshot.build(-1, fields)
    with pytest.raises(SecurityPolicyValidationError, match="generation"):
        SecurityPolicySnapshot.build("2", fields)  # type: ignore


def test_authorization_uses_one_snapshot():
    snapshot = make(
        AUTH_REQUIRED=True,
        AUTH_SCHEMES=("Bearer", "Token"),
        AUTH_TOKEN="expected",
    )
    assert snapshot.authorize("Bearer expected")
    assert snapshot.authorize("Token expected")
    assert not snapshot.authorize("Bearer other")
    assert not snapshot.authorize(None)
    assert not snapshot.authorize("Basic expected")

    disabled = make(AUTH_REQUIRED=False)
    assert disabled.authorize(None)


def test_forwarded_config_contains_only_policy_fields():
    snapshot = make(
        REAL_IP_HEADER="X-Real-IP",
        PROXIES_COUNT=2,
        FORWARDED_SECRET="proxy-secret",
    )
    config = snapshot.forwarded_config
    assert config.REAL_IP_HEADER == "X-Real-IP"
    assert config.PROXIES_COUNT == 2
    assert config.FORWARDED_SECRET == "proxy-secret"
    assert not hasattr(config, "REQUEST_MAX_SIZE")


def test_updated_keeps_all_other_fields():
    first = make(REAL_IP_HEADER="X-Real-IP")
    second = first.updated(2, {"PROXIES_COUNT": 1})
    assert second.generation == 2
    assert second.fields["REAL_IP_HEADER"] == "X-Real-IP"
    assert second.fields["PROXIES_COUNT"] == 1
