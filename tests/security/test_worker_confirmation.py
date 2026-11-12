from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sanic.security import (
    SecurityPolicySnapshot,
    fields_from_config,
)
from sanic.worker.multiplexer import WorkerMultiplexer


def base():
    from sanic.config import Config

    return SecurityPolicySnapshot.build(1, fields_from_config(Config()))


def test_ack_without_policy_stays_minimal(monkeypatch):
    monkeypatch.setenv("SANIC_WORKER_NAME", "Test")
    state = {"Test": {"foo": "bar"}}
    multiplexer = WorkerMultiplexer(Mock(), state)
    multiplexer.ack()

    assert state["Test"] == {"foo": "bar", "state": "ACKED"}


def test_ack_includes_generation_and_status_only(monkeypatch):
    monkeypatch.setenv("SANIC_WORKER_NAME", "Test")
    state = {"Test": {}}
    multiplexer = WorkerMultiplexer(Mock(), state)
    multiplexer.ack(security_generation=7, security_ready=True)

    snapshot = state["Test"]
    assert snapshot["security_generation"] == 7
    assert snapshot["security_status"] == "active"
    assert set(snapshot) == {
        "state",
        "security_generation",
        "security_status",
    }


def test_ack_never_contains_policy_contents(monkeypatch):
    monkeypatch.setenv("SANIC_WORKER_NAME", "Test")
    state = {"Test": {}}
    multiplexer = WorkerMultiplexer(Mock(), state)
    multiplexer.ack(security_generation=3, security_ready=True)
    rendered = repr(state["Test"])
    for name in ("FORWARDED_SECRET", "AUTH_TOKEN", "REAL_IP_HEADER"):
        assert name not in rendered
    assert "secret" not in rendered
    assert "token" not in rendered


@pytest.mark.parametrize(
    "worker_state,expected",
    (
        ({}, True),
        ({"state": "ACKED"}, True),
        (
            {
                "state": "ACKED",
                "security_generation": 1,
                "security_status": "active",
            },
            True,
        ),
        (
            {
                "state": "ACKED",
                "security_generation": 1,
                "security_status": "inactive",
            },
            False,
        ),
        ({"state": "ACKED", "security_generation": 1}, False),
        (
            {
                "state": "ACKED",
                "security_generation": "1",
                "security_status": "active",
            },
            False,
        ),
        ({"state": "STARTED", "security_generation": 1}, False),
    ),
)
def test_manager_requires_confirmed_security_generation(
    worker_state, expected
):
    from sanic.worker.manager import _security_confirmed

    worker_state = dict(worker_state)
    if "state" in worker_state:
        worker_state.setdefault("server", True)
        worker_state.setdefault("state", "ACKED")
    assert _security_confirmed(worker_state) is expected


def test_all_workers_ack_rejects_unconfirmed_security_worker():
    from sanic.worker.manager import WorkerManager

    manager = WorkerManager.__new__(WorkerManager)
    manager.num_server = 2  # type: ignore
    manager.security_enabled = True  # type: ignore
    manager.worker_state = {  # type: ignore
        "ok": {
            "server": True,
            "state": "ACKED",
            "security_generation": 4,
            "security_status": "active",
        },
        "bad": {
            "server": True,
            "state": "ACKED",
            "security_generation": 4,
            "security_status": "inactive",
        },
    }
    assert manager._all_workers_ack() is False

    manager.worker_state["bad"]["security_status"] = "active"
    assert manager._all_workers_ack() is True


def test_app_ack_only_advertises_generation_and_state():
    app = Mock()
    app._security_runtime.return_value = SimpleNamespace(
        generation=9, enabled=True
    )

    from sanic.app import Sanic

    Sanic.ack(app)
    app.multiplexer.ack.assert_called_once_with(
        security_generation=9, security_ready=True
    )


def test_disabled_runtime_uses_plain_ack():
    app = Mock()
    app._security_runtime.return_value = SimpleNamespace(
        generation=0, enabled=False
    )

    from sanic.app import Sanic

    Sanic.ack(app)
    app.multiplexer.ack.assert_called_once_with()
