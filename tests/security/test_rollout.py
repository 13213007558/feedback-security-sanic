from unittest.mock import Mock

import pytest

from sanic.security import (
    InMemoryWorkerChannel,
    PolicyCommand,
    SecurityPolicyCoordinator,
    SecurityPolicyRuntime,
    SecurityPolicySnapshot,
    WorkerEndpoint,
    fields_from_config,
)


def base():
    from sanic.config import Config

    return SecurityPolicySnapshot.build(1, fields_from_config(Config()))


def candidate(**changes):
    return base().updated(2, changes)


def make_worker(name, enabled=True):
    runtime = SecurityPolicyRuntime(base(), enabled=enabled, name=name)
    return WorkerEndpoint(runtime), runtime


def make_channel(*workers, timeout=0.02):
    channel = InMemoryWorkerChannel()
    for endpoint, _ in workers:
        channel.add_worker(endpoint)
    return channel, SecurityPolicyCoordinator(channel, timeout=timeout)


def snapshot_of(runtime):
    return runtime.active.generation


def test_two_phase_commit_reaches_every_worker():
    workers = [make_worker("w1"), make_worker("w2"), make_worker("w3")]
    channel, coordinator = make_channel(*workers)

    status = coordinator.rollout(candidate(PROXIES_COUNT=1), attempt=4)

    assert status.generation == 2
    assert status.status == "active"
    assert all(snapshot_of(rt) == 2 for _, rt in workers)
    assert [name for name, state in status.workers] == ["w1", "w2", "w3"]
    assert all(state == "active" for _, state in status.workers)


def test_staged_candidate_is_never_served_before_commit():
    endpoint, runtime = make_worker("w1")
    channel = InMemoryWorkerChannel()
    channel.add_worker(endpoint)
    staged = candidate(PROXIES_COUNT=1, REAL_IP_HEADER="X-Real-IP")
    endpoint.deliver(
        PolicyCommand(
            "stage", 1, staged.generation, staged.fingerprint, staged
        )
    )
    assert runtime.active.generation == 1
    assert runtime.active.fields["PROXIES_COUNT"] is None
    assert runtime.active.fields["REAL_IP_HEADER"] is None
    assert runtime.enabled


def test_late_ack_rolls_back_staged_candidate_everywhere():
    early_endpoint, early_runtime = make_worker("w1")
    late_endpoint, late_runtime = make_worker("w2")
    channel = InMemoryWorkerChannel()
    channel.add_worker(early_endpoint)
    channel.add_worker(late_endpoint, latency=5.0)
    coordinator = SecurityPolicyCoordinator(channel, timeout=0.02)
    late = candidate(PROXIES_COUNT=1)

    status = coordinator.rollout(late, attempt=2)

    assert status.status == "rolled_back"
    assert dict(status.workers) == {"w1": "rolled_back", "w2": "unconfirmed"}
    assert early_runtime.active.generation == 1
    assert late_runtime.active.generation == 1
    assert not [r for r in channel.pending if r.action == "commit"]
    late_reply = channel.release_late_replies()
    assert late_reply == [
        r for r in late_reply if r.worker == "w2" and r.action == "stage"
    ]

    # A late worker cannot be committed by a stale command.
    reply = late_endpoint.deliver(
        PolicyCommand("commit", 2, 2, late.fingerprint)
    )
    assert reply.status == "rejected"
    assert late_runtime.active.generation == 1


def test_failed_validation_never_reaches_the_channel():
    endpoint, runtime = make_worker("w1")
    channel = InMemoryWorkerChannel()
    channel.add_worker(endpoint)
    channel.send = Mock(wraps=channel.send)  # type: ignore
    coordinator = SecurityPolicyCoordinator(channel)
    invalid = SecurityPolicySnapshot(
        3,
        type(base().fields)({**base().fields, "PROXIES_COUNT": -1}),
        "bogus-fingerprint",
    )

    status = coordinator.rollout(invalid, attempt=3)

    assert status.status == "rejected"
    channel.send.assert_not_called()
    assert runtime.active.generation == 1
    assert "PROXIES_COUNT" in coordinator.error_log[-1]
    assert "-1" not in coordinator.error_log[-1]


def test_commit_failure_reverts_workers_that_already_committed():
    good_endpoint, good_runtime = make_worker("w1")
    bad_endpoint, bad_runtime = make_worker("w2")
    channel = InMemoryWorkerChannel()
    channel.add_worker(good_endpoint)
    channel.add_worker(bad_endpoint)
    original = bad_endpoint.deliver
    calls = {"n": 0}

    def flaky(command):
        calls["n"] += 1
        if command.action == "commit":
            return type(
                "_R",
                (),
                {
                    "worker": "w2",
                    "action": "commit",
                    "attempt": command.attempt,
                    "generation": command.generation,
                    "status": "rejected",
                    "reason": "StalePolicyTransaction",
                },
            )()
        return original(command)

    bad_endpoint.deliver = flaky  # type: ignore
    coordinator = SecurityPolicyCoordinator(channel, timeout=0.02)
    target = candidate()

    status = coordinator.rollout(target, attempt=5)

    assert status.status == "aborted"
    assert dict(status.workers) == {"w1": "reverted", "w2": "unconfirmed"}
    assert good_runtime.active.generation == 1
    assert bad_runtime.active.generation == 1


def test_worker_exit_during_staging_aborts_rollout():
    live_endpoint, live_runtime = make_worker("w1")
    dead_endpoint, dead_runtime = make_worker("w2")
    channel = InMemoryWorkerChannel()
    channel.add_worker(live_endpoint)
    channel.add_worker(dead_endpoint)
    channel.crash("w2", after="none")
    coordinator = SecurityPolicyCoordinator(channel, timeout=0.02)

    status = coordinator.rollout(candidate(), attempt=6)

    assert status.status == "aborted"
    assert dict(status.workers) == {"w1": "rolled_back", "w2": "exited"}
    assert live_runtime.active.generation == 1
    assert not dead_runtime.enabled


def test_worker_exit_during_commit_reverts_committed_workers():
    live_endpoint, live_runtime = make_worker("w1")
    dead_endpoint, dead_runtime = make_worker("w2")
    channel = InMemoryWorkerChannel()
    channel.add_worker(live_endpoint)
    channel.add_worker(dead_endpoint, latency=5.0)
    coordinator = SecurityPolicyCoordinator(channel, timeout=0.02)
    channel._crash_after["w2"] = "never"  # reply will never arrive

    status = coordinator.rollout(candidate(), attempt=7)

    assert status.status == "rolled_back"


def test_old_connection_pins_or_revalidates_explicitly():
    from types import SimpleNamespace
    from unittest.mock import Mock

    runtime = SecurityPolicyRuntime(base(), enabled=True, name="w1")
    conn = SimpleNamespace(ctx=SimpleNamespace())
    request = SimpleNamespace(
        conn_info=conn, headers=Mock(), ctx=SimpleNamespace()
    )
    request.headers.getone.return_value = None
    assert runtime.pin_request(request).generation == 1

    pinned = candidate(OLD_CONNECTION_POLICY="pin")
    runtime.stage(1, pinned)
    runtime.commit(1, pinned.generation, pinned.fingerprint)

    old_request = SimpleNamespace(
        conn_info=conn, headers=Mock(), ctx=SimpleNamespace()
    )
    old_request.headers.getone.return_value = None
    assert runtime.pin_request(old_request).generation == 1


def test_revalidate_policy_moves_old_connections_to_new_generation():
    from types import SimpleNamespace
    from unittest.mock import Mock

    runtime = SecurityPolicyRuntime(base(), enabled=True, name="w1")
    conn = SimpleNamespace(ctx=SimpleNamespace())
    request = SimpleNamespace(
        conn_info=conn, headers=Mock(), ctx=SimpleNamespace()
    )
    request.headers.getone.return_value = None
    runtime.pin_request(request)

    revalidate = candidate(OLD_CONNECTION_POLICY="revalidate")
    runtime.stage(2, revalidate)
    runtime.commit(2, revalidate.generation, revalidate.fingerprint)

    next_request = SimpleNamespace(
        conn_info=conn, headers=Mock(), ctx=SimpleNamespace()
    )
    next_request.headers.getone.return_value = None
    assert runtime.pin_request(next_request).generation == 2


def test_retired_generation_is_unavailable_under_pin_policy():
    from types import SimpleNamespace
    from unittest.mock import Mock

    from sanic.security import PolicyNotActive

    runtime = SecurityPolicyRuntime(base(), enabled=True, name="w1")
    conn = SimpleNamespace(ctx=SimpleNamespace())
    conn.ctx.sanic_security_generation = 0
    request = SimpleNamespace(
        conn_info=conn, headers=Mock(), ctx=SimpleNamespace()
    )
    request.headers.getone.return_value = None

    with pytest.raises(PolicyNotActive):
        runtime.pin_request(request)


def test_status_contains_only_generation_and_state():
    endpoint, runtime = make_worker("w1", enabled=False)
    channel = InMemoryWorkerChannel()
    channel.add_worker(endpoint)
    coordinator = SecurityPolicyCoordinator(channel)
    secret = "proxy-secret"
    target = candidate(FORWARDED_SECRET=secret, AUTH_TOKEN="token")

    status = coordinator.rollout(target, attempt=8)
    rendered = repr(status.as_dict())

    assert set(status.as_dict()) == {"generation", "status", "workers"}
    assert secret not in rendered
    assert "token" not in rendered
    assert "FORWARDED_SECRET" not in rendered
    assert status.as_dict()["generation"] == 2


def test_stale_or_reused_generation_is_rejected():
    from sanic.security import StalePolicyTransaction

    endpoint, runtime = make_worker("w1")
    with pytest.raises(StalePolicyTransaction, match="newer"):
        runtime.stage(1, base())
    runtime.stage(2, candidate())
    runtime.commit(2, 2, candidate().fingerprint)
    with pytest.raises(StalePolicyTransaction, match="newer"):
        runtime.stage(3, candidate())


def test_attempt_cannot_be_reused_after_rollback():
    from sanic.security import StalePolicyTransaction

    endpoint, runtime = make_worker("w1")
    endpoint.deliver(
        PolicyCommand(
            "stage",
            1,
            candidate().generation,
            candidate().fingerprint,
            candidate(),
        )
    )
    endpoint.deliver(PolicyCommand("rollback", 1, candidate().generation))
    with pytest.raises(StalePolicyTransaction, match="rolled back"):
        runtime.stage(1, candidate().updated(3, {}))
