from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from time import monotonic, sleep
from typing import Callable, Literal

from .policy import SecurityPolicyError, SecurityPolicySnapshot
from .runtime import PolicyAck, SecurityPolicyRuntime


PolicyAction = Literal["stage", "commit", "rollback", "revert", "exit"]
REPLY_ACKED = "acked"
REPLY_COMMITTED = "committed"
REPLY_ROLLED_BACK = "rolled_back"
REPLY_REVERTED = "reverted"
REPLY_REJECTED = "rejected"
REPLY_EXITED = "exited"


@dataclass(frozen=True, slots=True)
class PolicyCommand:
    action: PolicyAction
    attempt: int
    generation: int
    fingerprint: str = ""
    snapshot: SecurityPolicySnapshot | None = None


@dataclass(frozen=True, slots=True)
class PolicyReply:
    worker: str
    action: str
    attempt: int
    generation: int
    status: str
    reason: str = ""


class WorkerEndpoint:
    """One fake worker's policy state machine.

    The endpoint only mutates the runtime it owns; no request can observe a
    staged candidate because the runtime keeps it apart from the active
    snapshot.
    """

    def __init__(self, runtime: SecurityPolicyRuntime):
        self.runtime = runtime

    def deliver(self, command: PolicyCommand) -> PolicyReply:
        worker = self.runtime.name
        try:
            if command.action == "stage":
                if command.snapshot is None:
                    raise SecurityPolicyError("Missing candidate snapshot")
                ack: PolicyAck = self.runtime.stage(
                    command.attempt, command.snapshot
                )
                return PolicyReply(
                    worker,
                    command.action,
                    command.attempt,
                    ack.generation,
                    REPLY_ACKED,
                )
            if command.action == "commit":
                self.runtime.commit(
                    command.attempt,
                    command.generation,
                    command.fingerprint,
                )
                return PolicyReply(
                    worker,
                    command.action,
                    command.attempt,
                    command.generation,
                    REPLY_COMMITTED,
                )
            if command.action == "rollback":
                self.runtime.rollback(command.attempt, command.generation)
                return PolicyReply(
                    worker,
                    command.action,
                    command.attempt,
                    command.generation,
                    REPLY_ROLLED_BACK,
                )
            if command.action == "revert":
                self.runtime.revert_commit(
                    command.generation, command.fingerprint
                )
                return PolicyReply(
                    worker,
                    command.action,
                    command.attempt,
                    command.generation,
                    REPLY_REVERTED,
                )
            if command.action == "exit":
                self.runtime.exit()
                return PolicyReply(
                    worker,
                    command.action,
                    command.attempt,
                    self.runtime.active.generation,
                    REPLY_EXITED,
                )
            raise SecurityPolicyError("Unknown policy command")
        except SecurityPolicyError as e:
            return PolicyReply(
                worker,
                command.action,
                command.attempt,
                command.generation,
                REPLY_REJECTED,
                type(e).__name__,
            )


class PolicyChannel:
    """Minimal transport used by the coordinator.

    The real control plane may use a multiprocessing pipe; tests use
    :class:`InMemoryWorkerChannel` with the same contract.
    """

    def targets(self) -> list[str]:
        raise NotImplementedError

    def send(self, worker: str, command: PolicyCommand) -> None:
        raise NotImplementedError

    def receive(self, timeout: float) -> list[PolicyReply]:
        raise NotImplementedError

    def alive(self, worker: str) -> bool:
        raise NotImplementedError


class InMemoryWorkerChannel(PolicyChannel):
    """A fake worker channel for deterministic control-plane tests.

    Each worker can be given a reply latency, producing a late
    acknowledgement, or can be told to drop replies, producing an
    unconfirmed worker.
    """

    def __init__(self) -> None:
        self._endpoints: dict[str, WorkerEndpoint] = {}
        self._latency: dict[str, float] = {}
        self._drop: set[str] = set()
        self._alive: dict[str, bool] = {}
        self._crash_after: dict[str, str] = {}
        self._pending: deque[tuple[float, PolicyReply]] = deque()
        self._received: list[PolicyReply] = []
        self.clock: Callable[[], float] = monotonic
        self.sleeper: Callable[[float], None] = sleep

    def add_worker(
        self,
        endpoint: WorkerEndpoint,
        *,
        latency: float = 0.0,
        drop: bool = False,
    ) -> None:
        name = endpoint.runtime.name
        self._endpoints[name] = endpoint
        self._latency[name] = latency
        self._alive[name] = True
        if drop:
            self._drop.add(name)

    def set_latency(self, worker: str, latency: float) -> None:
        self._latency[worker] = latency

    def set_drop(self, worker: str, drop: bool = True) -> None:
        if drop:
            self._drop.add(worker)
        else:
            self._drop.discard(worker)

    def crash(self, worker: str, *, after: str = "stage") -> None:
        """Simulate a worker exiting while a rollout is in flight.

        ``after`` names the last action the worker is allowed to answer, so
        a crash can be placed before staging (``"none"``), after staging,
        after commit, or during the rollback itself.
        """
        self._alive[worker] = False
        self._drop.add(worker)
        self._crash_after[worker] = after
        endpoint = self._endpoints.get(worker)
        if endpoint is not None and after == "none":
            endpoint.runtime.exit()

    def _maybe_crash(self, worker: str, action: str) -> None:
        after = self._crash_after.get(worker)
        if after is None:
            return
        exited = after == action
        if exited:
            self._alive[worker] = False
            self._drop.add(worker)
            endpoint = self._endpoints[worker]
            endpoint.runtime.exit()

    def release_late_replies(self) -> list[PolicyReply]:
        """Deliver replies held back for an earlier attempt."""
        now = self.clock()
        due = [item for item in self._pending if item[0] <= now]
        self._pending = deque(item for item in self._pending if item[0] > now)
        replies = [reply for _, reply in due]
        self._received.extend(replies)
        return replies

    @property
    def pending(self) -> list[PolicyReply]:
        return [reply for _, reply in self._pending]

    def targets(self) -> list[str]:
        return list(self._endpoints)

    def alive_targets(self) -> list[str]:
        return [name for name, alive in self._alive.items() if alive]

    def alive(self, worker: str) -> bool:
        return bool(self._alive.get(worker, False))

    def send(self, worker: str, command: PolicyCommand) -> None:
        endpoint = self._endpoints[worker]
        if not self._alive[worker]:
            reply = PolicyReply(
                worker,
                command.action,
                command.attempt,
                command.generation,
                REPLY_EXITED,
            )
        elif worker in self._drop:
            return
        else:
            reply = endpoint.deliver(command)
            self._maybe_crash(worker, command.action)
        due = self.clock() + self._latency[worker]
        self._pending.append((due, reply))

    def receive(self, timeout: float) -> list[PolicyReply]:
        deadline = self.clock() + max(timeout, 0.0)
        while True:
            now = self.clock()
            due = [item for item in self._pending if item[0] <= now]
            if due:
                self._pending = deque(
                    item for item in self._pending if item[0] > now
                )
                replies = [reply for _, reply in due]
                self._received.extend(replies)
                return replies
            remaining = deadline - now
            if remaining <= 0:
                return []
            next_due = min(
                (item[0] for item in self._pending), default=deadline
            )
            self.sleeper(min(remaining, max(next_due - now, 0.001)))

    def drain(self) -> list[PolicyReply]:
        replies = self._received[:]
        self._received.clear()
        return replies
