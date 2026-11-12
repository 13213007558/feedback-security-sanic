from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .channel import (
    REPLY_ACKED,
    REPLY_COMMITTED,
    PolicyChannel,
    PolicyCommand,
    PolicyReply,
)
from .policy import (
    SecurityPolicySnapshot,
    SecurityPolicyValidationError,
)


@dataclass(frozen=True, slots=True)
class PolicyStatus:
    """Operator-visible rollout result.

    Only the generation and lifecycle state are public. Secret values, header
    names and worker acknowledgment payloads never appear here.
    """

    generation: int
    status: str
    workers: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "generation": self.generation,
            "status": self.status,
            "workers": [
                {"name": name, "status": status}
                for name, status in self.workers
            ],
        }


class SecurityPolicyCoordinator:
    """Two-phase rollout of an immutable policy snapshot.

    The lifecycle is deliberately linear:

    ``staging -> staged -> committing -> active``

    A candidate that fails validation never reaches the worker channel. A
    missing, late, rejected or dead-worker acknowledgment aborts the whole
    rollout and rolls the staged candidate back everywhere before any commit
    is sent. A failed commit reverts workers that already committed.
    """

    def __init__(
        self,
        channel: PolicyChannel,
        *,
        timeout: float = 0.05,
        poll_interval: float = 0.005,
    ):
        self.channel = channel
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.error_log: list[str] = []

    def rollout(
        self,
        candidate: SecurityPolicySnapshot,
        attempt: int,
        *,
        validate: bool = True,
    ) -> PolicyStatus:
        if validate:
            try:
                SecurityPolicySnapshot.build(
                    candidate.generation, candidate.fields
                )
            except SecurityPolicyValidationError as e:
                self.error_log.append(str(e))
                return PolicyStatus(candidate.generation, "rejected")

        targets = self.channel.targets()
        if not targets:
            return PolicyStatus(candidate.generation, "aborted")
        dead = [worker for worker in targets if not self.channel.alive(worker)]
        if dead:
            rolled = self._rollback(
                [w for w in targets if w not in dead],
                attempt,
                candidate.generation,
            )
            statuses = tuple(
                (
                    worker,
                    "exited"
                    if worker in dead
                    else (
                        "rolled_back" if worker in rolled else "unconfirmed"
                    ),
                )
                for worker in targets
            )
            return PolicyStatus(candidate.generation, "aborted", statuses)

        for worker in targets:
            self.channel.send(
                worker,
                PolicyCommand(
                    "stage",
                    attempt,
                    candidate.generation,
                    candidate.fingerprint,
                    candidate,
                ),
            )

        replies = self._collect("stage", attempt, targets)
        staged = {
            reply.worker for reply in replies if reply.status == REPLY_ACKED
        }
        unconfirmed = [
            reply for reply in replies if reply.status != REPLY_ACKED
        ]
        missing = sorted(set(targets) - staged)
        if unconfirmed or missing:
            rolled = self._rollback(targets, attempt, candidate.generation)
            statuses = tuple(
                (
                    worker,
                    "rolled_back" if worker in rolled else "unconfirmed",
                )
                for worker in targets
            )
            return PolicyStatus(candidate.generation, "rolled_back", statuses)

        for worker in targets:
            self.channel.send(
                worker,
                PolicyCommand(
                    "commit",
                    attempt,
                    candidate.generation,
                    candidate.fingerprint,
                ),
            )
        commit_replies = self._collect("commit", attempt, targets)
        committed = {
            reply.worker
            for reply in commit_replies
            if reply.status == REPLY_COMMITTED
        }
        if len(committed) != len(targets) or not all(
            self.channel.alive(worker) for worker in targets
        ):
            self._revert(list(committed), attempt, candidate)
            return PolicyStatus(
                candidate.generation,
                "aborted",
                self._worker_statuses(targets, committed, "reverted"),
            )

        return PolicyStatus(
            candidate.generation,
            "active",
            tuple((worker, "active") for worker in targets),
        )

    def _collect(
        self, action: str, attempt: int, targets: list[str]
    ) -> list[PolicyReply]:
        received: dict[str, PolicyReply] = {}
        remaining = self.timeout
        while remaining > 0 and len(received) < len(targets):
            replies = self.channel.receive(self.poll_interval)
            if not replies:
                remaining -= self.poll_interval
                continue
            remaining = self.timeout
            for reply in replies:
                if reply.action != action or reply.attempt != attempt:
                    continue
                if reply.worker not in targets or reply.worker in received:
                    continue
                received[reply.worker] = reply
        return [reply for reply in received.values()]

    def _rollback(
        self, workers: list[str], attempt: int, generation: int
    ) -> set[str]:
        for worker in workers:
            self.channel.send(
                worker,
                PolicyCommand("rollback", attempt, generation),
            )
        replies: list[PolicyReply] = []
        remaining = self.timeout
        while remaining > 0:
            more = self.channel.receive(self.poll_interval)
            if more:
                replies.extend(more)
                remaining = self.timeout
                if len(
                    {r.worker for r in replies if r.action == "rollback"}
                ) >= len(workers):
                    break
            else:
                remaining -= self.poll_interval
        return {r.worker for r in replies if r.action == "rollback"}

    def _revert(
        self,
        workers: list[str],
        attempt: int,
        candidate: SecurityPolicySnapshot,
    ) -> None:
        for worker in workers:
            self.channel.send(
                worker,
                PolicyCommand(
                    "revert",
                    attempt,
                    candidate.generation,
                    candidate.fingerprint,
                ),
            )
        self.channel.receive(self.timeout)

    @staticmethod
    def _worker_statuses(
        targets: list[str], complete: set[str], status: str
    ) -> tuple[tuple[str, str], ...]:
        return tuple(
            (
                worker,
                status if worker in complete else "unconfirmed",
            )
            for worker in targets
        )
