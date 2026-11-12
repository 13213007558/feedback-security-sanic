import asyncio

import pytest

from sanic import Sanic
from sanic.exceptions import UnauthorizedSignal


class BackupExtension:
    """Test double: extension performing a sensitive background action."""

    def __init__(self, app, event, **kwargs):
        self.calls = []
        app.add_signal(self.run_backup, event, require_sender=True, **kwargs)

    async def run_backup(self, **context):
        self.calls.append(context)


class MetricsExtension:
    """Test double: extension listening on public signals."""

    def __init__(self, app, event, **kwargs):
        self.calls = []
        app.add_signal(self.record, event, **kwargs)

    def record(self, **context):
        self.calls.append(context)


@pytest.fixture
def extensions(app):
    backup = BackupExtension(app, "ext.maintenance.run")
    metrics = MetricsExtension(app, "ext.maintenance.run")
    return backup, metrics


@pytest.mark.asyncio
async def test_same_name_signals_authorized_dispatch_runs_both(
    app, extensions
):
    backup, metrics = extensions
    app.signal_router.finalize()
    sender = app.create_signal_sender("ops")

    await app.dispatch("ext.maintenance.run", inline=True, sender=sender)

    assert len(backup.calls) == 1
    assert len(metrics.calls) == 1


@pytest.mark.asyncio
async def test_same_name_signals_unauthorized_rejected_before_handlers(
    app, extensions
):
    backup, metrics = extensions
    app.signal_router.finalize()

    with pytest.raises(UnauthorizedSignal, match="ext.maintenance.run"):
        await app.dispatch("ext.maintenance.run", inline=True)

    assert backup.calls == []
    assert metrics.calls == []


@pytest.mark.asyncio
async def test_public_signal_still_works_without_sender(app):
    metrics = MetricsExtension(app, "ext.metrics.flush")
    app.signal_router.finalize()

    await app.dispatch("ext.metrics.flush", inline=True)

    assert len(metrics.calls) == 1


@pytest.mark.asyncio
async def test_protected_signal_condition_matching(app):
    backup = BackupExtension(
        app, "ext.maintenance.run", condition={"mode": "full"}
    )
    app.signal_router.finalize()
    sender = app.create_signal_sender()

    with pytest.raises(UnauthorizedSignal):
        await app.dispatch(
            "ext.maintenance.run",
            condition={"mode": "full"},
            inline=True,
        )
    assert backup.calls == []

    await app.dispatch(
        "ext.maintenance.run",
        condition={"mode": "full"},
        inline=True,
        sender=sender,
    )
    assert len(backup.calls) == 1

    await app.dispatch(
        "ext.maintenance.run",
        condition={"mode": "quick"},
        inline=True,
        sender=sender,
    )
    assert len(backup.calls) == 1


@pytest.mark.asyncio
async def test_dispatch_then_wait_requires_sender(app, extensions):
    backup, _ = extensions
    app.signal_router.finalize()
    sender = app.create_signal_sender()

    event_task = asyncio.create_task(app.event("ext.maintenance.run"))
    await asyncio.sleep(0)

    task = await app.dispatch(
        "ext.maintenance.run", context={"job": "nightly"}
    )
    with pytest.raises(UnauthorizedSignal):
        await task
    await asyncio.sleep(0)
    assert not event_task.done()
    assert backup.calls == []

    await sender.dispatch(
        "ext.maintenance.run", context={"job": "nightly"}, inline=True
    )
    await asyncio.sleep(0)
    assert event_task.done()
    assert event_task.result() == {"job": "nightly"}
    assert len(backup.calls) == 1


@pytest.mark.asyncio
async def test_handler_exception_propagates_for_authorized_sender(app):
    class BrokenExtension:
        def __init__(self):
            self.calls = 0

        async def explode(self, **context):
            self.calls += 1
            raise RuntimeError("boom")

    broken = BrokenExtension()
    app.add_signal(broken.explode, "ext.maintenance.run", require_sender=True)
    app.signal_router.finalize()
    sender = app.create_signal_sender()

    with pytest.raises(RuntimeError, match="boom"):
        await app.dispatch("ext.maintenance.run", inline=True, sender=sender)
    assert broken.calls == 1

    with pytest.raises(UnauthorizedSignal):
        await app.dispatch("ext.maintenance.run", inline=True)
    assert broken.calls == 1


@pytest.mark.asyncio
async def test_sender_from_other_app_is_not_authorized(app, extensions):
    backup, metrics = extensions
    app.signal_router.finalize()
    other = Sanic("other")
    foreign_sender = other.create_signal_sender("foreign")

    with pytest.raises(UnauthorizedSignal):
        await app.dispatch(
            "ext.maintenance.run", inline=True, sender=foreign_sender
        )

    assert backup.calls == []
    assert metrics.calls == []
