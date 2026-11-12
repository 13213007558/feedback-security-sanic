"""Pytest wrapper around the interleaved-client integration scenario."""

import asyncio

from .run_integration import main


def test_interleaved_clients_ticket_lifecycle_and_bytes():
    failures = asyncio.run(main())
    assert failures == 0
