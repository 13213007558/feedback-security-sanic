from __future__ import annotations

import asyncio
import tempfile

from .app import create_app
from .asgi_harness import ASGIClient
from .file_store import FileStore
from .models import TicketState
from .ticket_store import TicketStore

FILE_ID = "report"
ALICE = "alice"
BOB = "bob"
ALICE_LAPTOP = "alice-laptop-1"
ALICE_PHONE = "alice-phone-9"
BOB_DESKTOP = "bob-desktop-2"

PASS = 0
FAIL = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}  {detail}")


async def publish(client: ASGIClient, file_id: str, content: bytes):
    import base64
    import json

    response = await client.request(
        "POST",
        f"/admin/files/{file_id}/publish",
        json_body={"content_base64": base64.b64encode(content).decode()},
    )
    assert response.status == 201, response.body
    return json.loads(response.body)


async def issue(client: ASGIClient, user: str, file_id: str):
    response = await client.request(
        "POST",
        f"/files/{file_id}/tickets",
        headers={"X-User": user},
    )
    assert response.status == 201, response.body
    import json

    return json.loads(response.body)


async def status(client: ASGIClient, ticket_id: str, user: str):
    response = await client.request(
        "GET",
        f"/tickets/{ticket_id}",
        headers={"X-User": user},
    )
    assert response.status == 200, response.body
    import json

    return json.loads(response.body)


async def main() -> int:
    base_dir = tempfile.mkdtemp(prefix="download-demo-test-")
    files = FileStore(base_dir=base_dir)
    tickets = TicketStore(ttl_seconds=300)
    app = create_app(
        file_store=files,
        ticket_store=tickets,
        chunk_size=512,
        app_name="download-demo-main",
    )
    client = ASGIClient(app)
    await client.startup()
    service = app.ctx.service

    v1_content = bytes((i * 7 + 3) % 256 for i in range(10_000))
    v2_content = b"V2-" + bytes((i * 11 + 1) % 256 for i in range(7_500))
    cut_point = 2048  # exact multiple of the 512-byte stream chunk size

    print("== setup: publish v1 and v2, issue tickets ==")
    await publish(client, FILE_ID, v1_content)
    ticket_alice = await issue(client, ALICE, FILE_ID)
    await publish(client, FILE_ID, v2_content)
    ticket_bob = await issue(client, BOB, FILE_ID)
    check("alice ticket pins v1", ticket_alice["version"] == 1)
    check("bob ticket pins v2", ticket_bob["version"] == 2)

    print("== 1. claim requires identity headers ==")
    no_headers = await client.request(
        "GET", f"/tickets/{ticket_alice['ticket_id']}/download"
    )
    check("missing identity -> 401", no_headers.status == 401)

    print(f"== 2. alice laptop claims, streams {cut_point} bytes, then disconnects ==")
    first = await client.request(
        "GET",
        f"/tickets/{ticket_alice['ticket_id']}/download",
        headers={"X-User": ALICE, "X-Client-Id": ALICE_LAPTOP},
        disconnect_after=cut_point,
    )
    check(
        "handler converted disconnect into an interrupted transfer",
        first.error is None and first.status == 200,
        f"error={first.error!r} status={first.status}",
    )
    check(f"{cut_point} bytes left the server",
          first.stream_byte_count == cut_point,
          f"got {first.stream_byte_count}")
    check(
        "first bytes match v1 snapshot",
        first.body == v1_content[:cut_point],
    )
    state_after_cut = await status(client, ticket_alice["ticket_id"], ALICE)
    check(
        "ticket state is interrupted",
        state_after_cut["state"] == TicketState.INTERRUPTED.value,
        state_after_cut["state"],
    )
    check(
        f"ticket accounting commits the {cut_point} authorized bytes",
        state_after_cut["delivered_bytes"] == cut_point,
        str(state_after_cut["delivered_bytes"]),
    )

    print("== 3. another identity (bob) cannot claim alice's ticket ==")
    bob_attempt = await client.request(
        "GET",
        f"/tickets/{ticket_alice['ticket_id']}/download",
        headers={"X-User": BOB, "X-Client-Id": BOB_DESKTOP},
    )
    check("cross-user claim -> 403", bob_attempt.status == 403)
    check(
        "no stream bytes leaked to other identity",
        bob_attempt.stream_byte_count == 0,
        str(bob_attempt.stream_byte_count),
    )

    print("== 4. alice's second client cannot steal an interrupted ticket ==")
    phone_attempt = await client.request(
        "GET",
        f"/tickets/{ticket_alice['ticket_id']}/download",
        headers={"X-User": ALICE, "X-Client-Id": ALICE_PHONE},
    )
    check("same-user different client -> 409", phone_attempt.status == 409)

    print("== 5. concurrent transfer for the same bound client is rejected ==")
    gate = asyncio.Event()
    service.stream_gate = gate
    laptop_coro = client.request(
        "GET",
        f"/tickets/{ticket_bob['ticket_id']}/download",
        headers={"X-User": BOB, "X-Client-Id": BOB_DESKTOP},
        disconnect_after=100_000,
    )
    laptop_task = asyncio.create_task(laptop_coro)
    await asyncio.sleep(0.15)
    concurrent = await client.request(
        "GET",
        f"/tickets/{ticket_bob['ticket_id']}/download",
        headers={"X-User": BOB, "X-Client-Id": BOB_DESKTOP},
    )
    check("overlapping transfer -> 409", concurrent.status == 409)
    check("rejected request sent no stream bytes",
          concurrent.stream_byte_count == 0)
    gate.set()
    laptop_full = await laptop_task
    service.stream_gate = None
    check(
        "first transfer finished with whole v2",
        laptop_full.byte_count == len(v2_content),
        f"got {laptop_full.byte_count}",
    )
    check(
        "outgoing bytes are exactly v2 content",
        laptop_full.body == v2_content,
    )
    bob_state = await status(client, ticket_bob["ticket_id"], BOB)
    check(
        "bob ticket is consumed",
        bob_state["state"] == TicketState.CONSUMED.value,
        bob_state["state"],
    )
    check(
        "consumed ticket accounting covers full file",
        bob_state["delivered_bytes"] == len(v2_content),
    )
    after_consumed = await client.request(
        "GET",
        f"/tickets/{ticket_bob['ticket_id']}/download",
        headers={"X-User": BOB, "X-Client-Id": BOB_DESKTOP},
    )
    check("re-download of consumed ticket -> 410",
          after_consumed.status == 410)

    print(f"== 6. alice laptop resumes with Range from byte {cut_point} ==")
    resume = await client.request(
        "GET",
        f"/tickets/{ticket_alice['ticket_id']}/download",
        headers={
            "X-User": ALICE,
            "X-Client-Id": ALICE_LAPTOP,
            "Range": f"bytes={cut_point}-",
        },
    )
    check("resume returns 206", resume.status == 206)
    check(
        "content-range describes the suffix",
        resume.headers.get("content-range")
        == f"bytes {cut_point}-{len(v1_content) - 1}/{len(v1_content)}",
        resume.headers.get("content-range"),
    )
    check(
        f"resumed bytes match v1[{cut_point}:]",
        resume.body == v1_content[cut_point:],
    )
    check(
        "resume sends exactly the missing suffix",
        resume.stream_byte_count == len(v1_content) - cut_point,
    )
    alice_state = await status(client, ticket_alice["ticket_id"], ALICE)
    check(
        "alice ticket consumed after full resume",
        alice_state["state"] == TicketState.CONSUMED.value,
        alice_state["state"],
    )
    check(
        "union of outgoing bytes equals the whole v1 file, no duplication",
        alice_state["delivered_bytes"] == len(v1_content),
        str(alice_state["delivered_bytes"]),
    )
    check(
        "reconstructed download equals original v1",
        first.body + resume.body == v1_content,
    )

    print("== 7. version pinning: old ticket never receives v2 bytes ==")
    v1_ticket_again = await issue(client, ALICE, FILE_ID)
    check("new ticket after v2 publish pins version 2",
          v1_ticket_again["version"] == 2)
    full = await client.request(
        "GET",
        f"/tickets/{v1_ticket_again['ticket_id']}/download",
        headers={"X-User": ALICE, "X-Client-Id": ALICE_LAPTOP},
    )
    check("fresh ticket serves current v2 content", full.body == v2_content)
    check("v2 marker never appears in alice's v1 download",
          v2_content[:3] not in (first.body + resume.body))

    print("== 8. failure recovery cannot widen ticket permissions ==")
    guard_cut = 512  # chunk-aligned interruption point
    guard_ticket = await issue(client, ALICE, FILE_ID)
    cut = await client.request(
        "GET",
        f"/tickets/{guard_ticket['ticket_id']}/download",
        headers={"X-User": ALICE, "X-Client-Id": ALICE_LAPTOP},
        disconnect_after=guard_cut,
    )
    check("guarded transfer cut at the chunk boundary",
          cut.stream_byte_count == guard_cut)
    overshoot = await client.request(
        "GET",
        f"/tickets/{guard_ticket['ticket_id']}/download",
        headers={
            "X-User": ALICE,
            "X-Client-Id": ALICE_LAPTOP,
            "Range": f"bytes={len(v2_content)}-{len(v2_content) + 99}",
        },
    )
    check(
        "range past snapshot end -> 416",
        overshoot.status == 416,
        str(overshoot.status),
    )
    bad_range = await client.request(
        "GET",
        f"/tickets/{guard_ticket['ticket_id']}/download",
        headers={
            "X-User": ALICE,
            "X-Client-Id": ALICE_LAPTOP,
            "Range": "bytes=999999-",
        },
    )
    check("start beyond file -> 416", bad_range.status == 416)
    malformed = await client.request(
        "GET",
        f"/tickets/{guard_ticket['ticket_id']}/download",
        headers={
            "X-User": ALICE,
            "X-Client-Id": ALICE_LAPTOP,
            "Range": "bytes=abc",
        },
    )
    check("malformed range -> 416", malformed.status == 416)
    guard_state = await status(client, guard_ticket["ticket_id"], ALICE)
    check(
        "rejected resumes do not advance byte accounting",
        guard_state["delivered_bytes"] == guard_cut,
        str(guard_state["delivered_bytes"]),
    )
    check(
        "ticket stays interrupted, not consumed or widened",
        guard_state["state"] == TicketState.INTERRUPTED.value,
        guard_state["state"],
    )
    finish = await client.request(
        "GET",
        f"/tickets/{guard_ticket['ticket_id']}/download",
        headers={
            "X-User": ALICE,
            "X-Client-Id": ALICE_LAPTOP,
            "Range": f"bytes={guard_cut}-{len(v2_content) - 1}",
        },
    )
    check(
        f"resumed suffix is v2[{guard_cut}:] and nothing more",
        finish.body == v2_content[guard_cut:],
    )
    final_guard = await status(client, guard_ticket["ticket_id"], ALICE)
    check(
        "final union is exactly one file length",
        final_guard["delivered_bytes"] == len(v2_content),
        str(final_guard["delivered_bytes"]),
    )
    check(
        "guard ticket ends consumed",
        final_guard["state"] == TicketState.CONSUMED.value,
        final_guard["state"],
    )

    print("== 9. expiry closes the ticket without enlarging access ==")
    short_tickets = TicketStore(ttl_seconds=0)
    short_app = create_app(
        file_store=files,
        ticket_store=short_tickets,
        chunk_size=512,
        app_name="download-demo-short-ttl",
    )
    short_client = ASGIClient(short_app)
    await short_client.startup()
    short_ticket = await issue(short_client, ALICE, FILE_ID)
    await asyncio.sleep(0.05)
    expired = await short_client.request(
        "GET",
        f"/tickets/{short_ticket['ticket_id']}/download",
        headers={"X-User": ALICE, "X-Client-Id": ALICE_LAPTOP},
    )
    check("expired claim -> 410", expired.status == 410)
    check("expired ticket leaks no stream bytes",
          expired.stream_byte_count == 0)

    print("== 10. cross-user status read is forbidden ==")
    peek = await client.request(
        "GET",
        f"/tickets/{ticket_alice['ticket_id']}",
        headers={"X-User": BOB},
    )
    check("other user cannot inspect ticket -> 403", peek.status == 403)

    await short_client.shutdown()
    await client.shutdown()
    print(f"\nresult: {PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
