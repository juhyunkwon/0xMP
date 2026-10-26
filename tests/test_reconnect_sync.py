"""P1 reconnect: offline delivery, cursor boundaries, ACK-loss recovery.

Key regression: a repeated SYNC_ACK value must be distinguishable as
'newly applied' vs 're-confirmation of an already applied cursor'.
SyncResult.newly_applied / reaffirmed_only provide that distinction.
"""
import asyncio
import uuid

import websockets

from oxmp_frame import Frame, FrameType, decode, encode
from oxmp_payload import Auth, Hello, HelloResult, MessageSend
from server.client import OxmpClient
from server.testing import running_server


def uid():
    return uuid.uuid4().bytes


def test_sync_ack_distinguishes_new_from_reaffirmed():
    async def scenario():
        async with running_server() as env:
            conv = uid()
            env.store.add_member(conv, env.bob.user_id)
            alice = OxmpClient(env.url, env.alice)
            await alice.connect()
            for i in range(3):  # Bob stays offline while Alice sends.
                await alice.send_text(conv, f"offline-{i}")
            await alice.close()

            bob = OxmpClient(env.url, env.bob)
            await bob.connect()
            first = await bob.sync(conv)
            assert first.newly_applied == 3
            assert (first.cursor_before, first.cursor_after) == (0, 3)
            assert not first.reaffirmed_only

            second = await bob.sync(conv)  # nothing new since the first sync
            assert second.newly_applied == 0
            assert second.reaffirmed_only  # <-- re-confirmation, NOT new data
            assert (second.cursor_before, second.cursor_after) == (3, 3)
            # Server-side cursor agrees and did not move on the second ACK.
            assert env.store.get_cursor(env.bob.device_id, conv) == 3
            await bob.close()
    asyncio.run(scenario())


def test_cursor_boundaries_empty_exact_and_beyond():
    async def scenario():
        async with running_server() as env:
            conv = uid()
            env.store.add_member(conv, env.bob.user_id)
            alice, bob = OxmpClient(env.url, env.alice), OxmpClient(env.url, env.bob)
            await alice.connect()
            await bob.connect()

            empty = await bob.sync(conv)  # empty conversation
            assert empty.newly_applied == 0 and empty.cursor_after == 0

            for i in range(5):
                await alice.send_text(conv, f"m{i}")
            paged = await bob.sync(conv, limit=2)  # pagination via has_more
            assert paged.newly_applied == 5
            assert [e.sequence for e in paged.events] == [1, 2, 3, 4, 5]

            bob.cursors[conv] = 999  # cursor beyond the end: no crash, no data
            beyond = await bob.sync(conv)
            assert beyond.newly_applied == 0 and beyond.cursor_after == 999
            await alice.close()
            await bob.close()
    asyncio.run(scenario())


def test_ack_loss_then_reconnect_retry_does_not_duplicate():
    """Send, drop the connection before reading ACCEPTED, reconnect, retry."""
    async def scenario():
        async with running_server() as env:
            conv, key, mid = uid(), uid(), uid()
            env.store.add_member(conv, env.bob.user_id)
            creds = env.alice
            async with websockets.connect(env.url) as ws:
                await ws.send(encode(Frame(FrameType.HELLO, Hello(
                    protocol_id="0xmp.v1", max_security_profile=2).SerializeToString())))
                hello = HelloResult.FromString(
                    decode(await ws.recv()).payload)
                sig = creds.private_key.sign(hello.session_id.encode())
                await ws.send(encode(Frame(FrameType.AUTH, Auth(
                    access_token=creds.access_token, device_id=creds.device_id,
                    signature=sig).SerializeToString())))
                await ws.recv()  # AUTH_RESULT; we never read MESSAGE_ACCEPTED
                send = MessageSend(message_id=mid, conversation_id=conv,
                                   sender_device_id=creds.device_id,
                                   idempotency_key=key)
                send.content.kind, send.content.body = 1, b"ack was lost"
                await ws.send(encode(Frame(FrameType.MESSAGE_SEND,
                                           send.SerializeToString())))
            # Connection dropped. Wait until the server has committed (or not).
            for _ in range(50):
                if env.store.count_messages(conv) == 1:
                    break
                await asyncio.sleep(0.1)
            assert env.store.count_messages(conv) == 1

            alice = OxmpClient(env.url, creds)
            await alice.connect()
            retry = await alice.send_text(conv, "ack was lost",
                                          idempotency_key=key, message_id=mid)
            assert retry.duplicate and retry.sequence == 1
            assert env.store.count_messages(conv) == 1
            await alice.close()
    asyncio.run(scenario())
