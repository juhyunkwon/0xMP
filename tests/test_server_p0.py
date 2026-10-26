"""P0 integration: auth over WebSocket, persist-then-ACK, replay, fan-out."""
import asyncio
import dataclasses
import uuid

import pytest
import websockets

from oxmp_frame import Frame, FrameType, encode
from oxmp_payload import Auth, Hello
from server.auth import TokenService
from server.client import OxmpClient
from server.testing import TEST_SECRET, running_server


def uid():
    return uuid.uuid4().bytes


def test_forged_and_expired_tokens_rejected_over_ws():
    async def scenario():
        async with running_server() as env:
            forged = dataclasses.replace(env.alice, access_token="forged.token")
            with pytest.raises(PermissionError):
                await OxmpClient(env.url, forged).connect()

            short = TokenService(TEST_SECRET, access_ttl_seconds=-1)
            expired_token = short.issue_access(env.alice.user_id, env.alice.device_id, 1)
            expired = dataclasses.replace(env.alice, access_token=expired_token)
            with pytest.raises(PermissionError):
                await OxmpClient(env.url, expired).connect()
    asyncio.run(scenario())


def test_wrong_device_signature_rejected():
    async def scenario():
        async with running_server() as env:
            # Bob's private key signing Alice's session must fail (SEC-04).
            impostor = dataclasses.replace(env.alice, private_key=env.bob.private_key)
            with pytest.raises(PermissionError):
                await OxmpClient(env.url, impostor).connect()
    asyncio.run(scenario())


def test_unauthenticated_message_rejected():
    async def scenario():
        async with running_server() as env:
            async with websockets.connect(env.url) as ws:
                await ws.send(encode(Frame(FrameType.HELLO, Hello(
                    protocol_id="0xmp.v1", max_security_profile=1).SerializeToString())))
                await ws.recv()  # HELLO_RESULT
                from oxmp_payload import MessageSend
                send = MessageSend(message_id=uid(), conversation_id=uid(),
                                   sender_device_id=env.alice.device_id)
                await ws.send(encode(Frame(FrameType.MESSAGE_SEND,
                                           send.SerializeToString())))
                reply = await asyncio.wait_for(ws.recv(), 5)
                from oxmp_frame import decode
                from oxmp_payload import Error
                frame = decode(reply)
                assert frame.frame_type is FrameType.ERROR
                assert Error.FromString(frame.payload).code == 0x0003
    asyncio.run(scenario())


def test_send_persists_before_ack_and_replay_is_duplicate():
    async def scenario():
        async with running_server() as env:
            conv = uid()
            env.store.add_member(conv, env.bob.user_id)
            alice = OxmpClient(env.url, env.alice)
            await alice.connect()
            key, mid = uid(), uid()
            accepted = await alice.send_text(conv, "durable", idempotency_key=key,
                                             message_id=mid)
            assert accepted.sequence == 1 and not accepted.duplicate
            # ACK was received, so the row MUST already be committed.
            assert env.store.count_messages(conv) == 1
            # Replay of the same request (e.g. the first ACK was lost):
            replay = await alice.send_text(conv, "durable", idempotency_key=key,
                                           message_id=mid)
            assert replay.duplicate and replay.sequence == accepted.sequence
            assert env.store.count_messages(conv) == 1
            await alice.close()
    asyncio.run(scenario())


def test_concurrent_duplicate_sends_store_once():
    async def scenario():
        async with running_server() as env:
            conv, key = uid(), uid()
            clients = [OxmpClient(env.url, env.alice) for _ in range(5)]
            for c in clients:
                await c.connect()
            results = await asyncio.gather(*[
                c.send_text(conv, "same", idempotency_key=key) for c in clients])
            assert len({r.sequence for r in results}) == 1
            assert sum(1 for r in results if not r.duplicate) == 1
            assert env.store.count_messages(conv) == 1
            for c in clients:
                await c.close()
    asyncio.run(scenario())


def test_fanout_to_online_member_and_ordering():
    async def scenario():
        async with running_server() as env:
            conv = uid()
            env.store.add_member(conv, env.bob.user_id)
            alice, bob = OxmpClient(env.url, env.alice), OxmpClient(env.url, env.bob)
            await alice.connect()
            await bob.connect()
            for i in range(5):
                await alice.send_text(conv, f"msg-{i}")
                incoming = await bob.wait_incoming()
                assert incoming.content.body.decode() == f"msg-{i}"
                assert incoming.sequence == i + 1
                await bob.delivery_ack(incoming)
            await alice.close()
            await bob.close()
    asyncio.run(scenario())
