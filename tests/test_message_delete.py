"""Message deletion: sender-only deletes, tombstone sync, whole-room clear."""
import asyncio

from server.client import OxmpClient
from server.provision import create_account
from server.testing import running_server


def test_sender_deletes_and_peer_sees_tombstone_on_sync():
    async def scenario():
        async with running_server() as env:
            conv = env.store.find_or_create_direct(env.alice.user_id,
                                                   env.bob.user_id)
            alice = OxmpClient(env.url, env.alice)
            bob = OxmpClient(env.url, env.bob)
            await alice.connect()
            await bob.connect()
            accepted = await alice.send_text(conv, "지울 메시지")
            incoming = await bob.wait_incoming()
            assert incoming.content.body == "지울 메시지".encode()

            # The peer converges in real time via the broadcast frame.
            await alice.delete_message(conv, accepted.message_id)
            event = await bob.wait_delete()
            assert event.message_id == accepted.message_id
            assert event.conversation_id == conv

            # And a fresh entry sync delivers a body-less tombstone.
            await bob.close()
            bob2 = OxmpClient(env.url, env.bob)
            await bob2.connect()
            result = await bob2.sync(conv)
            tombstones = [ev for ev in result.events if ev.type == 3]
            assert len(tombstones) == 1
            assert tombstones[0].message.message_id == accepted.message_id
            assert tombstones[0].message.content.body == b""
            stored = env.store.message_by_id(accepted.message_id)
            assert stored.deleted and stored.body == b""
            await alice.close()
            await bob2.close()
    asyncio.run(scenario())


def test_other_member_cannot_delete_my_message():
    async def scenario():
        async with running_server() as env:
            conv = env.store.find_or_create_direct(env.alice.user_id,
                                                   env.bob.user_id)
            alice = OxmpClient(env.url, env.alice)
            bob = OxmpClient(env.url, env.bob)
            await alice.connect()
            await bob.connect()
            accepted = await alice.send_text(conv, "남의 것")
            await bob.wait_incoming()
            # Bob tries to delete Alice's message: server must reject.
            await bob.delete_message(conv, accepted.message_id)
            reply = await bob.next_error()
            assert reply is not None
            stored = env.store.message_by_id(accepted.message_id)
            assert not stored.deleted and stored.body == "남의 것".encode()
            await alice.close()
            await bob.close()
    asyncio.run(scenario())


def test_clear_group_room_is_creator_only():
    async def scenario():
        async with running_server() as env:
            carol = create_account(env.store, env.tokens, "carol")
            room = env.store.create_conversation(
                env.alice.user_id, [env.bob.user_id, carol.user_id],
                title="팀", kind="group")
            alice = OxmpClient(env.url, env.alice)
            bob = OxmpClient(env.url, env.bob)
            await alice.connect()
            await bob.connect()
            await alice.send_text(room, "하나")
            await bob.wait_incoming()
            await bob.send_text(room, "둘")
            await alice.wait_incoming()

            # Bob is not the creator: a whole-room clear is rejected.
            await bob.delete_message(room, b"")
            reply = await bob.next_error()
            assert reply is not None
            assert env.store.count_messages(room) == 2
            assert env.store.tombstones(room) == []

            # Alice (creator) clears: everyone gets the clear broadcast.
            await alice.delete_message(room, b"")
            event = await bob.wait_delete()
            assert event.message_id == b""
            assert len(env.store.tombstones(room)) == 2
            await alice.close()
            await bob.close()
    asyncio.run(scenario())


def test_clear_direct_room_allowed_for_member():
    async def scenario():
        async with running_server() as env:
            conv = env.store.find_or_create_direct(env.alice.user_id,
                                                   env.bob.user_id)
            alice = OxmpClient(env.url, env.alice)
            bob = OxmpClient(env.url, env.bob)
            await alice.connect()
            await bob.connect()
            await alice.send_text(conv, "기록")
            await bob.wait_incoming()
            # In a 1:1 room either side may clear the shared history.
            await bob.delete_message(conv, b"")
            event = await alice.wait_delete()
            assert event.message_id == b""
            assert len(env.store.tombstones(conv)) == 1
            await alice.close()
            await bob.close()
    asyncio.run(scenario())
