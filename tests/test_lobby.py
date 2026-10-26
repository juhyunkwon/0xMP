"""Lobby/room system: user directory, direct rooms, group rooms, entry sync."""
import asyncio
import uuid

import pytest

from server.api import serve_in_thread
from server.auth import TokenService
from server.client import OxmpClient
from server.store import Store
from server.testing import running_server
from tests.test_api import SECRET, call


@pytest.fixture()
def api(tmp_path):
    store = Store(str(tmp_path / "lobby.db"))
    httpd = serve_in_thread(store, TokenService(SECRET), port=0,
                            media_dir=str(tmp_path / "m"))
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base, store
    httpd.shutdown()
    store.close()


def make_user(api_base, name):
    status, body = call(api_base, "/v1/accounts", {"name": name})
    assert status == 201
    return body


def test_user_directory_marks_self(api):
    base, _ = api
    alice = make_user(base, "alice")
    make_user(base, "bob")
    status, body = call(base, "/v1/users", token=alice["access_token"])
    assert status == 200
    by_name = {u["name"]: u for u in body["users"]}
    assert by_name["alice"]["is_self"] is True
    assert by_name["bob"]["is_self"] is False


def test_direct_room_is_idempotent_and_listed(api):
    base, store = api
    alice = make_user(base, "alice")
    bob = make_user(base, "bob")
    make_user(base, "mallory")
    status, room1 = call(base, "/v1/conversations/direct",
                         {"user_id": bob["user_id"]}, token=alice["access_token"])
    assert status == 201 and room1["kind"] == "direct"
    assert {m["name"] for m in room1["members"]} == {"alice", "bob"}
    status, room2 = call(base, "/v1/conversations/direct",
                         {"user_id": alice["user_id"]}, token=bob["access_token"])
    assert room2["conversation_id"] == room1["conversation_id"]  # same room

    conv_id = bytes.fromhex(room1["conversation_id"])
    assert store.is_member(conv_id, bytes.fromhex(alice["user_id"]))
    infos = store.list_conversation_infos(bytes.fromhex(bob["user_id"]))
    assert any(i["conversation_id"] == conv_id and i["kind"] == "direct"
               for i in infos)


def test_group_room_title_and_add_member(api):
    base, store = api
    alice = make_user(base, "alice")
    bob = make_user(base, "bob")
    carol = make_user(base, "carol")
    status, room = call(base, "/v1/conversations", {
        "title": "프로젝트 팀", "kind": "group",
        "member_user_ids": [bob["user_id"]]}, token=alice["access_token"])
    assert status == 201 and room["title"] == "프로젝트 팀"
    assert len(room["members"]) == 2
    status, room = call(
        base, f"/v1/conversations/{room['conversation_id']}/members",
        {"user_id": carol["user_id"]}, token=alice["access_token"])
    assert status == 200 and len(room["members"]) == 3
    # A non-member must not be able to add people.
    mallory = make_user(base, "mallory")
    status, _ = call(
        base, f"/v1/conversations/{room['conversation_id']}/members",
        {"user_id": mallory["user_id"]}, token=mallory["access_token"])
    assert status == 400


def test_direct_room_between_two_web_users_over_ws():
    """Full path: pair created in the store lobby style, chatted over WS,
    and history is visible on room entry sync for the other user."""
    async def scenario():
        async with running_server() as env:
            conv = env.store.find_or_create_direct(env.alice.user_id,
                                                   env.bob.user_id)
            alice = OxmpClient(env.url, env.alice)
            bob = OxmpClient(env.url, env.bob)
            await alice.connect()
            await bob.connect()
            await alice.send_text(conv, "1:1 안녕")
            incoming = await bob.wait_incoming()
            assert incoming.content.body == "1:1 안녕".encode()
            await alice.close()
            await bob.close()

            bob2 = OxmpClient(env.url, env.bob)
            await bob2.connect()
            entered = await bob2.sync(conv)  # what entering the room does
            assert entered.newly_applied == 1
            assert entered.events[0].message.content.body == "1:1 안녕".encode()
            await bob2.close()
    asyncio.run(scenario())
