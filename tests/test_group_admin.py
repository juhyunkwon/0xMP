"""Group administration: rename, leave, creator-only removal, conversion."""
import pytest

from server.api import serve_in_thread
from server.auth import TokenService
from server.store import Store
from tests.test_api import SECRET, call


@pytest.fixture()
def api(tmp_path):
    store = Store(str(tmp_path / "g.db"))
    httpd = serve_in_thread(store, TokenService(SECRET), port=0,
                            media_dir=str(tmp_path / "m"))
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base, store
    httpd.shutdown()
    store.close()


def user(base, name):
    status, body = call(base, "/v1/accounts", {"name": name})
    assert status == 201
    return body


def group(base, creator, members, title="팀"):
    status, room = call(base, "/v1/conversations", {
        "title": title, "kind": "group",
        "member_user_ids": [m["user_id"] for m in members]},
        token=creator["access_token"])
    assert status == 201
    return room


def test_rename_group_by_member_and_guards(api):
    base, _ = api
    alice, bob, mallory = user(base, "alice"), user(base, "bob"), user(base, "mallory")
    room = group(base, alice, [bob])
    url = f"/v1/conversations/{room['conversation_id']}/rename"
    status, renamed = call(base, url, {"title": "새 이름"}, token=bob["access_token"])
    assert status == 200 and renamed["title"] == "새 이름"
    status, _ = call(base, url, {"title": "침입"}, token=mallory["access_token"])
    assert status == 400  # non-member cannot rename
    assert renamed["created_by"] == alice["user_id"]


def test_leave_and_creator_only_remove(api):
    base, store = api
    alice, bob, carol = user(base, "alice"), user(base, "bob"), user(base, "carol")
    room = group(base, alice, [bob, carol])
    cid = room["conversation_id"]
    # Bob (not creator) cannot remove Carol.
    status, _ = call(base, f"/v1/conversations/{cid}/remove",
                     {"user_id": carol["user_id"]}, token=bob["access_token"])
    assert status == 400
    # Alice (creator) can.
    status, room = call(base, f"/v1/conversations/{cid}/remove",
                        {"user_id": carol["user_id"]}, token=alice["access_token"])
    assert status == 200 and len(room["members"]) == 2
    # Bob leaves on his own.
    status, _ = call(base, f"/v1/conversations/{cid}/leave", {},
                     token=bob["access_token"])
    assert status == 200
    assert not store.is_member(bytes.fromhex(cid), bytes.fromhex(bob["user_id"]))
    infos = store.list_conversation_infos(bytes.fromhex(bob["user_id"]))
    assert all(i["conversation_id"].hex() != cid for i in infos)


def test_direct_to_group_conversion_contents(api):
    """The web client's conversion: a new group containing both direct
    participants plus the invited users; the direct room is untouched."""
    base, store = api
    alice, bob, carol = user(base, "alice"), user(base, "bob"), user(base, "carol")
    status, direct = call(base, "/v1/conversations/direct",
                          {"user_id": bob["user_id"]}, token=alice["access_token"])
    assert status == 201
    status, converted = call(base, "/v1/conversations", {
        "title": "", "kind": "group",
        "member_user_ids": [bob["user_id"], carol["user_id"]]},
        token=alice["access_token"])
    assert status == 201 and converted["kind"] == "group"
    assert {m["name"] for m in converted["members"]} == {"alice", "bob", "carol"}
    direct_info = store.conversation_info(bytes.fromhex(direct["conversation_id"]))
    assert direct_info["kind"] == "direct" and len(direct_info["members"]) == 2
