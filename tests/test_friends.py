"""Friends: mutual add, friend-only directory flags, remove, guards."""
import pytest

from server.api import serve_in_thread
from server.auth import TokenService
from server.store import Store
from tests.test_api import SECRET, call


@pytest.fixture()
def api(tmp_path):
    store = Store(str(tmp_path / "f.db"))
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


def friends_of(base, account):
    status, body = call(base, "/v1/friends", token=account["access_token"])
    assert status == 200
    return {f["name"] for f in body["friends"]}


def test_friend_add_is_mutual_and_listed(api):
    base, _ = api
    alice, bob, carol = user(base, "alice"), user(base, "bob"), user(base, "carol")
    assert friends_of(base, alice) == set()
    status, body = call(base, "/v1/friends", {"user_id": bob["user_id"]},
                        token=alice["access_token"])
    assert status == 200
    assert {f["name"] for f in body["friends"]} == {"bob"}
    # Mutual: Bob sees Alice without doing anything.
    assert friends_of(base, bob) == {"alice"}
    # Carol is not a friend of either.
    assert friends_of(base, carol) == set()


def test_friend_add_is_idempotent_and_guards(api):
    base, _ = api
    alice, bob = user(base, "alice"), user(base, "bob")
    call(base, "/v1/friends", {"user_id": bob["user_id"]},
         token=alice["access_token"])
    status, body = call(base, "/v1/friends", {"user_id": bob["user_id"]},
                        token=alice["access_token"])
    assert status == 200 and len(body["friends"]) == 1  # no duplicate
    # Cannot friend yourself.
    status, _ = call(base, "/v1/friends", {"user_id": alice["user_id"]},
                     token=alice["access_token"])
    assert status == 400
    # Cannot friend a non-existent user.
    status, _ = call(base, "/v1/friends", {"user_id": "ab" * 16},
                     token=alice["access_token"])
    assert status == 400
    # Unauthenticated calls are rejected.
    status, _ = call(base, "/v1/friends", {"user_id": bob["user_id"]})
    assert status == 401


def test_friend_remove_is_mutual(api):
    base, _ = api
    alice, bob = user(base, "alice"), user(base, "bob")
    call(base, "/v1/friends", {"user_id": bob["user_id"]},
         token=alice["access_token"])
    assert friends_of(base, bob) == {"alice"}
    status, body = call(base, "/v1/friends/remove",
                        {"user_id": bob["user_id"]}, token=alice["access_token"])
    assert status == 200 and body["friends"] == []
    assert friends_of(base, bob) == set()  # removed on both sides


def test_user_directory_marks_friends(api):
    base, _ = api
    alice, bob, carol = user(base, "alice"), user(base, "bob"), user(base, "carol")
    call(base, "/v1/friends", {"user_id": bob["user_id"]},
         token=alice["access_token"])
    status, body = call(base, "/v1/users", token=alice["access_token"])
    assert status == 200
    flags = {u["name"]: (u["is_self"], u["is_friend"]) for u in body["users"]}
    assert flags["alice"] == (True, False)
    assert flags["bob"] == (False, True)
    assert flags["carol"] == (False, False)
