"""Session deletion (logout): this-device and all-device token revocation."""
import pytest

from server.api import serve_in_thread
from server.auth import TokenService
from server.store import Store
from tests.test_api import SECRET, call


@pytest.fixture()
def api(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    httpd = serve_in_thread(store, TokenService(SECRET), port=0,
                            media_dir=str(tmp_path / "m"))
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base, store
    httpd.shutdown()
    store.close()


def account(base, name):
    status, body = call(base, "/v1/accounts", {"name": name})
    assert status == 201
    return body


def second_device(base, account_body):
    status, body = call(base, "/v1/devices", {},
                        token=account_body["access_token"])
    assert status == 201
    return body


def test_logout_kills_only_this_device_session(api):
    base, _ = api
    alice = account(base, "alice")
    phone = second_device(base, alice)
    # Both devices' tokens work before logout.
    status, _ = call(base, "/v1/conversations", token=alice["access_token"])
    assert status == 200
    status, _ = call(base, "/v1/conversations", token=phone["access_token"])
    assert status == 200

    status, body = call(base, "/v1/auth/logout", {},
                        token=alice["access_token"])
    assert status == 200 and body["scope"] == "this_device"

    # The logged-out device: access token dead, refresh token dead.
    status, _ = call(base, "/v1/conversations", token=alice["access_token"])
    assert status == 401
    status, _ = call(base, "/v1/auth/refresh",
                     {"refresh_token": alice["refresh_token"]})
    assert status == 400
    # The other device is untouched.
    status, _ = call(base, "/v1/conversations", token=phone["access_token"])
    assert status == 200
    status, _ = call(base, "/v1/auth/refresh",
                     {"refresh_token": phone["refresh_token"]})
    assert status == 200


def test_logout_requires_auth(api):
    base, _ = api
    status, _ = call(base, "/v1/auth/logout", {})
    assert status == 401


def test_logout_all_kills_every_device(api):
    base, _ = api
    alice = account(base, "alice")
    phone = second_device(base, alice)
    status, body = call(base, "/v1/auth/logout-all", {},
                        token=alice["access_token"])
    assert status == 200 and body["devices"] == 2
    for creds in (alice, phone):
        status, _ = call(base, "/v1/conversations",
                         token=creds["access_token"])
        assert status == 401
        status, _ = call(base, "/v1/auth/refresh",
                         {"refresh_token": creds["refresh_token"]})
        assert status == 400


def test_device_not_revoked_by_logout(api):
    """Logout is a session delete, not a device revoke: the device row
    stays usable, so a fresh sign-in can issue new tokens for it."""
    base, store = api
    alice = account(base, "alice")
    device_id = bytes.fromhex(alice["device_id"])
    call(base, "/v1/auth/logout", {}, token=alice["access_token"])
    device = store.get_device(device_id)
    assert device is not None and not device["revoked"]
