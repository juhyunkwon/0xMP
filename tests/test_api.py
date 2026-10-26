"""Account/device provisioning API tests."""
import json
import urllib.request

import pytest

from server.api import serve_in_thread
from server.auth import TokenService
from server.store import Store

SECRET = b"api-test-secret-api-test-secret-32b"


@pytest.fixture()
def api(tmp_path):
    store = Store(str(tmp_path / "api.db"))
    tokens = TokenService(SECRET)
    httpd = serve_in_thread(store, tokens, port=0)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base, store, tokens
    httpd.shutdown()
    store.close()


def call(base, path, payload=None, token=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method="POST" if data else "GET")
    if data:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_health(api):
    base, _, _ = api
    with urllib.request.urlopen(base + "/v1/health") as resp:
        assert json.loads(resp.read()) == {"ok": True}


def test_account_creation_returns_usable_tokens(api):
    base, store, tokens = api
    status, body = call(base, "/v1/accounts", {"name": "alice"})
    assert status == 201
    claims = tokens.verify_access(body["access_token"])
    assert claims["sub"] == body["user_id"]
    assert len(bytes.fromhex(body["device_private_key_raw"])) == 32
    assert store.get_device(bytes.fromhex(body["device_id"])) is not None


def test_account_creation_with_device_generated_key(api):
    base, store, _ = api
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    status, body = call(base, "/v1/accounts",
                        {"name": "bob", "device_public_key": pub})
    assert status == 201
    assert "device_private_key_raw" not in body  # server never sees private keys


def test_add_device_and_revoke_flow(api):
    base, store, _ = api
    _, alice = call(base, "/v1/accounts", {"name": "alice"})
    status, second = call(base, "/v1/devices", {}, token=alice["access_token"])
    assert status == 201 and second["user_id"] == alice["user_id"]
    status, _ = call(base, "/v1/devices/revoke",
                     {"device_id": second["device_id"]}, token=alice["access_token"])
    assert status == 200
    assert store.get_device(bytes.fromhex(second["device_id"]))["revoked"]
    # Someone else's device cannot be revoked with Alice's token.
    _, mallory = call(base, "/v1/accounts", {"name": "mallory"})
    status, _ = call(base, "/v1/devices/revoke",
                     {"device_id": alice["device_id"]}, token=mallory["access_token"])
    assert status == 400


def test_refresh_endpoint_rotates_and_detects_reuse(api):
    base, _, tokens = api
    _, alice = call(base, "/v1/accounts", {"name": "alice"})
    status, rotated = call(base, "/v1/auth/refresh",
                           {"refresh_token": alice["refresh_token"]})
    assert status == 200 and rotated["refresh_token"] != alice["refresh_token"]
    tokens.verify_access(rotated["access_token"])
    status, body = call(base, "/v1/auth/refresh",
                        {"refresh_token": alice["refresh_token"]})  # reuse!
    assert status == 400 and "reuse" in body["error"]


def test_api_rejects_bad_bearer(api):
    base, _, _ = api
    status, body = call(base, "/v1/devices", {}, token="forged.token")
    assert status == 401
