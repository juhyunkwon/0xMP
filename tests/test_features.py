"""4. Messenger features: 1:1/group chat, offline, delivery notice,
file transfer, push notifications."""
import asyncio
import hashlib
import json
import urllib.request
import uuid

import pytest

from server.api import serve_in_thread
from server.client import OxmpClient
from server.push import RecordingPushProvider
from server.testing import running_server


def uid():
    return uuid.uuid4().bytes


def call(base, method, path, payload=None, token=None, raw=None):
    data = raw if raw is not None else (
        json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(base + path, data=data, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read()
            return resp.status, (json.loads(body) if body[:1] in b"[{" else body)
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, body


def test_group_chat_delivery_notice_and_offline_sync():
    async def scenario():
        push = RecordingPushProvider()
        async with running_server(push_provider=push) as env:
            carol_env = env  # third participant uses bob's second device model:
            # create a real third account through the store provisioning
            from server.provision import create_account
            carol = create_account(env.store, env.tokens, "carol")
            conv = env.store.create_conversation(
                env.alice.user_id, [env.bob.user_id, carol.user_id])
            env.store.save_push_token(carol.device_id, "push-token-carol", "test")

            alice = OxmpClient(env.url, env.alice)
            bob = OxmpClient(env.url, env.bob)
            await alice.connect()
            await bob.connect()  # Carol stays OFFLINE the whole time.

            await alice.send_text(conv, "group hello")
            incoming = await bob.wait_incoming()
            assert incoming.content.body == b"group hello"
            await bob.delivery_ack(incoming)

            notice = await alice.wait_delivered()  # sender gets the notice
            assert notice.delivered_device_id == env.bob.device_id
            assert notice.sequence == 1

            await asyncio.sleep(0.2)
            assert len(push.events) == 1  # only the offline device is pushed
            event = push.events[0]
            assert event.push_token == "push-token-carol"
            assert b"group hello" not in event.conversation_id.encode()
            assert "group hello" not in str(event.__dict__)  # no plaintext pushed

            carol_client = OxmpClient(env.url, carol)
            await carol_client.connect()
            synced = await carol_client.sync(conv)  # offline message recovered
            assert synced.newly_applied == 1
            assert synced.events[0].message.content.body == b"group hello"
            await alice.close(); await bob.close(); await carol_client.close()
    asyncio.run(scenario())


def test_conversation_api_and_membership_guard(tmp_path):
    from server.auth import TokenService
    from server.store import Store
    from tests.test_api import SECRET
    store = Store(str(tmp_path / "conv.db"))
    tokens = TokenService(SECRET)
    httpd = serve_in_thread(store, tokens, port=0, media_dir=str(tmp_path / "m"))
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        _, alice = call(base, "POST", "/v1/accounts", {"name": "alice"})
        _, bob = call(base, "POST", "/v1/accounts", {"name": "bob"})
        _, mallory = call(base, "POST", "/v1/accounts", {"name": "mallory"})
        status, conv = call(base, "POST", "/v1/conversations",
                            {"member_user_ids": [bob["user_id"]]},
                            token=alice["access_token"])
        assert status == 201
        conv_id = conv["conversation_id"]
        _, mine = call(base, "GET", "/v1/conversations", token=bob["access_token"])
        assert conv_id in [c["conversation_id"] for c in mine["conversations"]]
        _, other = call(base, "GET", "/v1/conversations", token=mallory["access_token"])
        assert conv_id not in [c["conversation_id"] for c in other["conversations"]]
    finally:
        httpd.shutdown()
        store.close()


def test_file_transfer_roundtrip_and_integrity(tmp_path):
    from server.auth import TokenService
    from server.store import Store
    from tests.test_api import SECRET
    store = Store(str(tmp_path / "file.db"))
    tokens = TokenService(SECRET)
    httpd = serve_in_thread(store, tokens, port=0, media_dir=str(tmp_path / "m"))
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        _, alice = call(base, "POST", "/v1/accounts", {"name": "alice"})
        _, bob = call(base, "POST", "/v1/accounts", {"name": "bob"})
        _, mallory = call(base, "POST", "/v1/accounts", {"name": "mallory"})
        _, conv = call(base, "POST", "/v1/conversations",
                       {"member_user_ids": [bob["user_id"]]},
                       token=alice["access_token"])
        content = b"0xMP file transfer payload " * 100
        digest = hashlib.sha256(content).hexdigest()
        status, grant = call(base, "POST", "/v1/media/init", {
            "conversation_id": conv["conversation_id"],
            "content_type": "application/octet-stream",
            "total_bytes": len(content), "sha256": digest,
        }, token=alice["access_token"])
        assert status == 201
        url = grant["upload_url"]

        status, _ = call(base, "PUT", url, token=alice["access_token"], raw=b"tampered")
        assert status == 400  # size/hash mismatch rejected, nothing becomes READY

        # Re-init (the failed attempt cannot be reused) and upload correctly.
        status, grant = call(base, "POST", "/v1/media/init", {
            "conversation_id": conv["conversation_id"],
            "content_type": "application/octet-stream",
            "total_bytes": len(content), "sha256": digest,
        }, token=alice["access_token"])
        url = grant["upload_url"]
        status, done = call(base, "PUT", url, token=alice["access_token"], raw=content)
        assert status == 200 and done["status"] == "READY"

        status, data = call(base, "GET", url, token=bob["access_token"])
        assert status == 200 and data == content  # conversation member can fetch
        status, _ = call(base, "GET", url, token=mallory["access_token"])
        assert status == 403  # non-member cannot
    finally:
        httpd.shutdown()
        store.close()


def test_push_token_registration_endpoint(tmp_path):
    from server.auth import TokenService
    from server.store import Store
    from tests.test_api import SECRET
    store = Store(str(tmp_path / "push.db"))
    tokens = TokenService(SECRET)
    httpd = serve_in_thread(store, tokens, port=0, media_dir=str(tmp_path / "m"))
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        _, alice = call(base, "POST", "/v1/accounts", {"name": "alice"})
        status, _ = call(base, "POST", "/v1/devices/push-token",
                         {"push_token": "fcm-token-123", "platform": "android"},
                         token=alice["access_token"])
        assert status == 200
        device = bytes.fromhex(alice["device_id"])
        assert store.push_tokens(device) == ["fcm-token-123"]
    finally:
        httpd.shutdown()
        store.close()
