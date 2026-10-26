"""Account & device provisioning HTTP API (spec 9.3 onboarding).

Endpoints (JSON):
  GET  /v1/health                         -> {"ok": true}
  POST /v1/accounts        {name}         -> create user + first device + tokens
  POST /v1/devices         Bearer <token> -> add a device to the caller's account
  POST /v1/auth/refresh    {refresh_token}-> rotate; reuse revokes the device
  POST /v1/devices/revoke  Bearer <token> {device_id} -> revoke own device

Development note: when the caller does not supply a device public key the
server generates a key pair and returns the private key ONCE. Production
clients MUST generate keys on-device and register only the public key
(SEC-04/SEC-05); gate or remove that behaviour outside development.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from .auth import AuthError, TokenService, hash_refresh
from .provision import REFRESH_TTL_SECONDS
from .store import Store


def _conversation_payload(info: dict) -> dict:
    return {
        "conversation_id": info["conversation_id"].hex(),
        "title": info["title"],
        "kind": info["kind"],
        "created_by": info["created_by"].hex() if info.get("created_by") else None,
        "members": [{"user_id": m["user_id"].hex(), "name": m["name"]}
                    for m in info["members"]],
        "last_sequence": info["last_sequence"],
    }


def _credentials_payload(store: Store, tokens: TokenService, user_id: bytes,
                         device_id: bytes, private_key: Ed25519PrivateKey | None) -> dict:
    device = store.get_device(device_id)
    access = tokens.issue_access(user_id, device_id, device["token_version"])
    refresh = tokens.new_refresh_token()
    store.save_refresh(hash_refresh(refresh), device_id,
                       int(time.time()) + REFRESH_TTL_SECONDS)
    public_raw = store.get_device(device_id)["public_key"]
    payload = {
        "user_id": user_id.hex(),
        "device_id": device_id.hex(),
        "device_public_key": public_raw.hex(),
        "access_token": access,
        "refresh_token": refresh,
        "access_expires_in": tokens.access_ttl,
    }
    if private_key is not None:  # development key generation: returned once
        payload["device_private_key_raw"] = private_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()).hex()
    return payload


def make_server(store: Store, tokens: TokenService,
                host: str = "127.0.0.1", port: int = 8770,
                media_dir: str | None = None) -> ThreadingHTTPServer:
    media_root = Path(media_dir) if media_dir else Path("media-blobs")
    media_root.mkdir(parents=True, exist_ok=True)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep test output clean; no secrets logged
            pass

        def _reply(self, status: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            # Development CORS: the web client is served from another port.
            # Tighten this to known origins before production use.
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
            self.send_header("Access-Control-Allow-Headers",
                             "Authorization, Content-Type")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length == 0:
                return {}
            return json.loads(self.rfile.read(length) or b"{}")

        def _bearer_claims(self) -> dict:
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                raise AuthError("malformed")
            claims = tokens.verify_access(header[7:])
            # Session deletion (logout / reuse detection) bumps the device
            # token_version; a signed-but-stale token must die immediately,
            # not at expiry. The WS path has always enforced this.
            device = store.get_device(bytes.fromhex(claims["dev"]))
            if device is None or device["revoked"] \
                    or int(claims["ver"]) != device["token_version"]:
                raise AuthError("session_revoked")
            return claims

        def do_GET(self):
            try:
                if self.path == "/v1/health":
                    self._reply(200, {"ok": True})
                elif self.path == "/v1/conversations":
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    self._reply(200, {"conversations": [
                        _conversation_payload(info)
                        for info in store.list_conversation_infos(user_id)]})
                elif self.path == "/v1/users":
                    claims = self._bearer_claims()
                    me = claims["sub"]
                    my_friends = store.friend_ids(bytes.fromhex(me))
                    self._reply(200, {"users": [
                        {"user_id": u["user_id"].hex(), "name": u["name"],
                         "is_self": u["user_id"].hex() == me,
                         "is_friend": u["user_id"] in my_friends}
                        for u in store.list_users()]})
                elif self.path == "/v1/friends":
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    self._reply(200, {"friends": [
                        {"user_id": f["user_id"].hex(), "name": f["name"]}
                        for f in store.list_friends(user_id)]})
                elif self.path.startswith("/v1/media/") and self.path.endswith("/content"):
                    claims = self._bearer_claims()
                    media_id = bytes.fromhex(self.path.split("/")[3])
                    media = store.get_media(media_id)
                    user_id = bytes.fromhex(claims["sub"])
                    allowed = media is not None and media["status"] == "READY" and (
                        media["owner_id"] == user_id or (
                            media["conversation_id"] and store.is_member(
                                media["conversation_id"], user_id)))
                    if not allowed:
                        self._reply(403, {"error": "media_download_denied"})
                        return
                    data = Path(media["path"]).read_bytes()
                    self.send_response(200)
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Content-Type", media["content_type"])
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self._reply(404, {"error": "not_found"})
            except AuthError as exc:
                self._reply(401, {"error": exc.reason})
            except (ValueError, KeyError) as exc:
                self._reply(400, {"error": str(exc)})

        def do_PUT(self):
            try:
                if not (self.path.startswith("/v1/media/")
                        and self.path.endswith("/content")):
                    self._reply(404, {"error": "not_found"})
                    return
                claims = self._bearer_claims()
                media_id = bytes.fromhex(self.path.split("/")[3])
                media = store.get_media(media_id)
                if media is None or media["owner_id"] != bytes.fromhex(claims["sub"]):
                    self._reply(403, {"error": "media_upload_denied"})
                    return
                length = int(self.headers.get("Content-Length") or 0)
                data = self.rfile.read(length) if length else b""
                path = media_root / f"{media_id.hex()}.bin"
                path.write_bytes(data)
                ok = (len(data) == media["total_bytes"]
                      and hashlib.sha256(data).digest() == media["sha256"])
                store.finish_media(media_id, str(path), ok)
                if not ok:
                    path.unlink(missing_ok=True)
                    self._reply(400, {"error": "media_integrity_failed"})
                    return
                self._reply(200, {"ok": True, "media_id": media_id.hex(),
                                  "status": "READY"})
            except AuthError as exc:
                self._reply(401, {"error": exc.reason})
            except (ValueError, KeyError) as exc:
                self._reply(400, {"error": str(exc)})

        def do_POST(self):
            try:
                body = self._body()
                if self.path == "/v1/accounts":
                    self._reply(201, self._create_account(body))
                elif self.path == "/v1/devices":
                    claims = self._bearer_claims()
                    self._reply(201, self._add_device(claims, body))
                elif self.path == "/v1/auth/refresh":
                    self._reply(200, self._refresh(body))
                elif self.path == "/v1/auth/logout":
                    claims = self._bearer_claims()
                    store.delete_device_sessions(bytes.fromhex(claims["dev"]))
                    self._reply(200, {"ok": True,
                                      "scope": "this_device"})
                elif self.path == "/v1/auth/logout-all":
                    claims = self._bearer_claims()
                    count = store.delete_all_sessions(
                        bytes.fromhex(claims["sub"]))
                    self._reply(200, {"ok": True, "scope": "all_devices",
                                      "devices": count})
                elif self.path == "/v1/devices/revoke":
                    claims = self._bearer_claims()
                    self._revoke(claims, body)
                    self._reply(200, {"ok": True})
                elif self.path == "/v1/conversations":
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    members = [bytes.fromhex(m)
                               for m in body.get("member_user_ids", [])]
                    kind = body.get("kind") or ("direct" if len(members) == 1 else "group")
                    conv = store.create_conversation(
                        user_id, members, title=body.get("title", ""), kind=kind)
                    self._reply(201, _conversation_payload(
                        store.conversation_info(conv)))
                elif self.path == "/v1/friends":
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    store.add_friend(user_id,
                                     bytes.fromhex(body.get("user_id") or ""))
                    self._reply(200, {"friends": [
                        {"user_id": f["user_id"].hex(), "name": f["name"]}
                        for f in store.list_friends(user_id)]})
                elif self.path == "/v1/friends/remove":
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    store.remove_friend(user_id,
                                        bytes.fromhex(body.get("user_id") or ""))
                    self._reply(200, {"friends": [
                        {"user_id": f["user_id"].hex(), "name": f["name"]}
                        for f in store.list_friends(user_id)]})
                elif self.path == "/v1/conversations/direct":
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    other = bytes.fromhex(body.get("user_id") or "")
                    if other == user_id:
                        raise ValueError("cannot open a direct room with yourself")
                    conv = store.find_or_create_direct(user_id, other)
                    self._reply(201, _conversation_payload(
                        store.conversation_info(conv)))
                elif self.path.startswith("/v1/conversations/") \
                        and self.path.endswith("/members"):
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    conv = bytes.fromhex(self.path.split("/")[3])
                    if not store.is_member(conv, user_id):
                        raise ValueError("not_a_conversation_member")
                    store.add_member(conv, bytes.fromhex(body.get("user_id") or ""))
                    self._reply(200, _conversation_payload(
                        store.conversation_info(conv)))
                elif self.path.startswith("/v1/conversations/") \
                        and self.path.endswith("/rename"):
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    conv = bytes.fromhex(self.path.split("/")[3])
                    info = store.conversation_info(conv)
                    if info is None or not store.is_member(conv, user_id):
                        raise ValueError("not_a_conversation_member")
                    if info["kind"] != "group":
                        raise ValueError("only_group_rooms_can_be_renamed")
                    title = (body.get("title") or "").strip()
                    if not title:
                        raise ValueError("title is required")
                    store.rename_conversation(conv, title)
                    self._reply(200, _conversation_payload(
                        store.conversation_info(conv)))
                elif self.path.startswith("/v1/conversations/") \
                        and self.path.endswith("/leave"):
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    conv = bytes.fromhex(self.path.split("/")[3])
                    if not store.is_member(conv, user_id):
                        raise ValueError("not_a_conversation_member")
                    store.remove_member(conv, user_id)
                    self._reply(200, {"ok": True})
                elif self.path.startswith("/v1/conversations/") \
                        and self.path.endswith("/remove"):
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    conv = bytes.fromhex(self.path.split("/")[3])
                    info = store.conversation_info(conv)
                    target = bytes.fromhex(body.get("user_id") or "")
                    if info is None or not store.is_member(conv, user_id):
                        raise ValueError("not_a_conversation_member")
                    is_creator = info.get("created_by") == user_id
                    if target != user_id and not is_creator:
                        raise ValueError("only_the_creator_can_remove_members")
                    store.remove_member(conv, target)
                    self._reply(200, _conversation_payload(
                        store.conversation_info(conv)))
                elif self.path == "/v1/media/init":
                    claims = self._bearer_claims()
                    user_id = bytes.fromhex(claims["sub"])
                    conv = (bytes.fromhex(body["conversation_id"])
                            if body.get("conversation_id") else None)
                    if conv and not store.is_member(conv, user_id):
                        raise ValueError("not_a_conversation_member")
                    media_id = store.create_media(
                        user_id, conv, body.get("content_type", "application/octet-stream"),
                        int(body["total_bytes"]), bytes.fromhex(body["sha256"]))
                    self._reply(201, {
                        "media_id": media_id.hex(),
                        "upload_url": f"/v1/media/{media_id.hex()}/content",
                        "expires_in": 300, "chunk_bytes": 256 * 1024})
                elif self.path == "/v1/devices/push-token":
                    claims = self._bearer_claims()
                    store.save_push_token(bytes.fromhex(claims["dev"]),
                                          body["push_token"],
                                          body.get("platform", "unknown"))
                    self._reply(200, {"ok": True})
                else:
                    self._reply(404, {"error": "not_found"})
            except AuthError as exc:
                self._reply(401, {"error": exc.reason})
            except (ValueError, KeyError) as exc:
                self._reply(400, {"error": str(exc)})

        # -- operations ---------------------------------------------------------
        def _register(self, user_id: bytes, body: dict):
            public_hex = body.get("device_public_key")
            private_key = None
            if public_hex:  # production path: key generated on the device
                public_key = bytes.fromhex(public_hex)
                if len(public_key) != 32:
                    raise ValueError("device_public_key must be 32 raw bytes (hex)")
            else:             # development path: server generates, returns once
                private_key = Ed25519PrivateKey.generate()
                public_key = private_key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            device_id = store.register_device(user_id, public_key)
            return _credentials_payload(store, tokens, user_id, device_id, private_key)

        def _create_account(self, body: dict) -> dict:
            name = (body.get("name") or "").strip()
            if not name:
                raise ValueError("name is required")
            user_id = store.create_user(name)
            return self._register(user_id, body)

        def _add_device(self, claims: dict, body: dict) -> dict:
            user_id = bytes.fromhex(claims["sub"])
            return self._register(user_id, body)

        def _refresh(self, body: dict) -> dict:
            refresh = body.get("refresh_token") or ""
            device_id = store.rotate_refresh(hash_refresh(refresh))
            device = store.get_device(device_id)
            if device is None or device["revoked"]:
                raise ValueError("device_revoked")
            return _credentials_payload(store, tokens, device["user_id"],
                                        device_id, None)

        def _revoke(self, claims: dict, body: dict) -> None:
            device_id = bytes.fromhex(body.get("device_id") or "")
            device = store.get_device(device_id)
            if device is None or device["user_id"].hex() != claims["sub"]:
                raise ValueError("device_not_found")
            store.revoke_device(device_id)

    return ThreadingHTTPServer((host, port), Handler)


def serve_in_thread(store: Store, tokens: TokenService,
                    host: str = "127.0.0.1", port: int = 8770,
                    media_dir: str | None = None) -> ThreadingHTTPServer:
    httpd = make_server(store, tokens, host, port, media_dir)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd
