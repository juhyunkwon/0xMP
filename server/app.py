"""0xMP WebSocket server.

Development transport note: this server speaks plain ws:// for local
testing only. Production MUST terminate TLS 1.3 in front of it (SEC-01)
or use wss://; plain-text deployment outside localhost is a spec violation.

Flow per connection: HELLO -> HELLO_RESULT, AUTH (signed token + Ed25519
device signature over the session challenge) -> AUTH_RESULT, then
MESSAGE_SEND / SYNC / PING traffic. Messages are committed to SQLite
before MESSAGE_ACCEPTED is sent.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

import websockets
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "samples"))

from oxmp_frame import Frame, FrameError, FrameType, decode, encode  # noqa: E402
from oxmp_payload import (  # noqa: E402
    Auth, AuthResult, DeleteEvent, DeliveryAck, DeliveryNotice, Error, Hello,
    HelloResult, KeyBundlePublish, KeyBundleRequest, KeyBundleResponse,
    MediaComplete, MediaGrant, MediaInit, MessageAccepted, MessageIncoming,
    MessageSend, SyncAck, SyncBatch, SyncRequest,
)
from .auth import AuthError, TokenService  # noqa: E402
from .store import ConflictError, Store  # noqa: E402

MAX_WS_BYTES = 1 * 1024 * 1024 + 4096
ERR = {"bad_frame": 0x0001, "version": 0x0002, "auth": 0x0003,
       "forbidden": 0x0004, "size": 0x0009, "type": 0x000B,
       "flag": 0x000C, "negotiation": 0x000D}


class Connection:
    def __init__(self, ws, server: "OxmpServer"):
        self.ws, self.server = ws, server
        self.session_id = ""
        self.user_id: bytes | None = None
        self.device_id: bytes | None = None
        # Per-connection outbound queue: fan-out NEVER blocks the sender's
        # handler. A full queue drops the real-time copy only; the message
        # is already persisted and recoverable via SYNC (spec section 10).
        self.outbox: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1000)

    @property
    def authenticated(self) -> bool:
        return self.user_id is not None

    async def writer(self) -> None:
        while True:
            data = await self.outbox.get()
            try:
                await self.ws.send(data)
            finally:
                self.outbox.task_done()

    async def flush(self) -> None:
        await self.outbox.join()

    async def send(self, frame: Frame) -> None:
        try:
            self.outbox.put_nowait(encode(frame))
        except asyncio.QueueFull:
            pass  # real-time fan-out shed; SYNC recovers it

    async def send_error(self, code: int, message: str, retryable=False) -> None:
        await self.send(Frame(FrameType.ERROR, Error(
            code=code, message=message, retryable=retryable,
            reference_id=uuid.uuid4().bytes).SerializeToString()))


class OxmpServer:
    def __init__(self, store: Store, tokens: TokenService, push_provider=None,
                 media_base_url: str = "http://127.0.0.1:8770"):
        self.store, self.tokens = store, tokens
        self.push = push_provider
        self.media_base_url = media_base_url.rstrip("/")
        self.online: dict[bytes, set[Connection]] = {}

    # -- lifecycle -----------------------------------------------------------
    async def handle(self, ws) -> None:
        conn = Connection(ws, self)
        writer_task = asyncio.create_task(conn.writer())
        try:
            async for raw in ws:
                if isinstance(raw, str):
                    raw = raw.encode()
                try:
                    frame = decode(raw)
                except FrameError as exc:  # forged/corrupt packet injection
                    await conn.send_error(ERR["bad_frame"], str(exc))
                    await conn.flush()
                    await ws.close(code=4001)
                    return
                keep = await self.dispatch(conn, frame)
                if not keep:
                    await conn.flush()
                    return
        except websockets.ConnectionClosed:
            pass
        finally:
            writer_task.cancel()
            if conn.device_id:
                peers = self.online.get(conn.device_id, set())
                peers.discard(conn)
                if not peers:
                    self.online.pop(conn.device_id, None)

    async def dispatch(self, conn: Connection, frame: Frame) -> bool:
        ftype = frame.frame_type
        if ftype is FrameType.PING:
            await conn.send(Frame(FrameType.PONG, frame.payload))
            return True
        if ftype is FrameType.HELLO:
            return await self.on_hello(conn, frame)
        if ftype is FrameType.AUTH:
            return await self.on_auth(conn, frame)
        if not conn.authenticated:
            await conn.send_error(ERR["auth"], "authentication required")
            return False
        handler = {
            FrameType.MESSAGE_SEND: self.on_send,
            FrameType.MESSAGE_DELETE: self.on_delete,
            FrameType.MESSAGE_DELIVERY_ACK: self.on_delivery_ack,
            FrameType.SYNC_REQUEST: self.on_sync_request,
            FrameType.SYNC_ACK: self.on_sync_ack,
            FrameType.KEY_BUNDLE_PUBLISH: self.on_bundle_publish,
            FrameType.KEY_BUNDLE_REQUEST: self.on_bundle_request,
            FrameType.MEDIA_INIT: self.on_media_init,
            FrameType.MEDIA_COMPLETE: self.on_media_complete,
            FrameType.MEDIA_DOWNLOAD_REQUEST: self.on_media_download,
        }.get(ftype)
        if handler is None:
            await conn.send_error(ERR["type"], f"unsupported frame {ftype.name}")
            return True
        return await handler(conn, frame)

    # -- frames ----------------------------------------------------------------
    async def on_hello(self, conn: Connection, frame: Frame) -> bool:
        req = Hello.FromString(frame.payload)
        if req.protocol_id != "0xmp.v1":
            await conn.send_error(ERR["negotiation"], "protocol mismatch")
            return False
        selected = min(req.max_security_profile, 2)
        if selected < req.min_security_profile:
            await conn.send_error(ERR["negotiation"], "no common security profile")
            return False
        conn.session_id = uuid.uuid4().hex
        await conn.send(Frame(FrameType.HELLO_RESULT, HelloResult(
            protocol_id="0xmp.v1", selected_security_profile=selected,
            features=[f for f in req.features if f in {"e2e.signal", "e2e.mls"}],
            max_payload_bytes=64 * 1024,
            session_id=conn.session_id).SerializeToString()))
        return True

    async def on_auth(self, conn: Connection, frame: Frame) -> bool:
        req = Auth.FromString(frame.payload)
        fail = AuthResult(ok=False, failure_reason="authentication failed")
        try:
            claims = self.tokens.verify_access(req.access_token)
        except AuthError:
            await conn.send(Frame(FrameType.AUTH_RESULT, fail.SerializeToString()))
            return False
        device = self.store.get_device(req.device_id)
        if (device is None or device["revoked"]
                or claims["sub"] != device["user_id"].hex()
                or claims["dev"] != req.device_id.hex()
                or int(claims["ver"]) != device["token_version"]):
            await conn.send(Frame(FrameType.AUTH_RESULT, fail.SerializeToString()))
            return False
        try:  # device signature over the HELLO challenge (SEC-04)
            Ed25519PublicKey.from_public_bytes(device["public_key"]).verify(
                req.signature, conn.session_id.encode())
        except (InvalidSignature, ValueError):
            await conn.send(Frame(FrameType.AUTH_RESULT, fail.SerializeToString()))
            return False
        conn.user_id, conn.device_id = device["user_id"], req.device_id
        self.online.setdefault(conn.device_id, set()).add(conn)
        await conn.send(Frame(FrameType.AUTH_RESULT, AuthResult(
            ok=True, user_id=conn.user_id, device_id=conn.device_id,
            access_token_expires_at_ms=int(claims["exp"]) * 1000,
        ).SerializeToString()))
        return True

    async def on_send(self, conn: Connection, frame: Frame) -> bool:
        req = MessageSend.FromString(frame.payload)
        if req.sender_device_id != conn.device_id:
            await conn.send_error(ERR["forbidden"], "device mismatch")
            return True
        if len(req.content.body) > 64 * 1024:
            await conn.send_error(ERR["size"], "message body too large")
            return True
        self.store.ensure_conversation(req.conversation_id, conn.user_id)
        try:
            stored, duplicate = self.store.save_message(
                message_id=req.message_id, conversation_id=req.conversation_id,
                sender_id=conn.user_id, sender_device_id=conn.device_id,
                idempotency_key=req.idempotency_key,
                kind=req.content.kind, body=req.content.body)
        except ConflictError as exc:
            await conn.send_error(ERR["bad_frame"], str(exc))
            return True
        # Persisted above; only now may we acknowledge (spec section 8).
        await conn.send(Frame(FrameType.MESSAGE_ACCEPTED, MessageAccepted(
            message_id=stored.message_id, sequence=stored.sequence,
            server_timestamp_ms=stored.server_timestamp_ms,
            duplicate=duplicate).SerializeToString()))
        if not duplicate:
            incoming = MessageIncoming(
                message_id=stored.message_id, conversation_id=stored.conversation_id,
                sender_id=stored.sender_id, sender_device_id=stored.sender_device_id,
                sequence=stored.sequence,
                server_timestamp_ms=stored.server_timestamp_ms)
            incoming.content.kind, incoming.content.body = stored.kind, stored.body
            out = Frame(FrameType.MESSAGE_INCOMING, incoming.SerializeToString())
            for device_id in self.store.member_devices(req.conversation_id):
                if device_id == conn.device_id:
                    continue
                peers = list(self.online.get(device_id, ()))
                for peer in peers:
                    await peer.send(out)
                if not peers and self.push is not None:
                    # Offline device: notify with identifiers only, never
                    # plaintext (mandatory for E2E, see server/push.py).
                    from .push import PushEvent
                    for token in self.store.push_tokens(device_id):
                        await self.push.send(PushEvent(
                            push_token=token,
                            conversation_id=req.conversation_id.hex(),
                            message_id=stored.message_id.hex()))
        return True

    async def _broadcast(self, conversation_id: bytes, frame: Frame,
                         exclude_device: bytes | None = None) -> None:
        for device_id in self.store.member_devices(conversation_id):
            if device_id == exclude_device:
                continue
            for peer in list(self.online.get(device_id, ())):
                await peer.send(frame)

    async def on_delete(self, conn: Connection, frame: Frame) -> bool:
        """MESSAGE_DELETE: tombstone one message, or the whole room when
        message_id is empty. Single deletes are sender-only; a whole-room
        clear is creator-only in groups, any member in 1:1 rooms."""
        req = DeleteEvent.FromString(frame.payload)
        conv = req.conversation_id
        if not conv or not self.store.is_member(conv, conn.user_id):
            await conn.send_error(ERR["forbidden"], "not a conversation member")
            return True
        if req.message_id:
            sequence = self.store.delete_message(
                conv, req.message_id, conn.user_id)
            if sequence is None:
                await conn.send_error(
                    ERR["forbidden"],
                    "message not found or not yours to delete")
                return True
        else:
            info = self.store.conversation_info(conv)
            if info and info["kind"] == "group" \
                    and info.get("created_by") != conn.user_id:
                await conn.send_error(
                    ERR["forbidden"], "only the room creator can clear a group")
                return True
            self.store.clear_messages(conv)
        # Echo to every online member device (including the requester's
        # other devices) so all views converge immediately; late joiners
        # receive the same state as sync tombstones.
        out = Frame(FrameType.MESSAGE_DELETE, DeleteEvent(
            message_id=req.message_id, conversation_id=conv,
            for_everyone=True).SerializeToString())
        await self._broadcast(conv, out)
        return True

    async def on_delivery_ack(self, conn: Connection, frame: Frame) -> bool:
        ack = DeliveryAck.FromString(frame.payload)
        self.store.mark_delivered(ack.message_id, conn.device_id)
        stored = self.store.message_by_id(ack.message_id)
        if stored is not None:
            notice = DeliveryNotice(
                message_id=ack.message_id, conversation_id=ack.conversation_id,
                delivered_device_id=conn.device_id, sequence=ack.sequence)
            out = Frame(FrameType.MESSAGE_DELIVERED, notice.SerializeToString())
            for device_id in self.store.member_devices(ack.conversation_id):
                device = self.store.get_device(device_id)
                if device and device["user_id"] == stored.sender_id \
                        and device_id != conn.device_id:
                    for peer in list(self.online.get(device_id, ())):
                        await peer.send(out)
        return True

    async def on_media_init(self, conn: Connection, frame: Frame) -> bool:
        req = MediaInit.FromString(frame.payload)
        if len(req.sha256) != 32:
            await conn.send_error(ERR["bad_frame"], "sha256 must be 32 bytes")
            return True
        media_id = self.store.create_media(
            conn.user_id, None, req.content_type, req.total_bytes, req.sha256)
        await conn.send(Frame(FrameType.MEDIA_UPLOAD_GRANT, MediaGrant(
            media_id=media_id,
            https_url=f"{self.media_base_url}/v1/media/{media_id.hex()}/content",
            expires_at_ms=int(__import__("time").time() * 1000) + 5 * 60 * 1000,
            chunk_bytes=256 * 1024).SerializeToString()))
        return True

    async def on_media_complete(self, conn: Connection, frame: Frame) -> bool:
        req = MediaComplete.FromString(frame.payload)
        media = self.store.get_media(req.media_id)
        if media is None or media["owner_id"] != conn.user_id:
            await conn.send_error(ERR["forbidden"], "media not found")
            return True
        if media["status"] != "READY":
            await conn.send_error(ERR["bad_frame"], "upload not verified")
            return True
        await conn.send(Frame(FrameType.MEDIA_UPLOAD_GRANT, MediaGrant(
            media_id=req.media_id,
            https_url=f"{self.media_base_url}/v1/media/{req.media_id.hex()}/content",
            chunk_bytes=256 * 1024).SerializeToString()))
        return True

    async def on_media_download(self, conn: Connection, frame: Frame) -> bool:
        from oxmp_payload import MediaDownloadRequest
        req = MediaDownloadRequest.FromString(frame.payload)
        media = self.store.get_media(req.media_id)
        allowed = media is not None and (
            media["owner_id"] == conn.user_id or (
                req.conversation_id
                and self.store.is_member(req.conversation_id, conn.user_id)))
        if not allowed or media["status"] != "READY":
            await conn.send_error(ERR["forbidden"], "media download denied")
            return True
        await conn.send(Frame(FrameType.MEDIA_DOWNLOAD_GRANT, MediaGrant(
            media_id=req.media_id,
            https_url=f"{self.media_base_url}/v1/media/{req.media_id.hex()}/content",
            expires_at_ms=int(__import__("time").time() * 1000) + 5 * 60 * 1000,
            chunk_bytes=256 * 1024).SerializeToString()))
        return True

    async def on_sync_request(self, conn: Connection, frame: Frame) -> bool:
        req = SyncRequest.FromString(frame.payload)
        if req.conversation_id and not self.store.is_member(
                req.conversation_id, conn.user_id):
            await conn.send_error(ERR["forbidden"], "not a conversation member")
            return True
        limit = min(req.limit or 100, 500)
        found = self.store.messages_after(req.conversation_id, req.after_sequence, limit + 1)
        page, has_more = found[:limit], len(found) > limit
        batch = SyncBatch(conversation_id=req.conversation_id, has_more=has_more)
        in_page = set()
        for msg in page:
            ev = batch.events.add()
            ev.sequence, ev.event_id = msg.sequence, uuid.uuid4().bytes
            ev.message.message_id = msg.message_id
            ev.message.conversation_id = msg.conversation_id
            ev.message.sequence = msg.sequence
            if msg.deleted:
                # Tombstone: identifiers only, never the original body.
                ev.type = 3
            else:
                ev.type = 1
                ev.message.sender_id = msg.sender_id
                ev.message.sender_device_id = msg.sender_device_id
                ev.message.server_timestamp_ms = msg.server_timestamp_ms
                ev.message.content.kind, ev.message.content.body = msg.kind, msg.body
            in_page.add(msg.message_id)
            batch.next_after_sequence = msg.sequence
        # Deletions are state, not a point in the sequence stream: re-send
        # every tombstone of the room (bounded) so a client whose cursor
        # already passed the original message still converges. Applying a
        # tombstone twice is a no-op on the client.
        for message_id, sequence in self.store.tombstones(req.conversation_id):
            if message_id in in_page:
                continue
            ev = batch.events.add()
            ev.type, ev.sequence, ev.event_id = 3, sequence, uuid.uuid4().bytes
            ev.message.message_id = message_id
            ev.message.conversation_id = req.conversation_id
            ev.message.sequence = sequence
        await conn.send(Frame(FrameType.SYNC_BATCH, batch.SerializeToString()))
        return True

    async def on_bundle_publish(self, conn: Connection, frame: Frame) -> bool:
        bundle = KeyBundlePublish.FromString(frame.payload)
        if bundle.device_id != conn.device_id:
            await conn.send_error(ERR["forbidden"], "device mismatch")
            return True
        # Public key material only; the server never sees private keys (9.5).
        self.store.save_key_bundle(conn.device_id, frame.payload)
        return True

    async def on_bundle_request(self, conn: Connection, frame: Frame) -> bool:
        req = KeyBundleRequest.FromString(frame.payload)
        blobs = self.store.key_bundles(
            user_id=req.user_id or None, device_id=req.device_id or None)
        response = KeyBundleResponse()
        for blob in blobs:
            response.bundles.append(KeyBundlePublish.FromString(blob))
        await conn.send(Frame(FrameType.KEY_BUNDLE_RESPONSE,
                              response.SerializeToString()))
        return True

    async def on_sync_ack(self, conn: Connection, frame: Frame) -> bool:
        ack = SyncAck.FromString(frame.payload)
        self.store.ack_cursor(conn.device_id, ack.conversation_id, ack.applied_sequence)
        return True


async def serve(db_path: str, host: str = "127.0.0.1", port: int = 8765,
                secret: bytes | None = None,
                ssl_context=None) -> websockets.Server:
    store = Store(db_path)
    if secret is None:
        secret = os.environ.get(
            "OXMP_SECRET", "dev-only-secret-change-me-32bytes!!").encode()
    tokens = TokenService(secret)
    server = OxmpServer(store, tokens)
    ws_server = await websockets.serve(server.handle, host, port,
                                       max_size=MAX_WS_BYTES, ssl=ssl_context)
    ws_server.oxmp_store, ws_server.oxmp_tokens = store, tokens  # for tests/CLI
    return ws_server


async def main() -> None:
    port = int(os.environ.get("OXMP_PORT", "8765"))
    db = os.environ.get("OXMP_DB", "oxmp.db")
    ws_server = await serve(db, port=port)
    print(f"0xMP dev server on ws://127.0.0.1:{port} db={db} "
          f"(plain ws: local development only, production requires TLS 1.3)")
    await ws_server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
