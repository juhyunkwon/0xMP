"""Async 0xMP client library (reference implementation for tests/tools)."""
from __future__ import annotations

import asyncio
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "samples"))

from oxmp_frame import Flag, Frame, FrameType, encode, decode  # noqa: E402
from oxmp_payload import (  # noqa: E402
    KIND_E2E_ENVELOPE, KIND_TEXT, Auth, AuthResult, DeliveryAck, Hello,
    HelloResult, KeyBundlePublish, KeyBundleRequest, KeyBundleResponse,
    MediaComplete, MediaGrant, MediaInit, MessageAccepted, MessageIncoming,
    MessageSend, SyncAck, SyncBatch, SyncRequest,
)
from .provision import Credentials  # noqa: E402


def uid() -> bytes:
    return uuid.uuid4().bytes


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class SyncResult:
    """Distinguishes newly applied events from a re-confirmation.

    newly_applied counts events received in THIS sync call. A second sync
    with an up-to-date cursor returns newly_applied == 0 while
    cursor_after stays unchanged: that is a re-confirmation, not new data.
    """

    events: list = field(default_factory=list)
    newly_applied: int = 0
    cursor_before: int = 0
    cursor_after: int = 0

    @property
    def reaffirmed_only(self) -> bool:
        return self.newly_applied == 0


class OxmpClient:
    def __init__(self, url: str, credentials: Credentials, ssl_context=None):
        self.url, self.creds = url, credentials
        self.ssl_context = ssl_context
        self.ws = None
        self.session_id = ""
        self.profile = 0
        self.incoming: asyncio.Queue[MessageIncoming] = asyncio.Queue()
        self.cursors: dict[bytes, int] = {}
        self._recv_task: asyncio.Task | None = None
        self._pending: dict[FrameType, asyncio.Queue] = {}

    # -- plumbing --------------------------------------------------------------
    def _queue_for(self, ftype: FrameType) -> asyncio.Queue:
        return self._pending.setdefault(ftype, asyncio.Queue())

    async def _reader(self) -> None:
        async for raw in self.ws:
            frame = decode(raw if isinstance(raw, bytes) else raw.encode())
            if frame.frame_type is FrameType.MESSAGE_INCOMING:
                await self.incoming.put(MessageIncoming.FromString(frame.payload))
            else:
                await self._queue_for(frame.frame_type).put(frame)

    async def _request(self, frame: Frame, expect: FrameType,
                       timeout: float = 5.0) -> Frame:
        await self.ws.send(encode(frame))
        return await asyncio.wait_for(self._queue_for(expect).get(), timeout)

    # -- session -----------------------------------------------------------------
    async def connect(self) -> None:
        self.ws = await websockets.connect(self.url, max_size=2 * 1024 * 1024,
                                           ssl=self.ssl_context)
        self._recv_task = asyncio.create_task(self._reader())
        reply = await self._request(Frame(FrameType.HELLO, Hello(
            protocol_id="0xmp.v1", min_security_profile=0, max_security_profile=2,
            features=["e2e.signal"], client_name=self.creds.name,
            client_version="0.3.0-dev").SerializeToString()), FrameType.HELLO_RESULT)
        result = HelloResult.FromString(reply.payload)
        self.session_id, self.profile = result.session_id, result.selected_security_profile

        signature = self.creds.private_key.sign(self.session_id.encode())
        reply = await self._request(Frame(FrameType.AUTH, Auth(
            access_token=self.creds.access_token, device_id=self.creds.device_id,
            device_public_key=b"", signature=signature).SerializeToString()),
            FrameType.AUTH_RESULT)
        auth = AuthResult.FromString(reply.payload)
        if not auth.ok:
            raise PermissionError("authentication failed")

    async def close(self) -> None:
        if self._recv_task:
            self._recv_task.cancel()
        if self.ws:
            await self.ws.close()

    async def ping(self) -> None:
        await self._request(Frame(FrameType.PING), FrameType.PONG)

    # -- messaging -----------------------------------------------------------------
    async def send_text(self, conversation_id: bytes, text: str, *,
                        idempotency_key: bytes | None = None,
                        message_id: bytes | None = None) -> MessageAccepted:
        send = MessageSend(
            message_id=message_id or uid(), conversation_id=conversation_id,
            sender_device_id=self.creds.device_id, client_timestamp_ms=now_ms(),
            idempotency_key=idempotency_key or uid())
        send.content.kind = KIND_TEXT
        send.content.body = text.encode()
        reply = await self._request(Frame(
            FrameType.MESSAGE_SEND, send.SerializeToString(), Flag.ACK_REQUESTED),
            FrameType.MESSAGE_ACCEPTED)
        return MessageAccepted.FromString(reply.payload)

    async def wait_incoming(self, timeout: float = 5.0) -> MessageIncoming:
        return await asyncio.wait_for(self.incoming.get(), timeout)

    async def next_error(self, timeout: float = 5.0):
        from oxmp_payload import Error
        frame = await asyncio.wait_for(
            self._queue_for(FrameType.ERROR).get(), timeout)
        return Error.FromString(frame.payload)

    async def send_e2e(self, conversation_id: bytes, envelope_body: bytes, *,
                       idempotency_key: bytes | None = None) -> MessageAccepted:
        """Send an opaque E2E envelope. The server stores/forwards it without
        being able to read it; `body` is E2EEnvelope protobuf bytes."""
        from oxmp_payload import MessageContent  # local to keep surface small
        send = MessageSend(
            message_id=uid(), conversation_id=conversation_id,
            sender_device_id=self.creds.device_id, client_timestamp_ms=now_ms(),
            idempotency_key=idempotency_key or uid())
        send.content.kind = KIND_E2E_ENVELOPE
        send.content.body = envelope_body
        reply = await self._request(Frame(
            FrameType.MESSAGE_SEND, send.SerializeToString(), Flag.E2E_ENCRYPTED),
            FrameType.MESSAGE_ACCEPTED)
        return MessageAccepted.FromString(reply.payload)

    async def publish_key_bundle(self, bundle: KeyBundlePublish) -> None:
        await self.ws.send(encode(Frame(
            FrameType.KEY_BUNDLE_PUBLISH, bundle.SerializeToString())))

    async def fetch_key_bundles(self, user_id: bytes = b"",
                                device_id: bytes = b"") -> list[KeyBundlePublish]:
        reply = await self._request(Frame(FrameType.KEY_BUNDLE_REQUEST,
                                          KeyBundleRequest(
                                              user_id=user_id,
                                              device_id=device_id).SerializeToString()),
                                    FrameType.KEY_BUNDLE_RESPONSE)
        return list(KeyBundleResponse.FromString(reply.payload).bundles)

    async def wait_delivered(self, timeout: float = 5.0):
        from oxmp_payload import DeliveryNotice
        frame = await asyncio.wait_for(
            self._queue_for(FrameType.MESSAGE_DELIVERED).get(), timeout)
        return DeliveryNotice.FromString(frame.payload)

    async def media_init(self, content_type: str, total_bytes: int,
                         sha256: bytes) -> MediaGrant:
        reply = await self._request(Frame(FrameType.MEDIA_INIT, MediaInit(
            content_type=content_type, total_bytes=total_bytes,
            sha256=sha256).SerializeToString()), FrameType.MEDIA_UPLOAD_GRANT)
        return MediaGrant.FromString(reply.payload)

    async def media_complete(self, media_id: bytes) -> MediaGrant:
        reply = await self._request(Frame(FrameType.MEDIA_COMPLETE, MediaComplete(
            media_id=media_id).SerializeToString()), FrameType.MEDIA_UPLOAD_GRANT)
        return MediaGrant.FromString(reply.payload)

    async def delete_message(self, conversation_id: bytes,
                             message_id: bytes = b"") -> None:
        """Send MESSAGE_DELETE. Empty message_id clears the whole room
        (group rooms: creator only). Confirmation arrives as a broadcast
        MESSAGE_DELETE frame; use wait_delete() to observe it."""
        from oxmp_payload import DeleteEvent
        await self.ws.send(encode(Frame(FrameType.MESSAGE_DELETE, DeleteEvent(
            message_id=message_id, conversation_id=conversation_id,
            for_everyone=True).SerializeToString())))

    async def wait_delete(self, timeout: float = 5.0):
        from oxmp_payload import DeleteEvent
        frame = await asyncio.wait_for(
            self._queue_for(FrameType.MESSAGE_DELETE).get(), timeout)
        return DeleteEvent.FromString(frame.payload)

    async def delivery_ack(self, msg: MessageIncoming) -> None:
        await self.ws.send(encode(Frame(FrameType.MESSAGE_DELIVERY_ACK, DeliveryAck(
            message_id=msg.message_id, conversation_id=msg.conversation_id,
            sequence=msg.sequence).SerializeToString())))

    async def sync(self, conversation_id: bytes, limit: int = 100) -> SyncResult:
        before = self.cursors.get(conversation_id, 0)
        result = SyncResult(cursor_before=before, cursor_after=before)
        after = before
        while True:
            reply = await self._request(Frame(FrameType.SYNC_REQUEST, SyncRequest(
                conversation_id=conversation_id, after_sequence=after,
                limit=limit).SerializeToString()), FrameType.SYNC_BATCH)
            batch = SyncBatch.FromString(reply.payload)
            for ev in batch.events:
                result.events.append(ev)
                after = max(after, ev.sequence)
            if not batch.has_more:
                break
        result.newly_applied = len(result.events)
        result.cursor_after = after
        self.cursors[conversation_id] = after
        await self.ws.send(encode(Frame(FrameType.SYNC_ACK, SyncAck(
            conversation_id=conversation_id,
            applied_sequence=after).SerializeToString())))
        return result
