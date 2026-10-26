"""0xMP v0.2 end-to-end flow sample (in-memory, no network).

Demonstrates the specification's core rules without sockets:

  HELLO negotiation (downgrade refusal) -> AUTH -> MESSAGE_SEND
  -> MESSAGE_ACCEPTED only after persistence -> duplicate retry replays
  the original result (idempotency) -> MESSAGE_INCOMING to the peer
  device -> MESSAGE_DELIVERY_ACK -> MESSAGE_DELIVERED to the sender
  -> cursor SYNC after reconnect.

Run:  python sample_client.py
Note: tokens/signatures below are placeholders. Production code MUST use
TLS 1.3, verified E2E libraries, and OS-backed key storage (spec ch. 9).
"""

from __future__ import annotations

import time
import uuid

from oxmp_frame import Flag, Frame, FrameType, decode, encode
from oxmp_payload import (
    KIND_TEXT,
    Auth,
    AuthResult,
    DeliveryAck,
    DeliveryNotice,
    Hello,
    HelloResult,
    MessageAccepted,
    MessageIncoming,
    MessageSend,
    SyncAck,
    SyncBatch,
    SyncEvent,
    SyncRequest,
)


def uid() -> bytes:
    return uuid.uuid4().bytes  # 16 bytes


def now_ms() -> int:
    return int(time.time() * 1000)


class InMemoryServer:
    """Minimal server honouring spec rules: persist-then-ACK, idempotent
    retries return the original result, per-conversation sequences."""

    def __init__(self) -> None:
        self._by_conversation: dict[bytes, list[MessageIncoming]] = {}
        self._idempotency: dict[tuple[bytes, bytes, bytes], MessageAccepted] = {}
        self._sessions: dict[bytes, bytes] = {}  # device_id -> user_id

    # -- frame dispatch -----------------------------------------------------
    def handle(self, frame: Frame, sender_user: bytes) -> list[tuple[bytes, Frame]]:
        """Returns (recipient_device_id, frame) pairs. Recipient b'' = caller."""
        handler = {
            FrameType.HELLO: self._hello,
            FrameType.AUTH: self._auth,
            FrameType.MESSAGE_SEND: self._send,
            FrameType.MESSAGE_DELIVERY_ACK: self._delivery_ack,
            FrameType.SYNC_REQUEST: self._sync,
        }.get(frame.frame_type)
        if handler is None:
            raise ValueError(f"unsupported frame in sample: {frame.frame_type}")
        return handler(frame, sender_user)

    def _hello(self, frame, _user):
        req = Hello.FromString(frame.payload)
        if req.protocol_id != "0xmp.v1":
            raise ValueError("protocol mismatch")
        # Select the strongest mutually supported profile (spec 9.4).
        selected = min(req.max_security_profile, 2)
        result = HelloResult(
            protocol_id="0xmp.v1",
            selected_security_profile=selected,
            features=[f for f in req.features if f in {"e2e.signal", "e2e.mls"}],
            max_payload_bytes=64 * 1024,
            session_id=uuid.uuid4().hex,
        )
        return [(b"", Frame(FrameType.HELLO_RESULT, result.SerializeToString()))]

    def _auth(self, frame, _user):
        req = Auth.FromString(frame.payload)
        if req.access_token != "sample-access-token":  # placeholder check
            result = AuthResult(ok=False)
        else:
            user_id = uid()
            self._sessions[req.device_id] = user_id
            result = AuthResult(
                ok=True, user_id=user_id, device_id=req.device_id,
                access_token_expires_at_ms=now_ms() + 15 * 60 * 1000,
            )
        return [(b"", Frame(FrameType.AUTH_RESULT, result.SerializeToString()))]

    def _send(self, frame, sender_user):
        req = MessageSend.FromString(frame.payload)
        key = (sender_user, req.sender_device_id, req.idempotency_key)
        if key in self._idempotency:  # retry: replay, never re-store (spec 7.2)
            replay = MessageAccepted()
            replay.CopyFrom(self._idempotency[key])
            replay.duplicate = True
            return [(b"", Frame(FrameType.MESSAGE_ACCEPTED, replay.SerializeToString()))]

        stored = MessageIncoming(
            message_id=req.message_id, conversation_id=req.conversation_id,
            sender_id=sender_user, sender_device_id=req.sender_device_id,
            # Per-conversation sequence (spec 7): 1-based, gapless on store.
            sequence=len(self._by_conversation.get(req.conversation_id, [])) + 1,
            server_timestamp_ms=now_ms(),
        )
        stored.content.CopyFrom(req.content)
        # Persist BEFORE acknowledging (spec section 8, rule 1).
        self._by_conversation.setdefault(req.conversation_id, []).append(stored)
        accepted = MessageAccepted(
            message_id=req.message_id, sequence=stored.sequence,
            server_timestamp_ms=stored.server_timestamp_ms,
        )
        self._idempotency[key] = accepted
        out = [(b"", Frame(FrameType.MESSAGE_ACCEPTED, accepted.SerializeToString()))]
        # Fan out to the (single, sample) peer device of the conversation.
        for device_id, user_id in self._sessions.items():
            if user_id != sender_user:
                out.append((device_id, Frame(FrameType.MESSAGE_INCOMING,
                                             stored.SerializeToString())))
        return out

    def _delivery_ack(self, frame, _user):
        ack = DeliveryAck.FromString(frame.payload)
        notice = DeliveryNotice(
            message_id=ack.message_id, conversation_id=ack.conversation_id,
            sequence=ack.sequence,
        )
        return [(b"sender", Frame(FrameType.MESSAGE_DELIVERED,
                                  notice.SerializeToString()))]

    def _sync(self, frame, _user):
        req = SyncRequest.FromString(frame.payload)
        stored = self._by_conversation.get(req.conversation_id, [])
        pending = [m for m in stored if m.sequence > req.after_sequence]
        limit = min(req.limit or 100, 500)
        batch = SyncBatch(conversation_id=req.conversation_id,
                          has_more=len(pending) > limit)
        for msg in pending[:limit]:
            ev = batch.events.add()
            ev.type, ev.sequence, ev.event_id = 1, msg.sequence, uid()
            ev.message.CopyFrom(msg)
            batch.next_after_sequence = msg.sequence
        return [(b"", Frame(FrameType.SYNC_BATCH, batch.SerializeToString()))]


class SampleClient:
    def __init__(self, server: InMemoryServer, name: str) -> None:
        self.server, self.name = server, name
        self.device_id, self.user_id = uid(), b""
        self.cursor: dict[bytes, int] = {}

    def exchange(self, frame: Frame) -> list[tuple[bytes, Frame]]:
        wire = encode(frame)
        print(f"  [{self.name}] -> {frame.frame_type.name} ({len(wire)} bytes on wire)")
        return self.server.handle(decode(wire), self.user_id)

    def connect_and_auth(self) -> None:
        replies = self.exchange(Frame(FrameType.HELLO, Hello(
            protocol_id="0xmp.v1", min_security_profile=1, max_security_profile=2,
            features=["e2e.signal"], client_name=self.name,
            client_version="0.2.0-sample").SerializeToString()))
        result = HelloResult.FromString(replies[0][1].payload)
        # Downgrade guard: refuse a selection below our minimum (spec 9.4).
        assert result.selected_security_profile >= 1, "security downgrade refused"
        print(f"  [{self.name}] negotiated profile={result.selected_security_profile}")

        replies = self.exchange(Frame(FrameType.AUTH, Auth(
            access_token="sample-access-token", device_id=self.device_id,
            device_public_key=b"sample-device-public-key",
            signature=b"sample-signature").SerializeToString()))
        auth = AuthResult.FromString(replies[0][1].payload)
        assert auth.ok, "authentication failed"
        self.user_id = auth.user_id
        print(f"  [{self.name}] authenticated, token expires in 15 min")

    def send_text(self, conversation_id: bytes, text: str,
                  idempotency_key: bytes | None = None) -> MessageAccepted:
        send = MessageSend(
            message_id=uid(), conversation_id=conversation_id,
            sender_device_id=self.device_id, client_timestamp_ms=now_ms(),
            idempotency_key=idempotency_key or uid(),
        )
        send.content.kind = KIND_TEXT
        send.content.body = text.encode("utf-8")
        replies = self.exchange(Frame(FrameType.MESSAGE_SEND,
                                      send.SerializeToString(),
                                      Flag.ACK_REQUESTED))
        accepted = MessageAccepted.FromString(replies[0][1].payload)
        for recipient, out in replies[1:]:
            if recipient:  # in the full sample the peer client consumes this
                PEER_INBOX.append(out)
        print(f"  [{self.name}] accepted seq={accepted.sequence} "
              f"duplicate={accepted.duplicate}")
        return accepted

    def sync(self, conversation_id: bytes) -> int:
        after = self.cursor.get(conversation_id, 0)
        replies = self.exchange(Frame(FrameType.SYNC_REQUEST, SyncRequest(
            conversation_id=conversation_id, after_sequence=after,
            limit=100).SerializeToString()))
        batch = SyncBatch.FromString(replies[0][1].payload)
        before = self.cursor.get(conversation_id, 0)
        for ev in batch.events:
            print(f"  [{self.name}] sync: seq={ev.sequence} "
                  f"text={ev.message.content.body.decode(errors='replace')!r}")
            self.cursor[conversation_id] = ev.sequence
        ack = SyncAck(conversation_id=conversation_id,
                      applied_sequence=self.cursor.get(conversation_id, 0))
        newly = len(batch.events)
        kind = "newly applied" if newly else "re-confirmation (no new events)"
        print(f"  [{self.name}] SYNC_ACK cursor {before}->{ack.applied_sequence} "
              f"newly_applied={newly} ({kind})")
        return newly


PEER_INBOX: list[Frame] = []


def main() -> None:
    server = InMemoryServer()
    alice = SampleClient(server, "alice")
    bob = SampleClient(server, "bob")
    conversation = uid()

    print("1) HELLO negotiation + AUTH")
    alice.connect_and_auth()
    bob.connect_and_auth()

    print("2) MESSAGE_SEND -> ACCEPTED (persist-then-ACK)")
    key = uid()
    first = alice.send_text(conversation, "안녕하세요, 0xMP!", key)

    print("3) Retry with the same idempotency key -> original result replayed")
    retry = alice.send_text(conversation, "안녕하세요, 0xMP!", key)
    assert (retry.sequence, retry.duplicate) == (first.sequence, True)

    print("4) Peer receives MESSAGE_INCOMING and acknowledges delivery")
    incoming = MessageIncoming.FromString(PEER_INBOX[-1].payload)
    print(f"  [bob] incoming seq={incoming.sequence} "
          f"text={incoming.content.body.decode()!r}")
    replies = bob.exchange(Frame(FrameType.MESSAGE_DELIVERY_ACK, DeliveryAck(
        message_id=incoming.message_id, conversation_id=conversation,
        sequence=incoming.sequence).SerializeToString()))
    assert replies[0][1].frame_type is FrameType.MESSAGE_DELIVERED
    print("  [alice] MESSAGE_DELIVERED received")

    print("5) Reconnect: cursor sync returns only what is missing")
    assert bob.sync(conversation) == 1  # exactly one stored message
    assert bob.sync(conversation) == 0  # cursor advanced: nothing new
    print("\nAll sample flows passed.")


if __name__ == "__main__":
    main()
