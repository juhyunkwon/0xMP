"""0xMP Python plugin: frame codec + the Protobuf messages a client sends.

No dependency on samples/ or server/. Frame encoding uses the standard
library. `sign_challenge` uses the `cryptography` package (Ed25519).

    from oxmp_plugin import encode_frame, encode_hello, FrameType
    wire = encode_frame(FrameType.HELLO, encode_hello(protocol_id="0xmp.v1"))
"""
from __future__ import annotations

import json
import struct
import time
from pathlib import Path

MAGIC = b"\x4d\x50"
VERSION = 0x01
MAX_PAYLOAD = 1024 * 1024
KNOWN_FLAGS = 0x0001 | 0x0002 | 0x0004 | 0x0008

class FrameType:
    HELLO = 0x01
    AUTH = 0x02
    AUTH_RESULT = 0x03
    HELLO_RESULT = 0x04
    MESSAGE_SEND = 0x10
    MESSAGE_ACCEPTED = 0x11
    MESSAGE_DELIVERED = 0x12
    MESSAGE_READ = 0x13
    MESSAGE_EDIT = 0x14
    MESSAGE_DELETE = 0x15
    MESSAGE_INCOMING = 0x16
    MESSAGE_DELIVERY_ACK = 0x17
    SYNC_REQUEST = 0x20
    SYNC_BATCH = 0x21
    SYNC_ACK = 0x22
    MEDIA_INIT = 0x30
    MEDIA_COMPLETE = 0x31
    PING = 0x40
    PONG = 0x41
    KEY_BUNDLE_PUBLISH = 0x50
    KEY_BUNDLE_REQUEST = 0x51
    KEY_BUNDLE_RESPONSE = 0x52
    ERROR = 0x7F


_TYPES = {v for k, v in vars(FrameType).items() if k.isupper()}


class FrameError(ValueError):
    pass


class Writer:
    def __init__(self) -> None:
        self.parts: list[bytes] = []

    def varint(self, value: int) -> "Writer":
        out = bytearray()
        v = int(value)
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                b |= 0x80
            out.append(b)
            if not v:
                break
        self.parts.append(bytes(out))
        return self

    def tag(self, field: int, wire: int) -> "Writer":
        return self.varint((field << 3) | wire)

    def bytes(self, field: int, data: bytes | None) -> "Writer":
        if not data:
            return self
        self.tag(field, 2)
        self.varint(len(data))
        self.parts.append(data)
        return self

    def string(self, field: int, text: str) -> "Writer":
        return self.bytes(field, text.encode() if text else b"")

    def uint(self, field: int, value: int) -> "Writer":
        if value:
            self.tag(field, 0)
            self.varint(value)
        return self

    def concat(self) -> bytes:
        return b"".join(self.parts)


def parse_fields(data: bytes) -> dict[int, list]:
    fields: dict[int, list] = {}
    at = 0

    def read_varint() -> int:
        nonlocal at
        shift = result = 0
        while True:
            if at >= len(data):
                raise FrameError("truncated varint")
            b = data[at]
            at += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7
            if shift > 63:
                raise FrameError("varint too long")

    while at < len(data):
        tag = read_varint()
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            value: bytes | int = read_varint()
        elif wire == 2:
            length = read_varint()
            if at + length > len(data):
                raise FrameError("truncated length-delimited field")
            value = data[at:at + length]
            at += length
        elif wire == 5:
            value = data[at:at + 4]
            at += 4
        elif wire == 1:
            value = data[at:at + 8]
            at += 8
        else:
            raise FrameError(f"unsupported wire type {wire}")
        fields.setdefault(field, []).append(value)
    return fields


def _get(fields: dict, n: int):
    vals = fields.get(n)
    return vals[0] if vals else None


def encode_frame(frame_type: int, payload: bytes = b"", flags: int = 0,
                 extension: bytes = b"") -> bytes:
    if frame_type not in _TYPES:
        raise FrameError(f"unknown frame type {frame_type}")
    if flags & ~KNOWN_FLAGS:
        raise FrameError("reserved flag bits set")
    body = payload
    if extension:
        flags |= 0x0004
        body = struct.pack(">H", len(extension)) + extension + payload
    if len(body) > MAX_PAYLOAD:
        raise FrameError("payload exceeds hard cap")
    header = struct.pack(">2sBBHI", MAGIC, VERSION, frame_type, flags, len(body))
    return header + body


def decode_frame(data: bytes) -> dict:
    if len(data) < 10:
        raise FrameError("frame shorter than fixed header")
    magic, version, frame_type, flags, length = struct.unpack_from(">2sBBHI", data)
    if magic != MAGIC:
        raise FrameError("bad magic")
    if version != VERSION:
        raise FrameError("unsupported frame version")
    if length > MAX_PAYLOAD:
        raise FrameError("payload_length exceeds hard cap")
    if len(data) != 10 + length:
        raise FrameError("frame length mismatch")
    if flags & ~KNOWN_FLAGS:
        raise FrameError("reserved flag bits set")
    if frame_type not in _TYPES:
        raise FrameError(f"unknown frame type {frame_type}")
    body = data[10:]
    extension = b""
    if flags & 0x0004:
        if len(body) < 2:
            raise FrameError("extension header truncated")
        (ext_len,) = struct.unpack_from(">H", body)
        if len(body) < 2 + ext_len:
            raise FrameError("extension body truncated")
        extension, body = body[2:2 + ext_len], body[2 + ext_len:]
    return {"type": frame_type, "flags": flags, "payload": body,
            "extension": extension, "version": VERSION}


def encode_hello(protocol_id: str = "0xmp.v1", min_profile: int = 0,
                 max_profile: int = 0, client_name: str = "",
                 client_version: str = "") -> bytes:
    return (Writer().string(1, protocol_id or "0xmp.v1").uint(2, min_profile)
            .uint(3, max_profile).string(5, client_name)
            .string(6, client_version).concat())


def decode_hello_result(data: bytes) -> dict:
    f = parse_fields(data)
    return {"protocol_id": (_get(f, 1) or b"").decode(),
            "selected_profile": int(_get(f, 2) or 0),
            "max_payload": int(_get(f, 4) or 0),
            "session_id": (_get(f, 5) or b"").decode()}


def sign_challenge(private_key_raw: bytes, session_id: str) -> bytes:
    """Ed25519 signature over the HELLO session id. The seed is 32 raw bytes,
    the same `device_private_key_raw` the account API returns once."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if len(private_key_raw) != 32:
        raise FrameError("Ed25519 seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(private_key_raw).sign(session_id.encode())


def encode_auth(access_token: str, device_id: bytes, signature: bytes) -> bytes:
    return Writer().string(1, access_token).bytes(2, device_id).bytes(4, signature).concat()


def decode_auth_result(data: bytes) -> dict:
    f = parse_fields(data)
    return {"ok": (_get(f, 1) or 0) == 1, "user_id": _get(f, 2),
            "device_id": _get(f, 3)}


def encode_message_send(*, message_id: bytes, conversation_id: bytes,
                        sender_device_id: bytes, idempotency_key: bytes,
                        body: bytes, kind: int = 1,
                        client_timestamp_ms: int = 0) -> bytes:
    content = Writer().uint(1, kind or 1).bytes(2, body).concat()
    ts = client_timestamp_ms or int(time.time() * 1000)
    return (Writer().bytes(1, message_id).bytes(2, conversation_id)
            .bytes(3, sender_device_id).uint(4, ts).bytes(5, idempotency_key)
            .bytes(6, content).concat())


def decode_message_accepted(data: bytes) -> dict:
    f = parse_fields(data)
    return {"message_id": _get(f, 1), "sequence": int(_get(f, 2) or 0),
            "server_timestamp_ms": int(_get(f, 3) or 0),
            "duplicate": (_get(f, 4) or 0) == 1}


def decode_message_incoming(data: bytes) -> dict:
    f = parse_fields(data)
    content = parse_fields(_get(f, 7) or b"")
    return {"message_id": _get(f, 1), "conversation_id": _get(f, 2),
            "sender_id": _get(f, 3), "sequence": int(_get(f, 5) or 0),
            "kind": int(_get(content, 1) or 0), "body": _get(content, 2) or b""}


def decode_sync_batch(data: bytes) -> dict:
    f = parse_fields(data)
    events = []
    for raw in f.get(2, []):
        ev = parse_fields(raw)
        events.append({
            "type": int(_get(ev, 1) or 0),
            "sequence": int(_get(ev, 2) or 0),
            "message": decode_message_incoming(_get(ev, 3)) if _get(ev, 3) else None,
        })
    return {"conversation_id": _get(f, 1), "events": events,
            "has_more": (_get(f, 3) or 0) == 1,
            "next_after_sequence": int(_get(f, 4) or 0)}


def encode_sync_request(conversation_id: bytes, after_sequence: int = 0,
                        limit: int = 100) -> bytes:
    return (Writer().bytes(1, conversation_id).uint(2, after_sequence)
            .uint(3, limit or 100).concat())


def encode_sync_ack(conversation_id: bytes, applied_sequence: int) -> bytes:
    return Writer().bytes(1, conversation_id).uint(2, applied_sequence).concat()


def encode_delivery_ack(message_id: bytes, conversation_id: bytes,
                        sequence: int) -> bytes:
    return (Writer().bytes(1, message_id).bytes(2, conversation_id)
            .uint(3, sequence).concat())


def encode_delete_event(conversation_id: bytes, message_id: bytes = b"",
                        for_everyone: bool = True) -> bytes:
    return (Writer().bytes(1, message_id).bytes(2, conversation_id)
            .uint(3, 1 if for_everyone else 0).concat())


def decode_delete_event(data: bytes) -> dict:
    f = parse_fields(data)
    return {"message_id": _get(f, 1) or b"", "conversation_id": _get(f, 2),
            "for_everyone": (_get(f, 3) or 0) == 1}


def decode_error(data: bytes) -> dict:
    f = parse_fields(data)
    return {"code": int(_get(f, 1) or 0), "message": (_get(f, 2) or b"").decode(),
            "retryable": (_get(f, 3) or 0) == 1}


def _hex_named(doc: dict, name: str) -> str:
    for section in ("frames", "payloads", "negative_frames"):
        for item in doc[section]:
            if item["name"] == name:
                return item["hex"]
    raise KeyError(name)


def conformance(vectors_path: Path | None = None) -> None:
    path = vectors_path or Path(__file__).resolve().parents[2] / "clients" / "test_vectors.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert encode_frame(FrameType.PING).hex() == _hex_named(doc, "ping_empty")
    hello = encode_frame(FrameType.HELLO, encode_hello())
    assert hello.hex() == _hex_named(doc, "hello_protocol_only")
    assert decode_frame(hello)["type"] == FrameType.HELLO
    ext = encode_frame(FrameType.PING, b"ab", 0, b"xy")
    assert ext.hex() == _hex_named(doc, "ping_with_extension")
    decoded = decode_frame(bytes.fromhex(_hex_named(doc, "ping_with_extension")))
    assert decoded["extension"] == b"xy" and decoded["payload"] == b"ab"
    for item in doc["negative_frames"]:
        try:
            decode_frame(bytes.fromhex(item["hex"]))
        except FrameError:
            continue
        raise AssertionError(item["name"])
    accepted = bytes.fromhex(_hex_named(doc, "message_accepted_seq1"))
    assert decode_message_accepted(accepted)["sequence"] == 1
    body = b"cross-platform " + bytes([0xE2, 0x9C, 0x93])
    sent = encode_message_send(
        message_id=bytes(range(16)),
        conversation_id=bytes(range(16, 32)),
        sender_device_id=bytes(range(32, 48)),
        idempotency_key=bytes(range(48, 64)),
        body=body, kind=1, client_timestamp_ms=1700000000000)
    assert sent.hex() == _hex_named(doc, "message_send_fixed_ids")
    batch = decode_sync_batch(bytes.fromhex(_hex_named(doc, "sync_batch_one_text")))
    assert batch["has_more"] is False and batch["next_after_sequence"] == 1
    assert batch["events"][0]["sequence"] == 1
    assert batch["events"][0]["message"]["body"] == b"room history"
    deleted = decode_delete_event(encode_delete_event(b"\x11" * 16))
    assert deleted["for_everyone"] is True and deleted["message_id"] == b""
    assert deleted["conversation_id"] == b"\x11" * 16
    signature = sign_challenge(bytes(range(32)), "0xmp-challenge")
    assert signature.hex() == (
        "b914dcdda90eba28435578c0b7f1a4cff88245a7f13dfa866a9ad722bb7b2360"
        "6fcb63f2d80f8adac7f266c3631e09e8937324f494c35dd799059b8030ba110e")
    assert len(encode_auth("token", bytes(range(16)), signature)) > 0
    print(f"python plugin: {path.name} OK")


if __name__ == "__main__":
    conformance()
