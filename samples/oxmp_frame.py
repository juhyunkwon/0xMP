"""0xMP v0.2 frame codec (reference sample).

Fixed 10-byte header, all multi-byte header integers are big-endian:

    offset  size  field
    0       2     magic           0x4D 0x50 ("MP" in ASCII)
    2       1     version         0x01 for 0xmp.v1
    3       1     type            frame type (see FrameType)
    4       2     flags           bit flags (see Flag)
    6       4     payload_length  bytes following the fixed header
    10      var   [extension]     only when Flag.HAS_EXTENSION is set:
                                  2-byte big-endian length + bytes
          var   payload           Protobuf-encoded body

Security rules implemented here (specification sections 5 and 9.8):
  * payload_length is checked against the 1 MiB hard cap BEFORE any
    payload buffer is allocated or read.
  * reserved flag bits, unknown versions and bad magic are rejected.
  * a compressed payload must also respect the cap after decompression
    (enforced by callers via check_decompressed_size()).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum, IntFlag

MAGIC = b"\x4d\x50"  # "MP"
VERSION = 0x01
HEADER_SIZE = 10
MAX_PAYLOAD_BYTES = 1 * 1024 * 1024  # 1 MiB protocol hard cap

# Negotiated per-type defaults (specification section 5.2).
LIMIT_CONTROL_BYTES = 4 * 1024
LIMIT_MESSAGE_BYTES = 64 * 1024


class FrameError(ValueError):
    """Raised when a frame violates the wire format."""


class FrameType(IntEnum):
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
    MEDIA_UPLOAD_GRANT = 0x32
    MEDIA_DOWNLOAD_REQUEST = 0x33
    MEDIA_DOWNLOAD_GRANT = 0x34
    PING = 0x40
    PONG = 0x41
    KEY_BUNDLE_PUBLISH = 0x50
    KEY_BUNDLE_REQUEST = 0x51
    KEY_BUNDLE_RESPONSE = 0x52
    DEVICE_LIST_UPDATE = 0x53
    ERROR = 0x7F


class Flag(IntFlag):
    NONE = 0x0000
    E2E_ENCRYPTED = 0x0001
    COMPRESSED = 0x0002      # only after HELLO negotiation
    HAS_EXTENSION = 0x0004
    ACK_REQUESTED = 0x0008
    # 0x0010-0x8000 are reserved: senders MUST NOT set them,
    # receivers MUST reject frames that carry them (spec 5.1).


_KNOWN_FLAGS = (
    Flag.E2E_ENCRYPTED | Flag.COMPRESSED | Flag.HAS_EXTENSION | Flag.ACK_REQUESTED
)
_HEADER = struct.Struct(">2sBBHI")


@dataclass(frozen=True)
class Frame:
    frame_type: FrameType
    payload: bytes = b""
    flags: Flag = Flag.NONE
    extension: bytes = b""
    version: int = VERSION


def encode(frame: Frame) -> bytes:
    flags = Flag(frame.flags)
    if int(flags) & ~int(_KNOWN_FLAGS):
        raise FrameError(f"reserved flag bits set: {flags:#06x}")
    body = frame.payload
    if frame.extension:
        flags |= Flag.HAS_EXTENSION
        body = struct.pack(">H", len(frame.extension)) + frame.extension + body
    if len(body) > MAX_PAYLOAD_BYTES:
        raise FrameError(f"payload {len(body)} exceeds {MAX_PAYLOAD_BYTES} hard cap")
    header = _HEADER.pack(MAGIC, frame.version, int(frame.frame_type), int(flags), len(body))
    return header + body


def decode(data: bytes) -> Frame:
    """Decode exactly one frame; trailing bytes are rejected."""
    if len(data) < HEADER_SIZE:
        raise FrameError("frame shorter than fixed header")
    magic, version, raw_type, raw_flags, payload_length = _HEADER.unpack_from(data)
    if magic != MAGIC:
        raise FrameError(f"bad magic: {magic!r}")
    if version != VERSION:
        raise FrameError(f"unsupported frame version: {version}")
    # Reject oversized frames before touching the payload (DoS guard).
    if payload_length > MAX_PAYLOAD_BYTES:
        raise FrameError(f"payload_length {payload_length} exceeds hard cap")
    if len(data) != HEADER_SIZE + payload_length:
        raise FrameError("frame length does not match payload_length")
    if raw_flags & ~int(_KNOWN_FLAGS):
        raise FrameError(f"reserved flag bits set: {raw_flags:#06x}")
    flags = Flag(raw_flags)
    try:
        frame_type = FrameType(raw_type)
    except ValueError as exc:
        raise FrameError(f"unknown frame type: {raw_type:#04x}") from exc

    body = data[HEADER_SIZE:]
    extension = b""
    if flags & Flag.HAS_EXTENSION:
        if len(body) < 2:
            raise FrameError("extension header truncated")
        (ext_len,) = struct.unpack_from(">H", body)
        if len(body) < 2 + ext_len:
            raise FrameError("extension body truncated")
        extension, body = body[2 : 2 + ext_len], body[2 + ext_len :]
    return Frame(frame_type, body, flags, extension, version)


def check_decompressed_size(size: int) -> None:
    """Call after decompression; guards against decompression bombs."""
    if size > MAX_PAYLOAD_BYTES:
        raise FrameError("decompressed payload exceeds hard cap")
