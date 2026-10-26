"""Generate the cross-platform test vector file (clients/test_vectors.json).

Any platform implementation (Python, JavaScript/web, and future macOS /
Android / iOS SDKs) must reproduce these exact bytes. Regenerate with:
    python tools/generate_vectors.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "samples"))

from oxmp_frame import Frame, FrameType, encode  # noqa: E402
from oxmp_payload import (  # noqa: E402
    Hello, MessageAccepted, MessageSend, SyncBatch,
)

send = MessageSend(
    message_id=bytes(range(16)), conversation_id=bytes(range(16, 32)),
    sender_device_id=bytes(range(32, 48)), client_timestamp_ms=1_700_000_000_000,
    idempotency_key=bytes(range(48, 64)))
send.content.kind = 1
send.content.body = "cross-platform ✓".encode()

def _sync_batch_hex() -> str:
    batch = SyncBatch(conversation_id=b"\x11" * 16, has_more=False,
                      next_after_sequence=1)
    event = batch.events.add()
    event.type, event.sequence = 1, 1
    event.event_id = b"\x22" * 16
    event.message.message_id = b"\x33" * 16
    event.message.conversation_id = b"\x11" * 16
    event.message.sender_id = b"\x44" * 16
    event.message.sequence = 1
    event.message.content.kind = 1
    event.message.content.body = b"room history"
    return batch.SerializeToString().hex()


vectors = {
    "description": "0xMP v0.3 cross-platform wire vectors. "
                   "Multi-byte header integers are big-endian; "
                   "payloads are Protobuf (package oxmp.v1).",
    "frames": [
        {"name": "ping_empty", "type": 0x40,
         "hex": encode(Frame(FrameType.PING)).hex()},
        {"name": "hello_protocol_only", "type": 0x01,
         "hex": encode(Frame(FrameType.HELLO,
                             Hello(protocol_id="0xmp.v1").SerializeToString())).hex()},
        {"name": "ping_with_extension", "type": 0x40,
         "hex": encode(Frame(FrameType.PING, b"ab", extension=b"xy")).hex()},
    ],
    "payloads": [
        {"name": "message_accepted_seq1",
         "hex": MessageAccepted(sequence=1).SerializeToString().hex()},
        {"name": "message_send_fixed_ids", "hex": send.SerializeToString().hex()},
        {"name": "sync_batch_one_text", "hex": _sync_batch_hex()},
    ],
    "negative_frames": [
        {"name": "bad_magic", "hex": "00000140000000000000"},
        {"name": "unknown_version", "hex": "4d500240000000000000"},
        {"name": "reserved_flag", "hex": "4d500140800000000000"},
        {"name": "unknown_type", "hex": "4d500166000000000000"},
        {"name": "oversize_length_claim", "hex": "4d500110000000200000"},
        {"name": "truncated_hello", "hex": "4d5001010000000000090a07"},
    ],
}

out = ROOT / "clients" / "test_vectors.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")
print(f"wrote {out}")
