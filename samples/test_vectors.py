"""0xMP v0.2 wire test vectors (specification appendix A).

Run:  python test_vectors.py   -> prints PASS lines, exits non-zero on failure.
These hex strings are normative for the sample implementation: any other
implementation that claims frame compatibility must reproduce them.
"""

from __future__ import annotations

from oxmp_frame import Flag, Frame, FrameError, FrameType, decode, encode
from oxmp_payload import Hello, MessageAccepted

# Vector 1: PING with an empty payload.
V1_PING_HEX = "4d500140000000000000"

# Vector 2: HELLO carrying Hello{protocol_id: "0xmp.v1"} only.
#   header: 4d 50 | 01 | 01 | 0000 | 00000009
#   body:   0a 07 "0xmp.v1"          (field 1, length-delimited)
V2_HELLO_HEX = "4d5001010000000000090a0730786d702e7631"

# Vector 3: MESSAGE_ACCEPTED{sequence: 1} with ACK_REQUESTED cleared.
V3_ACCEPTED_PAYLOAD_HEX = "1001"  # field 2 (sequence) varint = 1


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}  {name}")
    if not condition:
        raise SystemExit(1)


def main() -> None:
    ping = encode(Frame(FrameType.PING))
    check("v1 ping encoding", ping.hex() == V1_PING_HEX)
    check("v1 ping decoding", decode(bytes.fromhex(V1_PING_HEX)).frame_type is FrameType.PING)

    hello = Hello(protocol_id="0xmp.v1")
    frame = encode(Frame(FrameType.HELLO, hello.SerializeToString()))
    check("v2 hello encoding", frame.hex() == V2_HELLO_HEX)
    decoded = decode(bytes.fromhex(V2_HELLO_HEX))
    check("v2 hello payload", Hello.FromString(decoded.payload).protocol_id == "0xmp.v1")

    accepted = MessageAccepted(sequence=1)
    check("v3 accepted payload", accepted.SerializeToString().hex() == V3_ACCEPTED_PAYLOAD_HEX)

    # Negative vectors: every malformed frame must be rejected.
    def rejects(name: str, data: bytes) -> None:
        try:
            decode(data)
        except FrameError:
            check(name, True)
        else:
            check(name, False)

    rejects("bad magic rejected", bytes.fromhex("00000140000000000000"))
    rejects("unknown version rejected", bytes.fromhex("4d500240000000000000"))
    rejects("reserved flag rejected", bytes.fromhex("4d500140800000000000"))
    rejects("unknown type rejected", bytes.fromhex("4d500166000000000000"))
    # payload_length lies above the 1 MiB cap: rejected before reading a body.
    rejects("oversize length rejected", bytes.fromhex("4d500140000000200000"))
    rejects("truncated frame rejected", bytes.fromhex("4d5001400000"))

    # Extension header round-trip.
    ext = encode(Frame(FrameType.PING, b"ab", extension=b"xy"))
    decoded = decode(ext)
    check("extension round-trip", decoded.extension == b"xy" and decoded.payload == b"ab")

    print("\nAll test vectors passed.")


if __name__ == "__main__":
    main()
