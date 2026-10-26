"""1. Security / error-injection / boundary tests for the frame codec.

Extends samples/test_vectors.py (kept as the normative regression set) with
truncation, oversize and malformed-extension cases. Also pins down that
`python oxmp_frame.py` is a library run: silent, exit code 0, no tests run.
"""
import subprocess
import sys
from pathlib import Path

import pytest

from oxmp_frame import (MAX_PAYLOAD_BYTES, Flag, Frame, FrameError, FrameType,
                        decode, encode)
from oxmp_payload import Hello

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_regression_vectors_still_pass():
    assert encode(Frame(FrameType.PING)).hex() == "4d500140000000000000"
    hello = encode(Frame(FrameType.HELLO, Hello(protocol_id="0xmp.v1").SerializeToString()))
    assert hello.hex() == "4d5001010000000000090a0730786d702e7631"


def test_frame_module_alone_is_silent_library():
    proc = subprocess.run([sys.executable, "oxmp_frame.py"], cwd=SAMPLES,
                          capture_output=True, text=True)
    assert proc.returncode == 0
    assert proc.stdout == "" and proc.stderr == ""  # library only: no __main__


@pytest.mark.parametrize("hex_data", [
    "00000140000000000000",  # bad magic
    "4d500240000000000000",  # unknown version
    "4d500140800000000000",  # reserved flag bit 15
    "4d500140001000000000",  # reserved flag bit 4 (0x0010 in big-endian flags)
    "4d500166000000000000",  # unknown frame type 0x66
    "4d50017e000000000000",  # reserved frame type 0x7e
])
def test_forged_headers_rejected(hex_data):
    with pytest.raises(FrameError):
        decode(bytes.fromhex(hex_data))


def test_every_truncation_rejected():
    valid = encode(Frame(FrameType.HELLO, Hello(protocol_id="0xmp.v1").SerializeToString()))
    for cut in range(len(valid)):
        with pytest.raises(FrameError):
            decode(valid[:cut])


def test_trailing_garbage_rejected():
    valid = encode(Frame(FrameType.PING))
    with pytest.raises(FrameError):
        decode(valid + b"\x00")


def test_payload_length_at_and_over_cap():
    at_cap = Frame(FrameType.MESSAGE_SEND, b"x" * 1024)  # well under: sanity
    assert decode(encode(at_cap)).payload == b"x" * 1024
    with pytest.raises(FrameError):
        encode(Frame(FrameType.MESSAGE_SEND, b"x" * (MAX_PAYLOAD_BYTES + 1)))
    # Header that merely CLAIMS over-cap length is rejected before any body.
    forged = bytes.fromhex("4d5001100000") + (MAX_PAYLOAD_BYTES + 1).to_bytes(4, "big")
    with pytest.raises(FrameError):
        decode(forged)


def test_malformed_extension_rejected():
    raw = bytearray(encode(Frame(FrameType.PING, b"ab", extension=b"xy")))
    raw[10] = 0xFF  # corrupt extension length to claim more than present
    raw[11] = 0xFF
    with pytest.raises(FrameError):
        decode(bytes(raw))


def test_encode_rejects_reserved_flags():
    with pytest.raises(FrameError):
        encode(Frame(FrameType.PING, flags=Flag(0x0010)))
