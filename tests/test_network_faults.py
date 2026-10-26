"""4. Network fault tests: corrupt/partial frames over a real socket."""
import asyncio

import pytest
import websockets

from oxmp_frame import FrameError, FrameType, decode, encode
from oxmp_payload import Error


def _error_code(raw: bytes) -> int:
    frame = decode(raw)
    assert frame.frame_type is FrameType.ERROR
    return Error.FromString(frame.payload).code


def test_garbage_bytes_get_error_frame_then_close():
    async def scenario():
        from server.testing import running_server
        async with running_server() as env:
            async with websockets.connect(env.url) as ws:
                await ws.send(b"\x00\x01\x02\x03garbage")
                code = _error_code(await asyncio.wait_for(ws.recv(), 5))
                assert code == 0x0001  # malformed frame
                with pytest.raises(websockets.ConnectionClosed):
                    await asyncio.wait_for(ws.recv(), 5)
    asyncio.run(scenario())


def test_partial_frame_gets_error_not_hang():
    async def scenario():
        from server.testing import running_server
        async with running_server() as env:
            async with websockets.connect(env.url) as ws:
                # Header promises 9 payload bytes but only 2 arrive (as one
                # complete WebSocket message holding a truncated 0xMP frame).
                await ws.send(bytes.fromhex("4d5001010000000000090a07"))
                code = _error_code(await asyncio.wait_for(ws.recv(), 5))
                assert code == 0x0001
    asyncio.run(scenario())


def test_oversize_claim_rejected_before_body():
    async def scenario():
        from server.testing import running_server
        async with running_server() as env:
            async with websockets.connect(env.url) as ws:
                forged = bytes.fromhex("4d5001100000") + (2 * 1024 * 1024).to_bytes(4, "big")
                await ws.send(forged)
                code = _error_code(await asyncio.wait_for(ws.recv(), 5))
                assert code == 0x0001
    asyncio.run(scenario())


def test_codec_rejects_every_partial_prefix():
    from oxmp_frame import Frame
    from oxmp_payload import Hello
    valid = encode(Frame(FrameType.HELLO, Hello(protocol_id="0xmp.v1").SerializeToString()))
    for cut in range(len(valid)):
        with pytest.raises(FrameError):
            decode(valid[:cut])
