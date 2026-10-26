"""E2E Profile 1: key-bundle frames, ciphertext-only storage, ratchet reply.

Runs the flow in a subprocess because the legacy Signal-protocol port
requires the pure-Python protobuf implementation (server/e2e.py).
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_e2e_flow_over_real_server():
    env = dict(os.environ)
    env["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "e2e_flow.py")],
        capture_output=True, text=True, env=env, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "server DB holds ciphertext only: OK" in proc.stdout
    assert "bob decrypted: b'top secret: launch at dawn'" in proc.stdout
    assert "alice decrypted reply: b'roger, dawn it is'" in proc.stdout
    assert "E2E FLOW OK" in proc.stdout


def test_key_bundle_frames_require_matching_device():
    """Publishing a bundle for someone else's device must be rejected."""
    import asyncio
    import uuid

    from oxmp_payload import KeyBundlePublish
    from server.client import OxmpClient
    from server.testing import running_server

    async def scenario():
        async with running_server() as env:
            alice = OxmpClient(env.url, env.alice)
            await alice.connect()
            # Directly send a forged publish naming Bob's device.
            from oxmp_frame import Frame, FrameType, encode
            forged = KeyBundlePublish(device_id=env.bob.device_id,
                                      identity_key=b"x" * 33)
            await alice.ws.send(encode(Frame(
                FrameType.KEY_BUNDLE_PUBLISH, forged.SerializeToString())))
            await asyncio.sleep(0.3)
            assert env.store.key_bundles(device_id=env.bob.device_id) == []
            await alice.close()

    asyncio.run(scenario())
