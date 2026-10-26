"""E2E Profile 1 end-to-end flow over the real server.

Run with the pure-Python protobuf implementation (see server/e2e.py):
  PowerShell:  $env:PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION='python'; python tools/e2e_flow.py
  POSIX:       PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python tools/e2e_flow.py

Verifies: key bundles travel via KEY_BUNDLE_* frames, the server stores
only opaque ciphertext (plaintext never appears in the DB), and both
directions decrypt, including the Double Ratchet reply path.
"""
from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.client import OxmpClient  # noqa: E402
from server.e2e import E2EDevice  # noqa: E402
from server.testing import running_server  # noqa: E402

SECRET_TEXT = b"top secret: launch at dawn"


async def main_async() -> None:
    async with running_server() as env:
        conv = uuid.uuid4().bytes
        env.store.add_member(conv, env.bob.user_id)
        alice = OxmpClient(env.url, env.alice)
        bob = OxmpClient(env.url, env.bob)
        await alice.connect()
        await bob.connect()

        alice_e2e, bob_e2e = E2EDevice("alice"), E2EDevice("bob")
        await alice.publish_key_bundle(alice_e2e.make_bundle(env.alice.device_id))
        await bob.publish_key_bundle(bob_e2e.make_bundle(env.bob.device_id))
        await asyncio.sleep(0.3)  # publish is fire-and-forget

        bundles = await alice.fetch_key_bundles(user_id=env.bob.user_id)
        bob_bundle = next(b for b in bundles if b.device_id == env.bob.device_id)
        alice_e2e.process_bundle(env.bob.device_id.hex(), bob_bundle)

        envelope = alice_e2e.encrypt(env.bob.device_id.hex(),
                                     env.alice.device_id, SECRET_TEXT)
        accepted = await alice.send_e2e(conv, envelope)
        print(f"accepted seq={accepted.sequence} envelope_bytes={len(envelope)}")

        incoming = await bob.wait_incoming()
        assert incoming.content.body != SECRET_TEXT
        stored = env.store.messages_after(conv, 0, 10)
        assert SECRET_TEXT not in stored[0].body
        assert SECRET_TEXT.decode() not in str(env.store.__dict__)
        print("server DB holds ciphertext only: OK")

        plain = bob_e2e.decrypt(env.alice.device_id.hex(), incoming.content.body)
        assert plain == SECRET_TEXT, plain
        print(f"bob decrypted: {plain!r}")

        reply_env = bob_e2e.encrypt(env.alice.device_id.hex(),
                                    env.bob.device_id, b"roger, dawn it is")
        await bob.send_e2e(conv, reply_env)
        reply_in = await alice.wait_incoming()
        reply = alice_e2e.decrypt(env.bob.device_id.hex(), reply_in.content.body)
        assert reply == b"roger, dawn it is", reply
        print(f"alice decrypted reply: {reply!r}")
        await alice.close()
        await bob.close()
    print("E2E FLOW OK")


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
