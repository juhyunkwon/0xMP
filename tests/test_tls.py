"""TLS (wss://) transport test with a development self-signed certificate."""
import asyncio
import ssl
import subprocess
import sys
import uuid
from pathlib import Path

import websockets

from server.app import OxmpServer
from server.auth import TokenService
from server.client import OxmpClient
from server.provision import create_account
from server.store import Store
from server.testing import TEST_SECRET

ROOT = Path(__file__).resolve().parent.parent


def test_wss_roundtrip_with_verified_cert(tmp_path):
    cert_dir = tmp_path / "cert"
    subprocess.run([sys.executable, str(ROOT / "tools" / "make_dev_cert.py"),
                    str(cert_dir)], check=True, capture_output=True)

    async def scenario():
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert_dir / "cert.pem", cert_dir / "key.pem")
        store = Store(str(tmp_path / "tls.db"))
        tokens = TokenService(TEST_SECRET)
        alice = create_account(store, tokens, "alice")
        bob = create_account(store, tokens, "bob")
        conv = uuid.uuid4().bytes
        store.add_member(conv, bob.user_id)
        app = OxmpServer(store, tokens)
        ws = await websockets.serve(app.handle, "127.0.0.1", 0,
                                     max_size=2 * 1024 * 1024, ssl=server_ctx)
        port = ws.sockets[0].getsockname()[1]
        client_ctx = ssl.create_default_context(cafile=str(cert_dir / "cert.pem"))
        client = OxmpClient(f"wss://127.0.0.1:{port}", alice, ssl_context=client_ctx)
        await client.connect()  # certificate + hostname verified by default ctx
        accepted = await client.send_text(conv, "over tls")
        assert accepted.sequence == 1
        await client.close()
        ws.close()
        await ws.wait_closed()
        store.close()

    asyncio.run(scenario())
