"""Deployable entry point: WebSocket server + provisioning API together.

Environment:
  OXMP_DB          SQLite path                (default oxmp.db)
  OXMP_PORT        WebSocket port             (default 8765)
  OXMP_API_PORT    HTTP API port              (default 8770)
  OXMP_HOST        bind host                  (default 127.0.0.1)
  OXMP_SECRET      token signing secret >=32B (REQUIRED outside dev)
  OXMP_TLS_CERT / OXMP_TLS_KEY  PEM paths; when both are set the WebSocket
                   server speaks wss:// (TLS). Production MUST set them or
                   terminate TLS 1.3 in front (spec SEC-01).

Run:  python -m server.main
"""
from __future__ import annotations

import asyncio
import os
import ssl

import websockets

from .api import serve_in_thread
from .app import MAX_WS_BYTES, OxmpServer
from .auth import TokenService
from .store import Store


async def amain() -> None:
    secret = os.environ.get("OXMP_SECRET")
    if secret is None:
        print("WARNING: OXMP_SECRET unset; using a development secret. "
              "Set OXMP_SECRET (>=32 bytes) in production.")
        secret = "dev-only-secret-change-me-32bytes!!"
    store = Store(os.environ.get("OXMP_DB", "oxmp.db"))
    tokens = TokenService(secret.encode())

    cert, key = os.environ.get("OXMP_TLS_CERT"), os.environ.get("OXMP_TLS_KEY")
    ssl_context = None
    scheme = "ws"
    if cert and key:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # floor; 1.3 preferred
        ssl_context.load_cert_chain(cert, key)
        scheme = "wss"

    app = OxmpServer(store, tokens)
    host = os.environ.get("OXMP_HOST", "127.0.0.1")
    port = int(os.environ.get("OXMP_PORT", "8765"))
    api_port = int(os.environ.get("OXMP_API_PORT", "8770"))
    serve_in_thread(store, tokens, host, api_port)
    async with websockets.serve(app.handle, host, port, max_size=MAX_WS_BYTES,
                                ssl=ssl_context):
        print(f"0xMP server: {scheme}://{host}:{port}  "
              f"api=http://{host}:{api_port}  db={os.environ.get('OXMP_DB', 'oxmp.db')}")
        if ssl_context is None:
            print("WARNING: plain ws:// - local development only; "
                  "production requires TLS 1.3 (SEC-01).")
        await asyncio.Future()  # serve forever


if __name__ == "__main__":
    asyncio.run(amain())
