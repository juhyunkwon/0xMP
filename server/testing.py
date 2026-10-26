"""Test harness: runs a real server on an ephemeral port with a temp DB."""
from __future__ import annotations

import contextlib
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .app import OxmpServer
from .auth import TokenService
from .provision import Credentials, create_account
from .store import Store

import websockets

TEST_SECRET = b"test-secret-test-secret-test-secret!!"


@dataclass
class TestEnv:
    url: str
    store: Store
    tokens: TokenService
    alice: Credentials
    bob: Credentials
    db_path: str


@contextlib.asynccontextmanager
async def running_server(db_path: str | None = None, push_provider=None):
    tmp = None
    if db_path is None:
        tmp = tempfile.TemporaryDirectory()
        db_path = str(Path(tmp.name) / "oxmp-test.db")
    store = Store(db_path)
    tokens = TokenService(TEST_SECRET)
    alice = create_account(store, tokens, "alice")
    bob = create_account(store, tokens, "bob")
    app = OxmpServer(store, tokens, push_provider=push_provider)
    ws_server = await websockets.serve(app.handle, "127.0.0.1", 0,
                                        max_size=2 * 1024 * 1024)
    port = ws_server.sockets[0].getsockname()[1]
    env = TestEnv(f"ws://127.0.0.1:{port}", store, tokens, alice, bob, db_path)
    try:
        yield env
    finally:
        ws_server.close()
        await ws_server.wait_closed()
        store.close()
        if tmp:
            tmp.cleanup()
