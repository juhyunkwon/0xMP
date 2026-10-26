"""2. Durability: a full server restart keeps messages and cursors."""
import asyncio
import uuid

import websockets

from server.app import OxmpServer
from server.auth import TokenService
from server.client import OxmpClient
from server.provision import create_account
from server.store import Store
from server.testing import TEST_SECRET


def uid():
    return uuid.uuid4().bytes


async def _start(db_path):
    store = Store(db_path)
    tokens = TokenService(TEST_SECRET)
    app = OxmpServer(store, tokens)
    ws = await websockets.serve(app.handle, "127.0.0.1", 0, max_size=2 * 1024 * 1024)
    return ws, store, tokens, f"ws://127.0.0.1:{ws.sockets[0].getsockname()[1]}"


def test_restart_preserves_messages_and_cursor(tmp_path):
    async def scenario():
        db = str(tmp_path / "restart.db")
        conv = uid()
        ws1, store1, tokens1, url1 = await _start(db)
        alice = create_account(store1, tokens1, "alice")
        bob = create_account(store1, tokens1, "bob")
        store1.add_member(conv, bob.user_id)
        client = OxmpClient(url1, alice)
        await client.connect()
        await client.send_text(conv, "survive restart")
        await client.close()
        ws1.close(); await ws1.wait_closed(); store1.close()  # hard stop

        ws2, store2, tokens2, url2 = await _start(db)  # same file, new process state
        bob_client = OxmpClient(url2, bob)  # credentials from before the restart
        await bob_client.connect()
        result = await bob_client.sync(conv)
        assert result.newly_applied == 1
        assert result.events[0].message.content.body == b"survive restart"
        await bob_client.close()
        ws2.close(); await ws2.wait_closed(); store2.close()
    asyncio.run(scenario())
