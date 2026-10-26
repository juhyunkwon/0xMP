"""Browser CORS support on the HTTP API (web client account issuance)."""
import urllib.request

import pytest

from server.api import serve_in_thread
from server.auth import TokenService
from server.store import Store
from tests.test_api import SECRET


@pytest.fixture()
def api(tmp_path):
    store = Store(str(tmp_path / "cors.db"))
    httpd = serve_in_thread(store, TokenService(SECRET), port=0,
                            media_dir=str(tmp_path / "m"))
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    store.close()


def test_preflight_options(api):
    req = urllib.request.Request(api + "/v1/accounts", method="OPTIONS")
    req.add_header("Origin", "http://127.0.0.1:8000")
    req.add_header("Access-Control-Request-Method", "POST")
    req.add_header("Access-Control-Request-Headers", "Content-Type")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 204
        assert resp.headers["Access-Control-Allow-Origin"] == "*"
        assert "POST" in resp.headers["Access-Control-Allow-Methods"]


def test_actual_response_carries_cors_header(api):
    req = urllib.request.Request(api + "/v1/health")
    req.add_header("Origin", "http://127.0.0.1:8000")
    with urllib.request.urlopen(req) as resp:
        assert resp.headers["Access-Control-Allow-Origin"] == "*"
