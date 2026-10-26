"""6. Multi-platform: shared vectors hold, JS implementation reproduces them.

Verified here: Windows/Python (this suite) and JavaScript (Node, same code
as the browser client). macOS/Android/iOS SDKs are not executed in this
environment; clients/test_vectors.json is their conformance contract.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from oxmp_frame import Frame, FrameType, encode
from oxmp_payload import Hello

ROOT = Path(__file__).resolve().parent.parent
VECTORS = json.loads((ROOT / "clients" / "test_vectors.json").read_text(encoding="utf-8"))


def test_vector_file_matches_python_implementation():
    frames = {v["name"]: v["hex"] for v in VECTORS["frames"]}
    assert frames["ping_empty"] == encode(Frame(FrameType.PING)).hex()
    hello = encode(Frame(FrameType.HELLO,
                         Hello(protocol_id="0xmp.v1").SerializeToString()))
    assert frames["hello_protocol_only"] == hello.hex()
    assert len(VECTORS["negative_frames"]) >= 5


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_javascript_implementation_passes_same_vectors():
    proc = subprocess.run(
        ["node", "--test", str(ROOT / "clients" / "web" / "oxmp.test.mjs")],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "pass 4" in proc.stdout


def test_web_client_assets_present():
    web = ROOT / "clients" / "web"
    assert (web / "oxmp.js").exists() and (web / "index.html").exists()
    assert "wss://" in (web / "index.html").read_text(encoding="utf-8")
