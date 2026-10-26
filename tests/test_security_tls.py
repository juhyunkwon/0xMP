"""2. TLS & security verification.

Certificate verification (valid / untrusted / expired / wrong host),
client-authentication replay, raw frame replay, and E2E tamper detection.
"""
import asyncio
import datetime
import ipaddress
import os
import ssl
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from oxmp_frame import Frame, FrameType, decode, encode
from oxmp_payload import Auth, AuthResult, Hello, HelloResult, MessageAccepted, MessageSend
from server.app import OxmpServer
from server.auth import TokenService
from server.client import OxmpClient
from server.provision import create_account
from server.store import Store
from server.testing import TEST_SECRET

ROOT = Path(__file__).resolve().parent.parent


def make_cert(path: Path, *, days: int = 30, dns: str = "localhost",
              ip: str | None = "127.0.0.1") -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)])
    now = datetime.datetime.now(datetime.timezone.utc)
    sans = [x509.DNSName(dns)]
    if ip:
        sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(key, hashes.SHA256()))
    path.mkdir(parents=True, exist_ok=True)
    (path / "key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    (path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path / "cert.pem", path / "key.pem"


async def start_wss(tmp_path, cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    store = Store(str(tmp_path / "s.db"))
    tokens = TokenService(TEST_SECRET)
    alice = create_account(store, tokens, "alice")
    app = OxmpServer(store, tokens)
    ws = await websockets.serve(app.handle, "127.0.0.1", 0,
                                 max_size=2 * 1024 * 1024, ssl=ctx)
    return ws, store, alice, f"wss://127.0.0.1:{ws.sockets[0].getsockname()[1]}"


def test_valid_certificate_accepted(tmp_path):
    async def scenario():
        cert, key = make_cert(tmp_path / "c")
        ws, store, alice, url = await start_wss(tmp_path, cert, key)
        ctx = ssl.create_default_context(cafile=str(cert))
        client = OxmpClient(url, alice, ssl_context=ctx)
        await client.connect()  # chain + hostname verified, not disabled
        await client.close()
        ws.close(); await ws.wait_closed(); store.close()
    asyncio.run(scenario())


def test_untrusted_certificate_rejected(tmp_path):
    async def scenario():
        cert, key = make_cert(tmp_path / "c")
        ws, store, alice, url = await start_wss(tmp_path, cert, key)
        ctx = ssl.create_default_context()  # does NOT trust our self-signed CA
        client = OxmpClient(url, alice, ssl_context=ctx)
        with pytest.raises(ssl.SSLCertVerificationError):
            await client.connect()
        ws.close(); await ws.wait_closed(); store.close()
    asyncio.run(scenario())


def test_expired_certificate_rejected(tmp_path):
    async def scenario():
        cert, key = make_cert(tmp_path / "c", days=-1)  # already expired
        ws, store, alice, url = await start_wss(tmp_path, cert, key)
        ctx = ssl.create_default_context(cafile=str(cert))
        client = OxmpClient(url, alice, ssl_context=ctx)
        with pytest.raises(ssl.SSLCertVerificationError):
            await client.connect()
        ws.close(); await ws.wait_closed(); store.close()
    asyncio.run(scenario())


def test_wrong_host_certificate_rejected(tmp_path):
    async def scenario():
        cert, key = make_cert(tmp_path / "c", dns="example.com", ip=None)
        ws, store, alice, url = await start_wss(tmp_path, cert, key)
        ctx = ssl.create_default_context(cafile=str(cert))
        client = OxmpClient(url, alice, ssl_context=ctx)  # connects to 127.0.0.1
        with pytest.raises(ssl.SSLCertVerificationError):
            await client.connect()
        ws.close(); await ws.wait_closed(); store.close()
    asyncio.run(scenario())


async def _manual_auth(ws, creds) -> bytes:
    """Do HELLO+AUTH by hand; return the exact AUTH frame bytes sent."""
    await ws.send(encode(Frame(FrameType.HELLO, Hello(
        protocol_id="0xmp.v1", max_security_profile=2).SerializeToString())))
    hello = HelloResult.FromString(decode(await ws.recv()).payload)
    signature = creds.private_key.sign(hello.session_id.encode())
    auth_frame = encode(Frame(FrameType.AUTH, Auth(
        access_token=creds.access_token, device_id=creds.device_id,
        signature=signature).SerializeToString()))
    await ws.send(auth_frame)
    result = AuthResult.FromString(decode(await ws.recv()).payload)
    assert result.ok
    return auth_frame


def test_auth_frame_replay_on_new_connection_fails():
    """A captured AUTH frame is bound to its HELLO challenge (SEC-04):
    replaying it verbatim on a fresh connection must be rejected."""
    async def scenario():
        from server.testing import running_server
        async with running_server() as env:
            async with websockets.connect(env.url) as ws:
                captured = await _manual_auth(ws, env.alice)
            async with websockets.connect(env.url) as ws:
                await ws.send(encode(Frame(FrameType.HELLO, Hello(
                    protocol_id="0xmp.v1", max_security_profile=2).SerializeToString())))
                await ws.recv()  # new HELLO_RESULT = new challenge
                await ws.send(captured)  # replay: signature covers the OLD one
                result = AuthResult.FromString(decode(await ws.recv()).payload)
                assert not result.ok
    asyncio.run(scenario())


def test_message_frame_replay_is_idempotent_not_duplicated():
    async def scenario():
        from server.testing import running_server
        async with running_server() as env:
            conv = uuid.uuid4().bytes
            async with websockets.connect(env.url) as ws:
                await _manual_auth(ws, env.alice)
                send = MessageSend(message_id=uuid.uuid4().bytes,
                                   conversation_id=conv,
                                   sender_device_id=env.alice.device_id,
                                   idempotency_key=uuid.uuid4().bytes)
                send.content.kind, send.content.body = 1, b"replay me"
                raw = encode(Frame(FrameType.MESSAGE_SEND, send.SerializeToString()))
                await ws.send(raw)
                first = MessageAccepted.FromString(decode(await ws.recv()).payload)
                await ws.send(raw)  # exact replay of the captured frame
                second = MessageAccepted.FromString(decode(await ws.recv()).payload)
                assert not first.duplicate
                assert second.duplicate and second.sequence == first.sequence
            assert env.store.count_messages(conv) == 1
    asyncio.run(scenario())


def test_e2e_tampered_ciphertext_fails_decryption():
    """Message integrity: flipping one ciphertext byte breaks AEAD
    verification inside the Signal-protocol session and raises."""
    script = (
        "from server.e2e import E2EDevice\n"
        "a, b = E2EDevice('a'), E2EDevice('b')\n"
        "bundle = b.make_bundle(b'\\x02' * 16)\n"
        "a.process_bundle('peer', bundle)\n"
        "env = a.encrypt('peer', b'\\x01' * 16, b'integrity matters')\n"
        "from oxmp_payload import E2EEnvelope\n"
        "parsed = E2EEnvelope.FromString(env)\n"
        "ct = bytearray(parsed.ciphertext); ct[len(ct)//2] ^= 1\n"
        "parsed.ciphertext = bytes(ct)\n"
        "bad = parsed.SerializeToString()\n"
        "try:\n"
        "    b.decrypt('peer2', bad)\n"
        "    print('TAMPER NOT DETECTED')\n"
        "except Exception as exc:\n"
        "    print('TAMPER DETECTED:', type(exc).__name__)\n"
    )
    env = dict(os.environ)
    env["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run([sys.executable, "-c", script],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, timeout=120, cwd=ROOT)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "TAMPER DETECTED" in proc.stdout
