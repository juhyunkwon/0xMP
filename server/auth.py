"""Token authentication for 0xMP (spec SEC-03 / SEC-04).

Access tokens: HMAC-SHA256 signed, short-lived (default 15 min), carrying
user/device ids, a token version (for revocation) and an expiry.
Refresh tokens: opaque secrets; only their SHA-256 hash is stored.
Rotation is one-time-use; presenting an already-rotated refresh token is
treated as theft and revokes every session of that device.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid


class AuthError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ReuseDetected(AuthError):
    pass


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_refresh(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class TokenService:
    def __init__(self, secret: bytes, access_ttl_seconds: int = 15 * 60):
        if len(secret) < 32:
            raise ValueError("server secret must be at least 32 bytes")
        self._secret = secret
        self.access_ttl = access_ttl_seconds

    # -- access tokens -------------------------------------------------------
    def issue_access(self, user_id: bytes, device_id: bytes, token_version: int) -> str:
        now = int(time.time())
        payload = {
            "typ": "access",
            "sub": user_id.hex(),
            "dev": device_id.hex(),
            "ver": token_version,
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + self.access_ttl,
        }
        body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
        sig = hmac.new(self._secret, body.encode(), hashlib.sha256).digest()
        return f"{body}.{_b64e(sig)}"

    def verify_access(self, token: str) -> dict:
        try:
            body, sig_text = token.split(".", 1)
            given = _b64d(sig_text)
        except Exception as exc:
            raise AuthError("malformed") from exc
        expected = hmac.new(self._secret, body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, given):
            raise AuthError("bad_signature")
        try:
            claims = json.loads(_b64d(body))
        except Exception as exc:
            raise AuthError("malformed") from exc
        if claims.get("typ") != "access":
            raise AuthError("wrong_type")
        if int(claims.get("exp", 0)) <= int(time.time()):
            raise AuthError("expired")
        return claims

    # -- refresh tokens --------------------------------------------------------
    @staticmethod
    def new_refresh_token() -> str:
        return secrets.token_urlsafe(48)
