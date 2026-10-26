"""Account/device provisioning (development & tests).

Production onboarding (sign-up, device approval, recovery) is out of scope
for the protocol; this helper models its outputs: a user, a device with an
Ed25519 key pair (spec SEC-04), a short-lived access token and a rotating
refresh token (SEC-03). The private key never reaches the server store.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .auth import TokenService, hash_refresh
from .store import Store

REFRESH_TTL_SECONDS = 30 * 24 * 3600


@dataclass
class Credentials:
    name: str
    user_id: bytes
    device_id: bytes
    access_token: str
    refresh_token: str
    private_key: Ed25519PrivateKey

    def private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())


def create_account(store: Store, tokens: TokenService, name: str) -> Credentials:
    user_id = store.create_user(name)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    device_id = store.register_device(user_id, public_key)
    access = tokens.issue_access(user_id, device_id, token_version=1)
    refresh = tokens.new_refresh_token()
    store.save_refresh(hash_refresh(refresh), device_id,
                       int(time.time()) + REFRESH_TTL_SECONDS)
    return Credentials(name, user_id, device_id, access, refresh, private_key)


def refresh_session(store: Store, tokens: TokenService,
                    refresh_token: str) -> tuple[str, str, bytes, bytes]:
    """Rotate a refresh token. Returns (access, new_refresh, user_id, device_id).

    Raises ValueError('refresh_reuse_detected') when an already-rotated
    token is presented again; the store revokes the device in that case.
    """
    device_id = store.rotate_refresh(hash_refresh(refresh_token))
    device = store.get_device(device_id)
    if device is None or device["revoked"]:
        raise ValueError("device_revoked")
    access = tokens.issue_access(device["user_id"], device_id,
                                 device["token_version"])
    new_refresh = tokens.new_refresh_token()
    store.save_refresh(hash_refresh(new_refresh), device_id,
                       int(time.time()) + REFRESH_TTL_SECONDS)
    return access, new_refresh, device["user_id"], device_id
