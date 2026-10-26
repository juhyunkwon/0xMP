"""1. Security tests: forged / expired / reused credentials (unit level)."""
import time

import pytest

from server.auth import AuthError, TokenService, hash_refresh
from server.provision import create_account, refresh_session
from server.store import Store

SECRET = b"unit-test-secret-unit-test-secret-!!"


@pytest.fixture()
def env(tmp_path):
    store = Store(str(tmp_path / "auth.db"))
    tokens = TokenService(SECRET)
    creds = create_account(store, tokens, "alice")
    yield store, tokens, creds
    store.close()


def test_valid_token_verifies(env):
    _, tokens, creds = env
    claims = tokens.verify_access(creds.access_token)
    assert claims["sub"] == creds.user_id.hex()
    assert claims["dev"] == creds.device_id.hex()


def test_forged_signature_rejected(env):
    _, tokens, creds = env
    body, sig = creds.access_token.split(".")
    forged = f"{body}.{'A' if sig[0] != 'A' else 'B'}{sig[1:]}"
    with pytest.raises(AuthError) as exc:
        tokens.verify_access(forged)
    assert exc.value.reason == "bad_signature"


def test_tampered_payload_rejected(env):
    _, tokens, creds = env
    body, sig = creds.access_token.split(".")
    tampered = f"{'A' if body[0] != 'A' else 'B'}{body[1:]}.{sig}"
    with pytest.raises(AuthError):
        tokens.verify_access(tampered)


def test_wrong_secret_rejected(env):
    _, _, creds = env
    other = TokenService(b"another-secret-another-secret-32byte")
    with pytest.raises(AuthError):
        other.verify_access(creds.access_token)


def test_expired_token_rejected(env):
    _, tokens, creds = env
    short = TokenService(SECRET, access_ttl_seconds=-1)  # already expired
    expired = short.issue_access(creds.user_id, creds.device_id, 1)
    with pytest.raises(AuthError) as exc:
        tokens.verify_access(expired)
    assert exc.value.reason == "expired"


def test_malformed_tokens_rejected(env):
    _, tokens, _ = env
    for bad in ["", "abc", "a.b.c", ".", "!!!.???"]:
        with pytest.raises(AuthError):
            tokens.verify_access(bad)


def test_refresh_rotation_and_reuse_revokes_device(env):
    store, tokens, creds = env
    access2, refresh2, user_id, device_id = refresh_session(
        store, tokens, creds.refresh_token)
    assert tokens.verify_access(access2)["ver"] == 1
    # Reusing the OLD (already rotated) token = theft signal.
    with pytest.raises(ValueError, match="refresh_reuse_detected"):
        refresh_session(store, tokens, creds.refresh_token)
    device = store.get_device(device_id)
    assert device["token_version"] == 2  # bumped: old access tokens now invalid
    # Even the legitimately rotated refresh is revoked after reuse detection.
    with pytest.raises(ValueError):
        refresh_session(store, tokens, refresh2)
    assert hash_refresh(creds.refresh_token) != creds.refresh_token  # hashed at rest
