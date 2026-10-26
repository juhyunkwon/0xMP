"""E2E 1:1 client-side adapter (spec 9.4 Profile 1, 9.5).

Wraps the published Signal-protocol implementation `libsignal`
(SessionBuilder/SessionCipher: X3DH-style prekey bundles + Double Ratchet)
and maps it onto 0xMP transports:

  * KeyBundlePublish carries the public bundle via KEY_BUNDLE_PUBLISH,
  * encrypt() output (1 type byte + serialized Signal message) is placed
    in E2EEnvelope.ciphertext; the ratchet header travels inside the
    library serialization, so ratchet_header stays empty,
  * the server only ever stores/forwards these opaque bytes.

IMPORTANT environment note: this legacy pure-Python port bundles protobuf
code that requires PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python. The
0xMP wire code works under either implementation (covered by tests), but
this adapter should run in a process started with that variable set.
Production deployments SHOULD replace this adapter with the maintained
libsignal client bindings; the wire contract above does not change.
"""
from __future__ import annotations

import os
import time

os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

try:
    from libsignal.ecc.curve import Curve
    from libsignal.identitykey import IdentityKey
    from libsignal.protocol.prekeywhispermessage import PreKeyWhisperMessage
    from libsignal.protocol.whispermessage import WhisperMessage
    from libsignal.sessionbuilder import SessionBuilder
    from libsignal.sessioncipher import SessionCipher
    from libsignal.state.prekeybundle import PreKeyBundle
    from libsignal.state.prekeyrecord import PreKeyRecord
    from libsignal.state.signedprekeyrecord import SignedPreKeyRecord
    from libsignal.tests.inmemoryaxolotlstore import InMemoryAxolotlStore
    E2E_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # protobuf C-implementation conflict etc.
    E2E_IMPORT_ERROR = exc

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "samples"))
from oxmp_payload import E2EEnvelope, KeyBundlePublish  # noqa: E402

PREKEY_ID = 31337
SIGNED_PREKEY_ID = 22


def available() -> bool:
    return E2E_IMPORT_ERROR is None


class E2EDevice:
    """One device's E2E state. Peer sessions are keyed by a peer label."""

    def __init__(self, label: str):
        if E2E_IMPORT_ERROR is not None:
            raise RuntimeError(f"E2E library unavailable: {E2E_IMPORT_ERROR}")
        self.label = label
        self.store = InMemoryAxolotlStore()

    # -- key bundle -------------------------------------------------------------
    def make_bundle(self, device_id: bytes) -> KeyBundlePublish:
        prekey_pair = Curve.generateKeyPair()
        signed_pair = Curve.generateKeyPair()
        identity_pair = self.store.getIdentityKeyPair()
        signature = Curve.calculateSignature(
            identity_pair.getPrivateKey(), signed_pair.getPublicKey().serialize())
        self.store.storePreKey(PREKEY_ID, PreKeyRecord(PREKEY_ID, prekey_pair))
        self.store.storeSignedPreKey(SIGNED_PREKEY_ID, SignedPreKeyRecord(
            SIGNED_PREKEY_ID, int(time.time() * 1000), signed_pair, signature))
        bundle = KeyBundlePublish(
            device_id=device_id,
            identity_key=identity_pair.getPublicKey().serialize(),
            signed_prekey=signed_pair.getPublicKey().serialize(),
            signed_prekey_signature=signature,
            signed_prekey_id=SIGNED_PREKEY_ID)
        bundle.one_time_prekeys.append(prekey_pair.getPublicKey().serialize())
        bundle.one_time_prekey_ids.append(PREKEY_ID)
        return bundle

    def process_bundle(self, peer_label: str, bundle: KeyBundlePublish) -> None:
        identity = IdentityKey(Curve.decodePoint(bytearray(bundle.identity_key), 0))
        prekey_pub = (Curve.decodePoint(bytearray(bundle.one_time_prekeys[0]), 0)
                      if bundle.one_time_prekeys else None)
        remote = PreKeyBundle(
            self.store.getLocalRegistrationId(), 1,
            bundle.one_time_prekey_ids[0] if bundle.one_time_prekey_ids else 0,
            prekey_pub, bundle.signed_prekey_id,
            Curve.decodePoint(bytearray(bundle.signed_prekey), 0),
            bundle.signed_prekey_signature, identity)
        builder = SessionBuilder(self.store, self.store, self.store,
                                 self.store, peer_label, 1)
        builder.processPreKeyBundle(remote)

    # -- messaging ------------------------------------------------------------------
    def _cipher(self, peer_label: str) -> SessionCipher:
        return SessionCipher(self.store, self.store, self.store,
                             self.store, peer_label, 1)

    def encrypt(self, peer_label: str, sender_device_id: bytes,
                plaintext: bytes) -> bytes:
        message = self._cipher(peer_label).encrypt(plaintext)
        body = bytes([message.getType()]) + message.serialize()
        envelope = E2EEnvelope(profile=1, ciphertext=body,
                               sender_device_id=sender_device_id)
        return envelope.SerializeToString()

    def decrypt(self, peer_label: str, envelope_bytes: bytes) -> bytes:
        envelope = E2EEnvelope.FromString(envelope_bytes)
        if envelope.profile != 1:
            raise ValueError(f"unsupported E2E profile {envelope.profile}")
        kind, serialized = envelope.ciphertext[0], envelope.ciphertext[1:]
        cipher = self._cipher(peer_label)
        if kind == 3:  # PreKeyWhisperMessage: first message of a session
            return cipher.decryptPkmsg(PreKeyWhisperMessage(serialized=serialized))
        return cipher.decryptMsg(WhisperMessage(serialized=serialized))
