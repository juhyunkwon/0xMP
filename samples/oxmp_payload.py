"""Dynamic Protobuf messages for the 0xMP sample.

Builds the subset of ``oxmp.proto`` used by ``sample_client.py`` directly
from descriptors, so the sample runs with only the ``protobuf`` package
(no ``protoc`` step). Real projects should compile ``oxmp.proto`` instead.
"""

from __future__ import annotations

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

_FDP = descriptor_pb2.FileDescriptorProto()
_FDP.name = "oxmp.proto"
_FDP.package = "oxmp.v1"
_FDP.syntax = "proto3"


def _field(msg, name, number, label, ftype, type_name=None):
    f = msg.field.add()
    f.name, f.number, f.label, f.type = name, number, label, ftype
    if type_name:
        f.type_name = type_name


def _msg(name):
    m = _FDP.message_type.add()
    m.name = name
    return m


_LBL_OPT, _LBL_REP = 1, 3
_T_U32, _T_U64, _T_BOOL, _T_STR, _T_BYTES, _T_MSG = 13, 4, 8, 9, 12, 11

_hello = _msg("Hello")
_field(_hello, "protocol_id", 1, _LBL_OPT, _T_STR)
_field(_hello, "min_security_profile", 2, _LBL_OPT, _T_U32)
_field(_hello, "max_security_profile", 3, _LBL_OPT, _T_U32)
_field(_hello, "features", 4, _LBL_REP, _T_STR)
_field(_hello, "client_name", 5, _LBL_OPT, _T_STR)
_field(_hello, "client_version", 6, _LBL_OPT, _T_STR)

_hello_r = _msg("HelloResult")
_field(_hello_r, "protocol_id", 1, _LBL_OPT, _T_STR)
_field(_hello_r, "selected_security_profile", 2, _LBL_OPT, _T_U32)
_field(_hello_r, "features", 3, _LBL_REP, _T_STR)
_field(_hello_r, "max_payload_bytes", 4, _LBL_OPT, _T_U32)
_field(_hello_r, "session_id", 5, _LBL_OPT, _T_STR)

_auth = _msg("Auth")
_field(_auth, "access_token", 1, _LBL_OPT, _T_STR)
_field(_auth, "device_id", 2, _LBL_OPT, _T_BYTES)
_field(_auth, "device_public_key", 3, _LBL_OPT, _T_BYTES)
_field(_auth, "signature", 4, _LBL_OPT, _T_BYTES)

_auth_r = _msg("AuthResult")
_field(_auth_r, "ok", 1, _LBL_OPT, _T_BOOL)
_field(_auth_r, "user_id", 2, _LBL_OPT, _T_BYTES)
_field(_auth_r, "device_id", 3, _LBL_OPT, _T_BYTES)
_field(_auth_r, "access_token_expires_at_ms", 4, _LBL_OPT, _T_U64)
_field(_auth_r, "failure_reason", 5, _LBL_OPT, _T_STR)

_content = _msg("MessageContent")
_field(_content, "kind", 1, _LBL_OPT, 5)  # enum Kind, sent as varint (int32)
_field(_content, "body", 2, _LBL_OPT, _T_BYTES)

_send = _msg("MessageSend")
_field(_send, "message_id", 1, _LBL_OPT, _T_BYTES)
_field(_send, "conversation_id", 2, _LBL_OPT, _T_BYTES)
_field(_send, "sender_device_id", 3, _LBL_OPT, _T_BYTES)
_field(_send, "client_timestamp_ms", 4, _LBL_OPT, _T_U64)
_field(_send, "idempotency_key", 5, _LBL_OPT, _T_BYTES)
_field(_send, "content", 6, _LBL_OPT, _T_MSG, ".oxmp.v1.MessageContent")

_acc = _msg("MessageAccepted")
_field(_acc, "message_id", 1, _LBL_OPT, _T_BYTES)
_field(_acc, "sequence", 2, _LBL_OPT, _T_U64)
_field(_acc, "server_timestamp_ms", 3, _LBL_OPT, _T_U64)
_field(_acc, "duplicate", 4, _LBL_OPT, _T_BOOL)

_incoming = _msg("MessageIncoming")
_field(_incoming, "message_id", 1, _LBL_OPT, _T_BYTES)
_field(_incoming, "conversation_id", 2, _LBL_OPT, _T_BYTES)
_field(_incoming, "sender_id", 3, _LBL_OPT, _T_BYTES)
_field(_incoming, "sender_device_id", 4, _LBL_OPT, _T_BYTES)
_field(_incoming, "sequence", 5, _LBL_OPT, _T_U64)
_field(_incoming, "server_timestamp_ms", 6, _LBL_OPT, _T_U64)
_field(_incoming, "content", 7, _LBL_OPT, _T_MSG, ".oxmp.v1.MessageContent")

_ack = _msg("DeliveryAck")
_field(_ack, "message_id", 1, _LBL_OPT, _T_BYTES)
_field(_ack, "conversation_id", 2, _LBL_OPT, _T_BYTES)
_field(_ack, "sequence", 3, _LBL_OPT, _T_U64)

_delete = _msg("DeleteEvent")
_field(_delete, "message_id", 1, _LBL_OPT, _T_BYTES)  # empty = clear whole room
_field(_delete, "conversation_id", 2, _LBL_OPT, _T_BYTES)
_field(_delete, "for_everyone", 3, _LBL_OPT, _T_BOOL)

_notice = _msg("DeliveryNotice")
_field(_notice, "message_id", 1, _LBL_OPT, _T_BYTES)
_field(_notice, "conversation_id", 2, _LBL_OPT, _T_BYTES)
_field(_notice, "delivered_device_id", 3, _LBL_OPT, _T_BYTES)
_field(_notice, "sequence", 4, _LBL_OPT, _T_U64)

_sync_req = _msg("SyncRequest")
_field(_sync_req, "conversation_id", 1, _LBL_OPT, _T_BYTES)
_field(_sync_req, "after_sequence", 2, _LBL_OPT, _T_U64)
_field(_sync_req, "limit", 3, _LBL_OPT, _T_U32)

_event = _msg("SyncEvent")
_field(_event, "type", 1, _LBL_OPT, 5)  # enum Type, sent as varint (int32)
_field(_event, "sequence", 2, _LBL_OPT, _T_U64)
_field(_event, "message", 3, _LBL_OPT, _T_MSG, ".oxmp.v1.MessageIncoming")
_field(_event, "event_id", 4, _LBL_OPT, _T_BYTES)

_batch = _msg("SyncBatch")
_field(_batch, "conversation_id", 1, _LBL_OPT, _T_BYTES)
_field(_batch, "events", 2, _LBL_REP, _T_MSG, ".oxmp.v1.SyncEvent")
_field(_batch, "has_more", 3, _LBL_OPT, _T_BOOL)
_field(_batch, "next_after_sequence", 4, _LBL_OPT, _T_U64)

_sync_ack = _msg("SyncAck")
_field(_sync_ack, "conversation_id", 1, _LBL_OPT, _T_BYTES)
_field(_sync_ack, "applied_sequence", 2, _LBL_OPT, _T_U64)

_kb = _msg("KeyBundlePublish")
_field(_kb, "device_id", 1, _LBL_OPT, _T_BYTES)
_field(_kb, "identity_key", 2, _LBL_OPT, _T_BYTES)
_field(_kb, "signed_prekey", 3, _LBL_OPT, _T_BYTES)
_field(_kb, "signed_prekey_signature", 4, _LBL_OPT, _T_BYTES)
_field(_kb, "one_time_prekeys", 5, _LBL_REP, _T_BYTES)
_field(_kb, "signed_prekey_id", 6, _LBL_OPT, _T_U32)
_field(_kb, "one_time_prekey_ids", 7, _LBL_REP, _T_U32)

_kb_req = _msg("KeyBundleRequest")
_field(_kb_req, "user_id", 1, _LBL_OPT, _T_BYTES)
_field(_kb_req, "device_id", 2, _LBL_OPT, _T_BYTES)

_kb_resp = _msg("KeyBundleResponse")
_field(_kb_resp, "bundles", 1, _LBL_REP, _T_MSG, ".oxmp.v1.KeyBundlePublish")

_env = _msg("E2EEnvelope")
_field(_env, "profile", 1, _LBL_OPT, _T_U32)
_field(_env, "ratchet_header", 2, _LBL_OPT, _T_BYTES)
_field(_env, "ciphertext", 3, _LBL_OPT, _T_BYTES)
_field(_env, "mls_message", 4, _LBL_OPT, _T_BYTES)
_field(_env, "epoch", 5, _LBL_OPT, _T_U64)
_field(_env, "sender_device_id", 6, _LBL_OPT, _T_BYTES)

_mi = _msg("MediaInit")
_field(_mi, "content_type", 1, _LBL_OPT, _T_STR)
_field(_mi, "total_bytes", 2, _LBL_OPT, _T_U64)
_field(_mi, "sha256", 3, _LBL_OPT, _T_BYTES)

_mg = _msg("MediaGrant")
_field(_mg, "media_id", 1, _LBL_OPT, _T_BYTES)
_field(_mg, "https_url", 2, _LBL_OPT, _T_STR)
_field(_mg, "expires_at_ms", 3, _LBL_OPT, _T_U64)
_field(_mg, "chunk_bytes", 4, _LBL_OPT, _T_U32)

_mc = _msg("MediaComplete")
_field(_mc, "media_id", 1, _LBL_OPT, _T_BYTES)

_mdr = _msg("MediaDownloadRequest")
_field(_mdr, "media_id", 1, _LBL_OPT, _T_BYTES)
_field(_mdr, "conversation_id", 2, _LBL_OPT, _T_BYTES)

_err = _msg("Error")
_field(_err, "code", 1, _LBL_OPT, _T_U32)
_field(_err, "message", 2, _LBL_OPT, _T_STR)
_field(_err, "retryable", 3, _LBL_OPT, _T_BOOL)
_field(_err, "retry_after_ms", 4, _LBL_OPT, _T_U64)
_field(_err, "reference_id", 5, _LBL_OPT, _T_BYTES)

_pool = descriptor_pool.DescriptorPool()
_pool.Add(_FDP)


def message_class(name: str):
    return message_factory.GetMessageClass(_pool.FindMessageTypeByName(f"oxmp.v1.{name}"))


Hello = message_class("Hello")
HelloResult = message_class("HelloResult")
Auth = message_class("Auth")
AuthResult = message_class("AuthResult")
MessageContent = message_class("MessageContent")
MessageSend = message_class("MessageSend")
MessageAccepted = message_class("MessageAccepted")
MessageIncoming = message_class("MessageIncoming")
DeliveryAck = message_class("DeliveryAck")
DeliveryNotice = message_class("DeliveryNotice")
DeleteEvent = message_class("DeleteEvent")
SyncRequest = message_class("SyncRequest")
SyncEvent = message_class("SyncEvent")
SyncBatch = message_class("SyncBatch")
SyncAck = message_class("SyncAck")
KeyBundlePublish = message_class("KeyBundlePublish")
KeyBundleRequest = message_class("KeyBundleRequest")
KeyBundleResponse = message_class("KeyBundleResponse")
E2EEnvelope = message_class("E2EEnvelope")
MediaInit = message_class("MediaInit")
MediaGrant = message_class("MediaGrant")
MediaComplete = message_class("MediaComplete")
MediaDownloadRequest = message_class("MediaDownloadRequest")
Error = message_class("Error")

# MessageContent.Kind values (mirror oxmp.proto).
KIND_TEXT = 1
KIND_E2E_ENVELOPE = 4
