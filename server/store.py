"""SQLite persistence for 0xMP (spec section 8).

Guarantees implemented here:
  * a message is committed BEFORE the server sends MESSAGE_ACCEPTED,
  * (sender_id, sender_device_id, idempotency_key) is UNIQUE, so retries
    and concurrent duplicates can never store a second copy,
  * sequence is assigned inside a BEGIN IMMEDIATE transaction as
    max(sequence)+1 per conversation: gapless and order-preserving,
  * sync cursors only move forward,
  * refresh tokens are stored hashed, one-time-use, with reuse detection.
"""
from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass


def _uid() -> bytes:
    return uuid.uuid4().bytes


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class StoredMessage:
    message_id: bytes
    conversation_id: bytes
    sender_id: bytes
    sender_device_id: bytes
    sequence: int
    server_timestamp_ms: int
    kind: int
    body: bytes
    deleted: bool = False


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (user_id BLOB PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
  device_id BLOB PRIMARY KEY, user_id BLOB NOT NULL, public_key BLOB NOT NULL,
  token_version INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY, device_id BLOB NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS conversations (
  conversation_id BLOB PRIMARY KEY, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS members (
  conversation_id BLOB NOT NULL, user_id BLOB NOT NULL,
  PRIMARY KEY (conversation_id, user_id));
CREATE TABLE IF NOT EXISTS messages (
  conversation_id BLOB NOT NULL, sequence INTEGER NOT NULL,
  message_id BLOB NOT NULL UNIQUE,
  sender_id BLOB NOT NULL, sender_device_id BLOB NOT NULL,
  idempotency_key BLOB NOT NULL, kind INTEGER NOT NULL, body BLOB NOT NULL,
  server_timestamp_ms INTEGER NOT NULL,
  PRIMARY KEY (conversation_id, sequence),
  UNIQUE (sender_id, sender_device_id, idempotency_key));
CREATE TABLE IF NOT EXISTS deliveries (
  message_id BLOB NOT NULL, device_id BLOB NOT NULL, status TEXT NOT NULL,
  updated_at INTEGER NOT NULL, PRIMARY KEY (message_id, device_id));
CREATE TABLE IF NOT EXISTS sync_cursors (
  device_id BLOB NOT NULL, conversation_id BLOB NOT NULL,
  applied_sequence INTEGER NOT NULL, PRIMARY KEY (device_id, conversation_id));
CREATE TABLE IF NOT EXISTS key_bundles (
  device_id BLOB PRIMARY KEY, bundle BLOB NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS media (
  media_id BLOB PRIMARY KEY, owner_id BLOB NOT NULL, conversation_id BLOB,
  content_type TEXT NOT NULL, total_bytes INTEGER NOT NULL, sha256 BLOB NOT NULL,
  status TEXT NOT NULL DEFAULT 'INIT', path TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS push_tokens (
  device_id BLOB PRIMARY KEY, token TEXT NOT NULL, platform TEXT NOT NULL,
  updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS friendships (
  user_id BLOB NOT NULL, friend_id BLOB NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, friend_id));
"""


class ConflictError(Exception):
    pass


class Store:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        with self._lock:
            self._db.executescript(_SCHEMA)
            # Lobby/room metadata added in v0.6: migrate older databases.
            cols = {r[1] for r in self._db.execute(
                "PRAGMA table_info(conversations)").fetchall()}
            for name, ddl in (("title", "ALTER TABLE conversations ADD COLUMN title TEXT NOT NULL DEFAULT ''"),
                              ("kind", "ALTER TABLE conversations ADD COLUMN kind TEXT NOT NULL DEFAULT 'group'"),
                              ("created_by", "ALTER TABLE conversations ADD COLUMN created_by BLOB")):
                if name not in cols:
                    self._db.execute(ddl)
            # Message deletion (tombstones) added later: same migration style.
            mcols = {r[1] for r in self._db.execute(
                "PRAGMA table_info(messages)").fetchall()}
            if "deleted" not in mcols:
                self._db.execute(
                    "ALTER TABLE messages ADD COLUMN deleted "
                    "INTEGER NOT NULL DEFAULT 0")
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- accounts ------------------------------------------------------------
    def create_user(self, name: str) -> bytes:
        user_id = _uid()
        with self._lock:
            self._db.execute("INSERT INTO users VALUES (?,?)", (user_id, name))
            self._db.commit()
        return user_id

    def register_device(self, user_id: bytes, public_key: bytes) -> bytes:
        device_id = _uid()
        with self._lock:
            self._db.execute(
                "INSERT INTO devices (device_id,user_id,public_key) VALUES (?,?,?)",
                (device_id, user_id, public_key))
            self._db.commit()
        return device_id

    def get_device(self, device_id: bytes) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT user_id, public_key, token_version, revoked "
                "FROM devices WHERE device_id=?", (device_id,)).fetchone()
        if row is None:
            return None
        return {"user_id": row[0], "public_key": row[1],
                "token_version": row[2], "revoked": bool(row[3])}

    def revoke_device(self, device_id: bytes) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE devices SET revoked=1, token_version=token_version+1 "
                "WHERE device_id=?", (device_id,))
            self._db.execute(
                "UPDATE refresh_tokens SET revoked=1 WHERE device_id=?", (device_id,))
            self._db.commit()

    def delete_device_sessions(self, device_id: bytes) -> None:
        """Log out ONE device: invalidate its access tokens (version bump)
        and every refresh token, WITHOUT revoking the device itself, so the
        same device key can sign in again later. Other devices of the same
        user keep their sessions."""
        with self._lock:
            self._db.execute(
                "UPDATE devices SET token_version=token_version+1 "
                "WHERE device_id=?", (device_id,))
            self._db.execute(
                "UPDATE refresh_tokens SET revoked=1 WHERE device_id=?",
                (device_id,))
            self._db.commit()

    def delete_all_sessions(self, user_id: bytes) -> int:
        """Log out EVERY device of a user. Returns the device count."""
        with self._lock:
            rows = self._db.execute(
                "SELECT device_id FROM devices WHERE user_id=? AND revoked=0",
                (user_id,)).fetchall()
            for (device_id,) in rows:
                self._db.execute(
                    "UPDATE devices SET token_version=token_version+1 "
                    "WHERE device_id=?", (device_id,))
                self._db.execute(
                    "UPDATE refresh_tokens SET revoked=1 WHERE device_id=?",
                    (device_id,))
            self._db.commit()
        return len(rows)

    # -- refresh tokens ---------------------------------------------------------
    def save_refresh(self, token_hash: str, device_id: bytes, expires_at: int) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO refresh_tokens VALUES (?,?,?,NULL,0)",
                (token_hash, device_id, expires_at))
            self._db.commit()

    def rotate_refresh(self, token_hash: str) -> bytes:
        """Mark used and return device_id. Raises on unknown/expired/reuse."""
        with self._lock:
            row = self._db.execute(
                "SELECT device_id, expires_at, used_at, revoked FROM refresh_tokens "
                "WHERE token_hash=?", (token_hash,)).fetchone()
            if row is None or row[3]:
                raise ValueError("invalid_refresh")
            device_id, expires_at, used_at, _ = row
            if expires_at <= int(time.time()):
                raise ValueError("expired_refresh")
            if used_at is not None:
                # Theft signal: kill every session of this device (SEC-03).
                self._db.execute(
                    "UPDATE devices SET token_version=token_version+1 WHERE device_id=?",
                    (device_id,))
                self._db.execute(
                    "UPDATE refresh_tokens SET revoked=1 WHERE device_id=?", (device_id,))
                self._db.commit()
                raise ValueError("refresh_reuse_detected")
            self._db.execute(
                "UPDATE refresh_tokens SET used_at=? WHERE token_hash=?",
                (int(time.time()), token_hash))
            self._db.commit()
            return device_id

    # -- E2E key bundles (public material only, spec 9.5) -------------------------
    def save_key_bundle(self, device_id: bytes, bundle: bytes) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO key_bundles VALUES (?,?,?) ON CONFLICT(device_id) "
                "DO UPDATE SET bundle=excluded.bundle, updated_at=excluded.updated_at",
                (device_id, bundle, now_ms()))
            self._db.commit()

    def key_bundles(self, user_id: bytes | None = None,
                    device_id: bytes | None = None) -> list[bytes]:
        with self._lock:
            if device_id:
                rows = self._db.execute(
                    "SELECT bundle FROM key_bundles WHERE device_id=?",
                    (device_id,)).fetchall()
            elif user_id:
                rows = self._db.execute(
                    "SELECT kb.bundle FROM key_bundles kb JOIN devices d "
                    "ON d.device_id=kb.device_id WHERE d.user_id=? AND d.revoked=0",
                    (user_id,)).fetchall()
            else:
                rows = self._db.execute("SELECT bundle FROM key_bundles").fetchall()
        return [r[0] for r in rows]

    # -- media / push ---------------------------------------------------------------
    def create_media(self, owner_id: bytes, conversation_id: bytes | None,
                     content_type: str, total_bytes: int, sha256: bytes) -> bytes:
        media_id = _uid()
        with self._lock:
            self._db.execute(
                "INSERT INTO media (media_id,owner_id,conversation_id,content_type,"
                "total_bytes,sha256,created_at) VALUES (?,?,?,?,?,?,?)",
                (media_id, owner_id, conversation_id, content_type,
                 total_bytes, sha256, now_ms()))
            self._db.commit()
        return media_id

    def get_media(self, media_id: bytes) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT owner_id, conversation_id, content_type, total_bytes, "
                "sha256, status, path FROM media WHERE media_id=?",
                (media_id,)).fetchone()
        if row is None:
            return None
        return {"owner_id": row[0], "conversation_id": row[1], "content_type": row[2],
                "total_bytes": row[3], "sha256": row[4], "status": row[5], "path": row[6]}

    def finish_media(self, media_id: bytes, path: str, ok: bool) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE media SET status=?, path=? WHERE media_id=?",
                ("READY" if ok else "FAILED", path if ok else None, media_id))
            self._db.commit()

    def save_push_token(self, device_id: bytes, token: str, platform: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO push_tokens VALUES (?,?,?,?) ON CONFLICT(device_id) "
                "DO UPDATE SET token=excluded.token, platform=excluded.platform, "
                "updated_at=excluded.updated_at",
                (device_id, token, platform, now_ms()))
            self._db.commit()

    def push_tokens(self, device_id: bytes) -> list[str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT token FROM push_tokens WHERE device_id=?",
                (device_id,)).fetchall()
        return [r[0] for r in rows]

    def message_by_id(self, message_id: bytes) -> StoredMessage | None:
        with self._lock:
            row = self._db.execute(
                "SELECT conversation_id, sender_id, sender_device_id, sequence, "
                "server_timestamp_ms, kind, body, deleted FROM messages "
                "WHERE message_id=?", (message_id,)).fetchone()
        if row is None:
            return None
        return StoredMessage(message_id, row[0], row[1], row[2], row[3], row[4],
                             row[5], row[6], bool(row[7]))

    def create_conversation(self, creator_id: bytes,
                            member_ids: list[bytes], title: str = "",
                            kind: str = "group") -> bytes:
        conversation_id = _uid()
        with self._lock:
            self._db.execute(
                "INSERT INTO conversations (conversation_id, created_at, title, kind, created_by) "
                "VALUES (?,?,?,?,?)",
                (conversation_id, now_ms(), title, kind, creator_id))
            for user_id in {creator_id, *member_ids}:
                self._db.execute("INSERT OR IGNORE INTO members VALUES (?,?)",
                                 (conversation_id, user_id))
            self._db.commit()
        return conversation_id

    def list_conversations(self, user_id: bytes) -> list[bytes]:
        with self._lock:
            rows = self._db.execute(
                "SELECT conversation_id FROM members WHERE user_id=?",
                (user_id,)).fetchall()
        return [r[0] for r in rows]

    def list_users(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT user_id, name FROM users ORDER BY name").fetchall()
        return [{"user_id": r[0], "name": r[1]} for r in rows]

    def user_name(self, user_id: bytes) -> str:
        with self._lock:
            row = self._db.execute(
                "SELECT name FROM users WHERE user_id=?", (user_id,)).fetchone()
        return row[0] if row else ""

    # -- friends ------------------------------------------------------------------
    def add_friend(self, user_id: bytes, friend_id: bytes) -> None:
        """Mutual friendship: stored as two rows so lookups stay one-way.

        Raises ValueError for self-adds and unknown users. Idempotent:
        adding an existing friend again is a no-op.
        """
        if user_id == friend_id:
            raise ValueError("cannot_add_yourself_as_friend")
        with self._lock:
            for uid in (user_id, friend_id):
                if self._db.execute("SELECT 1 FROM users WHERE user_id=?",
                                    (uid,)).fetchone() is None:
                    raise ValueError("user_not_found")
            ts = now_ms()
            for a, b in ((user_id, friend_id), (friend_id, user_id)):
                self._db.execute(
                    "INSERT OR IGNORE INTO friendships VALUES (?,?,?)",
                    (a, b, ts))
            self._db.commit()

    def remove_friend(self, user_id: bytes, friend_id: bytes) -> None:
        with self._lock:
            self._db.execute(
                "DELETE FROM friendships WHERE (user_id=? AND friend_id=?) "
                "OR (user_id=? AND friend_id=?)",
                (user_id, friend_id, friend_id, user_id))
            self._db.commit()

    def friend_ids(self, user_id: bytes) -> set[bytes]:
        with self._lock:
            rows = self._db.execute(
                "SELECT friend_id FROM friendships WHERE user_id=?",
                (user_id,)).fetchall()
        return {r[0] for r in rows}

    def list_friends(self, user_id: bytes) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT u.user_id, u.name FROM friendships f JOIN users u "
                "ON u.user_id=f.friend_id WHERE f.user_id=? ORDER BY u.name",
                (user_id,)).fetchall()
        return [{"user_id": r[0], "name": r[1]} for r in rows]

    def conversation_info(self, conversation_id: bytes) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT title, kind, created_by FROM conversations "
                "WHERE conversation_id=?", (conversation_id,)).fetchone()
            if row is None:
                return None
            members = self._db.execute(
                "SELECT m.user_id, u.name FROM members m JOIN users u "
                "ON u.user_id=m.user_id WHERE m.conversation_id=?",
                (conversation_id,)).fetchall()
            last = self._db.execute(
                "SELECT COALESCE(MAX(sequence),0) FROM messages "
                "WHERE conversation_id=?", (conversation_id,)).fetchone()[0]
        return {"conversation_id": conversation_id, "title": row[0],
                "kind": row[1], "created_by": row[2],
                "members": [{"user_id": m[0], "name": m[1]} for m in members],
                "last_sequence": last}

    def list_conversation_infos(self, user_id: bytes) -> list[dict]:
        return [info for cid in self.list_conversations(user_id)
                if (info := self.conversation_info(cid)) is not None]

    def rename_conversation(self, conversation_id: bytes, title: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE conversations SET title=? WHERE conversation_id=?",
                (title, conversation_id))
            self._db.commit()

    def remove_member(self, conversation_id: bytes, user_id: bytes) -> None:
        with self._lock:
            self._db.execute(
                "DELETE FROM members WHERE conversation_id=? AND user_id=?",
                (conversation_id, user_id))
            self._db.commit()

    def find_or_create_direct(self, user_a: bytes, user_b: bytes) -> bytes:
        """Return the existing 1:1 room for this pair, or create it."""
        with self._lock:
            rows = self._db.execute(
                "SELECT m1.conversation_id FROM members m1 "
                "JOIN members m2 ON m2.conversation_id=m1.conversation_id "
                "JOIN conversations c ON c.conversation_id=m1.conversation_id "
                "WHERE m1.user_id=? AND m2.user_id=? AND c.kind='direct'",
                (user_a, user_b)).fetchall()
            for (cid,) in rows:
                count = self._db.execute(
                    "SELECT COUNT(*) FROM members WHERE conversation_id=?",
                    (cid,)).fetchone()[0]
                if count == 2:
                    return cid
        return self.create_conversation(user_a, [user_b], kind="direct")

    # -- conversations ------------------------------------------------------------
    def ensure_conversation(self, conversation_id: bytes, creator_id: bytes) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO conversations (conversation_id, created_at) VALUES (?,?)",
                (conversation_id, now_ms()))
            self._db.execute(
                "INSERT OR IGNORE INTO members VALUES (?,?)",
                (conversation_id, creator_id))
            self._db.commit()

    def add_member(self, conversation_id: bytes, user_id: bytes) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO conversations (conversation_id, created_at) VALUES (?,?)",
                (conversation_id, now_ms()))
            self._db.execute(
                "INSERT OR IGNORE INTO members VALUES (?,?)",
                (conversation_id, user_id))
            self._db.commit()

    def is_member(self, conversation_id: bytes, user_id: bytes) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM members WHERE conversation_id=? AND user_id=?",
                (conversation_id, user_id)).fetchone()
        return row is not None

    def member_devices(self, conversation_id: bytes) -> list[bytes]:
        with self._lock:
            rows = self._db.execute(
                "SELECT d.device_id FROM devices d JOIN members m "
                "ON m.user_id=d.user_id WHERE m.conversation_id=? AND d.revoked=0",
                (conversation_id,)).fetchall()
        return [r[0] for r in rows]

    # -- messages ---------------------------------------------------------------------
    def save_message(self, *, message_id: bytes, conversation_id: bytes,
                     sender_id: bytes, sender_device_id: bytes,
                     idempotency_key: bytes, kind: int, body: bytes
                     ) -> tuple[StoredMessage, bool]:
        """Returns (stored, duplicate). Commits before returning (persist-then-ACK)."""
        with self._lock:
            cur = self._db.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute(
                    "SELECT conversation_id, sequence, server_timestamp_ms, kind, body "
                    "FROM messages WHERE sender_id=? AND sender_device_id=? "
                    "AND idempotency_key=?",
                    (sender_id, sender_device_id, idempotency_key)).fetchone()
                if row is not None:
                    cur.execute("COMMIT")
                    return StoredMessage(message_id, row[0], sender_id, sender_device_id,
                                         row[1], row[2], row[3], row[4]), True
                if cur.execute("SELECT 1 FROM messages WHERE message_id=?",
                               (message_id,)).fetchone():
                    raise ConflictError("message_id already used with another key")
                sequence = cur.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM messages "
                    "WHERE conversation_id=?", (conversation_id,)).fetchone()[0]
                ts = now_ms()
                cur.execute(
                    "INSERT INTO messages (conversation_id, sequence, message_id,"
                    " sender_id, sender_device_id, idempotency_key, kind, body,"
                    " server_timestamp_ms) VALUES (?,?,?,?,?,?,?,?,?)",
                    (conversation_id, sequence, message_id, sender_id,
                     sender_device_id, idempotency_key, kind, body, ts))
                cur.execute("COMMIT")
                return StoredMessage(message_id, conversation_id, sender_id,
                                     sender_device_id, sequence, ts, kind, body), False
            except Exception:
                try:
                    cur.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    # -- message deletion (tombstones) -------------------------------------------
    def delete_message(self, conversation_id: bytes, message_id: bytes,
                       requester_id: bytes) -> int | None:
        """Tombstone one message. Only the original sender may delete.

        Returns the message sequence, or None when the message does not
        exist in this conversation or belongs to someone else. The row is
        kept (body wiped) so the sequence space stays gapless and sync can
        propagate the deletion as a DELETE tombstone. Idempotent.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT sender_id, sequence, deleted FROM messages "
                "WHERE conversation_id=? AND message_id=?",
                (conversation_id, message_id)).fetchone()
            if row is None or row[0] != requester_id:
                return None
            if not row[2]:
                self._db.execute(
                    "UPDATE messages SET deleted=1, body=? "
                    "WHERE conversation_id=? AND message_id=?",
                    (b"", conversation_id, message_id))
                self._db.commit()
            return row[1]

    def clear_messages(self, conversation_id: bytes) -> int:
        """Tombstone EVERY message in a conversation. Returns the count."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE messages SET deleted=1, body=? "
                "WHERE conversation_id=? AND deleted=0", (b"", conversation_id))
            self._db.commit()
            return cur.rowcount

    def tombstones(self, conversation_id: bytes,
                   limit: int = 500) -> list[tuple[bytes, int]]:
        """(message_id, sequence) pairs of deleted messages, oldest first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT message_id, sequence FROM messages "
                "WHERE conversation_id=? AND deleted=1 "
                "ORDER BY sequence LIMIT ?", (conversation_id, limit)).fetchall()
        return [(r[0], r[1]) for r in rows]

    def count_messages(self, conversation_id: bytes) -> int:
        with self._lock:
            return self._db.execute(
                "SELECT COUNT(*) FROM messages WHERE conversation_id=?",
                (conversation_id,)).fetchone()[0]

    def messages_after(self, conversation_id: bytes, after_sequence: int,
                       limit: int) -> list[StoredMessage]:
        with self._lock:
            rows = self._db.execute(
                "SELECT message_id, sender_id, sender_device_id, sequence, "
                "server_timestamp_ms, kind, body, deleted FROM messages "
                "WHERE conversation_id=? AND sequence>? ORDER BY sequence LIMIT ?",
                (conversation_id, after_sequence, limit)).fetchall()
        return [StoredMessage(r[0], conversation_id, r[1], r[2], r[3], r[4],
                              r[5], r[6], bool(r[7]))
                for r in rows]

    # -- delivery / sync cursors ------------------------------------------------------
    def mark_delivered(self, message_id: bytes, device_id: bytes) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO deliveries VALUES (?,?,?,?) "
                "ON CONFLICT(message_id,device_id) DO UPDATE SET status=excluded.status",
                (message_id, device_id, "DELIVERED", now_ms()))
            self._db.commit()

    def get_cursor(self, device_id: bytes, conversation_id: bytes) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT applied_sequence FROM sync_cursors "
                "WHERE device_id=? AND conversation_id=?",
                (device_id, conversation_id)).fetchone()
        return row[0] if row else 0

    def ack_cursor(self, device_id: bytes, conversation_id: bytes,
                   applied_sequence: int) -> tuple[int, int]:
        """Advance monotonically. Returns (before, after)."""
        with self._lock:
            before = self.get_cursor(device_id, conversation_id)
            after = max(before, applied_sequence)
            self._db.execute(
                "INSERT INTO sync_cursors VALUES (?,?,?) "
                "ON CONFLICT(device_id,conversation_id) "
                "DO UPDATE SET applied_sequence=excluded.applied_sequence",
                (device_id, conversation_id, after))
            self._db.commit()
            return before, after
