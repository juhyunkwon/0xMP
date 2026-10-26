"""2. Durability tests: persistence across reopen, idempotency, ordering."""
import threading
import uuid

import pytest

from server.store import ConflictError, Store


def uid():
    return uuid.uuid4().bytes


def save(store, conv, key=None, mid=None, body=b"hello"):
    return store.save_message(
        message_id=mid or uid(), conversation_id=conv, sender_id=b"u" * 16,
        sender_device_id=b"d" * 16, idempotency_key=key or uid(),
        kind=1, body=body)


def test_messages_survive_reopen(tmp_path):
    path = str(tmp_path / "durable.db")
    conv = uid()
    store = Store(path)
    stored, dup = save(store, conv)
    assert not dup and stored.sequence == 1
    store.close()  # simulated server restart: process state is gone
    reopened = Store(path)
    rows = reopened.messages_after(conv, 0, 10)
    assert len(rows) == 1 and rows[0].body == b"hello"
    assert rows[0].sequence == 1
    reopened.close()


def test_duplicate_key_returns_original_without_restoring(tmp_path):
    store = Store(str(tmp_path / "dup.db"))
    conv, key = uid(), uid()
    first, _ = save(store, conv, key=key)
    second, dup = save(store, conv, key=key, body=b"different retry body")
    assert dup and second.sequence == first.sequence
    assert store.count_messages(conv) == 1
    store.close()


def test_message_id_conflict_with_other_key_rejected(tmp_path):
    store = Store(str(tmp_path / "conflict.db"))
    conv, mid = uid(), uid()
    save(store, conv, mid=mid)
    with pytest.raises(ConflictError):
        save(store, conv, mid=mid)  # same message_id, new idempotency key
    store.close()


def test_sequence_is_gapless_and_per_conversation(tmp_path):
    store = Store(str(tmp_path / "seq.db"))
    conv_a, conv_b = uid(), uid()
    seqs_a = [save(store, conv_a)[0].sequence for _ in range(5)]
    seqs_b = [save(store, conv_b)[0].sequence for _ in range(3)]
    assert seqs_a == [1, 2, 3, 4, 5]
    assert seqs_b == [1, 2, 3]
    store.close()


def test_concurrent_same_key_stores_exactly_once(tmp_path):
    store = Store(str(tmp_path / "conc.db"))
    conv, key = uid(), uid()
    results, errors = [], []

    def worker():
        try:
            results.append(save(store, conv, key=key))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert store.count_messages(conv) == 1
    assert sum(1 for _, dup in results if not dup) == 1  # exactly one real store
    assert len({s.sequence for s, _ in results}) == 1    # all see the same result
    store.close()


def test_cursor_only_moves_forward(tmp_path):
    store = Store(str(tmp_path / "cursor.db"))
    dev, conv = uid(), uid()
    assert store.ack_cursor(dev, conv, 5) == (0, 5)
    assert store.ack_cursor(dev, conv, 3) == (5, 5)  # stale ACK cannot rewind
    assert store.get_cursor(dev, conv) == 5
    store.close()
