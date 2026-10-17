from __future__ import annotations

import sqlite3

import pytest

from sentinel.audit import AuditStore, AuditWriteError, sanitize
from sentinel.contracts import EventType, SecurityEvent


def ev(**kw) -> SecurityEvent:
    return SecurityEvent(trace_id="t", actor_id="a", event_type=EventType.HEARTBEAT, **kw)


@pytest.fixture
def store(tmp_path):
    s = AuditStore(tmp_path / "a.db")
    yield s
    s.close()


def test_append_and_chain_verifies(store):
    for _ in range(5):
        store.append(ev())
    report = store.verify_chain()
    assert report.ok and report.checked == 5


def test_update_and_delete_blocked(store):
    store.append(ev())
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store._conn.execute("UPDATE events SET actor_id='x'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store._conn.execute("DELETE FROM events")


def test_tamper_detected_even_if_triggers_dropped(store):
    for _ in range(3):
        store.append(ev())
    store._conn.execute("DROP TRIGGER events_no_update")
    store._conn.execute(
        "UPDATE events SET body=replace(body, '\"actor_id\":\"a\"', '\"actor_id\":\"z\"') WHERE seq=2")
    report = store.verify_chain()
    assert not report.ok and report.first_bad_seq == 2


def test_deleted_row_breaks_chain(store):
    for _ in range(3):
        store.append(ev())
    store._conn.execute("DROP TRIGGER events_no_delete")
    store._conn.execute("DELETE FROM events WHERE seq=2")
    assert not store.verify_chain().ok


def test_secrets_redacted_and_long_values_bounded(store):
    stored = store.append(ev(metadata={"api_key": "sk-123", "nested": {"Password": "p"},
                                       "body": "x" * 5000}))
    md = store.get(stored.event.event_id).event.metadata
    assert md["api_key"] == "[REDACTED]" and md["nested"]["Password"] == "[REDACTED]"
    assert len(md["body"]) < 200 and "5000 chars" in md["body"]


def test_sanitize_lists():
    assert sanitize([{"token": "t"}]) == [{"token": "[REDACTED]"}]


def test_injected_failure(store):
    store.fail_writes = True
    with pytest.raises(AuditWriteError):
        store.append(ev())
    assert store.count() == 0


def test_read_only_store_cannot_write(tmp_path, store):
    store.append(ev())
    ro = AuditStore(tmp_path / "a.db", read_only=True)
    assert ro.count() == 1 and ro.verify_chain().ok
    with pytest.raises(AuditWriteError):
        ro.append(ev())
    ro.close()


def test_duplicate_event_id_rejected(store):
    e = ev()
    store.append(e)
    with pytest.raises(AuditWriteError):
        store.append(e)
    assert store.verify_chain().ok
