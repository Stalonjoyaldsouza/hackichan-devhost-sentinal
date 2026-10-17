"""Append-only, hash-chained audit store (SQLite).

Tamper evidence has two layers:
1. Triggers reject UPDATE and DELETE on the events table.
2. Every row stores sha256(prev_hash || canonical_event_json); `verify_chain` recomputes the chain,
   so edits made by bypassing SQLite triggers (e.g. editing the file, dropping triggers) are detected.

This is tamper-*evident*, not tamper-*proof*: an attacker who can rewrite the whole file can rebuild
a consistent chain. Anchoring the head hash externally is future work (docs/architecture.md §4).
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.contracts import EventType, SecurityEvent

GENESIS = "0" * 64
_SECRET_KEY = re.compile(r"(pass(word)?|secret|token|api[_-]?key|credential|authorization|ssn)", re.I)
_MAX_STR = 200

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   TEXT NOT NULL UNIQUE,
    timestamp  TEXT NOT NULL,
    trace_id   TEXT NOT NULL,
    run_id     TEXT,
    actor_id   TEXT NOT NULL,
    event_type TEXT NOT NULL,
    synthetic  INTEGER NOT NULL,
    body       TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_trace ON events(trace_id);
CREATE INDEX IF NOT EXISTS ix_events_run ON events(run_id);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


class AuditWriteError(Exception):
    """The event could not be durably recorded. Callers must fail closed."""


def sanitize(value: Any) -> Any:
    """Redact secret-looking keys and bound long strings (store a hash instead of the payload)."""
    if isinstance(value, dict):
        return {
            k: "[REDACTED]" if _SECRET_KEY.search(str(k)) else sanitize(v) for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [sanitize(v) for v in value]
    if isinstance(value, str) and len(value) > _MAX_STR:
        digest = hashlib.sha256(value.encode()).hexdigest()[:16]
        return f"{value[:60]}…[{len(value)} chars sha256:{digest}]"
    return value


def _canonical(event: SecurityEvent) -> str:
    return json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _chain_hash(prev_hash: str, body: str) -> str:
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


@dataclass(frozen=True)
class StoredEvent:
    seq: int
    event: SecurityEvent
    hash: str


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    detail: str = ""


class AuditStore:
    def __init__(self, path: Path | str, read_only: bool = False):
        self.path = str(path)
        self.read_only = read_only
        self._lock = threading.Lock()
        if read_only:
            uri = f"file:{Path(self.path).resolve()}?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        else:
            self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.executescript(_SCHEMA)
        # Fault-injection switch for control-validation tests/demos (Scenario D).
        self.fail_writes = False

    def close(self) -> None:
        self._conn.close()

    # ---- writes ----------------------------------------------------------------------------
    def append(self, event: SecurityEvent) -> StoredEvent:
        if self.read_only:
            raise AuditWriteError("store opened read-only")
        if self.fail_writes:
            raise AuditWriteError("audit persistence unavailable (injected fault)")
        event = event.model_copy(update={"metadata": sanitize(event.metadata)})
        body = _canonical(event)
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute(
                    "SELECT hash FROM events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev = row[0] if row else GENESIS
                digest = _chain_hash(prev, body)
                cur = self._conn.execute(
                    "INSERT INTO events (event_id, timestamp, trace_id, run_id, actor_id, event_type,"
                    " synthetic, body, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        event.event_id,
                        event.timestamp.isoformat(),
                        event.trace_id,
                        event.run_id,
                        event.actor_id,
                        event.event_type.value,
                        int(event.synthetic),
                        body,
                        prev,
                        digest,
                    ),
                )
                self._conn.execute("COMMIT")
            except sqlite3.Error as exc:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise AuditWriteError(f"audit write failed: {exc}") from exc
        return StoredEvent(seq=int(cur.lastrowid or 0), event=event, hash=digest)

    # ---- reads -----------------------------------------------------------------------------
    def _rows(self, sql: str, params: tuple[Any, ...] = ()) -> Iterator[StoredEvent]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        for seq, body, digest in rows:
            yield StoredEvent(seq=seq, event=SecurityEvent.model_validate_json(body), hash=digest)

    def get(self, event_id: str) -> StoredEvent | None:
        return next(self._rows("SELECT seq, body, hash FROM events WHERE event_id=?", (event_id,)), None)

    def since(self, seq: int, limit: int = 500) -> list[StoredEvent]:
        return list(
            self._rows(
                "SELECT seq, body, hash FROM events WHERE seq>? ORDER BY seq LIMIT ?", (seq, limit)
            )
        )

    def by_run(self, run_id: str) -> list[StoredEvent]:
        return list(self._rows("SELECT seq, body, hash FROM events WHERE run_id=? ORDER BY seq", (run_id,)))

    def by_trace(self, trace_id: str) -> list[StoredEvent]:
        return list(
            self._rows("SELECT seq, body, hash FROM events WHERE trace_id=? ORDER BY seq", (trace_id,))
        )

    def all(self) -> list[StoredEvent]:
        return list(self._rows("SELECT seq, body, hash FROM events ORDER BY seq"))

    def count(self, event_type: EventType | None = None, include_synthetic: bool = True) -> int:
        sql, params = "SELECT COUNT(*) FROM events WHERE 1=1", []
        if event_type is not None:
            sql += " AND event_type=?"
            params.append(event_type.value)
        if not include_synthetic:
            sql += " AND synthetic=0"
        with self._lock:
            return int(self._conn.execute(sql, tuple(params)).fetchone()[0])

    def head(self) -> tuple[int, str]:
        with self._lock:
            row = self._conn.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else (0, GENESIS)

    def verify_chain(self) -> ChainReport:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, event_id, body, prev_hash, hash FROM events ORDER BY seq"
            ).fetchall()
        prev = GENESIS
        for seq, event_id, body, stored_prev, stored_hash in rows:
            if stored_prev != prev:
                return ChainReport(False, seq, seq, f"broken link at seq {seq}")
            if _chain_hash(prev, body) != stored_hash:
                return ChainReport(False, seq, seq, f"hash mismatch at seq {seq}")
            try:
                if SecurityEvent.model_validate_json(body).event_id != event_id:
                    return ChainReport(False, seq, seq, f"event_id column altered at seq {seq}")
            except ValueError:
                return ChainReport(False, seq, seq, f"unparseable body at seq {seq}")
            prev = stored_hash
        return ChainReport(True, len(rows))
