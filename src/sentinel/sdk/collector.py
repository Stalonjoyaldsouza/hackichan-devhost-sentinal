"""Central audit collector and the store-and-forward client that feeds it.

Problem: every replica of a deployed app otherwise keeps its own `.sentinel/audit.db`, which a
container redeploy discards and which nobody can read as one picture.

    app replica ─▶ local spool (durable) ─▶ forwarder thread ─HTTP─▶ collector ─▶ central audit.db
                                                                          └▶ `sentinel sdk watch/health`

* The local store is written first, so an unreachable collector never loses or blocks events; the
  forwarder retries from a persisted cursor. (If the filesystem is read-only the SDK spools in
  memory instead — bounded, and lost if the process dies before the next successful forward.)
* The collector validates every event with the strict `SecurityEvent` model, de-duplicates on
  event_id (so retries are safe), enforces size limits, and requires a bearer token.
* It speaks plain HTTP: bind it to loopback, or put it behind a TLS-terminating proxy and pass
  `--allow-remote`. The central store keeps its own hash chain, verified by `sentinel audit verify`.
"""

from __future__ import annotations

import hmac
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinel.audit import AuditStore, AuditWriteError
from sentinel.contracts import SecurityEvent

MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_EVENTS_PER_POST = 500
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class CollectorConfigError(Exception):
    pass


def make_server(db_path: Path | str, host: str, port: int, token: str | None, *,
                allow_remote: bool = False) -> ThreadingHTTPServer:
    if host not in LOOPBACK and not allow_remote:
        raise CollectorConfigError(
            f"refusing to bind {host}: this collector speaks plain HTTP. Bind to 127.0.0.1, or put "
            "it behind a TLS proxy and pass --allow-remote.")
    if host not in LOOPBACK and not token:
        raise CollectorConfigError("a bearer token is required when binding a non-loopback address "
                                   "(set SENTINEL_COLLECTOR_TOKEN)")
    store = AuditStore(db_path)
    ingest_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "SentinelCollector/1"

        def log_message(self, *a: Any) -> None:  # quiet; the audit trail is the record
            return

        def _send(self, code: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _authorised(self) -> bool:
            if not token:
                return True  # loopback-only without a token (enforced above)
            given = self.headers.get("Authorization", "")
            return hmac.compare_digest(given.encode(), f"Bearer {token}".encode())

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._send(200, {"status": "ok", "events": store.count()})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/events":
                return self._send(404, {"error": "not found"})
            if not self._authorised():
                return self._send(401, {"error": "unauthorised"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._send(400, {"error": "bad content-length"})
            if length <= 0 or length > MAX_BODY_BYTES:
                return self._send(413, {"error": f"body must be 1..{MAX_BODY_BYTES} bytes"})
            try:
                events = json.loads(self.rfile.read(length))["events"]
                if not isinstance(events, list) or len(events) > MAX_EVENTS_PER_POST:
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                return self._send(400, {"error": f"expected {{'events': [≤{MAX_EVENTS_PER_POST}]}}"})
            accepted = duplicates = rejected = 0
            with ingest_lock:
                for raw in events:
                    try:
                        ev = SecurityEvent.model_validate(raw)
                    except ValidationError:
                        rejected += 1
                        continue
                    if store.get(ev.event_id) is not None:
                        duplicates += 1
                        continue
                    try:
                        store.append(ev)
                        accepted += 1
                    except AuditWriteError:
                        return self._send(503, {"error": "central audit store unavailable",
                                                "accepted": accepted})
            self._send(200, {"accepted": accepted, "duplicates": duplicates, "rejected": rejected})

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    srv.sentinel_store = store  # type: ignore[attr-defined]
    return srv


class CollectorForwarder:
    """Reads new events from the local spool store and POSTs them. Never raises."""

    def __init__(self, url: str, token: str | None, store: AuditStore, cursor_path: Path | None,
                 timeout: float = 3.0, batch: int = 200):
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"collector_url must be http(s), got {url!r}")
        self.url = url.rstrip("/") + "/v1/events"
        self.token, self.store, self.cursor_path = token, store, cursor_path
        self.timeout, self.batch = timeout, batch
        self.ok: bool | None = None          # None = never tried
        self.last_error = ""
        self.forwarded = 0
        self._cursor = self._load_cursor()
        self._lock = threading.Lock()

    def _load_cursor(self) -> int:
        try:
            return int(self.cursor_path.read_text()) if self.cursor_path else 0
        except (OSError, ValueError):
            return 0

    def _save_cursor(self) -> None:
        if self.cursor_path:
            try:
                self.cursor_path.write_text(str(self._cursor))
            except OSError:
                pass  # worst case: some events are re-sent; the collector de-duplicates

    @property
    def pending(self) -> int:
        return self.store.head()[0] - self._cursor

    def flush(self) -> int:
        """Send everything pending (several batches). Returns events accepted or deduplicated."""
        sent = 0
        with self._lock:
            while True:
                try:
                    rows = self.store.since(self._cursor, self.batch)
                except ValueError:
                    return sent  # a corrupt local row; surfaced by the audit-chain check
                if not rows:
                    self.ok = True if self.ok is None else self.ok
                    return sent
                body = json.dumps({"events": [r.event.model_dump(mode="json") for r in rows]}).encode()
                req = urllib.request.Request(self.url, data=body, method="POST", headers={  # noqa: S310
                    "Content-Type": "application/json",
                    **({"Authorization": f"Bearer {self.token}"} if self.token else {})})
                try:
                    with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                        result = json.loads(resp.read())
                except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
                    self.ok, self.last_error = False, f"{type(exc).__name__}: {exc}"[:160]
                    return sent
                self._cursor = rows[-1].seq
                self._save_cursor()
                self.ok, self.last_error = True, ""
                sent += len(rows)
                self.forwarded += int(result.get("accepted", 0))
