"""Human approvals for REQUIRE_APPROVAL decisions in the SDK (enforce mode).

A guarded call that needs approval is refused and a PENDING approval is recorded in
`.sentinel/approvals.json`. A human approves it with `sentinel sdk approve ID`; the application's
next identical call (same point, function and destination) consumes the approval once and proceeds.
Approvals expire. The file is locked while it is read-modify-written so several processes can share it.

Trust note: this is a local, file-based workflow. Anyone who can write the file can approve, so
protect `.sentinel/` like any other deployment secret; the approver id must be in `config.approvers`.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # Windows: no inter-process lock (documented limitation)
    fcntl = None  # type: ignore[assignment]

from sentinel.contracts import new_id

DEFAULT_TTL_SECONDS = 900


class ApprovalError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def fingerprint(point_id: str, function: str, destination: str | None) -> str:
    raw = json.dumps([point_id.upper(), function, destination or ""], separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


class ApprovalFile:
    def __init__(self, path: Path):
        self.path = path

    @contextlib.contextmanager
    def _locked(self) -> Iterator[dict[str, Any]]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock = open(str(self.path) + ".lock", "a+")  # noqa: SIM115 — closed in finally
        try:
            if fcntl is not None:
                fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                data = json.loads(self.path.read_text()) if self.path.exists() else {}
            except (json.JSONDecodeError, OSError):
                data = {}
            data.setdefault("approvals", {})
            yield data
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
            os.replace(tmp, self.path)
        finally:
            if fcntl is not None:
                fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()

    # ---- application side ------------------------------------------------------------------
    def consume_granted(self, fp: str) -> dict[str, Any] | None:
        """Single use: returns a granted, unexpired approval for exactly this request and burns it."""
        with self._locked() as data:
            for a in data["approvals"].values():
                if (a["fingerprint"] == fp and a["state"] == "GRANTED"
                        and datetime.fromisoformat(a["expires_at"]) > _now()):
                    a["state"] = "CONSUMED"
                    a["consumed_at"] = _now().isoformat()
                    return dict(a)
        return None

    def request(self, point_id: str, function: str, destination: str | None, fp: str,
                requester: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> tuple[dict[str, Any], bool]:
        """Returns (approval, created). Reuses an existing live PENDING one for the same request."""
        with self._locked() as data:
            for a in data["approvals"].values():
                if (a["fingerprint"] == fp and a["state"] == "PENDING"
                        and datetime.fromisoformat(a["expires_at"]) > _now()):
                    return dict(a), False
            a = {"approval_id": new_id()[:8], "fingerprint": fp, "point_id": point_id.upper(),
                 "function": function, "destination": destination, "requester": requester,
                 "state": "PENDING", "created_at": _now().isoformat(),
                 "expires_at": (_now() + timedelta(seconds=ttl_seconds)).isoformat(),
                 "decided_by": None}
            data["approvals"][a["approval_id"]] = a
            return dict(a), True

    # ---- human side ------------------------------------------------------------------------
    def list(self) -> list[dict[str, Any]]:
        with self._locked() as data:
            return sorted((dict(a) for a in data["approvals"].values()),
                          key=lambda a: a["created_at"])

    def decide(self, approval_id: str, approver: str, allowed: list[str], grant: bool) -> dict[str, Any]:
        with self._locked() as data:
            a = data["approvals"].get(approval_id)
            if a is None:
                raise ApprovalError("NOT_FOUND", f"unknown approval '{approval_id}'")
            if approver not in allowed:
                raise ApprovalError("APPROVER_NOT_AUTHORISED",
                                    f"'{approver}' is not in config.approvers {allowed}")
            if approver == a["requester"]:
                raise ApprovalError("SELF_APPROVAL", "the requesting application cannot approve itself")
            if a["state"] != "PENDING":
                raise ApprovalError("NOT_PENDING", f"approval is already {a['state']}")
            if datetime.fromisoformat(a["expires_at"]) <= _now():
                raise ApprovalError("EXPIRED", "approval expired; the application must ask again")
            a["state"] = "GRANTED" if grant else "REJECTED"
            a["decided_by"], a["decided_at"] = approver, _now().isoformat()
            return dict(a)
