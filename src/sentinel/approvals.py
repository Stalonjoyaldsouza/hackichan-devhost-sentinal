"""Human approval workflow.

An approval is bound to the exact request (hash of actor, run, tool and arguments), expires, can be
consumed once, and must be granted by a configured approver who is not the requester.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from sentinel.contracts import new_id, utcnow


class ApprovalState(StrEnum):
    PENDING = "PENDING"
    GRANTED = "GRANTED"
    REJECTED = "REJECTED"
    CONSUMED = "CONSUMED"


class ApprovalError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def request_hash(actor_id: str, run_id: str, tool_name: str, arguments: dict[str, Any]) -> str:
    body = json.dumps(
        {"actor": actor_id, "run": run_id, "tool": tool_name, "args": arguments},
        sort_keys=True, default=str, separators=(",", ":"),
    )
    return hashlib.sha256(body.encode()).hexdigest()


@dataclass(frozen=True)
class Approval:
    approval_id: str
    trace_id: str
    requester_id: str
    run_id: str
    tool_name: str
    arguments: dict[str, Any]
    request_hash: str
    reason_codes: tuple[str, ...]
    policy_version: str
    created_at: datetime
    expires_at: datetime
    state: ApprovalState = ApprovalState.PENDING
    decided_by: str | None = None


class ApprovalService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, Approval] = {}

    def create(
        self, *, trace_id: str, requester_id: str, run_id: str, tool_name: str,
        arguments: dict[str, Any], reason_codes: tuple[str, ...], policy_version: str,
        ttl_seconds: int,
    ) -> Approval:
        now = utcnow()
        a = Approval(
            approval_id=new_id(), trace_id=trace_id, requester_id=requester_id, run_id=run_id,
            tool_name=tool_name, arguments=dict(arguments),
            request_hash=request_hash(requester_id, run_id, tool_name, arguments),
            reason_codes=reason_codes, policy_version=policy_version,
            created_at=now, expires_at=now + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._items[a.approval_id] = a
        return a

    def get(self, approval_id: str) -> Approval:
        with self._lock:
            a = self._items.get(approval_id)
        if a is None:
            raise ApprovalError("APPROVAL_NOT_FOUND", "unknown approval id")
        return a

    def pending(self) -> list[Approval]:
        with self._lock:
            return [a for a in self._items.values() if a.state is ApprovalState.PENDING]

    def decide(
        self, approval_id: str, *, approver_id: str, approvers: tuple[str, ...], grant: bool,
        record: Callable[[Approval], None] | None = None,
    ) -> Approval:
        """`record` must durably audit the decision; if it raises, the decision is not applied."""
        with self._lock:
            a = self._items.get(approval_id)
            if a is None:
                raise ApprovalError("APPROVAL_NOT_FOUND", "unknown approval id")
            if approver_id not in approvers:
                raise ApprovalError("APPROVER_NOT_AUTHORISED", f"{approver_id} is not an approver")
            if approver_id == a.requester_id:
                raise ApprovalError("SELF_APPROVAL", "requester cannot approve own request")
            if a.state is not ApprovalState.PENDING:
                raise ApprovalError("APPROVAL_NOT_PENDING", f"approval is {a.state}")
            if utcnow() >= a.expires_at:
                raise ApprovalError("APPROVAL_EXPIRED", "approval expired")
            a = replace(
                a, state=ApprovalState.GRANTED if grant else ApprovalState.REJECTED,
                decided_by=approver_id,
            )
            if record is not None:
                record(a)
            self._items[approval_id] = a
            return a

    def consume(self, approval_id: str, req_hash: str) -> Approval:
        """Single-use: a granted approval for exactly this request becomes CONSUMED."""
        with self._lock:
            a = self._items.get(approval_id)
            if a is None:
                raise ApprovalError("APPROVAL_NOT_FOUND", "unknown approval id")
            if a.request_hash != req_hash:
                raise ApprovalError("APPROVAL_REQUEST_MISMATCH", "approval is for a different request")
            if a.state is ApprovalState.CONSUMED:
                raise ApprovalError("APPROVAL_ALREADY_USED", "approval already used")
            if a.state is not ApprovalState.GRANTED:
                raise ApprovalError("APPROVAL_NOT_GRANTED", f"approval is {a.state}")
            if utcnow() >= a.expires_at:
                raise ApprovalError("APPROVAL_EXPIRED", "approval expired")
            a = replace(a, state=ApprovalState.CONSUMED)
            self._items[approval_id] = a
            return a
