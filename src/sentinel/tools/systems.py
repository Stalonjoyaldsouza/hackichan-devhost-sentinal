"""Mock target systems (CLAUDE.md §10: no real destructive actions in demos).

Each system keeps its **own** access log, independent of the gateway's audit trail. The watchdog
reconciles these logs against audited executions to detect calls that bypassed the gateway, and the
outcome verifier reads system state directly instead of trusting tool responses.

Fault switches (`faulty_*`) simulate tools that claim success without doing the work (Scenario C).
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from typing import Any

from sentinel.contracts import DataLabel, new_id


@dataclass
class AccessLogEntry:
    op: str
    trace_id: str | None
    mutating: bool
    detail: dict[str, Any] = field(default_factory=dict)


class TargetSystem:
    name = "system"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._log: list[AccessLogEntry] = []

    def _record(self, op: str, trace_id: str | None, mutating: bool, **detail: Any) -> None:
        with self._lock:
            self._log.append(AccessLogEntry(op, trace_id, mutating, detail))

    def access_log(self) -> list[AccessLogEntry]:
        with self._lock:
            return list(self._log)


@dataclass(frozen=True)
class Document:
    doc_id: str
    title: str
    content: str
    labels: frozenset[DataLabel]


class DocumentStore(TargetSystem):
    name = "docs"

    def __init__(self, documents: list[Document]):
        super().__init__()
        self._docs = {d.doc_id: d for d in documents}

    def read(self, doc_id: str, trace_id: str | None = None) -> Document:
        self._record("read", trace_id, mutating=False, doc_id=doc_id)
        if doc_id not in self._docs:
            raise KeyError(f"document {doc_id!r} not found")
        return self._docs[doc_id]

    def peek(self, doc_id: str) -> Document | None:
        """Independent read path for the verifier/watchdog (not logged as agent access)."""
        return self._docs.get(doc_id)


class CRM(TargetSystem):
    name = "crm"
    UPDATABLE = frozenset({"tier", "notes", "status"})

    def __init__(self, records: dict[str, dict[str, Any]]):
        super().__init__()
        self._records = copy.deepcopy(records)
        self.faulty_silent_drop = False

    def get(self, record_id: str, trace_id: str | None = None) -> dict[str, Any]:
        self._record("get", trace_id, mutating=False, record_id=record_id)
        with self._lock:
            if record_id not in self._records:
                raise KeyError(f"record {record_id!r} not found")
            return copy.deepcopy(self._records[record_id])

    def update(self, record_id: str, field_name: str, value: str, trace_id: str | None = None) -> dict:
        self._record("update", trace_id, mutating=True, record_id=record_id, field=field_name)
        with self._lock:
            if record_id not in self._records:
                raise KeyError(f"record {record_id!r} not found")
            if field_name not in self.UPDATABLE:
                raise ValueError(f"field {field_name!r} is not updatable")
            if not self.faulty_silent_drop:
                self._records[record_id][field_name] = value
        # The faulty variant still reports success — exactly the case Scenario C must catch.
        return {"status": "ok", "record_id": record_id, "updated": {field_name: value}}

    def export(self, trace_id: str | None = None) -> list[dict[str, Any]]:
        self._record("export", trace_id, mutating=False)
        with self._lock:
            return [{"record_id": k, **copy.deepcopy(v)} for k, v in self._records.items()]

    def bulk_delete(self, where_tier: str, trace_id: str | None = None) -> int:
        self._record("bulk_delete", trace_id, mutating=True, where_tier=where_tier)
        with self._lock:
            doomed = [k for k, v in self._records.items() if v.get("tier") == where_tier]
            for k in doomed:
                del self._records[k]
            return len(doomed)

    def peek(self, record_id: str) -> dict[str, Any] | None:
        with self._lock:
            rec = self._records.get(record_id)
            return copy.deepcopy(rec) if rec is not None else None

    def size(self) -> int:
        with self._lock:
            return len(self._records)


@dataclass(frozen=True)
class SentMessage:
    message_id: str
    to: str
    subject: str
    body: str


class Mailer(TargetSystem):
    name = "mail"

    def __init__(self) -> None:
        super().__init__()
        self._outbox: dict[str, SentMessage] = {}

    def send(self, to: str, subject: str, body: str, trace_id: str | None = None) -> str:
        self._record("send", trace_id, mutating=True, to=to)
        msg = SentMessage(new_id(), to, subject, body)
        with self._lock:
            self._outbox[msg.message_id] = msg
        return msg.message_id

    def peek(self, message_id: str) -> SentMessage | None:
        with self._lock:
            return self._outbox.get(message_id)

    def outbox(self) -> list[SentMessage]:
        with self._lock:
            return list(self._outbox.values())


class Payments(TargetSystem):
    name = "payments"

    def __init__(self, orders: dict[str, float]):
        super().__init__()
        self._orders = {k: {"amount": v, "refunded": 0.0} for k, v in orders.items()}
        self.faulty_partial = False

    def refund(self, order_id: str, amount: float, trace_id: str | None = None) -> dict[str, Any]:
        self._record("refund", trace_id, mutating=True, order_id=order_id, amount=amount)
        with self._lock:
            order = self._orders.get(order_id)
            if order is None:
                raise KeyError(f"order {order_id!r} not found")
            if order["refunded"] + amount > order["amount"]:
                raise ValueError("refund exceeds order amount")
            applied = amount / 2 if self.faulty_partial else amount
            order["refunded"] += applied
        return {"status": "ok", "order_id": order_id, "refunded": amount}

    def peek(self, order_id: str) -> dict[str, float] | None:
        with self._lock:
            o = self._orders.get(order_id)
            return dict(o) if o else None


class Canary(TargetSystem):
    """Synthetic protected tool. If it ever executes, enforcement is broken."""

    name = "canary"

    def __init__(self) -> None:
        super().__init__()
        self.executions = 0

    def run(self, trace_id: str | None = None) -> dict[str, Any]:
        self._record("run", trace_id, mutating=True)
        with self._lock:
            self.executions += 1
        return {"status": "ok"}


@dataclass
class Systems:
    docs: DocumentStore
    crm: CRM
    mail: Mailer
    payments: Payments
    canary: Canary

    def all(self) -> list[TargetSystem]:
        return [self.docs, self.crm, self.mail, self.payments, self.canary]
