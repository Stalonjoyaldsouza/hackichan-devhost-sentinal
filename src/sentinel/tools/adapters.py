"""Tool adapters: the only code path from the gateway to a target system.

Each adapter declares a strict argument schema, how to derive the resource/destination for policy
evaluation, which data labels its output carries, and what text leaves the organisation (for
fingerprint-based data-flow checks).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from sentinel.contracts import DataLabel
from sentinel.tools.systems import Systems


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class DocsReadArgs(Args):
    doc_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")


class CrmGetArgs(Args):
    record_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")


class CrmUpdateArgs(Args):
    record_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    field: str = Field(pattern=r"^[a-z_]{1,32}$")
    value: str = Field(max_length=500)


class CrmExportArgs(Args):
    pass


class CrmBulkDeleteArgs(Args):
    where_tier: str = Field(pattern=r"^[a-z]{1,20}$")


class EmailSendArgs(Args):
    to: EmailStr
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(max_length=20_000)


class RefundArgs(Args):
    order_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    amount: float = Field(gt=0, le=1_000_000)


class NoArgs(Args):
    pass


def _none(_: Any) -> None:
    return None


def _no_labels(_a: Any, _r: dict[str, Any]) -> set[DataLabel]:
    return set()


@dataclass(frozen=True)
class ToolAdapter:
    name: str
    args_model: type[Args]
    execute: Callable[[Any, str], dict[str, Any]]
    resource: Callable[[Any], str | None] = _none
    destination: Callable[[Any], str | None] = _none
    output_labels: Callable[[Any, dict[str, Any]], set[DataLabel]] = _no_labels
    output_text: Callable[[dict[str, Any]], str | None] = _none
    outbound_text: Callable[[Any], str | None] = _none
    mutating: bool = field(default=True)


def build_adapters(s: Systems) -> dict[str, ToolAdapter]:
    def docs_read(a: DocsReadArgs, trace: str) -> dict[str, Any]:
        d = s.docs.read(a.doc_id, trace_id=trace)
        return {"doc_id": d.doc_id, "title": d.title, "content": d.content,
                "labels": sorted(label.value for label in d.labels)}

    def crm_get(a: CrmGetArgs, trace: str) -> dict[str, Any]:
        return {"record_id": a.record_id, **s.crm.get(a.record_id, trace_id=trace)}

    def crm_update(a: CrmUpdateArgs, trace: str) -> dict[str, Any]:
        return s.crm.update(a.record_id, a.field, a.value, trace_id=trace)

    def crm_export(_a: CrmExportArgs, trace: str) -> dict[str, Any]:
        rows = s.crm.export(trace_id=trace)
        return {"count": len(rows), "records": rows}

    def crm_bulk_delete(a: CrmBulkDeleteArgs, trace: str) -> dict[str, Any]:
        return {"deleted": s.crm.bulk_delete(a.where_tier, trace_id=trace)}

    def email_send(a: EmailSendArgs, trace: str) -> dict[str, Any]:
        mid = s.mail.send(str(a.to), a.subject, a.body, trace_id=trace)
        return {"status": "sent", "message_id": mid}

    def refund(a: RefundArgs, trace: str) -> dict[str, Any]:
        return s.payments.refund(a.order_id, a.amount, trace_id=trace)

    def canary(_a: NoArgs, trace: str) -> dict[str, Any]:
        return s.canary.run(trace_id=trace)

    def record_text(r: dict[str, Any]) -> str:
        return " ".join(str(v) for k, v in sorted(r.items()) if k != "record_id")

    adapters = [
        ToolAdapter(
            "docs.read", DocsReadArgs, docs_read, mutating=False,
            resource=lambda a: f"doc:{a.doc_id}",
            output_labels=lambda _a, r: {DataLabel(x) for x in r["labels"]},
            output_text=lambda r: r["content"],
        ),
        ToolAdapter(
            "crm.get_record", CrmGetArgs, crm_get, mutating=False,
            resource=lambda a: f"crm:{a.record_id}",
            output_labels=lambda _a, _r: {DataLabel.PII},
            output_text=record_text,
        ),
        ToolAdapter("crm.update_record", CrmUpdateArgs, crm_update,
                    resource=lambda a: f"crm:{a.record_id}"),
        ToolAdapter(
            "crm.export", CrmExportArgs, crm_export, mutating=False,
            resource=lambda _a: "crm:*",
            output_labels=lambda _a, _r: {DataLabel.PII, DataLabel.CONFIDENTIAL},
            output_text=lambda r: " ".join(record_text(x) for x in r["records"]),
        ),
        ToolAdapter("crm.bulk_delete", CrmBulkDeleteArgs, crm_bulk_delete,
                    resource=lambda a: f"crm:tier={a.where_tier}"),
        ToolAdapter(
            "email.send", EmailSendArgs, email_send,
            destination=lambda a: str(a.to),
            outbound_text=lambda a: f"{a.subject}\n{a.body}",
        ),
        ToolAdapter("payments.refund", RefundArgs, refund, resource=lambda a: f"order:{a.order_id}"),
        ToolAdapter("canary.protected_noop", NoArgs, canary, resource=lambda _a: "canary"),
    ]
    return {a.name: a for a in adapters}
