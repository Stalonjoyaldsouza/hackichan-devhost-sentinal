"""Independent outcome verification (CLAUDE.md §5.6).

The verifier never looks at the tool's natural-language or success-shaped response to decide an
outcome. It snapshots target-system state *before* execution and reads it back *after*, then
compares the observed change to the intended operation.

VERIFIED      state changed exactly as intended
PARTIAL       some but not all of the intended change is present
FAILED        intended change absent (or wrong) despite the call
INCONCLUSIVE  no independent evidence source, or verifier unavailable
"""

from __future__ import annotations

import hashlib
from typing import Any

from sentinel.contracts import OutcomeResult, OutcomeStatus
from sentinel.tools.systems import Systems


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


SELFTEST_DOC = "sentinel-selftest"
SELFTEST_SHA = _sha("sentinel verifier self test fixture v1")


class OutcomeVerifier:
    def __init__(self, systems: Systems):
        self._s = systems
        # Fault-injection switch for control-validation tests/demos (Scenario D).
        self.available = True

    # ---- pre-execution snapshot ------------------------------------------------------------
    def snapshot(self, tool_name: str, args: Any) -> dict[str, Any]:
        s = self._s
        match tool_name:
            case "crm.update_record":
                rec = s.crm.peek(args.record_id)
                return {"exists": rec is not None, "value": (rec or {}).get(args.field)}
            case "payments.refund":
                o = s.payments.peek(args.order_id)
                return {"refunded": o["refunded"] if o else None}
            case "crm.bulk_delete":
                return {"size": s.crm.size()}
            case "email.send":
                return {"outbox": len(s.mail.outbox())}
        return {}

    # ---- post-execution check --------------------------------------------------------------
    def verify(
        self, *, trace_id: str, tool_name: str, args: Any, result: dict[str, Any] | None,
        before: dict[str, Any],
    ) -> OutcomeResult:
        def out(status: OutcomeStatus, evidence: dict[str, Any], *disc: str) -> OutcomeResult:
            return OutcomeResult(status=status, trace_id=trace_id, tool_name=tool_name,
                                 evidence=evidence, discrepancies=tuple(disc))

        if not self.available:
            return out(OutcomeStatus.INCONCLUSIVE, {}, "outcome verifier unavailable")
        s, result = self._s, result or {}
        try:
            match tool_name:
                case "crm.update_record":
                    rec = s.crm.peek(args.record_id)
                    observed = (rec or {}).get(args.field)
                    ev = {"source": "crm.read_back", "record_id": args.record_id,
                          "field": args.field, "before": before.get("value"), "observed": observed,
                          "intended": args.value}
                    if observed == args.value:
                        return out(OutcomeStatus.VERIFIED, ev)
                    return out(OutcomeStatus.FAILED, ev,
                               f"{args.field} is {observed!r}, expected {args.value!r}")
                case "payments.refund":
                    o = s.payments.peek(args.order_id)
                    delta = (o["refunded"] if o else 0.0) - (before.get("refunded") or 0.0)
                    ev = {"source": "payments.ledger", "order_id": args.order_id,
                          "intended": args.amount, "observed_delta": delta}
                    if abs(delta - args.amount) < 1e-9:
                        return out(OutcomeStatus.VERIFIED, ev)
                    if delta > 0:
                        return out(OutcomeStatus.PARTIAL, ev,
                                   f"ledger shows {delta} refunded, expected {args.amount}")
                    return out(OutcomeStatus.FAILED, ev, "no refund recorded in ledger")
                case "email.send":
                    mid = result.get("message_id")
                    msg = s.mail.peek(mid) if isinstance(mid, str) else None
                    ev = {"source": "mail.outbox", "message_id": mid}
                    if msg is None:
                        return out(OutcomeStatus.FAILED, ev, "message not present in outbox")
                    ev |= {"to": msg.to, "body_sha": _sha(msg.body)}
                    if msg.to == str(args.to) and msg.body == args.body:
                        return out(OutcomeStatus.VERIFIED, ev)
                    return out(OutcomeStatus.PARTIAL, ev, "outbox message differs from request")
                case "crm.bulk_delete":
                    delta = before.get("size", 0) - s.crm.size()
                    ev = {"source": "crm.count", "claimed": result.get("deleted"), "observed": delta}
                    if delta == result.get("deleted"):
                        return out(OutcomeStatus.VERIFIED, ev)
                    return out(OutcomeStatus.FAILED, ev, "deleted count does not match claim")
                case "docs.read":
                    doc = s.docs.peek(args.doc_id)
                    ev = {"source": "docs.read_back", "doc_id": args.doc_id}
                    if doc and _sha(doc.content) == _sha(str(result.get("content", ""))):
                        return out(OutcomeStatus.VERIFIED, ev)
                    return out(OutcomeStatus.FAILED, ev, "returned content differs from store")
                case "crm.get_record" | "crm.export":
                    return out(OutcomeStatus.VERIFIED, {"source": "read-only operation"})
        except Exception as exc:  # noqa: BLE001 — evidence collection failure is not success
            return out(OutcomeStatus.INCONCLUSIVE, {}, f"evidence collection failed: {exc}")
        return out(OutcomeStatus.INCONCLUSIVE, {}, "no independent evidence source for tool")

    def self_test(self) -> bool:
        """Known-answer test used by the watchdog."""
        if not self.available:
            return False
        doc = self._s.docs.peek(SELFTEST_DOC)
        return doc is not None and _sha(doc.content) == SELFTEST_SHA
