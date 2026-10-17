"""Gateway / tool-boundary interceptor (CLAUDE.md §5.1) — deterministic.

Pipeline for every call:
  authenticate → validate request → validate tool args → data-flow labels → policy decision
  → audit (MUST persist, else fail closed) → [approval] → execute → audit → verify → audit

Fail-closed rules:
  * bad credential / invalid request / invalid args / unknown tool        → DENY
  * policy engine unavailable or erroring                                 → DENY POLICY_UNAVAILABLE
  * request or decision event cannot be persisted                         → DENY AUDIT_UNAVAILABLE
Once a side effect has happened, later audit failures cannot undo it: the event is kept in an
in-memory `unpersisted` buffer, shown on the terminal, and the watchdog's coverage probe flags it.
"""

from __future__ import annotations

import concurrent.futures
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from sentinel.approvals import Approval, ApprovalError, ApprovalService, request_hash
from sentinel.audit import AuditStore, AuditWriteError
from sentinel.contracts import (
    CallOutcome,
    Decision,
    DecisionRequest,
    EventType,
    ExecutionStatus,
    GatewayResponse,
    Mode,
    OutcomeStatus,
    PolicyDecision,
    SecurityEvent,
    ToolCallRequest,
    new_id,
)
from sentinel.dataflow import DataFlowTracker
from sentinel.identity import AuthenticationError, IdentityRegistry, Principal, PrincipalKind
from sentinel.policy import PolicyEngine, PolicyUnavailable
from sentinel.tools.adapters import ToolAdapter
from sentinel.verification import OutcomeVerifier

Listener = Callable[[SecurityEvent, bool], None]


@dataclass
class GatewayCounters:
    requests: int = 0
    allowed: int = 0
    denied: int = 0
    pending: int = 0
    executed: int = 0
    audit_failures: int = 0


@dataclass
class _Ctx:
    trace_id: str
    principal: Principal | None
    req: ToolCallRequest | None = None
    adapter: ToolAdapter | None = None
    args: Any = None
    resource: str | None = None
    destination: str | None = None
    labels: tuple = ()
    provenance: list = field(default_factory=list)


def _summarise_result(result: dict[str, Any]) -> dict[str, Any]:
    """Keep audit metadata small and free of payloads: keys, ids and sizes only."""
    out: dict[str, Any] = {}
    for k, v in result.items():
        if k in {"message_id", "record_id", "doc_id", "order_id", "status", "count", "deleted",
                 "refunded"}:
            out[k] = v
        elif isinstance(v, str | list | dict):
            out[f"{k}_size"] = len(v)
    return out


class Gateway:
    SYNTHETIC_ACTORS = frozenset({"service.watchdog", "service.containment-probe"})

    def __init__(
        self,
        *,
        identities: IdentityRegistry,
        policy: PolicyEngine,
        store: AuditStore,
        adapters: dict[str, ToolAdapter],
        dataflow: DataFlowTracker,
        approvals: ApprovalService,
        verifier: OutcomeVerifier,
        mode: Callable[[], Mode],
        tool_timeout_seconds: float = 5.0,
    ):
        self.identities = identities
        self.policy = policy
        self.store = store
        self.adapters = adapters
        self.dataflow = dataflow
        self.approvals = approvals
        self.verifier = verifier
        self._mode = mode
        self._timeout = tool_timeout_seconds
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="tool")
        self._lock = threading.Lock()
        self.listeners: list[Listener] = []
        self.counters = GatewayCounters()
        self.executed_traces: set[str] = set()
        self.unpersisted: list[SecurityEvent] = []

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    # ---- event emission ------------------------------------------------------------------
    def emit(self, event: SecurityEvent) -> bool:
        """Persist and broadcast. Returns False (and buffers the event) if persistence failed."""
        try:
            self.store.append(event)
            persisted = True
        except AuditWriteError:
            persisted = False
            with self._lock:
                self.counters.audit_failures += 1
                self.unpersisted.append(event)
        for listener in list(self.listeners):
            try:
                listener(event, persisted)
            except Exception:  # noqa: BLE001,S110 — a broken listener must not break enforcement
                pass
        return persisted

    def flush_unpersisted(self) -> int:
        """Retry persisting buffered events once the audit store is back. Late events keep their
        original id and timestamp and are marked `persisted_late` so the gap stays visible."""
        with self._lock:
            pending, self.unpersisted = self.unpersisted, []
        flushed, failed = 0, []
        for ev in pending:
            try:
                self.store.append(ev.model_copy(update={"metadata": {**ev.metadata,
                                                                     "persisted_late": True}}))
                flushed += 1
            except AuditWriteError:
                failed.append(ev)
        if failed:
            with self._lock:
                self.unpersisted = failed + self.unpersisted
        return flushed

    def _require(self, event: SecurityEvent) -> None:
        if not self.emit(event):
            raise AuditWriteError("required audit event not persisted")

    def _event(self, ctx: _Ctx, event_type: EventType, **kw: Any) -> SecurityEvent:
        actor = ctx.principal.principal_id if ctx.principal else "unauthenticated"
        return SecurityEvent(
            trace_id=ctx.trace_id,
            run_id=ctx.req.run_id if ctx.req else None,
            session_id=ctx.req.session_id if ctx.req else None,
            actor_id=actor,
            event_type=event_type,
            tool_name=ctx.req.tool_name if ctx.req else kw.pop("tool_name", None),
            resource=ctx.resource,
            destination=ctx.destination,
            data_labels=ctx.labels,
            synthetic=actor in self.SYNTHETIC_ACTORS,
            **kw,
        )

    def _deny(self, ctx: _Ctx, reasons: tuple[str, ...], *,
              decision: PolicyDecision | None = None, **meta: Any) -> GatewayResponse:
        """Record and return a DENY. If the audit store is down the event is buffered and shown
        on the terminal as NOT PERSISTED; the deny itself never depends on the write."""
        with self._lock:
            self.counters.denied += 1
        self.emit(self._event(
            ctx, EventType.POLICY_DECISION, policy_decision=Decision.DENY,
            policy_version=decision.policy_version if decision else None,
            reason_codes=reasons, metadata=meta,
        ))
        return GatewayResponse(trace_id=ctx.trace_id, outcome=CallOutcome.DENIED,
                               decision=Decision.DENY, reason_codes=reasons)

    # ---- public API ----------------------------------------------------------------------
    def call(self, credential: str, request: ToolCallRequest | dict[str, Any]) -> GatewayResponse:
        return self._process(credential, request, approval_id=None)

    def resume(self, credential: str, approval_id: str) -> GatewayResponse:
        """Re-submit a request that was approved. Policy is evaluated again at this point."""
        try:
            a = self.approvals.get(approval_id)
        except ApprovalError as exc:
            ctx = _Ctx(new_id(), None)
            return self._deny(ctx, (exc.code,))
        req = ToolCallRequest(tool_name=a.tool_name, arguments=a.arguments, run_id=a.run_id)
        return self._process(credential, req, approval_id=approval_id, trace_id=a.trace_id)

    def decide_approval(self, credential: str, approval_id: str, grant: bool) -> Approval:
        principal = self.identities.authenticate(credential)
        if principal.kind is not PrincipalKind.HUMAN:
            raise ApprovalError("APPROVER_NOT_HUMAN", "only humans may decide approvals")

        def record(a: Approval) -> None:
            self._require(SecurityEvent(
                trace_id=a.trace_id, run_id=a.run_id, actor_id=principal.principal_id,
                parent_actor_id=a.requester_id, tool_name=a.tool_name,
                event_type=EventType.APPROVAL_GRANTED if grant else EventType.APPROVAL_REJECTED,
                policy_decision=Decision.REQUIRE_APPROVAL, policy_version=a.policy_version,
                reason_codes=a.reason_codes, metadata={"approval_id": a.approval_id},
            ))

        return self.approvals.decide(
            approval_id, approver_id=principal.principal_id,
            approvers=self.policy.bundle.approvers, grant=grant, record=record,
        )

    # ---- pipeline ------------------------------------------------------------------------
    def _process(
        self, credential: str, request: ToolCallRequest | dict[str, Any], *,
        approval_id: str | None, trace_id: str | None = None,
    ) -> GatewayResponse:
        ctx = _Ctx(trace_id or new_id(), None)
        with self._lock:
            self.counters.requests += 1

        # 1. identity — never taken from the request
        try:
            ctx.principal = self.identities.authenticate(credential)
        except AuthenticationError:
            return self._deny(ctx, ("AUTHENTICATION_FAILED",))

        # 2. request shape
        try:
            ctx.req = (request if isinstance(request, ToolCallRequest)
                       else ToolCallRequest.model_validate(request))
        except ValidationError as exc:
            return self._deny(ctx, ("INVALID_REQUEST",), errors=_err_locs(exc))

        # 3. tool + arguments
        ctx.adapter = self.adapters.get(ctx.req.tool_name)
        if ctx.adapter is None:
            return self._deny(ctx, ("UNKNOWN_TOOL",))
        try:
            ctx.args = ctx.adapter.args_model.model_validate(ctx.req.arguments)
        except ValidationError as exc:
            return self._deny(ctx, ("INVALID_ARGUMENTS",), errors=_err_locs(exc))
        ctx.resource = ctx.adapter.resource(ctx.args)
        ctx.destination = ctx.adapter.destination(ctx.args)
        canonical_args = ctx.args.model_dump(mode="json")

        # 4. data-flow labels for the outbound data
        ctx.provenance = self.dataflow.labels_for(
            actor_id=ctx.principal.principal_id, run_id=ctx.req.run_id,
            outbound_text=ctx.adapter.outbound_text(ctx.args),
        )
        ctx.labels = tuple(sorted({p.label for p in ctx.provenance}))

        # 5. record the request (fail closed)
        try:
            self._require(self._event(ctx, EventType.TOOL_CALL_REQUESTED,
                                      metadata={"arguments": canonical_args,
                                                "purpose": ctx.req.purpose,
                                                "resumed_approval": approval_id}))
        except AuditWriteError:
            return self._deny(ctx, ("AUDIT_UNAVAILABLE",))

        # 6. deterministic policy decision
        dreq = DecisionRequest(
            request_id=ctx.trace_id, actor_id=ctx.principal.principal_id,
            actor_roles=ctx.principal.roles, tool_name=ctx.req.tool_name,
            arguments=canonical_args, resource=ctx.resource, destination=ctx.destination,
            data_labels=ctx.labels, prior_tools_in_run=self.dataflow.prior_tools(ctx.req.run_id),
            mode=self._mode(),
        )
        try:
            decision = self.policy.evaluate(dreq)
        except PolicyUnavailable:
            return self._deny(ctx, ("POLICY_UNAVAILABLE",))
        except Exception as exc:  # noqa: BLE001 — any engine fault fails closed
            return self._deny(ctx, ("POLICY_ERROR",), error=type(exc).__name__)

        provenance_meta = [
            {"label": p.label.value, "mechanism": p.mechanism, "source_event_id": p.source_event_id}
            for p in ctx.provenance
        ]
        decision_event = self._event(
            ctx, EventType.POLICY_DECISION, policy_decision=decision.decision,
            policy_version=decision.policy_version, reason_codes=decision.reason_codes,
            evidence_refs=tuple(dict.fromkeys(p.source_event_id for p in ctx.provenance)),
            metadata={"matched_rules": list(decision.matched_rules), "mode": dreq.mode.value,
                      "provenance": provenance_meta, "prior_tools": list(dreq.prior_tools_in_run)},
        )
        try:
            self._require(decision_event)
        except AuditWriteError:
            return self._deny(ctx, ("AUDIT_UNAVAILABLE",))

        if decision.decision is Decision.DENY:
            with self._lock:
                self.counters.denied += 1
            return GatewayResponse(trace_id=ctx.trace_id, outcome=CallOutcome.DENIED,
                                   decision=Decision.DENY, reason_codes=decision.reason_codes)

        # 7. human approval
        if decision.decision is Decision.REQUIRE_APPROVAL:
            if approval_id is None:
                return self._request_approval(ctx, decision, canonical_args)
            try:
                self.approvals.consume(
                    approval_id,
                    request_hash(ctx.principal.principal_id, ctx.req.run_id, ctx.req.tool_name,
                                 canonical_args),
                )
            except ApprovalError as exc:
                return self._deny(ctx, (exc.code,), decision=decision, approval_id=approval_id)

        with self._lock:
            self.counters.allowed += 1
        return self._execute(ctx, decision, approval_id)

    def _request_approval(self, ctx: _Ctx, decision: PolicyDecision,
                          args: dict[str, Any]) -> GatewayResponse:
        assert ctx.req and ctx.principal
        a = self.approvals.create(
            trace_id=ctx.trace_id, requester_id=ctx.principal.principal_id, run_id=ctx.req.run_id,
            tool_name=ctx.req.tool_name, arguments=args, reason_codes=decision.reason_codes,
            policy_version=decision.policy_version,
            ttl_seconds=self.policy.bundle.approval_ttl_seconds,
        )
        try:
            self._require(self._event(
                ctx, EventType.APPROVAL_REQUESTED, policy_decision=Decision.REQUIRE_APPROVAL,
                policy_version=decision.policy_version, reason_codes=decision.reason_codes,
                metadata={"approval_id": a.approval_id, "expires_at": a.expires_at.isoformat()},
            ))
        except AuditWriteError:
            return self._deny(ctx, ("AUDIT_UNAVAILABLE",))
        with self._lock:
            self.counters.pending += 1
        return GatewayResponse(trace_id=ctx.trace_id, outcome=CallOutcome.PENDING_APPROVAL,
                               decision=Decision.REQUIRE_APPROVAL,
                               reason_codes=decision.reason_codes, approval_id=a.approval_id)

    def _execute(self, ctx: _Ctx, decision: PolicyDecision,
                 approval_id: str | None) -> GatewayResponse:
        assert ctx.req and ctx.adapter and ctx.principal
        adapter, args = ctx.adapter, ctx.args
        before = self.verifier.snapshot(adapter.name, args) if self.verifier.available else {}

        result: dict[str, Any] | None = None
        error: str | None = None
        future = self._pool.submit(adapter.execute, args, ctx.trace_id)
        try:
            result = future.result(timeout=self._timeout)
            status = ExecutionStatus.SUCCEEDED
        except concurrent.futures.TimeoutError:
            # The call may still complete in the background; outcome is genuinely unknown.
            status, error = ExecutionStatus.UNKNOWN, "TOOL_TIMEOUT"
        except Exception as exc:  # noqa: BLE001 — tool failures are recorded, not raised
            status, error = ExecutionStatus.FAILED, f"{type(exc).__name__}: {exc}"[:200]

        with self._lock:
            self.counters.executed += 1
            self.executed_traces.add(ctx.trace_id)
        exec_event = self._event(
            ctx, EventType.TOOL_EXECUTED, policy_decision=decision.decision,
            policy_version=decision.policy_version, reason_codes=decision.reason_codes,
            execution_status=status,
            metadata={"result": _summarise_result(result or {}), "error": error,
                      "approval_id": approval_id},
        )
        self.emit(exec_event)  # side effect already happened: never fail the call here

        if status is ExecutionStatus.SUCCEEDED and result is not None:
            self.dataflow.record_execution(
                actor_id=ctx.principal.principal_id, run_id=ctx.req.run_id,
                tool_name=adapter.name, output_labels=adapter.output_labels(args, result),
                output_text=adapter.output_text(result), source_event_id=exec_event.event_id,
            )

        verification: OutcomeStatus | None = None
        if status in (ExecutionStatus.SUCCEEDED, ExecutionStatus.UNKNOWN):
            outcome = self.verifier.verify(trace_id=ctx.trace_id, tool_name=adapter.name,
                                           args=args, result=result, before=before)
            if status is ExecutionStatus.UNKNOWN and outcome.status is OutcomeStatus.FAILED:
                # A timed-out call may still land; absence of change is not yet proof of failure.
                outcome = outcome.model_copy(update={
                    "status": OutcomeStatus.INCONCLUSIVE,
                    "discrepancies": (*outcome.discrepancies, "tool timed out; may still complete"),
                })
            verification = outcome.status
            self.emit(self._event(
                ctx, EventType.OUTCOME_VERIFIED, execution_status=status,
                evidence_refs=(exec_event.event_id,),
                metadata={"outcome": outcome.status.value, "evidence": outcome.evidence,
                          "discrepancies": list(outcome.discrepancies)},
            ))

        return GatewayResponse(
            trace_id=ctx.trace_id,
            outcome=CallOutcome.EXECUTED if status is ExecutionStatus.SUCCEEDED else CallOutcome.ERROR,
            decision=decision.decision, reason_codes=decision.reason_codes
            + ((error,) if error else ()),
            result=result, verification=verification,
        )


def _err_locs(exc: ValidationError) -> list[str]:
    """Field locations and error types only — never the offending values."""
    return [f"{'.'.join(str(p) for p in e['loc'])}:{e['type']}" for e in exc.errors()][:10]


class GatewayClient:
    """The only handle an agent receives. It carries a credential, never tool objects."""

    def __init__(self, gateway: Gateway, credential: str, run_id: str):
        self._gw = gateway
        self._cred = credential
        self.run_id = run_id

    def call(self, tool_name: str, purpose: str | None = None, **arguments: Any) -> GatewayResponse:
        return self._gw.call(self._cred, {"tool_name": tool_name, "arguments": arguments,
                                          "run_id": self.run_id, "purpose": purpose})

    def resume(self, approval_id: str) -> GatewayResponse:
        return self._gw.resume(self._cred, approval_id)
