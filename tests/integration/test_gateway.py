"""Gateway → policy → execution → audit, including fail-closed paths."""

from __future__ import annotations

import time

import pytest

from sentinel.approvals import ApprovalError
from sentinel.contracts import CallOutcome, EventType, ExecutionStatus, Mode, OutcomeStatus
from sentinel.identity import PrincipalKind


def types(rt, trace_id):
    return [s.event.event_type for s in rt.store.by_trace(trace_id)]


def test_allowed_call_full_audit_trail_in_order(rt):
    agent = rt.agent("agent.s", ("support_agent",), "run-1")
    r = agent.call("crm.update_record", record_id="cust-001", field="notes", value="hi")
    assert r.outcome is CallOutcome.EXECUTED and r.verification is OutcomeStatus.VERIFIED
    assert types(rt, r.trace_id) == [EventType.TOOL_CALL_REQUESTED, EventType.POLICY_DECISION,
                                     EventType.TOOL_EXECUTED, EventType.OUTCOME_VERIFIED]
    decision = rt.store.by_trace(r.trace_id)[1].event
    assert decision.actor_id == "agent.s" and decision.policy_version == rt.policy.version


def test_scenario_a_denied_tool_never_reaches_target(rt):
    agent = rt.agent("agent.s", ("support_agent",), "run-a")
    before = (rt.systems.crm.size(), len(rt.systems.crm.access_log()))
    r = agent.call("crm.bulk_delete", where_tier="gold")
    assert r.outcome is CallOutcome.DENIED and r.reason_codes == ("DESTRUCTIVE_BULK_OPERATION",)
    assert (rt.systems.crm.size(), len(rt.systems.crm.access_log())) == before
    assert EventType.TOOL_EXECUTED not in types(rt, r.trace_id)
    decision = rt.store.by_trace(r.trace_id)[-1].event
    assert decision.metadata["matched_rules"] == ["R-NO-BULK-DELETE"]


def test_bad_credential_denied_and_recorded(rt):
    r = rt.gateway.call("forged", {"tool_name": "docs.read", "arguments": {"doc_id": "x"},
                                   "run_id": "r"})
    assert r.outcome is CallOutcome.DENIED and r.reason_codes == ("AUTHENTICATION_FAILED",)
    assert rt.store.by_trace(r.trace_id)[0].event.actor_id == "unauthenticated"


def test_actor_spoofing_field_rejected(rt):
    cred = rt.identities.register("agent.s", PrincipalKind.AGENT, ("support_agent",))
    r = rt.gateway.call(cred, {"tool_name": "docs.read", "arguments": {"doc_id": "faq-returns"},
                               "run_id": "r", "actor_id": "human.secops"})
    assert r.reason_codes == ("INVALID_REQUEST",)


@pytest.mark.parametrize("args", [
    {"record_id": "cust-001", "field": "tier", "value": "x", "extra": 1},
    {"record_id": "../../etc", "field": "tier", "value": "x"},
    {"record_id": "cust-001", "field": "tier", "value": "x" * 501},
    {"record_id": "cust-001"},
])
def test_invalid_arguments_rejected_before_execution(rt, args):
    agent = rt.agent("agent.s", ("support_agent",), "r")
    n = len(rt.systems.crm.access_log())
    r = agent.call("crm.update_record", **args)
    assert r.reason_codes == ("INVALID_ARGUMENTS",)
    assert len(rt.systems.crm.access_log()) == n


def test_invalid_argument_values_not_logged(rt):
    agent = rt.agent("agent.s", ("support_agent",), "r")
    r = agent.call("email.send", to="not-an-email", subject="s", body="secret-ish body")
    ev = rt.store.by_trace(r.trace_id)[-1].event
    assert "secret-ish" not in ev.model_dump_json()


def test_unknown_tool(rt):
    r = rt.agent("agent.s", ("support_agent",), "r").call("shell.exec", cmd="rm -rf /")
    assert r.reason_codes == ("UNKNOWN_TOOL",)


def test_policy_unavailable_fails_closed(rt):
    rt.policy.available = False
    agent = rt.agent("agent.s", ("support_agent",), "r")
    r = agent.call("crm.update_record", record_id="cust-001", field="notes", value="x")
    assert r.reason_codes == ("POLICY_UNAVAILABLE",)
    assert not [e for e in rt.systems.crm.access_log() if e.mutating]


def test_policy_crash_fails_closed(rt, monkeypatch):
    def boom(_):
        raise ZeroDivisionError

    monkeypatch.setattr(rt.policy, "evaluate", boom)
    r = rt.agent("agent.s", ("support_agent",), "r").call("docs.read", doc_id="faq-returns")
    assert r.reason_codes == ("POLICY_ERROR",)


def test_audit_failure_fails_closed_and_buffers(rt):
    rt.store.fail_writes = True
    agent = rt.agent("agent.s", ("support_agent",), "r")
    r = agent.call("crm.update_record", record_id="cust-001", field="notes", value="x")
    assert r.reason_codes == ("AUDIT_UNAVAILABLE",)
    assert not [e for e in rt.systems.crm.access_log() if e.mutating]
    assert rt.gateway.unpersisted  # visible, not silently dropped
    rt.store.fail_writes = False
    assert rt.gateway.flush_unpersisted() >= 2
    late = [s.event for s in rt.store.by_trace(r.trace_id)]
    assert late and all(e.metadata.get("persisted_late") for e in late)


def test_tool_exception_recorded_as_failed(rt):
    agent = rt.agent("agent.s", ("support_agent",), "r")
    r = agent.call("crm.update_record", record_id="cust-999", field="notes", value="x")
    assert r.outcome is CallOutcome.ERROR
    ex = next(s.event for s in rt.store.by_trace(r.trace_id)
              if s.event.event_type is EventType.TOOL_EXECUTED)
    assert ex.execution_status is ExecutionStatus.FAILED and "KeyError" in ex.metadata["error"]


def test_tool_timeout_is_unknown_not_failed(tmp_path, policy_path):
    from sentinel.runtime import Runtime

    rt = Runtime.build(tmp_path / "t.db", policy_path, tool_timeout_seconds=0.05)
    try:
        original = rt.systems.crm.update

        def slow(*a, **k):
            time.sleep(0.3)
            return original(*a, **k)

        rt.systems.crm.update = slow
        r = rt.agent("agent.s", ("support_agent",), "r").call(
            "crm.update_record", record_id="cust-001", field="notes", value="late")
        assert r.outcome is CallOutcome.ERROR and "TOOL_TIMEOUT" in r.reason_codes
        assert r.verification is OutcomeStatus.INCONCLUSIVE
    finally:
        rt.close()


class TestApprovalFlow:
    def test_full_flow(self, rt, secops):
        agent = rt.agent("agent.b", ("support_agent",), "r")
        r = agent.call("payments.refund", order_id="ord-200", amount=900)
        assert r.outcome is CallOutcome.PENDING_APPROVAL
        assert rt.systems.payments.peek("ord-200")["refunded"] == 0
        early = agent.resume(r.approval_id)
        assert early.reason_codes == ("APPROVAL_NOT_GRANTED",)
        rt.gateway.decide_approval(secops, r.approval_id, grant=True)
        done = agent.resume(r.approval_id)
        assert done.outcome is CallOutcome.EXECUTED and done.verification is OutcomeStatus.VERIFIED
        assert rt.systems.payments.peek("ord-200")["refunded"] == 900
        assert EventType.APPROVAL_GRANTED in types(rt, r.trace_id)

    def test_agent_cannot_approve(self, rt):
        cred = rt.identities.register("agent.b", PrincipalKind.AGENT, ("support_agent",))
        r = rt.gateway.call(cred, {"tool_name": "payments.refund", "run_id": "r",
                                   "arguments": {"order_id": "ord-200", "amount": 900}})
        with pytest.raises(ApprovalError) as e:
            rt.gateway.decide_approval(cred, r.approval_id, grant=True)
        assert e.value.code == "APPROVER_NOT_HUMAN"

    def test_non_listed_human_cannot_approve(self, rt):
        intern = rt.human("human.intern")
        agent = rt.agent("agent.b", ("support_agent",), "r")
        r = agent.call("payments.refund", order_id="ord-200", amount=900)
        with pytest.raises(ApprovalError):
            rt.gateway.decide_approval(intern, r.approval_id, grant=True)

    def test_other_agent_cannot_use_approval(self, rt, secops):
        a = rt.agent("agent.b", ("support_agent",), "r")
        thief = rt.agent("agent.thief", ("support_agent",), "r")
        r = a.call("payments.refund", order_id="ord-200", amount=900)
        rt.gateway.decide_approval(secops, r.approval_id, grant=True)
        stolen = thief.resume(r.approval_id)
        assert stolen.reason_codes == ("APPROVAL_REQUEST_MISMATCH",)
        assert rt.systems.payments.peek("ord-200")["refunded"] == 0

    def test_policy_reevaluated_at_resume(self, rt, secops):
        agent = rt.agent("agent.b", ("support_agent",), "r")
        r = agent.call("payments.refund", order_id="ord-200", amount=900)
        rt.gateway.decide_approval(secops, r.approval_id, grant=True)
        rt.controller.enter_restricted("TEST")
        resumed = agent.resume(r.approval_id)
        assert resumed.reason_codes == ("SAFE_MODE_RESTRICTED",)
        assert rt.systems.payments.peek("ord-200")["refunded"] == 0
        assert rt.controller.mode is Mode.RESTRICTED
