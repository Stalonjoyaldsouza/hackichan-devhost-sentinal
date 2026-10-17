"""Approvals, identity, data-flow tracker and contract validation."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from sentinel import approvals as ap
from sentinel.contracts import DataLabel, ToolCallRequest
from sentinel.dataflow import DataFlowTracker
from sentinel.identity import AuthenticationError, IdentityRegistry, PrincipalKind

APPROVERS = ("human.secops",)


def make(svc: ap.ApprovalService, ttl: int = 60) -> ap.Approval:
    return svc.create(trace_id="t", requester_id="agent.a", run_id="r", tool_name="payments.refund",
                      arguments={"amount": 900}, reason_codes=("X",), policy_version="v",
                      ttl_seconds=ttl)


class TestApprovals:
    def test_grant_then_consume_once(self):
        svc = ap.ApprovalService()
        a = make(svc)
        svc.decide(a.approval_id, approver_id="human.secops", approvers=APPROVERS, grant=True)
        svc.consume(a.approval_id, a.request_hash)
        with pytest.raises(ap.ApprovalError) as e:
            svc.consume(a.approval_id, a.request_hash)
        assert e.value.code == "APPROVAL_ALREADY_USED"

    @pytest.mark.parametrize("approver,code", [
        ("agent.a", "APPROVER_NOT_AUTHORISED"), ("human.other", "APPROVER_NOT_AUTHORISED"),
    ])
    def test_unauthorised_approvers(self, approver, code):
        svc = ap.ApprovalService()
        a = make(svc)
        with pytest.raises(ap.ApprovalError) as e:
            svc.decide(a.approval_id, approver_id=approver, approvers=APPROVERS, grant=True)
        assert e.value.code == code

    def test_self_approval_blocked_even_if_listed(self):
        svc = ap.ApprovalService()
        a = make(svc)
        with pytest.raises(ap.ApprovalError) as e:
            svc.decide(a.approval_id, approver_id="agent.a", approvers=("agent.a",), grant=True)
        assert e.value.code == "SELF_APPROVAL"

    def test_mismatched_request_rejected(self):
        svc = ap.ApprovalService()
        a = make(svc)
        svc.decide(a.approval_id, approver_id="human.secops", approvers=APPROVERS, grant=True)
        other = ap.request_hash("agent.a", "r", "payments.refund", {"amount": 9000})
        with pytest.raises(ap.ApprovalError) as e:
            svc.consume(a.approval_id, other)
        assert e.value.code == "APPROVAL_REQUEST_MISMATCH"

    def test_rejected_cannot_be_consumed(self):
        svc = ap.ApprovalService()
        a = make(svc)
        svc.decide(a.approval_id, approver_id="human.secops", approvers=APPROVERS, grant=False)
        with pytest.raises(ap.ApprovalError) as e:
            svc.consume(a.approval_id, a.request_hash)
        assert e.value.code == "APPROVAL_NOT_GRANTED"

    def test_expired(self, monkeypatch):
        svc = ap.ApprovalService()
        a = make(svc, ttl=1)
        later = a.expires_at + timedelta(seconds=1)
        monkeypatch.setattr(ap, "utcnow", lambda: later)
        with pytest.raises(ap.ApprovalError) as e:
            svc.decide(a.approval_id, approver_id="human.secops", approvers=APPROVERS, grant=True)
        assert e.value.code == "APPROVAL_EXPIRED"

    def test_decision_not_applied_if_audit_fails(self):
        svc = ap.ApprovalService()
        a = make(svc)

        def boom(_):
            raise RuntimeError("audit down")

        with pytest.raises(RuntimeError):
            svc.decide(a.approval_id, approver_id="human.secops", approvers=APPROVERS, grant=True,
                       record=boom)
        assert svc.get(a.approval_id).state is ap.ApprovalState.PENDING


class TestIdentity:
    def test_roundtrip_and_rejection(self):
        reg = IdentityRegistry()
        cred = reg.register("agent.a", PrincipalKind.AGENT, ("r",))
        assert reg.authenticate(cred).principal_id == "agent.a"
        for bad in ("", "nope", cred + "x"):
            with pytest.raises(AuthenticationError):
                reg.authenticate(bad)

    def test_duplicate_registration_rejected(self):
        reg = IdentityRegistry()
        reg.register("agent.a", PrincipalKind.AGENT)
        with pytest.raises(ValueError):
            reg.register("agent.a", PrincipalKind.HUMAN)


CONF = "the board approved an offer of forty two million for the robotics company in december"


class TestDataFlow:
    def test_run_and_actor_taint(self):
        t = DataFlowTracker()
        t.record_execution(actor_id="a", run_id="r1", tool_name="docs.read",
                           output_labels={DataLabel.CONFIDENTIAL}, output_text=CONF, source_event_id="e1")
        same_run = t.labels_for(actor_id="a", run_id="r1", outbound_text="hello")
        new_run = t.labels_for(actor_id="a", run_id="r2", outbound_text="hello")
        other = t.labels_for(actor_id="b", run_id="r3", outbound_text="hello")
        assert {p.mechanism for p in same_run} == {"run_taint", "actor_taint"}
        assert {p.mechanism for p in new_run} == {"actor_taint"}
        assert other == []
        assert t.prior_tools("r1") == ("docs.read",)

    def test_actor_taint_expires(self):
        t = DataFlowTracker(actor_taint_ttl_seconds=-1)
        t.record_execution(actor_id="a", run_id="r1", tool_name="docs.read",
                           output_labels={DataLabel.PII}, output_text=None, source_event_id="e1")
        assert t.labels_for(actor_id="a", run_id="r2", outbound_text=None) == []

    def test_fingerprint_crosses_actors_and_ignores_case_and_punctuation(self):
        t = DataFlowTracker()
        t.record_execution(actor_id="a", run_id="r1", tool_name="docs.read",
                           output_labels={DataLabel.CONFIDENTIAL}, output_text=CONF, source_event_id="e1")
        pasted = "FYI — The Board approved an offer of FORTY-TWO million for the robotics company!"
        hits = t.labels_for(actor_id="b", run_id="r9", outbound_text=pasted)
        assert [(p.label, p.mechanism, p.source_event_id) for p in hits] == [
            (DataLabel.CONFIDENTIAL, "fingerprint", "e1")]

    def test_public_data_not_tracked(self):
        t = DataFlowTracker()
        t.record_execution(actor_id="a", run_id="r1", tool_name="docs.read",
                           output_labels={DataLabel.PUBLIC}, output_text=CONF, source_event_id="e1")
        assert t.labels_for(actor_id="a", run_id="r1", outbound_text=CONF) == []


class TestContracts:
    def test_actor_id_cannot_be_supplied_in_request(self):
        with pytest.raises(ValidationError):
            ToolCallRequest.model_validate({"tool_name": "docs.read", "run_id": "r",
                                            "actor_id": "human.secops"})

    @pytest.mark.parametrize("name", ["", "Docs.Read", "docs read", "../x", "a" * 101])
    def test_tool_name_validated(self, name):
        with pytest.raises(ValidationError):
            ToolCallRequest(tool_name=name, run_id="r")
