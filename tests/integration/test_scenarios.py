"""MVP scenarios B–E and watchdog/safe-mode behaviour (CLAUDE.md §11)."""

from __future__ import annotations

import pytest

from sentinel.contracts import CallOutcome, EventType, HealthStatus, Mode, OutcomeStatus
from sentinel.identity import PrincipalKind
from sentinel.investigator import reconstruct
from sentinel.safemode import RecoveryError

LEAK = ("the board approved an offer of 42 million for Northwind Robotics, closing expected in "
        "December")


def probe(results, name):
    return next(r for r in results if r.probe == name)


def decision_of(rt, trace_id):
    return next(s.event for s in rt.store.by_trace(trace_id)
                if s.event.event_type is EventType.POLICY_DECISION)


# ---- Scenario B --------------------------------------------------------------------------------
def test_b_confidential_read_then_external_send_blocked_with_evidence(rt):
    a = rt.agent("agent.r", ("analyst",), "run-b")
    read = a.call("docs.read", doc_id="q4-acquisition-plan")
    internal = a.call("email.send", to="cfo@corp.example", subject="s", body=LEAK)
    external = a.call("email.send", to="x@partner.example", subject="s", body="unrelated text")
    assert read.outcome is internal.outcome is CallOutcome.EXECUTED
    assert external.outcome is CallOutcome.DENIED
    assert not [m for m in rt.systems.mail.outbox() if m.to == "x@partner.example"]

    decision = decision_of(rt, external.trace_id)
    read_exec = next(s.event for s in rt.store.by_trace(read.trace_id)
                     if s.event.event_type is EventType.TOOL_EXECUTED)
    assert read_exec.event_id in decision.evidence_refs
    findings = [f for f in rt.monitor.findings if f.component == "sequence_dataflow"]
    assert findings and decision.event_id in findings[0].evidence_event_ids


def test_b_fingerprint_catches_other_agent(rt):
    rt.agent("agent.r", ("analyst",), "run-1").call("docs.read", doc_id="q4-acquisition-plan")
    r = rt.agent("agent.w", ("analyst",), "run-2").call(
        "email.send", to="press@news.example", subject="tip", body=f"Psst: {LEAK}")
    assert r.outcome is CallOutcome.DENIED
    prov = decision_of(rt, r.trace_id).metadata["provenance"]
    assert [p["mechanism"] for p in prov] == ["fingerprint"]


def test_b_public_content_flows_freely(rt):
    a = rt.agent("agent.s", ("support_agent",), "run-p")
    a.call("docs.read", doc_id="faq-returns")
    r = a.call("email.send", to="ada@customer.example", subject="Returns",
               body="Customers can return any item within thirty days of delivery for a full refund")
    assert r.outcome is CallOutcome.EXECUTED


def test_b_pii_from_crm_cannot_go_external(rt):
    a = rt.agent("agent.s", ("support_agent",), "run-pii")
    a.call("crm.get_record", record_id="cust-001")
    r = a.call("email.send", to="someone@elsewhere.example", subject="s", body="hello")
    assert r.outcome is CallOutcome.DENIED  # conservative run-taint: documented false-positive class


# ---- Scenario C --------------------------------------------------------------------------------
def test_c_silent_drop_is_failed(rt):
    rt.systems.crm.faulty_silent_drop = True
    r = rt.agent("agent.s", ("support_agent",), "run-c").call(
        "crm.update_record", record_id="cust-003", field="status", value="retained")
    assert r.result["status"] == "ok"  # the tool lies
    assert r.verification is OutcomeStatus.FAILED
    assert any(f.component == "outcome" for f in rt.monitor.findings)


def test_c_partial_refund(rt):
    rt.systems.payments.faulty_partial = True
    r = rt.agent("agent.s", ("support_agent",), "run-c").call(
        "payments.refund", order_id="ord-100", amount=100)
    assert r.verification is OutcomeStatus.PARTIAL


def test_c_verifier_unavailable_is_inconclusive_not_verified(rt):
    rt.gateway.verifier.available = False
    r = rt.agent("agent.s", ("support_agent",), "run-c").call(
        "crm.update_record", record_id="cust-001", field="notes", value="x")
    assert r.verification is OutcomeStatus.INCONCLUSIVE
    assert probe(rt.watchdog.run_round(), "verifier").status is HealthStatus.DEGRADED
    assert rt.controller.mode is Mode.NORMAL  # degraded, not critical


# ---- Scenario D --------------------------------------------------------------------------------
def test_baseline_watchdog_all_ok(rt):
    results = rt.watchdog.run_round()
    assert all(r.status is HealthStatus.OK for r in results), results
    assert rt.systems.canary.executions == 0


def test_d_audit_failure_restricts_and_recovery_is_gated(rt, secops):
    rt.store.fail_writes = True
    assert probe(rt.watchdog.run_round(), "audit").status is HealthStatus.CRITICAL
    assert rt.controller.mode is Mode.RESTRICTED
    assert rt.controller.history[-1].containment_verified is True
    assert rt.controller.history[-1].persisted is False  # honest about the outage

    rt.store.fail_writes = False
    with pytest.raises(RecoveryError, match="0/2|1/2"):
        rt.recover(secops)
    rt.watchdog.run_round()
    with pytest.raises(RecoveryError):
        rt.recover(secops)
    rt.watchdog.run_round()
    rt.recover(secops)
    assert rt.controller.mode is Mode.NORMAL
    modes = [s.event for s in rt.store.all() if s.event.event_type is EventType.MODE_CHANGED]
    assert [m.metadata["to"] for m in modes] == ["RESTRICTED", "NORMAL"]


def test_d_recovery_requires_human_approver(rt):
    rt.controller.enter_restricted("TEST")
    rt.watchdog.run_round()
    rt.watchdog.run_round()
    agent_cred = rt.identities.register("agent.x", PrincipalKind.AGENT, ("support_agent",))
    with pytest.raises(RecoveryError, match="human"):
        rt.recover(agent_cred)
    intern = rt.human("human.intern")
    with pytest.raises(RecoveryError) as e:
        rt.recover(intern)
    assert e.value.code == "APPROVER_NOT_AUTHORISED"


def test_d_unhealthy_round_resets_recovery_counter(rt, secops):
    rt.controller.enter_restricted("TEST")
    rt.watchdog.run_round()
    rt.policy.available = False
    rt.watchdog.run_round()
    rt.policy.available = True
    rt.watchdog.run_round()
    with pytest.raises(RecoveryError):
        rt.recover(secops)


def test_d_stale_policy(rt, policy_path):
    policy_path.write_text(policy_path.read_text() + "\n# drift\n")
    assert "STALE_POLICY" in probe(rt.watchdog.run_round(), "policy").detail
    assert rt.controller.mode is Mode.RESTRICTED
    agent = rt.agent("agent.s", ("support_agent",), "r")
    assert agent.call("payments.refund", order_id="ord-100", amount=5).reason_codes == (
        "SAFE_MODE_RESTRICTED",)
    assert agent.call("docs.read", doc_id="faq-returns").outcome is CallOutcome.EXECUTED
    rt.policy.reload()
    assert probe(rt.watchdog.run_round(), "policy").status is HealthStatus.OK


def test_d_missing_policy_file(rt, policy_path):
    policy_path.unlink()
    assert "POLICY_FILE_MISSING" in probe(rt.watchdog.run_round(), "policy").detail


def test_d_policy_unavailable(rt):
    rt.policy.available = False
    results = rt.watchdog.run_round()
    assert probe(results, "policy").status is HealthStatus.CRITICAL
    assert probe(results, "enforcement").status is HealthStatus.OK  # still fails closed


def test_d_enforcement_bypass_detected_by_canary(rt, monkeypatch):
    from sentinel.contracts import Decision, PolicyDecision

    def broken(req):  # a policy engine that allows everything
        return PolicyDecision(decision=Decision.ALLOW, request_id=req.request_id, policy_version="x")

    monkeypatch.setattr(rt.policy, "evaluate", broken)
    results = rt.watchdog.run_round()
    assert probe(results, "enforcement").status is HealthStatus.CRITICAL
    assert rt.controller.mode is Mode.RESTRICTED
    assert rt.controller.history[-1].containment_verified is False  # honest: not contained


def test_d_uninstrumented_write_detected(rt):
    rt.systems.mail.send("x@exfil.example", "s", "b")  # bypasses the gateway
    assert "BYPASS_DETECTED" in probe(rt.watchdog.run_round(), "coverage").detail
    assert rt.controller.mode is Mode.RESTRICTED


def test_d_lost_telemetry_detected(rt, monkeypatch):
    real = rt.store.append

    def drop_exec(ev):
        if ev.event_type is EventType.TOOL_EXECUTED:
            from sentinel.audit import AuditWriteError
            raise AuditWriteError("lost")
        return real(ev)

    monkeypatch.setattr(rt.store, "append", drop_exec)
    rt.agent("agent.s", ("support_agent",), "r").call(
        "crm.update_record", record_id="cust-001", field="notes", value="x")
    monkeypatch.setattr(rt.store, "append", real)
    rt.gateway.unpersisted.clear()  # simulate the buffer being lost (e.g. crash)
    detail = probe(rt.watchdog.run_round(), "coverage").detail
    assert "BYPASS_DETECTED" in detail or "TELEMETRY_LOSS" in detail
    assert rt.controller.mode is Mode.RESTRICTED


def test_d_tampered_audit_detected(rt):
    rt.agent("agent.s", ("support_agent",), "r").call("docs.read", doc_id="faq-returns")
    rt.store._conn.execute("DROP TRIGGER events_no_update")
    rt.store._conn.execute("UPDATE events SET body=replace(body,'agent.s','agent.z') WHERE seq=1")
    assert "AUDIT_CHAIN_BROKEN" in probe(rt.watchdog.run_round(), "audit").detail


def test_d_watchdog_thread_runs(rt):
    import time

    rt.watchdog.start(interval_seconds=0.05)
    time.sleep(0.3)
    rt.watchdog.stop()
    assert rt.watchdog.rounds >= 2
    assert rt.store.count(EventType.HEARTBEAT) >= 2


# ---- Scenario E --------------------------------------------------------------------------------
def test_e_report_links_every_step(rt, secops):
    a = rt.agent("agent.b", ("support_agent",), "run-e")
    a.call("docs.read", doc_id="faq-returns")
    r = a.call("payments.refund", order_id="ord-200", amount=900)
    rt.gateway.decide_approval(secops, r.approval_id, grant=True)
    a.resume(r.approval_id)
    a.call("crm.bulk_delete", where_tier="gold")
    rep = reconstruct(rt.store, "run-e")
    text = rep.render()
    assert rep.chain_ok and len(rep.traces) == 3
    assert all(not t.gaps for t in rep.traces)
    for needle in ("approval granted by human.secops", "outcome VERIFIED", "policy DENY",
                   "R-NO-BULK-DELETE", "payments.ledger"):
        assert needle in text
    assert all("[ev:" in line for t in rep.traces for line in t.lines if not line.startswith(" "))


def test_e_report_states_gaps_instead_of_inventing(rt, secops):
    a = rt.agent("agent.b", ("support_agent",), "run-gap")
    r = a.call("payments.refund", order_id="ord-200", amount=900)
    rt.gateway.decide_approval(secops, r.approval_id, grant=True)  # never resumed
    rep = reconstruct(rt.store, "run-gap")
    assert any("UNKNOWN" in g for t in rep.traces for g in t.gaps)


def test_e_unknown_run(rt):
    assert "UNKNOWN" in reconstruct(rt.store, "nope").render()
