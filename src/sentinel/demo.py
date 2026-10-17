"""Scripted, deterministic demo of the MVP scenarios (CLAUDE.md §11).

The "agents" here are scripted clients, not LLMs. Each scenario prints live events and then
CHECK lines that assert the security property against independent state.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.contracts import CallOutcome, HealthStatus, Mode, OutcomeStatus
from sentinel.investigator import reconstruct
from sentinel.runtime import DEFAULT_POLICY, Runtime
from sentinel.safemode import RecoveryError
from sentinel.termlog import BOLD, GREEN, RED, YELLOW, TerminalLog

LEAK_TEXT = (
    "FYI from the planning doc: the board approved an offer of 42 million for Northwind Robotics, "
    "closing expected in December."
)


@dataclass
class Demo:
    rt: Runtime
    log: TerminalLog
    secops: str = ""  # credential of the human approver
    checks: list[tuple[str, str, bool]] = field(default_factory=list)
    scenario: str = ""

    def check(self, label: str, ok: bool) -> bool:
        self.checks.append((self.scenario, label, ok))
        mark = self.log.s("✔ CHECK", BOLD, GREEN) if ok else self.log.s("✘ CHECK", BOLD, RED)
        self.log.write(f"   {mark} {label}")
        return ok

    def health_round(self) -> list:
        results = self.rt.watchdog.run_round()
        bad = [r for r in results if r.status is not HealthStatus.OK]
        summary = "all controls OK" if not bad else ", ".join(f"{r.probe}={r.status.value}" for r in bad)
        color = GREEN if not bad else (RED if any(r.status is HealthStatus.CRITICAL for r in bad)
                                       else YELLOW)
        self.log.write(f"   {self.log.s('♥ WATCHDOG', BOLD, color)} round {self.rt.watchdog.rounds}:"
                       f" {summary}  mode={self.rt.controller.mode.value}")
        return results


# ---- scenarios -----------------------------------------------------------------------------
def baseline(d: Demo) -> None:
    d.log.banner("Baseline — allowed work is allowed, executed and verified")
    agent = d.rt.agent("agent.support", ("support_agent",), run_id="run-baseline")
    r1 = agent.call("docs.read", purpose="answer a returns question", doc_id="faq-returns")
    r2 = agent.call("crm.update_record", record_id="cust-002", field="notes",
                    value="Customer asked about returns; sent FAQ.")
    d.check("FAQ read allowed", r1.outcome is CallOutcome.EXECUTED)
    d.check("CRM note update executed and independently VERIFIED by read-back",
            r2.outcome is CallOutcome.EXECUTED and r2.verification is OutcomeStatus.VERIFIED)


def scenario_a(d: Demo) -> None:
    d.log.banner("Scenario A — prohibited action blocked before execution")
    agent = d.rt.agent("agent.cleanup", ("support_agent",), run_id="run-A")
    size_before = d.rt.systems.crm.size()
    log_before = len(d.rt.systems.crm.access_log())
    r = agent.call("crm.bulk_delete", purpose="tidy up old records", where_tier="gold")
    d.check("decision is DENY with rule R-NO-BULK-DELETE",
            r.outcome is CallOutcome.DENIED and "DESTRUCTIVE_BULK_OPERATION" in r.reason_codes)
    d.check("side effect did not occur (CRM record count unchanged)",
            d.rt.systems.crm.size() == size_before)
    d.check("target system never received the call (its own access log is unchanged)",
            len(d.rt.systems.crm.access_log()) == log_before)
    r2 = agent.call("crm.update_record", record_id="cust-001", field="tier; DROP TABLE", value="x")
    d.check("malformed arguments rejected at the boundary (INVALID_ARGUMENTS)",
            r2.outcome is CallOutcome.DENIED and "INVALID_ARGUMENTS" in r2.reason_codes)


def scenario_b(d: Demo) -> None:
    d.log.banner("Scenario B — individually allowed steps that form a prohibited data flow")
    analyst = d.rt.agent("agent.research", ("analyst",), run_id="run-B")
    r1 = analyst.call("docs.read", purpose="prepare internal briefing", doc_id="q4-acquisition-plan")
    r2 = analyst.call("email.send", to="cfo@corp.example", subject="Briefing", body=LEAK_TEXT)
    r3 = analyst.call("email.send", to="contact@northwind-robotics.example",
                      subject="Quick heads-up", body=LEAK_TEXT)
    d.check("step 1: reading the confidential plan is allowed", r1.outcome is CallOutcome.EXECUTED)
    d.check("step 2: sending it to an internal address is allowed", r2.outcome is CallOutcome.EXECUTED)
    d.check("step 3: sending it outside corp.example is DENIED by data-flow rule",
            r3.outcome is CallOutcome.DENIED
            and "SENSITIVE_DATA_TO_UNAPPROVED_DESTINATION" in r3.reason_codes)
    external = [m for m in d.rt.systems.mail.outbox() if m.to.endswith("northwind-robotics.example")]
    d.check("no message reached the external domain (mail outbox read-back)", not external)

    d.log.note("A different agent in a different run, which never read the document, now tries "
               "to send pasted content — the content fingerprint still carries the label.")
    writer = d.rt.agent("agent.writer", ("analyst",), run_id="run-B2")
    r4 = writer.call("email.send", to="press@newswire.example", subject="Tip", body=LEAK_TEXT)
    d.check("cross-agent leak via copied content is DENIED (fingerprint provenance)",
            r4.outcome is CallOutcome.DENIED)
    decision = next(s.event for s in d.rt.store.by_trace(r4.trace_id)
                    if s.event.event_type.value == "policy_decision")
    d.check("deny decision links back to the originating read event",
            bool(decision.evidence_refs)
            and d.rt.store.get(decision.evidence_refs[0]).event.tool_name == "docs.read")

    d.log.note("Sequence rule: an export followed by an external email in the same run.")
    exporter = d.rt.agent("agent.export", ("analyst",), run_id="run-B3")
    exporter.call("crm.export", purpose="quarterly analysis")
    r5 = exporter.call("email.send", to="someone@gmail.example", subject="numbers", body="see attached")
    d.check("export → external send is DENIED even though the body has no copied data",
            r5.outcome is CallOutcome.DENIED and "EXPORT_FOLLOWED_BY_EXTERNAL_SEND" in r5.reason_codes)


def scenario_approval(d: Demo) -> None:
    d.log.banner("Approval path — high-value refund needs a human")
    agent = d.rt.agent("agent.billing", ("support_agent",), run_id="run-APPROVAL")
    r = agent.call("payments.refund", purpose="customer complaint", order_id="ord-200", amount=900)
    d.check("refund above threshold is held for approval",
            r.outcome is CallOutcome.PENDING_APPROVAL and r.approval_id is not None)
    d.check("nothing refunded while pending", d.rt.systems.payments.peek("ord-200")["refunded"] == 0)
    assert r.approval_id
    d.rt.gateway.decide_approval(d.secops, r.approval_id, grant=True)
    r2 = agent.resume(r.approval_id)
    d.check("after approval the refund executes and is VERIFIED against the ledger",
            r2.outcome is CallOutcome.EXECUTED and r2.verification is OutcomeStatus.VERIFIED)
    r3 = agent.resume(r.approval_id)
    d.check("replaying the same approval is refused (single-use)",
            r3.outcome is CallOutcome.DENIED and "APPROVAL_ALREADY_USED" in r3.reason_codes)


def scenario_c(d: Demo) -> None:
    d.log.banner("Scenario C — tool claims success, target state disagrees")
    agent = d.rt.agent("agent.accounts", ("support_agent",), run_id="run-C")
    d.rt.systems.crm.faulty_silent_drop = True
    r = agent.call("crm.update_record", record_id="cust-003", field="status", value="retained")
    d.rt.systems.crm.faulty_silent_drop = False
    d.check("tool response looked successful", (r.result or {}).get("status") == "ok")
    d.check("independent read-back marks it FAILED, not success",
            r.verification is OutcomeStatus.FAILED)
    d.rt.systems.payments.faulty_partial = True
    r2 = agent.call("payments.refund", order_id="ord-100", amount=100)
    d.rt.systems.payments.faulty_partial = False
    d.check("half-applied refund is marked PARTIAL from the ledger",
            r2.verification is OutcomeStatus.PARTIAL)


def scenario_d(d: Demo, policy_path: Path) -> None:
    d.log.banner("Scenario D — critical controls fail; safe mode contains and recovers")
    rt = d.rt
    agent = rt.agent("agent.ops", ("support_agent",), run_id="run-D")

    d.log.note("D1: audit persistence fails.")
    rt.store.fail_writes = True
    d.health_round()
    d.check("watchdog detected audit failure and entered RESTRICTED",
            rt.controller.mode is Mode.RESTRICTED)
    last = rt.controller.history[-1]
    d.check("containment was verified by a live probe (protected call refused, target untouched)",
            last.containment_verified is True)
    r = agent.call("crm.update_record", record_id="cust-001", field="notes", value="during outage")
    d.check("protected write refused while audit is down", r.outcome is CallOutcome.DENIED)
    r_read = agent.call("docs.read", doc_id="faq-returns")
    d.check("reads also refused: nothing may run unaudited", r_read.outcome is CallOutcome.DENIED)
    rt.store.fail_writes = False
    try:
        rt.recover(d.secops)
        d.check("early recovery is refused", False)
    except RecoveryError as exc:
        d.check(f"early recovery refused ({exc.code})", exc.code == "HEALTH_NOT_RESTORED")
    d.health_round()
    d.health_round()
    rt.recover(d.secops)
    d.check("recovered to NORMAL after 2 healthy rounds + human override",
            rt.controller.mode is Mode.NORMAL)
    d.check("safe-mode transitions buffered during the outage were persisted afterwards",
            not rt.gateway.unpersisted)

    d.log.note("D2: policy file changes on disk but the running engine was not reloaded (stale).")
    original = policy_path.read_text()
    policy_path.write_text(original + "\n# edited out-of-band\n")
    d.health_round()
    d.check("stale policy detected → RESTRICTED", rt.controller.mode is Mode.RESTRICTED)
    r = agent.call("payments.refund", order_id="ord-100", amount=5)
    d.check("refunds blocked in RESTRICTED mode (SAFE_MODE_RESTRICTED)",
            r.outcome is CallOutcome.DENIED and "SAFE_MODE_RESTRICTED" in r.reason_codes)
    r2 = agent.call("docs.read", doc_id="faq-returns")
    d.check("explicitly safe read-only tool still works in RESTRICTED",
            r2.outcome is CallOutcome.EXECUTED)
    policy_path.write_text(original)
    d.health_round()
    d.health_round()
    rt.recover(d.secops)
    d.check("recovered after policy restored and re-verified", rt.controller.mode is Mode.NORMAL)

    d.log.note("D3: something writes to a target system without going through the gateway.")
    rt.systems.mail.send("dropbox@exfil.example", "raw", "uninstrumented path")
    results = d.health_round()
    cov = next(x for x in results if x.probe == "coverage")
    d.check("bypass detected by reconciling the mail system's own log with the audit trail",
            "BYPASS_DETECTED" in cov.detail and rt.controller.mode is Mode.RESTRICTED)
    d.log.note("The system stays RESTRICTED: an unexplained write needs human investigation. "
               "(Acknowledgement workflow is not implemented in the MVP.)")


def scenario_e(d: Demo, run_id: str = "run-B") -> None:
    d.log.banner(f"Scenario E — audit reconstruction for {run_id}")
    report = reconstruct(d.rt.store, run_id)
    for line in report.render().splitlines():
        d.log.write("   " + line)
    d.check("audit hash chain verifies", report.chain_ok)
    d.check("timeline covers every trace in the run with no unexplained gaps",
            bool(report.traces) and all(not t.gaps for t in report.traces))


SCENARIOS: dict[str, Callable[..., None]] = {
    "baseline": baseline, "A": scenario_a, "B": scenario_b, "approval": scenario_approval,
    "C": scenario_c, "D": scenario_d, "E": scenario_e,
}


def run(selected: list[str], db_path: Path, log: TerminalLog) -> list[tuple[str, str, bool]]:
    workdir = Path(tempfile.mkdtemp(prefix="sentinel-policy-"))
    policy_path = workdir / "policy.yaml"
    shutil.copy(DEFAULT_POLICY, policy_path)  # D2 edits this copy, never the repo file
    rt = Runtime.build(db_path, policy_path, listeners=[log])
    d = Demo(rt, log, secops=rt.human("human.secops"))
    try:
        log.banner(f"Sentinel MVP demo  audit_db={db_path}  policy={rt.policy.version}", BOLD)
        log.note("Agents are scripted and tools are in-memory mocks; nothing external is called.")
        d.scenario = "startup"
        d.health_round()
        order = ["baseline", "A", "B", "approval", "C", "E", "D"]
        for name in order:
            if name not in selected:
                continue
            d.scenario = name
            if name == "D":
                scenario_d(d, policy_path)
            elif name == "E" and "B" not in selected:
                scenario_b(d)
                scenario_e(d)
            else:
                SCENARIOS[name](d)
    finally:
        rt.close()
        shutil.rmtree(workdir, ignore_errors=True)

    passed = sum(ok for *_, ok in d.checks)
    log.banner(f"Result: {passed}/{len(d.checks)} checks passed",
               GREEN if passed == len(d.checks) else RED)
    for scen, label, ok in d.checks:
        if not ok:
            log.write(log.s(f"   FAILED [{scen}] {label}", RED))
    log.note(f"Inspect later:  sentinel audit report --db {db_path} --run run-B")
    return d.checks
