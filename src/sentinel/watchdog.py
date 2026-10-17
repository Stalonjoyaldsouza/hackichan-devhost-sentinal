"""Independent health watchdog / continuous control validation (CLAUDE.md §5.8) — deterministic.

Probes test *behaviour*, not self-reported status:

policy        engine answers; loaded digest == digest on disk (else STALE); canary request is DENIED
audit         write a probe event, read it back by id, verify the whole hash chain
enforcement   send a canary call through the real gateway; it must be denied AND not executed
coverage      every mutating entry in the target systems' own access logs maps to an audited
              execution (bypass detection), and every execution the gateway performed was audited
              (telemetry loss detection)
verifier      known-answer self-test against fixture state

Any CRITICAL probe requests RESTRICTED mode from the safe-mode controller.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from sentinel.audit import AuditStore, AuditWriteError
from sentinel.contracts import (
    CallOutcome,
    DecisionRequest,
    EventType,
    HealthStatus,
    Mode,
    ProbeResult,
    SecurityEvent,
    new_id,
)
from sentinel.gateway import Gateway
from sentinel.policy import PolicyUnavailable
from sentinel.safemode import SafeModeController
from sentinel.tools.systems import Systems

ACTOR = "service.watchdog"
CANARY_TOOL = "canary.protected_noop"


class Watchdog:
    def __init__(
        self, *, gateway: Gateway, store: AuditStore, systems: Systems,
        controller: SafeModeController, credential: str,
    ):
        self.gw = gateway
        self.store = store
        self.systems = systems
        self.controller = controller
        self._cred = credential
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_results: list[ProbeResult] = []
        self.rounds = 0
        self.on_round: Callable[[list[ProbeResult]], None] | None = None

    # ---- probes ----------------------------------------------------------------------------
    def probe_policy(self) -> ProbeResult:
        engine = self.gw.policy
        try:
            version = engine.version
            canary = engine.evaluate(DecisionRequest(
                request_id=new_id(), actor_id=ACTOR, actor_roles=("support_agent", "analyst"),
                tool_name=CANARY_TOOL, arguments={}, resource="canary", destination=None,
                data_labels=(), prior_tools_in_run=(), mode=Mode.NORMAL,
            ))
        except PolicyUnavailable as exc:
            return ProbeResult(probe="policy", status=HealthStatus.CRITICAL,
                               detail=f"POLICY_UNAVAILABLE: {exc}")
        disk = engine.disk_digest()
        ev = {"version": version, "loaded_digest": (engine.digest or "")[:12],
              "disk_digest": (disk or "missing")[:12]}
        if disk is None:
            return ProbeResult(probe="policy", status=HealthStatus.CRITICAL,
                               detail="POLICY_FILE_MISSING", evidence=ev)
        if disk != engine.digest:
            return ProbeResult(probe="policy", status=HealthStatus.CRITICAL,
                               detail="STALE_POLICY: file on disk differs from loaded policy",
                               evidence=ev)
        if canary.decision.value != "DENY":
            return ProbeResult(probe="policy", status=HealthStatus.CRITICAL,
                               detail="CANARY_NOT_DENIED by policy engine", evidence=ev)
        return ProbeResult(probe="policy", status=HealthStatus.OK, detail="loaded, fresh, canary denied",
                           evidence=ev)

    def probe_audit(self) -> ProbeResult:
        probe_id = new_id()
        try:
            stored = self.store.append(SecurityEvent(
                trace_id=probe_id, actor_id=ACTOR, event_type=EventType.AUDIT_PROBE, synthetic=True,
            ))
        except AuditWriteError as exc:
            return ProbeResult(probe="audit", status=HealthStatus.CRITICAL,
                               detail=f"AUDIT_WRITE_FAILED: {exc}")
        back = self.store.get(stored.event.event_id)
        if back is None or back.hash != stored.hash:
            return ProbeResult(probe="audit", status=HealthStatus.CRITICAL,
                               detail="AUDIT_READBACK_MISMATCH")
        chain = self.store.verify_chain()
        if not chain.ok:
            return ProbeResult(probe="audit", status=HealthStatus.CRITICAL,
                               detail=f"AUDIT_CHAIN_BROKEN: {chain.detail}",
                               evidence={"first_bad_seq": chain.first_bad_seq})
        return ProbeResult(probe="audit", status=HealthStatus.OK,
                           detail=f"write/read-back ok, chain verified ({chain.checked} events)")

    def probe_enforcement(self) -> ProbeResult:
        before = self.systems.canary.executions
        resp = self.gw.call(self._cred, {"tool_name": CANARY_TOOL, "arguments": {},
                                         "run_id": f"watchdog-{self.rounds}"})
        executed = self.systems.canary.executions != before
        ev = {"outcome": resp.outcome.value, "reasons": list(resp.reason_codes)}
        if executed or resp.outcome is not CallOutcome.DENIED:
            return ProbeResult(probe="enforcement", status=HealthStatus.CRITICAL,
                               detail="ENFORCEMENT_BYPASSED: canary was not blocked", evidence=ev)
        return ProbeResult(probe="enforcement", status=HealthStatus.OK,
                           detail="canary denied and not executed", evidence=ev)

    def probe_coverage(self) -> ProbeResult:
        audited = {
            s.event.trace_id for s in self.store.all()
            if s.event.event_type is EventType.TOOL_EXECUTED
        }
        bypass = [
            {"system": sys.name, "op": e.op, "trace_id": e.trace_id}
            for sys in self.systems.all() for e in sys.access_log()
            if e.mutating and e.trace_id not in audited
        ]
        lost = sorted(self.gw.executed_traces - audited)
        if bypass:
            return ProbeResult(probe="coverage", status=HealthStatus.CRITICAL,
                               detail=f"BYPASS_DETECTED: {len(bypass)} target-system write(s) "
                                      "with no audited gateway execution",
                               evidence={"unaudited": bypass[:10]})
        if lost:
            return ProbeResult(probe="coverage", status=HealthStatus.CRITICAL,
                               detail=f"TELEMETRY_LOSS: {len(lost)} execution(s) missing from audit",
                               evidence={"trace_ids": lost[:10]})
        return ProbeResult(probe="coverage", status=HealthStatus.OK,
                           detail="target-system logs reconcile with audit trail")

    def probe_verifier(self) -> ProbeResult:
        if self.gw.verifier.self_test():
            return ProbeResult(probe="verifier", status=HealthStatus.OK, detail="self-test passed")
        return ProbeResult(probe="verifier", status=HealthStatus.DEGRADED,
                           detail="VERIFIER_UNAVAILABLE: outcomes will be INCONCLUSIVE")

    # ---- rounds ----------------------------------------------------------------------------
    def run_round(self) -> list[ProbeResult]:
        self.gw.flush_unpersisted()
        results = []
        for probe in (self.probe_policy, self.probe_audit, self.probe_enforcement,
                      self.probe_coverage, self.probe_verifier):
            try:
                results.append(probe())
            except Exception as exc:  # noqa: BLE001 — a crashing probe is itself a failure
                results.append(ProbeResult(probe=probe.__name__.removeprefix("probe_"),
                                           status=HealthStatus.CRITICAL,
                                           detail=f"PROBE_CRASHED: {type(exc).__name__}: {exc}"))
        self.rounds += 1
        self.last_results = results
        for r in results:
            self.gw.emit(SecurityEvent(
                trace_id=new_id(), actor_id=ACTOR, event_type=EventType.HEALTH_CHECK,
                synthetic=True, reason_codes=(r.status.value,),
                metadata={"probe": r.probe, "status": r.status.value, "detail": r.detail,
                          "evidence": r.evidence},
            ))
        critical = [r for r in results if r.status is HealthStatus.CRITICAL]
        self.controller.observe_round(all_ok=all(r.status is HealthStatus.OK for r in results))
        if critical:
            self.controller.enter_restricted("CRITICAL_CONTROL_FAILURE:" + ",".join(
                r.probe for r in critical))
        self.gw.emit(SecurityEvent(
            trace_id=new_id(), actor_id=ACTOR, event_type=EventType.HEARTBEAT, synthetic=True,
            metadata={"round": self.rounds, "mode": self.controller.mode.value},
        ))
        if self.on_round:
            self.on_round(results)
        return results

    def start(self, interval_seconds: float = 2.0) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(interval_seconds):
                self.run_round()

        self._thread = threading.Thread(target=loop, name="watchdog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
