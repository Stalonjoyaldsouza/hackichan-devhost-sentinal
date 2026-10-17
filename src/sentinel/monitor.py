"""Deterministic monitoring (CLAUDE.md §5.3/§5.4, MVP subset — no LLM).

Turns raw events into findings with evidence links. Findings are advisory: the monitor cannot
allow anything, and it only *recommends* responses. Enforcement stays in the policy engine.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Callable

from sentinel.contracts import (
    Decision,
    EventType,
    Finding,
    SecurityEvent,
    Severity,
)

DATAFLOW_REASONS = frozenset({"SENSITIVE_DATA_TO_UNAPPROVED_DESTINATION",
                              "EXPORT_FOLLOWED_BY_EXTERNAL_SEND"})
REPEATED_DENY_THRESHOLD = 3


class Monitor:
    ACTOR = "service.monitor"

    def __init__(self, emit: Callable[[SecurityEvent], bool]):
        self._emit = emit
        self._lock = threading.Lock()
        self._denies: dict[tuple[str, str], list[str]] = defaultdict(list)
        self._flagged_runs: set[tuple[str, str]] = set()
        self._critical_probes: set[str] = set()
        self.findings: list[Finding] = []

    def _raise(self, source: SecurityEvent, finding: Finding) -> None:
        self.findings.append(finding)
        self._emit(SecurityEvent(
            trace_id=source.trace_id, run_id=source.run_id, actor_id=self.ACTOR,
            parent_actor_id=source.actor_id, event_type=EventType.FINDING,
            tool_name=source.tool_name, evidence_refs=finding.evidence_event_ids,
            reason_codes=(finding.severity.value,), metadata=finding.model_dump(mode="json"),
        ))

    def __call__(self, ev: SecurityEvent, persisted: bool) -> None:
        if ev.event_type is EventType.FINDING:
            return
        with self._lock:
            pending = self._analyse(ev)
        for f in pending:
            self._raise(ev, f)

    def _analyse(self, ev: SecurityEvent) -> list[Finding]:
        out: list[Finding] = []
        if ev.event_type is EventType.POLICY_DECISION and ev.policy_decision is Decision.DENY \
                and not ev.synthetic:
            if DATAFLOW_REASONS & set(ev.reason_codes):
                out.append(Finding(
                    component="sequence_dataflow", severity=Severity.HIGH,
                    summary=f"{ev.actor_id} attempted to move labelled data "
                            f"{[lbl.value for lbl in ev.data_labels]} to {ev.destination} "
                            f"via {ev.tool_name}; blocked",
                    evidence_event_ids=(ev.event_id, *ev.evidence_refs), confidence=1.0,
                    recommended_action="Review the agent's task and the source documents; "
                                       "consider revoking the agent's access to labelled data.",
                ))
            key = (ev.actor_id, ev.run_id or "-")
            self._denies[key].append(ev.event_id)
            if len(self._denies[key]) >= REPEATED_DENY_THRESHOLD and key not in self._flagged_runs:
                self._flagged_runs.add(key)
                out.append(Finding(
                    component="monitoring", severity=Severity.HIGH,
                    summary=f"{ev.actor_id} hit {len(self._denies[key])} denied actions in run "
                            f"{key[1]} — possible prompt injection or probing",
                    evidence_event_ids=tuple(self._denies[key]), confidence=0.6,
                    recommended_action="Pause the run and inspect its inputs for injected "
                                       "instructions.",
                ))
        elif ev.event_type is EventType.OUTCOME_VERIFIED:
            outcome = ev.metadata.get("outcome")
            if outcome in {"FAILED", "PARTIAL"}:
                out.append(Finding(
                    component="outcome", severity=Severity.HIGH if outcome == "FAILED"
                    else Severity.MEDIUM,
                    summary=f"{ev.tool_name} reported success but independent evidence says "
                            f"{outcome}: {'; '.join(ev.metadata.get('discrepancies', []))}",
                    evidence_event_ids=(ev.event_id, *ev.evidence_refs), confidence=1.0,
                    recommended_action="Do not treat the action as done; reconcile target state "
                                       "manually. Do not auto-retry.",
                ))
        elif ev.event_type is EventType.HEALTH_CHECK:
            probe, status = ev.metadata.get("probe"), ev.metadata.get("status")
            if status == "CRITICAL" and probe not in self._critical_probes:
                self._critical_probes.add(probe)
                out.append(Finding(
                    component="watchdog", severity=Severity.CRITICAL,
                    summary=f"control '{probe}' failed: {ev.metadata.get('detail')}",
                    evidence_event_ids=(ev.event_id,), confidence=1.0,
                    recommended_action="Restore the control; safe mode stays on until health "
                                       "checks pass and an approver lifts it.",
                ))
            elif status == "OK":
                self._critical_probes.discard(probe)
        return out
