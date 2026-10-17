"""Audit reconstruction (CLAUDE.md §5.7, Scenario E) — deterministic.

Builds a per-trace timeline for a run from the append-only store. Every line cites the event id it
is based on. Gaps are stated as UNKNOWN rather than filled in.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.audit import AuditStore
from sentinel.contracts import EventType, SecurityEvent


@dataclass
class TraceSummary:
    trace_id: str
    lines: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


@dataclass
class Report:
    run_id: str
    chain_ok: bool
    chain_detail: str
    traces: list[TraceSummary]
    findings: list[str]

    def render(self) -> str:
        out = [f"AUDIT REPORT  run={self.run_id}",
               f"  audit chain: {'VERIFIED' if self.chain_ok else 'BROKEN — ' + self.chain_detail}"]
        if not self.traces:
            out.append("  UNKNOWN — no events recorded for this run")
        for t in self.traces:
            out.append(f"  trace {t.trace_id[:8]}")
            out += [f"    {line}" for line in t.lines]
            out += [f"    ! {gap}" for gap in t.gaps]
        if self.findings:
            out.append("  findings:")
            out += [f"    {f}" for f in self.findings]
        return "\n".join(out)


def _ref(ev: SecurityEvent) -> str:
    return f"[ev:{ev.event_id[:8]}]"


def reconstruct(store: AuditStore, run_id: str) -> Report:
    chain = store.verify_chain()
    events = [s.event for s in store.by_run(run_id)]
    by_trace: dict[str, list[SecurityEvent]] = {}
    for ev in events:
        by_trace.setdefault(ev.trace_id, []).append(ev)

    traces, findings = [], []
    for trace_id, evs in by_trace.items():
        t = TraceSummary(trace_id)
        types = {e.event_type for e in evs}
        for ev in evs:
            ts = ev.timestamp.strftime("%H:%M:%S")
            match ev.event_type:
                case EventType.TOOL_CALL_REQUESTED:
                    t.lines.append(f"{ts} {ev.actor_id} requested {ev.tool_name}"
                                   f" resource={ev.resource} dest={ev.destination}"
                                   f" labels={[x.value for x in ev.data_labels]} {_ref(ev)}")
                case EventType.POLICY_DECISION:
                    rules = ev.metadata.get("matched_rules", [])
                    t.lines.append(f"{ts} policy {ev.policy_decision.value} rules={rules}"
                                   f" reasons={list(ev.reason_codes)} policy={ev.policy_version}"
                                   f" {_ref(ev)}")
                    for p in ev.metadata.get("provenance", []):
                        t.lines.append(f"      ↳ label '{p['label']}' via {p['mechanism']} from"
                                       f" [ev:{p['source_event_id'][:8]}]")
                case EventType.APPROVAL_REQUESTED:
                    t.lines.append(f"{ts} approval requested id={ev.metadata.get('approval_id')}"
                                   f" {_ref(ev)}")
                case EventType.APPROVAL_GRANTED | EventType.APPROVAL_REJECTED:
                    verb = "granted" if ev.event_type is EventType.APPROVAL_GRANTED else "rejected"
                    t.lines.append(f"{ts} approval {verb} by {ev.actor_id} {_ref(ev)}")
                case EventType.TOOL_EXECUTED:
                    late = " (persisted late)" if ev.metadata.get("persisted_late") else ""
                    t.lines.append(f"{ts} executed status={ev.execution_status.value}"
                                   f" result={ev.metadata.get('result')}{late} {_ref(ev)}")
                case EventType.OUTCOME_VERIFIED:
                    disc = ev.metadata.get("discrepancies") or []
                    t.lines.append(f"{ts} outcome {ev.metadata.get('outcome')}"
                                   f" evidence={ev.metadata.get('evidence', {}).get('source')}"
                                   f"{' discrepancies=' + str(disc) if disc else ''} {_ref(ev)}")
                case EventType.FINDING:
                    findings.append(f"{ev.metadata.get('severity')} {ev.metadata.get('component')}:"
                                    f" {ev.metadata.get('summary')} {_ref(ev)}")
        decided = [e for e in evs if e.event_type is EventType.POLICY_DECISION]
        if EventType.TOOL_CALL_REQUESTED in types and not decided:
            t.gaps.append("UNKNOWN — no policy decision recorded")
        allowed = any(e.policy_decision.value == "ALLOW" for e in decided)
        granted = EventType.APPROVAL_GRANTED in types
        if (allowed or granted) and EventType.TOOL_EXECUTED not in types:
            t.gaps.append("UNKNOWN — permitted but no execution record (not executed, or record lost)")
        if EventType.TOOL_EXECUTED in types and EventType.OUTCOME_VERIFIED not in types:
            t.gaps.append("UNKNOWN — executed but no outcome verification recorded")
        if t.lines:
            traces.append(t)
    return Report(run_id, chain.ok, chain.detail, traces, findings)
