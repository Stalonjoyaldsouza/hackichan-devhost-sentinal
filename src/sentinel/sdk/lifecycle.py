"""Monitoring-point lifecycle, derived from evidence on every call — never stored or asserted.

  IDENTIFIED   in analysis.json
  SELECTED     in state.json
  IMPLEMENTED  selected AND a `guard("MP-…")` / `monitor("MP-…")` / `check("MP-…")` reference
               exists in the project's source
  ACTIVE       implemented AND the audit store holds a policy evaluation for the point within the
               activity window AND the audit hash chain verifies

A guard that exists in source but has never evaluated a call stays IMPLEMENTED: code being present
does not show that the mechanism works.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sentinel.audit import AuditStore
from sentinel.contracts import Decision, EventType
from sentinel.sdk.models import AnalysisResult, PointState
from sentinel.sdk.scanner import scan
from sentinel.sdk.workspace import Workspace

GUARD_REF = re.compile(r"""\b(?:guard|monitor|check)\(\s*["'](MP-[0-9A-Fa-f]{8})["']""")


@dataclass
class PointStatus:
    state: PointState
    notes: list[str] = field(default_factory=list)
    code_refs: list[str] = field(default_factory=list)
    last_seen: datetime | None = None
    evaluations: int = 0


@dataclass
class StatusReport:
    points: dict[str, PointStatus]
    orphan_refs: dict[str, list[str]]  # guard references to ids not in the analysis
    audit_ok: bool | None              # None = no audit store yet
    audit_detail: str = ""


def find_guard_refs(ws: Workspace) -> dict[str, list[str]]:
    refs: dict[str, list[str]] = {}
    for f in scan(ws.project_root).files:
        for i, line in enumerate(f.lines, 1):
            if line.lstrip().startswith(("#", "//")):
                continue
            for m in GUARD_REF.finditer(line):
                refs.setdefault(m.group(1).upper(), []).append(f"{f.rel}:{i}")
    return refs


def compute_status(ws: Workspace, analysis: AnalysisResult, *, now: datetime | None = None) -> StatusReport:
    cfg = ws.load_config()
    now = now or datetime.now(UTC)
    selected = ws.load_selected()
    refs = find_guard_refs(ws)

    seen: dict[str, datetime] = {}
    counts: dict[str, int] = {}
    audit_ok: bool | None = None
    detail = ""
    if ws.audit_path.exists():
        store = AuditStore(ws.audit_path, read_only=True)
        try:
            chain = store.verify_chain()
            audit_ok, detail = chain.ok, ("" if chain.ok else chain.detail)
            # A broken chain means no event in it can be trusted (and a tampered row may not even
            # parse), so no runtime evidence is read at all.
            for s in (store.all() if chain.ok else []):
                ev = s.event
                pid = ev.metadata.get("point_id")
                if not pid:
                    continue
                if (ev.event_type is EventType.POLICY_DECISION
                      and ev.policy_decision is not Decision.NOT_EVALUATED):
                    counts[pid] = counts.get(pid, 0) + 1
                    seen[pid] = max(seen.get(pid, ev.timestamp), ev.timestamp)
        finally:
            store.close()

    window = timedelta(hours=cfg.activity_window_hours)
    out: dict[str, PointStatus] = {}
    for p in analysis.points:
        pid = p.point_id
        st = PointStatus(PointState.IDENTIFIED, code_refs=refs.get(pid, []))
        if pid in selected:
            st.state = PointState.SELECTED
            if st.code_refs:
                st.state = PointState.IMPLEMENTED
                if audit_ok is False:
                    st.notes.append("audit chain is broken: runtime evidence cannot be trusted, "
                                    "so ACTIVE cannot be claimed")
                elif pid in seen:
                    st.last_seen, st.evaluations = seen[pid], counts[pid]
                    if now - seen[pid] <= window:
                        st.state = PointState.ACTIVE
                    else:
                        st.notes.append(f"last evaluated {now - seen[pid]} ago (outside the "
                                        f"{cfg.activity_window_hours:g}h window)")
                else:
                    st.notes.append("no runtime evaluation recorded — run the application")
            else:
                st.notes.append("no guard in source yet — see `sentinel sdk snippet " + pid + "`")
        elif st.code_refs:
            st.notes.append("guard exists in code but the point is not selected → NOT monitored "
                            "(calls log POINT_NOT_SELECTED)")
        out[pid] = st
    known = {p.point_id for p in analysis.points}
    orphans = {pid: where for pid, where in refs.items() if pid not in known}
    return StatusReport(out, orphans, audit_ok, detail)
