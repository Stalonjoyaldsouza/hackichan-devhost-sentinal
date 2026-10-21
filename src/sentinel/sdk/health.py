"""Independent health evaluation for a deployed application using the SDK.

Runs in a *different process* from the application (`sentinel sdk health`, `sentinel sdk watch`) and
trusts nothing the app says about itself beyond what it can corroborate:

  APP_NOT_REPORTING      heartbeats stopped without a clean-shutdown marker
  POLICY_*               policy file missing/invalid/out of date vs selection+config, or the running
                         app reports an older policy than the one on disk
  GUARD_REMOVED/MISSING  a selected point has no guard in source (REMOVED if it ever evaluated)
  AUDIT_CHAIN_BROKEN     hash chain does not verify
  APP_AUDIT_FAILING      the app reports it cannot write its audit trail
  COLLECTOR_UNREACHABLE  events are being spooled but not reaching the central collector
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import Any

from sentinel.audit import GENESIS, AuditStore
from sentinel.contracts import Decision, EventType
from sentinel.policy import PolicyEngine, PolicyError
from sentinel.sdk.lifecycle import find_guard_refs
from sentinel.sdk.policygen import render_policy
from sentinel.sdk.workspace import Workspace, WorkspaceError


class Level(IntEnum):
    OK = 0
    INFO = 1
    DEGRADED = 2
    CRITICAL = 3


@dataclass(frozen=True)
class HealthItem:
    level: Level
    code: str
    detail: str


@dataclass
class HealthReport:
    items: list[HealthItem] = field(default_factory=list)
    chain_state: tuple[int, str] = (0, GENESIS)   # for incremental verification by a watcher

    @property
    def level(self) -> Level:
        return max((i.level for i in self.items), default=Level.OK)

    @property
    def exit_code(self) -> int:
        return {Level.OK: 0, Level.INFO: 0, Level.DEGRADED: 1, Level.CRITICAL: 2}[self.level]


def _digest12(path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    except OSError:
        return None


def evaluate_health(ws: Workspace, *, now: datetime | None = None, heartbeat_timeout: float | None = None,
                    analysis=None, chain_state: tuple[int, str] | None = None,
                    full_verify: bool = True) -> HealthReport:
    """`chain_state` (seq, hash) from a previous report enables incremental chain verification."""
    now = now or datetime.now(UTC)
    rep = HealthReport()
    add = lambda lvl, code, detail: rep.items.append(HealthItem(lvl, code, detail))  # noqa: E731
    try:
        cfg = ws.load_config()
    except WorkspaceError as exc:
        add(Level.CRITICAL, "CONFIG_INVALID", str(exc))
        return rep
    selected = ws.load_selected()
    timeout = heartbeat_timeout or max(30.0, 3 * (cfg.heartbeat_seconds or 10.0))

    # ---- policy on disk ----------------------------------------------------------------------
    disk = _digest12(ws.policy_path)
    if selected and disk is None:
        add(Level.CRITICAL, "POLICY_MISSING", "policy.yaml is missing — run `sentinel sdk policy`")
    elif disk is not None:
        try:
            PolicyEngine(ws.policy_path)
        except PolicyError as exc:
            add(Level.CRITICAL, "POLICY_INVALID", str(exc)[:200])
        try:
            expected = render_policy(ws)[0]
            if ws.policy_path.read_text() != expected:
                add(Level.DEGRADED, "POLICY_OUT_OF_DATE",
                    "selection/config changed since policy.yaml was generated — run `sentinel sdk policy`")
        except (OSError, WorkspaceError):
            pass

    # ---- audit trail ---------------------------------------------------------------------------
    if not ws.audit_path.exists():
        add(Level.INFO, "NO_RUNTIME_DATA", "no audit trail yet — the application has not run with guards")
        _guards(ws, rep, analysis, selected, set(), add)
        return rep
    store = AuditStore(ws.audit_path, read_only=True)
    try:
        if chain_state and not full_verify:
            report, seq, h = store.verify_from(*chain_state)
        else:
            report, seq, h = store.verify_from(0, GENESIS)
        rep.chain_state = (seq, h)
        if not report.ok:
            add(Level.CRITICAL, "AUDIT_CHAIN_BROKEN", report.detail)
            _guards(ws, rep, analysis, selected, set(), add)
            return rep
        recent_hb = store.recent([EventType.HEARTBEAT.value], (now - timedelta(hours=6)).isoformat())
        decisions = store.recent([EventType.POLICY_DECISION.value], (now - timedelta(days=14)).isoformat())
    finally:
        store.close()

    ever_evaluated = {s.event.metadata["point_id"] for s in decisions
                      if s.event.metadata.get("point_id")
                      and s.event.policy_decision is not Decision.NOT_EVALUATED}

    # ---- application heartbeats ----------------------------------------------------------------
    latest: dict[tuple[str, int], tuple[datetime, dict[str, Any]]] = {}
    first: dict[tuple[str, int], datetime] = {}
    for s in recent_hb:
        md = s.event.metadata
        if md.get("kind") == "app_heartbeat":
            key = (md.get("host", "?"), md.get("pid", 0))
            latest[key] = (s.event.timestamp, md)
            first.setdefault(key, s.event.timestamp)
    alive = {k: v for k, v in latest.items()
             if not v[1].get("stopping") and (now - v[0]).total_seconds() <= timeout}
    stopped = {k: v for k, v in latest.items() if v[1].get("stopping")}
    silent = {k: v for k, v in latest.items()
              if not v[1].get("stopping") and (now - v[0]).total_seconds() > timeout}

    def replaced(key: tuple[str, int], last_seen: datetime, app: Any) -> bool:
        """A NEW process of the same app started after this one went silent (a restart).
        Replicas that were already running do not count, so a lost replica is still reported."""
        return any(first[k] > last_seen and latest[k][1].get("app") == app
                   for k in latest if k != key)

    restarted = {k: v for k, v in silent.items() if replaced(k, v[0], v[1].get("app"))}
    # A process inside the timeout window that has missed 3+ of its heartbeats AND been superseded by
    # a newer process of the same app is a crash already followed by a restart, not a live process.
    missed = 3 * (cfg.heartbeat_seconds or 10.0)
    for k, v in list(alive.items()):
        if (now - v[0]).total_seconds() > missed and replaced(k, v[0], v[1].get("app")):
            restarted[k] = alive.pop(k)
    dead = {k: v for k, v in silent.items() if k not in restarted}
    for (host, pid), (_ts, md) in restarted.items():
        add(Level.INFO, "APP_RESTARTED_AFTER_CRASH",
            f"{md.get('app')}@{host} pid {pid} stopped without a shutdown marker and was replaced by "
            "a newer process")
    if alive:
        add(Level.OK, "APP_ALIVE", f"{len(alive)} process(es) reporting "
            f"({', '.join(sorted({v[1].get('app', '?') for v in alive.values()}))})")
        for (host, pid), (_ts, md) in alive.items():
            who = f"{md.get('app')}@{host} pid {pid}"
            if md.get("policy_ok") is False or md.get("policy_digest") is None:
                add(Level.CRITICAL, "POLICY_NOT_LOADED_IN_APP", f"{who} has no valid policy loaded")
            elif disk and md.get("policy_digest") != disk:
                add(Level.DEGRADED, "POLICY_STALE_IN_APP",
                    f"{who} runs policy {md.get('policy_digest')} but disk has {disk} "
                    "(it reloads within seconds; restart if this persists)")
            if md.get("audit_ok") is False:
                add(Level.CRITICAL, "APP_AUDIT_FAILING", f"{who} reports it cannot write its audit trail")
            if md.get("collector_ok") is False:
                add(Level.DEGRADED, "COLLECTOR_UNREACHABLE",
                    f"{who}: central collector unreachable, {md.get('collector_pending')} event(s) spooled")
        for (host, pid), (ts, md) in dead.items():
            add(Level.DEGRADED, "APP_PROCESS_LOST",
                f"{md.get('app')}@{host} pid {pid} stopped reporting {int((now - ts).total_seconds())}s "
                "ago without a shutdown marker while other processes are still alive")
    elif dead:
        host, pid = max(dead, key=lambda k: dead[k][0])
        ts, md = dead[(host, pid)]
        add(Level.CRITICAL, "APP_NOT_REPORTING",
            f"no heartbeat for {int((now - ts).total_seconds())}s from {md.get('app')}@{host} pid {pid} "
            "(no clean-shutdown marker): crashed, killed or Sentinel stopped inside it")
    elif stopped:
        add(Level.INFO, "APP_STOPPED", "the application shut down cleanly (not currently running)")
    else:
        add(Level.INFO, "NO_HEARTBEAT", "no application heartbeat recorded yet")

    _guards(ws, rep, analysis, selected, ever_evaluated, add)
    return rep


def _guards(ws, rep, analysis, selected, ever_evaluated, add) -> None:
    if not selected:
        add(Level.INFO, "NO_POINTS_SELECTED", "no monitoring points are selected")
        return
    try:
        analysis = analysis or ws.load_analysis()
    except WorkspaceError:
        return
    refs = find_guard_refs(ws)
    titles = {p.point_id: p.title for p in analysis.points}
    removed, missing = [], []
    for pid in sorted(selected):
        if pid in refs:
            continue
        (removed if pid in ever_evaluated else missing).append(f"{pid} ({titles.get(pid, '?')})")

    def listing(items: list[str]) -> str:
        shown = "; ".join(items[:4])
        return shown + (f"; … and {len(items) - 4} more" if len(items) > 4 else "")

    if removed:
        add(Level.CRITICAL, "GUARD_REMOVED",
            f"{len(removed)} point(s) were monitored before but their guard is no longer in the source "
            f"code: {listing(removed)}")
    if missing:
        add(Level.DEGRADED, "GUARD_MISSING",
            f"{len(missing)} selected point(s) have no guard in the source code yet "
            f"(`sentinel sdk instrument` or `snippet`): {listing(missing)}")
