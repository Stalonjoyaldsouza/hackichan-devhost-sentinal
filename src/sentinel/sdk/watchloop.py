"""`sentinel sdk watch`: tail the audit trail live, raise health alerts, optionally run the AI agents."""

from __future__ import annotations

import time

from sentinel.audit import AuditStore
from sentinel.sdk.health import HealthItem, Level, evaluate_health
from sentinel.sdk.monitor import StreamMonitor
from sentinel.sdk.workspace import Workspace
from sentinel.termlog import BOLD, GREEN, RED, YELLOW, TerminalLog

_COLOR = {Level.CRITICAL: RED, Level.DEGRADED: YELLOW, Level.INFO: None, Level.OK: GREEN}


def _fmt(log: TerminalLog, item: HealthItem, prefix: str) -> str:
    color = _COLOR[item.level]
    text = f"   ▌{prefix} {item.level.name} {item.code}: {item.detail} "
    return log.s(text, BOLD, color) if color else log.s(text, "2")


def watch_project(ws: Workspace, log: TerminalLog, *, interval: float = 1.0,
                  health_interval: float = 10.0, full_verify_every: float = 600.0,
                  from_start: bool = False, monitor: StreamMonitor | None = None,
                  max_iterations: int | None = None) -> int:
    log.banner(f"sentinel sdk watch  project={ws.project_root.name}"
               + ("  ai=" + monitor.ai.provider.name if monitor and monitor.ai else ""))
    waited = False
    while not ws.audit_path.exists():
        if not waited:
            log.note("waiting for the application's audit trail …")
        waited = True
        if max_iterations is not None:
            break
        time.sleep(interval)
    store: AuditStore | None = AuditStore(ws.audit_path, read_only=True) if ws.audit_path.exists() else None
    cursor = 0 if (from_start or waited or store is None) else store.head()[0]
    if monitor and max_iterations is None:
        monitor.start()           # live mode: AI runs in the background; bounded mode drains inline
    shown: dict[str, HealthItem] = {}
    chain = None
    last_health = last_full = 0.0
    i = 0
    try:
        while max_iterations is None or i < max_iterations:
            i += 1
            if store is None and ws.audit_path.exists():
                store = AuditStore(ws.audit_path, read_only=True)
            if store is not None:
                try:
                    batch = store.since(cursor)
                except ValueError:  # tampered row that no longer parses; health check reports it
                    batch = []
                for row in batch:
                    cursor = row.seq
                    log(row.event)
                    if monitor:
                        monitor.handle(row.event)
            now = time.monotonic()
            if now - last_health >= health_interval or last_health == 0.0:
                full = chain is None or now - last_full >= full_verify_every
                rep = evaluate_health(ws, chain_state=chain, full_verify=full)
                if rep.level is not Level.CRITICAL or full:
                    chain = rep.chain_state
                if full:
                    last_full = now
                current = {f"{it.code}|{it.detail}": it for it in rep.items if it.level >= Level.INFO}
                for key, item in current.items():
                    if key not in shown:
                        log.write(_fmt(log, item, "HEALTH"))
                for key, item in shown.items():
                    if key not in current and item.level >= Level.DEGRADED:
                        log.write(log.s(f"   ▌HEALTH RESOLVED {item.code} ", BOLD, GREEN))
                shown = current
                last_health = now
            if monitor:
                monitor.drain() if max_iterations is not None else None
            if max_iterations is None:
                time.sleep(interval)
    except KeyboardInterrupt:
        log.note("stopped")
    finally:
        if monitor:
            monitor.close()
        if store is not None:
            store.close()
    return 0

