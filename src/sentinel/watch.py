"""`sentinel watch` — an independent, read-only process that tails the audit store.

It shares no memory with the runtime: it opens the SQLite file read-only, prints events as they
are appended, re-verifies the hash chain, and raises a terminal alert when the runtime's heartbeat
stops (missing telemetry) or the chain breaks (tampering).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from sentinel.audit import AuditStore
from sentinel.contracts import EventType
from sentinel.termlog import BOLD, GREEN, RED, TerminalLog


def watch(
    db_path: Path, log: TerminalLog, *, interval: float = 1.0, heartbeat_timeout: float = 15.0,
    from_start: bool = False, max_iterations: int | None = None,
) -> int:
    log.banner(f"sentinel watch  db={db_path}  heartbeat_timeout={heartbeat_timeout:g}s")
    waited = False
    while not db_path.exists():
        if not waited:
            log.note("waiting for audit store to be created…")
        waited = True
        time.sleep(interval)
    store = AuditStore(db_path, read_only=True)
    # A store created after we started watching is new: show it from its first event.
    cursor = 0 if (from_start or waited) else store.head()[0]
    last_heartbeat: float | None = None
    started = time.time()
    hb_alerted = chain_alerted = False
    iterations = 0
    try:
        while max_iterations is None or iterations < max_iterations:
            iterations += 1
            for stored in store.since(cursor):
                cursor = stored.seq
                ev = stored.event
                if ev.event_type is EventType.HEARTBEAT:
                    last_heartbeat = ev.timestamp.timestamp()
                log(ev)

            now = datetime.now(UTC).timestamp()
            reference = last_heartbeat if last_heartbeat is not None else started
            if now - reference > heartbeat_timeout:
                if not hb_alerted:
                    log.write(log.s(f"   ▌CRITICAL TELEMETRY_MISSING: no watchdog heartbeat for "
                                    f"{now - reference:.0f}s — runtime down or not instrumented ",
                                    BOLD, RED))
                    hb_alerted = True
            elif hb_alerted:
                log.write(log.s("   ▌heartbeat restored ", BOLD, GREEN))
                hb_alerted = False

            chain = store.verify_chain()
            if not chain.ok and not chain_alerted:
                log.write(log.s(f"   ▌CRITICAL AUDIT_CHAIN_BROKEN: {chain.detail} ", BOLD, RED))
                chain_alerted = True
            elif chain.ok and chain_alerted:
                chain_alerted = False
            time.sleep(interval)
    except KeyboardInterrupt:
        log.note("stopped")
    finally:
        store.close()
    return 0
