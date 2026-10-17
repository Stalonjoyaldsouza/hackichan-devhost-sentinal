"""Agent activity tracking: which SDK agent is doing what, right now, and what finished.

Every task transition is an `agent_task` event in the project's audit store, so the same live view
(`sentinel sdk watch`) and the same tamper-evident trail cover SDK activity. Tracking is best
effort: a failing audit write never aborts an analysis, but is counted and surfaced.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel.audit import AuditStore, AuditWriteError
from sentinel.contracts import EventType, SecurityEvent, new_id

RUNNING, COMPLETED, FAILED = "RUNNING", "COMPLETED", "FAILED"


class TaskHandle:
    def __init__(self, tracker: ActivityTracker, task_id: str, agent: str, description: str):
        self._t, self.task_id, self.agent, self.description = tracker, task_id, agent, description
        self.detail = ""

    def update(self, target: str | None = None, progress: str | None = None) -> None:
        self._t._emit(self.task_id, self.agent, self.description, RUNNING, target=target,
                      progress=progress)

    def result(self, summary: str) -> None:
        self.detail = summary


class ActivityTracker:
    def __init__(self, store: AuditStore | None, run_id: str,
                 sink: Callable[[SecurityEvent], None] | None = None):
        self.store, self.run_id, self.sink = store, run_id, sink
        self.write_failures = 0

    def _emit(self, task_id: str, agent: str, description: str, status: str, *,
              target: str | None = None, progress: str | None = None, detail: str = "",
              duration: float | None = None) -> None:
        ev = SecurityEvent(
            trace_id=task_id, run_id=self.run_id, actor_id=f"sdk.{agent}",
            event_type=EventType.AGENT_TASK, reason_codes=(status,),
            metadata={"agent": agent, "task_id": task_id, "description": description,
                      "status": status, "target": target, "progress": progress, "detail": detail,
                      "duration_s": None if duration is None else round(duration, 3)})
        if self.store is not None:
            try:
                self.store.append(ev)
            except AuditWriteError:
                self.write_failures += 1
        if self.sink:
            self.sink(ev)

    @contextmanager
    def task(self, agent: str, description: str, target: str | None = None) -> Iterator[TaskHandle]:
        """Context manager: emits RUNNING, then COMPLETED (or FAILED if the block raises)."""
        task_id = new_id()
        handle = TaskHandle(self, task_id, agent, description)
        started = time.monotonic()
        self._emit(task_id, agent, description, RUNNING, target=target)
        try:
            yield handle
        except Exception as exc:
            self._emit(task_id, agent, description, FAILED, target=target,
                       detail=f"{type(exc).__name__}: {exc}"[:300],
                       duration=time.monotonic() - started)
            raise
        else:
            self._emit(task_id, agent, description, COMPLETED, target=target, detail=handle.detail,
                       duration=time.monotonic() - started)


@dataclass(frozen=True)
class TaskRow:
    task_id: str
    agent: str
    description: str
    status: str
    target: str | None
    progress: str | None
    detail: str
    duration_s: float | None
    started: datetime
    updated: datetime


def read_tasks(store: AuditStore, run_id: str | None = None) -> list[TaskRow]:
    """Collapse agent_task events into one row per task (latest state wins)."""
    rows: dict[str, TaskRow] = {}
    for s in store.all():
        ev = s.event
        if ev.event_type is not EventType.AGENT_TASK or (run_id and ev.run_id != run_id):
            continue
        md: dict[str, Any] = ev.metadata
        prev = rows.get(ev.trace_id)
        rows[ev.trace_id] = TaskRow(
            ev.trace_id, md.get("agent", "?"), md.get("description", ""), md.get("status", "?"),
            md.get("target") or (prev.target if prev else None),
            md.get("progress") or (prev.progress if prev else None), md.get("detail") or "",
            md.get("duration_s"), prev.started if prev else ev.timestamp, ev.timestamp)
    return sorted(rows.values(), key=lambda r: r.started)


def latest_run_id(store: AuditStore) -> str | None:
    run = None
    for s in store.all():
        if s.event.event_type is EventType.AGENT_TASK:
            run = s.event.run_id
    return run
