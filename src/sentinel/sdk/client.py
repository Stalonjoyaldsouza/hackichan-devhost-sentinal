"""Runtime guard: the mechanism that makes a monitoring point actually monitored.

    from sentinel.sdk import guard

    @guard("MP-1A2B3C4D", destination_arg="to", labels=["pii"])
    def send_email(to, subject, body): ...

Each guarded call: records a request event → evaluates the project policy with the deterministic
`PolicyEngine` → records the decision → (enforce mode) raises `SentinelDenied` instead of running
the function → records the execution. Only argument *names* are logged, never values.

observe mode (default)  log everything, report `would_block`, never interfere
enforce mode            DENY / REQUIRE_APPROVAL raise before the function runs; if the policy or
                        audit store is unavailable the call fails closed (SentinelUnavailable)

A guard on a point that is not selected records `POINT_NOT_SELECTED` and runs unmodified.
Data-flow: `produces=[...]` labels what a source returns (taints the current run); a later guarded
sink in the same run is evaluated with those labels, so "read PII then send externally" is caught
even though each call alone is allowed. Use `with sentinel.run("request-id"):` to scope a run
(default: one run per process, which is conservative).
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import inspect
import os
import sys
import threading
import time
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.audit import AuditStore, AuditWriteError
from sentinel.contracts import (
    DataLabel,
    Decision,
    DecisionRequest,
    EventType,
    ExecutionStatus,
    Mode,
    SecurityEvent,
    new_id,
)
from sentinel.dataflow import DataFlowTracker
from sentinel.policy import PolicyEngine, PolicyError, PolicyUnavailable
from sentinel.sdk.models import tool_name_for
from sentinel.sdk.policygen import write_policy
from sentinel.sdk.workspace import Workspace, WorkspaceError, find_workspace

_POLICY_RECHECK_SECONDS = 5.0
_run_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("sentinel_run", default=None)


class SentinelDenied(Exception):
    def __init__(self, point_id: str, reasons: Sequence[str], decision: str = "DENY"):
        super().__init__(f"{point_id} blocked by policy ({decision}): {', '.join(reasons)}")
        self.point_id, self.reasons, self.decision = point_id, tuple(reasons), decision


class SentinelApprovalRequired(SentinelDenied):
    pass


class SentinelUnavailable(Exception):
    """Enforce mode could not evaluate or audit the call, so it failed closed."""


@dataclass
class GuardDecision:
    point_id: str
    trace_id: str
    decision: str
    reasons: tuple[str, ...]
    would_block: bool
    evaluated: bool


def _labels(values: Sequence[str | DataLabel]) -> tuple[DataLabel, ...]:
    try:
        return tuple(DataLabel(v) for v in values)
    except ValueError as exc:
        raise ValueError(f"unknown data label in {list(values)}; use "
                         f"{[x.value for x in DataLabel]}") from exc


class Sentinel:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.cfg = workspace.load_config()
        self.actor = f"app.{self.cfg.app_name}"
        self.store = AuditStore(workspace.audit_path)
        self.flow = DataFlowTracker()
        self._process_run = f"proc-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self._lock = threading.Lock()
        self._registered: set[str] = set()
        self._warned: set[str] = set()
        self._engine: PolicyEngine | None = None
        self._last_policy_check = 0.0
        self._load_policy(initial=True)

    @classmethod
    def from_project(cls, path: Path | str | None = None) -> Sentinel:
        return cls(find_workspace(path))

    # ---- policy ----------------------------------------------------------------------------
    def _load_policy(self, initial: bool = False) -> None:
        if initial and not self.ws.policy_path.exists():
            write_policy(self.ws)
        try:
            if self._engine is None:
                self._engine = PolicyEngine(self.ws.policy_path)
            elif self._engine.disk_digest() != self._engine.digest:
                self._engine.reload()
        except PolicyError as exc:
            self._warn_once("policy", f"policy unavailable: {exc}")
            if initial:
                self._engine = None
        self._last_policy_check = time.monotonic()

    def _refresh_policy(self) -> None:
        if time.monotonic() - self._last_policy_check > _POLICY_RECHECK_SECONDS:
            with self._lock:
                self._load_policy()

    def _warn_once(self, key: str, msg: str) -> None:
        if key not in self._warned:
            self._warned.add(key)
            print(f"[sentinel] WARNING: {msg}", file=sys.stderr)

    # ---- events ----------------------------------------------------------------------------
    def _emit(self, ev: SecurityEvent) -> bool:
        try:
            self.store.append(ev)
            return True
        except AuditWriteError as exc:
            self._warn_once("audit", f"audit write failed: {exc}")
            if self.cfg.mode == "enforce":
                raise SentinelUnavailable("audit store unavailable; failing closed") from exc
            return False

    def _event(self, etype: EventType, trace_id: str, point_id: str, **kw: Any) -> SecurityEvent:
        metadata = {"point_id": point_id, "mode": self.cfg.mode, **kw.pop("metadata", {})}
        return SecurityEvent(trace_id=trace_id, run_id=self._run_id(), actor_id=self.actor,
                             event_type=etype, tool_name=tool_name_for(point_id),
                             metadata=metadata, **kw)

    def _run_id(self) -> str:
        return _run_var.get() or self._process_run

    def _flow_actor(self) -> str:
        """Taint is scoped to the run: the core tracker also taints the actor across runs, which
        would defeat `sentinel.run()` isolation for an application that is one actor."""
        return f"{self.actor}@{self._run_id()}"

    @contextlib.contextmanager
    def run(self, run_id: str) -> Iterator[str]:
        token = _run_var.set(run_id)
        try:
            yield run_id
        finally:
            _run_var.reset(token)

    # ---- core check ------------------------------------------------------------------------
    def check(self, point_id: str, *, function: str = "", arg_names: Sequence[str] = (),
              destination: str | None = None, labels: Sequence[str | DataLabel] = (),
              purpose: str | None = None) -> GuardDecision:
        point_id = point_id.upper()
        trace_id = new_id()
        declared = _labels(labels)
        if point_id not in self._registered:
            self._registered.add(point_id)
            self._emit(self._event(EventType.HEARTBEAT, trace_id, point_id,
                                   metadata={"registered_point": point_id, "function": function,
                                             "pid": os.getpid()}))
        self._refresh_policy()
        run_id = self._run_id()
        tainted = {p.label for p in self.flow.labels_for(actor_id=self._flow_actor(), run_id=run_id,
                                                         outbound_text=None)}
        all_labels = tuple(sorted({*declared, *tainted}, key=lambda d: d.value))
        self._emit(self._event(
            EventType.TOOL_CALL_REQUESTED, trace_id, point_id, destination=destination,
            data_labels=all_labels,
            metadata={"function": function, "arg_names": list(arg_names), "purpose": purpose}))

        engine = self._engine
        tool = tool_name_for(point_id)
        if engine is not None and tool not in engine.bundle.tools:
            self._emit(self._event(EventType.POLICY_DECISION, trace_id, point_id,
                                   policy_decision=Decision.NOT_EVALUATED,
                                   reason_codes=("POINT_NOT_SELECTED",), data_labels=all_labels))
            return GuardDecision(point_id, trace_id, "NOT_EVALUATED", ("POINT_NOT_SELECTED",),
                                 False, False)
        try:
            if engine is None:
                raise PolicyUnavailable("no policy loaded")
            decision = engine.evaluate(DecisionRequest(
                request_id=trace_id, actor_id=self.actor, actor_roles=("app",), tool_name=tool,
                arguments={}, resource=function or None, destination=destination,
                data_labels=all_labels, prior_tools_in_run=self.flow.prior_tools(run_id),
                mode=Mode.NORMAL))
        except (PolicyUnavailable, PolicyError, ValueError) as exc:
            self._emit(self._event(EventType.POLICY_DECISION, trace_id, point_id,
                                   policy_decision=Decision.NOT_EVALUATED,
                                   reason_codes=("POLICY_UNAVAILABLE",), data_labels=all_labels))
            if self.cfg.mode == "enforce":
                raise SentinelUnavailable(f"policy unavailable; failing closed: {exc}") from exc
            self._warn_once("policy", f"policy unavailable, running unmonitored: {exc}")
            return GuardDecision(point_id, trace_id, "NOT_EVALUATED", ("POLICY_UNAVAILABLE",),
                                 False, False)

        allowed = decision.decision is Decision.ALLOW
        would_block = not allowed
        self._emit(self._event(
            EventType.POLICY_DECISION, trace_id, point_id, policy_decision=decision.decision,
            policy_version=decision.policy_version, reason_codes=decision.reason_codes,
            data_labels=all_labels, destination=destination,
            metadata={"matched_rules": list(decision.matched_rules), "would_block": would_block,
                      "tainted_labels": sorted(t.value for t in tainted)}))
        if would_block and self.cfg.mode == "enforce":
            exc_cls = (SentinelApprovalRequired if decision.decision is Decision.REQUIRE_APPROVAL
                       else SentinelDenied)
            raise exc_cls(point_id, decision.reason_codes, decision.decision.value)
        return GuardDecision(point_id, trace_id, decision.decision.value, decision.reason_codes,
                             would_block, True)

    def _done(self, gd: GuardDecision, *, ok: bool, error: str | None = None,
              produces: Sequence[str | DataLabel] = ()) -> None:
        ev = self._event(EventType.TOOL_EXECUTED, gd.trace_id, gd.point_id,
                         execution_status=ExecutionStatus.SUCCEEDED if ok else ExecutionStatus.FAILED,
                         metadata={"error": error, "evaluated": gd.evaluated})
        try:
            self._emit(ev)
        except SentinelUnavailable:
            pass  # the side effect already happened; nothing to fail closed on
        if ok and produces:
            self.flow.record_execution(
                actor_id=self._flow_actor(), run_id=self._run_id(),
                tool_name=tool_name_for(gd.point_id), output_labels=set(_labels(produces)),
                output_text=None, source_event_id=ev.event_id)
        else:
            self.flow.record_execution(actor_id=self._flow_actor(), run_id=self._run_id(),
                                       tool_name=tool_name_for(gd.point_id), output_labels=set(),
                                       output_text=None, source_event_id=ev.event_id)

    # ---- developer API ---------------------------------------------------------------------
    @contextlib.contextmanager
    def monitor(self, point_id: str, *, destination: str | None = None,
                labels: Sequence[str] = (), produces: Sequence[str] = (),
                purpose: str | None = None) -> Iterator[GuardDecision]:
        gd = self.check(point_id, destination=destination, labels=labels, purpose=purpose)
        try:
            yield gd
        except BaseException as exc:
            self._done(gd, ok=False, error=type(exc).__name__)
            raise
        self._done(gd, ok=True, produces=produces)

    def guard(self, point_id: str, *, destination_arg: str | None = None,
              destination: str | None = None, labels: Sequence[str] = (),
              produces: Sequence[str] = (), purpose: str | None = None):
        _labels(labels), _labels(produces)  # fail at decoration time on a typo

        def decorate(fn):
            sig = inspect.signature(fn)
            names = [n for n in sig.parameters if n not in {"self", "cls"}]

            def dest(args: tuple, kwargs: dict) -> str | None:
                if destination_arg is None:
                    return destination
                try:
                    value = sig.bind_partial(*args, **kwargs).arguments.get(destination_arg)
                except TypeError:
                    return destination
                if isinstance(value, list | tuple | set):
                    value = next(iter(value), None)
                return str(value)[:200] if value is not None else destination

            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def awrapper(*args, **kwargs):
                    gd = self.check(point_id, function=fn.__qualname__, arg_names=names,
                                    destination=dest(args, kwargs), labels=labels, purpose=purpose)
                    try:
                        result = await fn(*args, **kwargs)
                    except BaseException as exc:
                        self._done(gd, ok=False, error=type(exc).__name__)
                        raise
                    self._done(gd, ok=True, produces=produces)
                    return result
                return awrapper

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                gd = self.check(point_id, function=fn.__qualname__, arg_names=names,
                                destination=dest(args, kwargs), labels=labels, purpose=purpose)
                try:
                    result = fn(*args, **kwargs)
                except BaseException as exc:
                    self._done(gd, ok=False, error=type(exc).__name__)
                    raise
                self._done(gd, ok=True, produces=produces)
                return result
            return wrapper
        return decorate

    def close(self) -> None:
        self.store.close()


# ---- module-level convenience (lazy default instance) -------------------------------------------
class _Unconfigured:
    """Used when no `.sentinel/` workspace exists: warns once and never blocks the application."""

    def __init__(self, reason: str):
        print(f"[sentinel] WARNING: {reason}; guards are NOT monitoring", file=sys.stderr)

    def check(self, *a: Any, **k: Any) -> GuardDecision:
        return GuardDecision("", "", "NOT_EVALUATED", ("SENTINEL_NOT_CONFIGURED",), False, False)

    def _done(self, *a: Any, **k: Any) -> None:
        return None


_default: Sentinel | _Unconfigured | None = None
_default_lock = threading.Lock()


def get_default() -> Sentinel | _Unconfigured:
    global _default
    with _default_lock:
        if _default is None:
            try:
                _default = Sentinel.from_project()
            except WorkspaceError as exc:
                if os.environ.get("SENTINEL_REQUIRE") == "1":
                    raise
                _default = _Unconfigured(str(exc))
        return _default


def guard(point_id: str, **options: Any):
    """Decorator using the project's default Sentinel (created on first call)."""
    _labels(options.get("labels", ())), _labels(options.get("produces", ()))

    def decorate(fn):
        inner: dict[str, Any] = {}

        def resolved():
            if "fn" not in inner:
                s = get_default()
                inner["fn"] = (s.guard(point_id, **options)(fn) if isinstance(s, Sentinel) else fn)
            return inner["fn"]

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapper(*a, **k):
                return await resolved()(*a, **k)
            return awrapper

        @functools.wraps(fn)
        def wrapper(*a, **k):
            return resolved()(*a, **k)
        return wrapper
    return decorate


@contextlib.contextmanager
def monitor(point_id: str, **options: Any) -> Iterator[GuardDecision]:
    s = get_default()
    if isinstance(s, Sentinel):
        with s.monitor(point_id, **options) as gd:
            yield gd
    else:
        yield s.check()
