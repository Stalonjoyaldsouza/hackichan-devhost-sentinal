"""Runtime guard: the mechanism that makes a monitoring point actually monitored.

    from sentinel.sdk import guard

    @guard("MP-1A2B3C4D", destination_arg="to", labels=["pii"])
    def send_email(to, subject, body): ...

Each guarded call: records a request event → evaluates the project policy with the deterministic
`PolicyEngine` → records the decision → (enforce mode) refuses to run the function when the policy
says no → records the execution → optionally verifies the outcome. Only argument *names* are logged.

observe mode (default)  log everything and report `would_block`; never interferes. Problems with
                        Sentinel itself (read-only disk, bad config, internal bug) degrade to one
                        stderr warning — monitoring must never take the application down.
enforce mode            DENY raises `SentinelDenied`; REQUIRE_APPROVAL raises
                        `SentinelApprovalRequired` (approve with `sentinel sdk approve`); if the policy
                        or audit trail is unavailable the call fails closed (`SentinelUnavailable`).

Alongside the guards a background thread sends an app heartbeat (policy freshness, audit health,
collector status, guarded points) so an *independent* process (`sentinel sdk health` / `watch`) can
tell when the app, a guard, the policy or the audit trail stops working.

A guard on a point that is not selected records `POINT_NOT_SELECTED` and runs unmodified.
Data-flow: `produces=[...]` labels what a source returns (taints the current run); a later guarded
sink in the same run is evaluated with those labels. Scope a run with `sentinel.run("request-id")`.
"""

from __future__ import annotations

import atexit
import contextlib
import contextvars
import functools
import hashlib
import inspect
import os
import socket
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
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
from sentinel.sdk.approvals import ApprovalError, ApprovalFile, fingerprint
from sentinel.sdk.collector import CollectorForwarder
from sentinel.sdk.models import tool_name_for
from sentinel.sdk.policygen import write_policy
from sentinel.sdk.workspace import Workspace, WorkspaceError, find_workspace

_POLICY_RECHECK_SECONDS = 5.0
_SYNC_SECONDS = 1.0
_run_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("sentinel_run", default=None)
_purpose_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("sentinel_purpose", default=None)


@contextlib.contextmanager
def purpose(text: str) -> Iterator[None]:
    """Tell Sentinel why the agent is acting (e.g. the user's request) for every guarded call inside.
    The advisory risk/threat agents compare it with what the agent actually does. Truncated to 500
    characters; it is stored in the audit trail, so do not put secrets in it."""
    token = _purpose_var.set(text[:500])
    try:
        yield
    finally:
        _purpose_var.reset(token)


class SentinelDenied(Exception):
    def __init__(self, point_id: str, reasons: Sequence[str], decision: str = "DENY"):
        super().__init__(f"{point_id} blocked by policy ({decision}): {', '.join(reasons)}")
        self.point_id, self.reasons, self.decision = point_id, tuple(reasons), decision


class SentinelApprovalRequired(SentinelDenied):
    def __init__(self, point_id: str, reasons: Sequence[str], approval_id: str | None = None):
        super().__init__(point_id, reasons, "REQUIRE_APPROVAL")
        self.approval_id = approval_id
        if approval_id:
            self.args = (f"{point_id} needs human approval: run `sentinel sdk approve {approval_id}`, "
                         "then retry",)


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
    def __init__(self, workspace: Workspace, *, heartbeat: bool | None = None):
        self.ws = workspace
        self.cfg = workspace.load_config()
        self.enforcing = self.cfg.mode == "enforce"
        self.actor = f"app.{self.cfg.app_name}"
        self.flow = DataFlowTracker()
        self._process_run = f"proc-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self._lock = threading.Lock()
        self._registered: set[str] = set()
        self._warned: set[str] = set()
        self._engine: PolicyEngine | None = None
        self._policy_file: Path = workspace.policy_path
        self._last_policy_check = 0.0
        self._audit_ok: bool | None = None
        self._closed = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.store: AuditStore | None = self._open_store()
        self.forwarder = self._make_forwarder()
        self.approvals = ApprovalFile(workspace.approvals_path)
        self._load_policy(initial=True)
        want = (self.cfg.heartbeat_seconds > 0 and os.environ.get("SENTINEL_HEARTBEAT") != "0"
                if heartbeat is None else heartbeat)
        if want:
            self._thread = threading.Thread(target=self._loop, name="sentinel-heartbeat", daemon=True)
            self._thread.start()
            atexit.register(self.close)

    @classmethod
    def from_project(cls, path: Path | str | None = None, **kw: Any) -> Sentinel:
        return cls(find_workspace(path), **kw)

    # ---- setup that must never crash the host application ------------------------------------
    def _open_store(self) -> AuditStore | None:
        try:
            return AuditStore(self.ws.audit_path)
        except (OSError, Exception) as exc:  # noqa: BLE001 — sqlite3.Error, PermissionError, …
            if self.cfg.collector_url:
                self._warn_once("store", f"local audit store unavailable ({exc}); spooling in memory "
                                         "for the central collector")
                return AuditStore(":memory:")
            self._warn_once("store", f"audit store unavailable: {exc}")
            return None

    def _make_forwarder(self) -> CollectorForwarder | None:
        if not self.cfg.collector_url or self.store is None:
            return None
        token = os.environ.get(self.cfg.collector_token_env) or None
        cursor = None if self.store.path == ":memory:" else self.ws.spool_cursor_path
        try:
            return CollectorForwarder(self.cfg.collector_url, token, self.store, cursor)
        except ValueError as exc:
            self._warn_once("collector", f"collector disabled: {exc}")
            return None

    def _load_policy(self, initial: bool = False) -> None:
        if initial and not self.ws.policy_path.exists():
            try:
                write_policy(self.ws)
            except OSError:  # read-only deployment: keep the generated policy outside the project
                digest = hashlib.sha256(str(self.ws.project_root).encode()).hexdigest()[:10]
                self._policy_file = Path(tempfile.gettempdir()) / f"sentinel-{digest}" / "policy.yaml"
                try:
                    write_policy(self.ws, self._policy_file)
                    self._warn_once("policy-gen", "policy.yaml is missing and .sentinel/ is read-only; "
                                    "generated a temporary copy — run `sentinel sdk policy` at build time")
                except (OSError, WorkspaceError) as exc:
                    self._warn_once("policy-gen", f"cannot generate a policy: {exc}")
            except WorkspaceError as exc:
                self._warn_once("policy-gen", f"cannot generate a policy: {exc}")
        try:
            if self._engine is None:
                self._engine = PolicyEngine(self._policy_file)
            elif self._engine.disk_digest() != self._engine.digest:
                self._engine.reload()
        except PolicyError as exc:
            self._warn_once("policy", f"policy unavailable: {exc}")
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
    def _emit(self, ev: SecurityEvent, *, required: bool = True) -> bool:
        try:
            if self.store is None:
                raise AuditWriteError("no audit store available")
            self.store.append(ev)
            self._audit_ok = True
            return True
        except AuditWriteError as exc:
            self._audit_ok = False
            self._warn_once("audit", f"audit write failed: {exc}")
            if self.enforcing and required:
                raise SentinelUnavailable("audit trail unavailable; failing closed") from exc
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

    # ---- heartbeat / sync thread -------------------------------------------------------------
    def _loop(self) -> None:
        last_beat = 0.0
        while not self._stop.wait(_SYNC_SECONDS if last_beat else 0):
            try:
                if self.forwarder:
                    self.forwarder.flush()
                if time.monotonic() - last_beat >= self.cfg.heartbeat_seconds or last_beat == 0.0:
                    self._beat()
                    last_beat = time.monotonic()
            except Exception:  # noqa: BLE001,S110 — the health thread must never raise
                pass

    def _beat(self, stopping: bool = False) -> None:
        self._refresh_policy()
        eng = self._engine
        self._emit(SecurityEvent(
            trace_id=new_id(), run_id=self._process_run, actor_id=self.actor,
            event_type=EventType.HEARTBEAT, synthetic=True,
            metadata={"kind": "app_heartbeat", "pid": os.getpid(), "host": socket.gethostname(),
                      "app": self.cfg.app_name, "mode": self.cfg.mode, "stopping": stopping,
                      "policy_version": eng.version if eng else None,
                      "policy_digest": (eng.digest or "")[:12] if eng else None,
                      "policy_ok": bool(eng and eng.disk_digest() == eng.digest),
                      "audit_ok": self._audit_ok is not False,
                      "collector_ok": self.forwarder.ok if self.forwarder else None,
                      "collector_pending": self.forwarder.pending if self.forwarder else None,
                      "guarded_points": sorted(self._registered)[:50]}), required=False)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
        with contextlib.suppress(Exception):
            self._beat(stopping=True)  # clean shutdown marker: not an outage
            if self.forwarder:
                self.forwarder.flush()
        with contextlib.suppress(Exception):
            atexit.unregister(self.close)
        if self.store is not None:
            with contextlib.suppress(Exception):
                self.store.close()

    # ---- core check ------------------------------------------------------------------------
    def check(self, point_id: str, *, function: str = "", arg_names: Sequence[str] = (),
              destination: str | None = None, labels: Sequence[str | DataLabel] = (),
              purpose: str | None = None) -> GuardDecision:
        point_id = point_id.upper()
        try:
            return self._check(point_id, function, arg_names, destination, labels, purpose)
        except (SentinelDenied, SentinelUnavailable):
            raise
        except Exception as exc:  # noqa: BLE001 — an internal bug must not break the application
            if self.enforcing:
                raise SentinelUnavailable(f"internal error; failing closed: {exc!r}") from exc
            self._warn_once("internal", f"internal error, call ran unmonitored: {exc!r}")
            return GuardDecision(point_id, "", "NOT_EVALUATED", ("SENTINEL_INTERNAL_ERROR",),
                                 False, False)

    def _check(self, point_id: str, function: str, arg_names: Sequence[str],
               destination: str | None, labels: Sequence[str | DataLabel],
               purpose: str | None) -> GuardDecision:
        trace_id = new_id()
        declared = _labels(labels)
        if point_id not in self._registered:
            self._registered.add(point_id)
            self._emit(self._event(EventType.HEARTBEAT, trace_id, point_id,
                                   metadata={"registered_point": point_id, "function": function,
                                             "pid": os.getpid()}), required=False)
        self._refresh_policy()
        run_id = self._run_id()
        tainted = {p.label for p in self.flow.labels_for(actor_id=self._flow_actor(), run_id=run_id,
                                                         outbound_text=None)}
        all_labels = tuple(sorted({*declared, *tainted}, key=lambda d: d.value))
        self._emit(self._event(
            EventType.TOOL_CALL_REQUESTED, trace_id, point_id, destination=destination,
            data_labels=all_labels,
            metadata={"function": function, "arg_names": list(arg_names),
                      "purpose": purpose or _purpose_var.get()}))

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
            if self.enforcing:
                raise SentinelUnavailable(f"policy unavailable; failing closed: {exc}") from exc
            self._warn_once("policy", f"policy unavailable, running unmonitored: {exc}")
            return GuardDecision(point_id, trace_id, "NOT_EVALUATED", ("POLICY_UNAVAILABLE",),
                                 False, False)

        allowed = decision.decision is Decision.ALLOW
        approval_id: str | None = None
        if decision.decision is Decision.REQUIRE_APPROVAL and self.enforcing:
            fp = fingerprint(point_id, function, destination)
            granted = self._try_approval(fp)
            if granted:
                allowed, approval_id = True, granted["approval_id"]
            else:
                approval_id = self._request_approval(point_id, function, destination, fp, trace_id,
                                                     decision.policy_version, decision.reason_codes)
        would_block = not allowed
        self._emit(self._event(
            EventType.POLICY_DECISION, trace_id, point_id, policy_decision=decision.decision,
            policy_version=decision.policy_version, reason_codes=decision.reason_codes,
            data_labels=all_labels, destination=destination,
            metadata={"matched_rules": list(decision.matched_rules), "would_block": would_block,
                      "tainted_labels": sorted(t.value for t in tainted),
                      "approval_id": approval_id}))
        if would_block and self.enforcing:
            if decision.decision is Decision.REQUIRE_APPROVAL:
                raise SentinelApprovalRequired(point_id, decision.reason_codes, approval_id)
            raise SentinelDenied(point_id, decision.reason_codes, decision.decision.value)
        return GuardDecision(point_id, trace_id, decision.decision.value, decision.reason_codes,
                             would_block, True)

    # ---- approvals -------------------------------------------------------------------------
    def _try_approval(self, fp: str) -> dict[str, Any] | None:
        try:
            return self.approvals.consume_granted(fp)
        except OSError as exc:
            self._warn_once("approvals", f"approvals store unavailable: {exc}")
            return None

    def _request_approval(self, point_id: str, function: str, destination: str | None, fp: str,
                          trace_id: str, policy_version: str, reasons: Sequence[str]) -> str | None:
        try:
            ap, created = self.approvals.request(point_id, function, destination, fp, self.actor)
        except OSError as exc:
            self._warn_once("approvals", f"approvals store unavailable: {exc}")
            return None
        if created:
            self._emit(self._event(
                EventType.APPROVAL_REQUESTED, trace_id, point_id, destination=destination,
                policy_decision=Decision.REQUIRE_APPROVAL, policy_version=policy_version,
                reason_codes=tuple(reasons),
                metadata={"approval_id": ap["approval_id"], "function": function,
                          "expires_at": ap["expires_at"]}), required=False)
        return ap["approval_id"]

    # ---- completion / verification ---------------------------------------------------------
    def _done(self, gd: GuardDecision, *, ok: bool, error: str | None = None,
              produces: Sequence[str | DataLabel] = (),
              verify: Callable[[], Any] | None = None) -> None:
        try:
            ev = self._event(EventType.TOOL_EXECUTED, gd.trace_id, gd.point_id,
                             execution_status=ExecutionStatus.SUCCEEDED if ok
                             else ExecutionStatus.FAILED,
                             metadata={"error": error, "evaluated": gd.evaluated})
            self._emit(ev, required=False)  # the side effect already happened
            self.flow.record_execution(
                actor_id=self._flow_actor(), run_id=self._run_id(),
                tool_name=tool_name_for(gd.point_id),
                output_labels=set(_labels(produces)) if ok else set(), output_text=None,
                source_event_id=ev.event_id)
            if ok and verify is not None and gd.trace_id:
                self._verify(gd, verify)
        except Exception as exc:  # noqa: BLE001 — post-processing must never break the app
            self._warn_once("done", f"post-call recording failed: {exc!r}")

    def _verify(self, gd: GuardDecision, verify: Callable[[], Any]) -> None:
        """Developer-supplied independent read-back. True → VERIFIED; False/str → FAILED with the
        string as the discrepancy; an exception → INCONCLUSIVE. Nothing is claimed without a verifier."""
        outcome, disc = "VERIFIED", []
        try:
            res = verify()
            if res is False or isinstance(res, str):
                outcome = "FAILED"
                disc = [res if isinstance(res, str) else "verifier returned False"]
        except Exception as exc:  # noqa: BLE001
            outcome, disc = "INCONCLUSIVE", [f"verifier raised {type(exc).__name__}"]
        self._emit(self._event(
            EventType.OUTCOME_VERIFIED, gd.trace_id, gd.point_id,
            metadata={"outcome": outcome, "discrepancies": disc,
                      "evidence": {"source": "developer verify() callback"}}), required=False)

    # ---- developer API ---------------------------------------------------------------------
    @contextlib.contextmanager
    def monitor(self, point_id: str, *, destination: str | None = None,
                labels: Sequence[str] = (), produces: Sequence[str] = (),
                purpose: str | None = None,
                verify: Callable[[], Any] | None = None) -> Iterator[GuardDecision]:
        gd = self.check(point_id, destination=destination, labels=labels, purpose=purpose)
        try:
            yield gd
        except BaseException as exc:
            self._done(gd, ok=False, error=type(exc).__name__)
            raise
        self._done(gd, ok=True, produces=produces, verify=verify)

    def guard(self, point_id: str, *, destination_arg: str | None = None,
              destination: str | None = None, labels: Sequence[str] = (),
              produces: Sequence[str] = (), purpose: str | None = None,
              verify: Callable[..., Any] | None = None):
        """`verify(result, *args, **kwargs)` is an optional independent read-back."""
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

            def checker(args: tuple, kwargs: dict) -> GuardDecision:
                return self.check(point_id, function=fn.__qualname__, arg_names=names,
                                  destination=dest(args, kwargs), labels=labels, purpose=purpose)

            def verifier(result: Any, args: tuple, kwargs: dict):
                return (lambda: verify(result, *args, **kwargs)) if verify else None

            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def awrapper(*args, **kwargs):
                    gd = checker(args, kwargs)
                    try:
                        result = await fn(*args, **kwargs)
                    except BaseException as exc:
                        self._done(gd, ok=False, error=type(exc).__name__)
                        raise
                    self._done(gd, ok=True, produces=produces, verify=verifier(result, args, kwargs))
                    return result
                return awrapper

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                gd = checker(args, kwargs)
                try:
                    result = fn(*args, **kwargs)
                except BaseException as exc:
                    self._done(gd, ok=False, error=type(exc).__name__)
                    raise
                self._done(gd, ok=True, produces=produces, verify=verifier(result, args, kwargs))
                return result
            return wrapper
        return decorate


# ---- module-level convenience (lazy default instance) -------------------------------------------
class _Unconfigured:
    """Used when Sentinel cannot start: warns once and never blocks the application."""

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
            except Exception as exc:  # noqa: BLE001 — never crash the host app because of Sentinel
                if os.environ.get("SENTINEL_REQUIRE") == "1":
                    raise
                _default = _Unconfigured(f"Sentinel failed to start ({exc!r})")
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


__all__ = ["ApprovalError", "GuardDecision", "Sentinel", "SentinelApprovalRequired",
           "SentinelDenied", "SentinelUnavailable", "get_default", "guard", "monitor", "purpose"]
