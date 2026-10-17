"""Restricted/safe-mode controller (CLAUDE.md §5.9) — deterministic.

Trigger:   any CRITICAL watchdog probe.
Effect:    mode=RESTRICTED; the policy engine then denies every tool not marked
           `safe_in_restricted` (reason SAFE_MODE_RESTRICTED).
Verify:    after the transition a containment probe asks the gateway to run a protected tool and
           checks it was refused and not executed. Unverified containment is reported as such.
Recovery:  only after `required_healthy_rounds` consecutive all-OK watchdog rounds AND an override
           by a configured human approver.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sentinel.contracts import EventType, Mode, SecurityEvent, Severity, new_id, utcnow


class RecoveryError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Transition:
    at: datetime
    from_mode: Mode
    to_mode: Mode
    reason: str
    actor_id: str
    containment_verified: bool | None
    persisted: bool


class SafeModeController:
    ACTOR = "service.safemode"

    def __init__(
        self,
        emit: Callable[[SecurityEvent], bool],
        approvers: Callable[[], tuple[str, ...]],
        required_healthy_rounds: int = 2,
    ):
        self._emit = emit
        self._approvers = approvers
        self._required = required_healthy_rounds
        self._lock = threading.Lock()
        self._mode = Mode.NORMAL
        self._reason = ""
        self._healthy_rounds = 0
        self.history: list[Transition] = []
        # Returns (contained, evidence). Injected by the runtime to avoid a gateway import cycle.
        self.containment_probe: Callable[[], tuple[bool, dict]] | None = None

    @property
    def mode(self) -> Mode:
        return self._mode

    @property
    def reason(self) -> str:
        return self._reason

    @property
    def healthy_rounds(self) -> int:
        return self._healthy_rounds

    def _transition(self, to: Mode, reason: str, actor_id: str, severity: Severity) -> Transition:
        from_mode = self._mode
        self._mode, self._reason = to, reason
        verified: bool | None = None
        probe_evidence: dict = {}
        if to is Mode.RESTRICTED and self.containment_probe is not None:
            try:
                verified, probe_evidence = self.containment_probe()
            except Exception as exc:  # noqa: BLE001 — a probe crash means containment is unverified
                verified, probe_evidence = False, {"error": f"{type(exc).__name__}: {exc}"}
        persisted = self._emit(
            SecurityEvent(
                trace_id=new_id(), actor_id=actor_id, event_type=EventType.MODE_CHANGED,
                reason_codes=(reason,),
                metadata={"from": from_mode.value, "to": to.value, "severity": severity.value,
                          "containment_verified": verified, "containment_evidence": probe_evidence},
            )
        )
        t = Transition(utcnow(), from_mode, to, reason, actor_id, verified, persisted)
        self.history.append(t)
        return t

    def enter_restricted(self, reason: str) -> Transition | None:
        with self._lock:
            self._healthy_rounds = 0
            if self._mode is Mode.RESTRICTED:
                return None
            return self._transition(Mode.RESTRICTED, reason, self.ACTOR, Severity.CRITICAL)

    def observe_round(self, all_ok: bool) -> None:
        with self._lock:
            self._healthy_rounds = self._healthy_rounds + 1 if all_ok else 0

    def recover(self, approver_id: str) -> Transition:
        """Human override back to NORMAL; only allowed when controls are demonstrably healthy."""
        with self._lock:
            if self._mode is Mode.NORMAL:
                raise RecoveryError("NOT_RESTRICTED", "already in NORMAL mode")
            if approver_id not in self._approvers():
                raise RecoveryError("APPROVER_NOT_AUTHORISED", f"{approver_id} cannot lift safe mode")
            if self._healthy_rounds < self._required:
                raise RecoveryError(
                    "HEALTH_NOT_RESTORED",
                    f"{self._healthy_rounds}/{self._required} consecutive healthy watchdog rounds",
                )
            return self._transition(Mode.NORMAL, "RECOVERY_APPROVED", approver_id, Severity.INFO)
