"""Terminal rendering of security events. Shared by the in-process runtime and `sentinel watch`.

All event-derived strings are passed through `_clean` to strip control characters, so agent- or
tool-controlled text cannot inject terminal escape sequences.
"""

from __future__ import annotations

import os
import re
import sys
from typing import TextIO

from sentinel.contracts import EventType, SecurityEvent

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _clean(value: object, limit: int = 160) -> str:
    text = _CTRL.sub("?", str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return f"\033[{';'.join(codes)}m{text}\033[0m"


RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, DIM, BOLD, REV = "31", "32", "33", "34", "35", "36", "2", "1", "7"


class TerminalLog:
    def __init__(self, stream: TextIO | None = None, verbose: bool = False, color: bool | None = None):
        self.stream = stream or sys.stdout
        self.verbose = verbose
        if color is None:
            color = self.stream.isatty() and os.environ.get("NO_COLOR") is None
        self.s = Style(color)

    def write(self, line: str) -> None:
        print(line, file=self.stream, flush=True)

    def banner(self, text: str, color: str = CYAN) -> None:
        self.write("")
        self.write(self.s(f"━━ {text} " + "━" * max(0, 72 - len(text)), BOLD, color))

    def note(self, text: str) -> None:
        self.write(self.s(f"   {_clean(text, 400)}", DIM))

    def __call__(self, ev: SecurityEvent, persisted: bool = True) -> None:
        line = self.format(ev)
        if line is None:
            return
        if not persisted:
            line += " " + self.s("[NOT PERSISTED]", BOLD, RED)
        self.write(line)

    def format(self, ev: SecurityEvent) -> str | None:  # noqa: C901 — flat dispatch on event type
        s, t = self.s, ev.event_type
        quiet = {EventType.HEARTBEAT, EventType.AUDIT_PROBE}
        if not self.verbose and (t in quiet or (ev.synthetic and t is not EventType.HEALTH_CHECK)):
            return None
        if t is EventType.HEALTH_CHECK and not self.verbose and ev.metadata.get("status") == "OK":
            return None

        ts = s(ev.timestamp.strftime("%H:%M:%S.%f")[:-3], DIM)
        who = _clean(ev.actor_id, 32)
        tool = _clean(ev.tool_name or "", 24)
        tag = s(f"{ev.trace_id[:8]}", DIM)

        def row(label: str, color: str, body: str) -> str:
            return f"{ts} {s(f'{label:<11}', BOLD, color)} {who:<22} {body} {tag}"

        reasons = ",".join(_clean(r, 60) for r in ev.reason_codes)
        match t:
            case EventType.TOOL_CALL_REQUESTED:
                extra = []
                if ev.resource:
                    extra.append(f"resource={_clean(ev.resource, 40)}")
                if ev.destination:
                    extra.append(f"dest={_clean(ev.destination, 60)}")
                if ev.data_labels:
                    extra.append(s(f"labels={[x.value for x in ev.data_labels]}", MAGENTA))
                return row("→ REQUEST", BLUE, f"{tool} {' '.join(extra)}")
            case EventType.POLICY_DECISION:
                d = ev.policy_decision.value
                color, label = {"ALLOW": (GREEN, "✔ ALLOW"), "DENY": (RED, "✖ DENY"),
                                "REQUIRE_APPROVAL": (YELLOW, "⏸ HOLD")}.get(d, (DIM, d))
                rules = ",".join(ev.metadata.get("matched_rules", []))
                body = f"{tool} reasons={reasons}" + (f" rules={rules}" if rules else "")
                if ev.policy_decision.value == "DENY" and ev.evidence_refs:
                    body += s(f" evidence={[r[:8] for r in ev.evidence_refs]}", MAGENTA)
                return row(label, color, body)
            case EventType.APPROVAL_REQUESTED:
                return row("⏸ APPROVAL?", YELLOW,
                           f"{tool} approval_id={_clean(ev.metadata.get('approval_id'))}")
            case EventType.APPROVAL_GRANTED:
                return row("✔ APPROVED", GREEN, f"{tool} by {who}")
            case EventType.APPROVAL_REJECTED:
                return row("✖ REJECTED", RED, f"{tool} by {who}")
            case EventType.TOOL_EXECUTED:
                st = ev.execution_status.value
                color = GREEN if st == "SUCCEEDED" else RED if st == "FAILED" else YELLOW
                err = ev.metadata.get("error")
                return row("⚙ EXECUTED", color, f"{tool} status={st}"
                           + (f" error={_clean(err, 80)}" if err else ""))
            case EventType.OUTCOME_VERIFIED:
                o = str(ev.metadata.get("outcome"))
                color = {"VERIFIED": GREEN, "FAILED": RED, "PARTIAL": YELLOW}.get(o, DIM)
                disc = "; ".join(_clean(d, 80) for d in ev.metadata.get("discrepancies", []))
                src = (ev.metadata.get("evidence") or {}).get("source", "-")
                return row(f"◎ {o}"[:11], color, f"{tool} evidence={_clean(src, 30)}"
                           + (f" — {disc}" if disc else ""))
            case EventType.FINDING:
                sev = str(ev.metadata.get("severity"))
                color = RED if sev in {"HIGH", "CRITICAL"} else YELLOW
                src = ev.metadata.get("source")
                ai = s(f" [AI:{_clean(src, 40)}]", MAGENTA) if src else ""
                return row("⚠ FINDING", color,
                           f"{sev} {ev.metadata.get('component')}: "
                           f"{_clean(ev.metadata.get('summary'), 200)}{ai}")
            case EventType.HEALTH_CHECK:
                st = str(ev.metadata.get("status"))
                color = {"OK": GREEN, "DEGRADED": YELLOW}.get(st, RED)
                return row(f"♥ {st}"[:11], color, f"probe={ev.metadata.get('probe')}"
                           f" {_clean(ev.metadata.get('detail'), 140)}")
            case EventType.MODE_CHANGED:
                to = ev.metadata.get("to")
                cv = ev.metadata.get("containment_verified")
                cont = "" if cv is None else (" containment=VERIFIED" if cv
                                              else " containment=UNVERIFIED")
                color = RED if to == "RESTRICTED" else GREEN
                return s(f"{ts} ▌MODE {ev.metadata.get('from')} → {to} reason={reasons}{cont}"
                         f" by {who} ", BOLD, REV, color)
            case EventType.HEARTBEAT:
                return row("· HEARTBEAT", DIM, f"round={ev.metadata.get('round')}"
                           f" mode={ev.metadata.get('mode')}")
            case EventType.AUDIT_PROBE:
                return row("· AUDITPROBE", DIM, "")
        return None
