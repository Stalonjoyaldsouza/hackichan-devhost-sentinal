"""Live monitoring of a deployed application's guard events — in a process *separate* from the app.

Reads new events from the audit trail (local or the central collector's store) and feeds them to:

  * the deterministic `Monitor` (data-flow denials, repeated denials, outcome mismatches)
  * optionally the advisory AI agents (threat / risk / audit) through the same `AISupervisor` the
    control plane uses, with the real provider (Groq) or the offline stand-in

Findings are appended to the audit trail as `finding` events, so they appear in `sdk watch`,
`sdk findings` and `sdk status`. The AI sees point titles and categories (from analysis.json) and
only masked destinations and purposes: e-mail local parts are reduced to their first letter (also
inside free text) and URLs to their host.
Nothing here can allow, deny or alter a call: it reads events and writes findings.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from sentinel.ai.agents import AISupervisor
from sentinel.ai.providers import Provider
from sentinel.audit import AuditStore, AuditWriteError
from sentinel.contracts import SecurityEvent
from sentinel.monitor import Monitor
from sentinel.sdk.models import AnalysisResult
from sentinel.sdk.workspace import Workspace


def mask_destination(dest: str | None) -> str | None:
    if not dest:
        return dest
    if "@" in dest and "://" not in dest:
        local, _, domain = dest.rpartition("@")
        return f"{local[:1]}***@{domain.lower()}"
    host = urlparse(dest).hostname
    return host or dest[:40]


_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def mask_text(text: str | None) -> str | None:
    """Mask e-mail local parts inside free text (purposes, function args never leave as values)."""
    return _EMAIL.sub(r"\1***@\2", text) if text else text


class StreamMonitor:
    def __init__(self, ws: Workspace, analysis: AnalysisResult | None, provider: Provider | None):
        self.store = AuditStore(ws.audit_path)
        self.by_tool = {p.tool_name: p for p in (analysis.points if analysis else [])}
        self.write_failures = 0
        self.det = Monitor(self._emit)
        self.ai = (AISupervisor(provider, self.store, self._emit, batch_size=40, transform=self._enrich)
                   if provider else None)

    def _emit(self, ev: SecurityEvent) -> bool:
        try:
            self.store.append(ev)
            return True
        except AuditWriteError:
            self.write_failures += 1
            return False

    def _enrich(self, ev: SecurityEvent) -> SecurityEvent:
        if ev.metadata.get("point_title"):
            return ev  # already enriched
        point = self.by_tool.get(ev.tool_name or "")
        extra = {"point_title": point.title, "category": point.category.value,
                 "risk": point.risk.value} if point else {}
        return ev.model_copy(update={
            "destination": mask_destination(ev.destination),
            "tool_name": point.title[:60] if point else ev.tool_name,
            "metadata": {**ev.metadata, **extra,
                         **({"purpose": mask_text(ev.metadata["purpose"])}
                            if ev.metadata.get("purpose") else {})}})

    def handle(self, ev: SecurityEvent) -> None:
        if not ev.metadata.get("point_id"):
            return  # not a guard event (heartbeats, findings, agent tasks …)
        enriched = self._enrich(ev)
        self.det(enriched, True)
        if self.ai:
            self.ai(enriched, True)

    def start(self) -> None:
        if self.ai:
            self.ai.start()

    def drain(self) -> None:
        if self.ai:
            self.ai.drain()

    def close(self) -> None:
        if self.ai:
            self.ai.stop()
        self.store.close()
