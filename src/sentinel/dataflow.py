"""Sequence and data-flow tracking (CLAUDE.md §5.4) — deterministic.

Two mechanisms label outbound data:

1. **Taint** — labels of sensitive data an actor has *read* propagate to the run and, for a bounded
   TTL, to the actor (so starting a new run does not launder the data). Conservative: it can
   over-block an unrelated outbound message after a sensitive read in the same run.
2. **Content fingerprints** — 8-word shingles of sensitive outputs. Outbound text that contains any
   shingle inherits the source labels, regardless of which actor or run read it.

Not detected: paraphrased/summarised/encoded content that removes all shingles, and data that
enters through uninstrumented paths. Provenance is reported only when one of the mechanisms fired.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass, field

from sentinel.contracts import DataLabel

SENSITIVE = frozenset({DataLabel.CONFIDENTIAL, DataLabel.PII})
SHINGLE_WORDS = 8
_WORD = re.compile(r"[a-z0-9]+")


def _shingles(text: str) -> set[str]:
    words = _WORD.findall(text.lower())
    if len(words) < SHINGLE_WORDS:
        return {hashlib.sha256(" ".join(words).encode()).hexdigest()} if len(words) >= 3 else set()
    return {
        hashlib.sha256(" ".join(words[i : i + SHINGLE_WORDS]).encode()).hexdigest()
        for i in range(len(words) - SHINGLE_WORDS + 1)
    }


@dataclass(frozen=True)
class Provenance:
    label: DataLabel
    mechanism: str  # "run_taint" | "actor_taint" | "fingerprint"
    source_event_id: str


@dataclass
class _Taint:
    labels: dict[DataLabel, str] = field(default_factory=dict)  # label -> first source event id
    expires_at: float = float("inf")


class DataFlowTracker:
    def __init__(self, actor_taint_ttl_seconds: float = 3600.0):
        self._lock = threading.Lock()
        self._ttl = actor_taint_ttl_seconds
        self._run_taint: dict[str, _Taint] = {}
        self._actor_taint: dict[str, _Taint] = {}
        self._fingerprints: dict[str, tuple[frozenset[DataLabel], str]] = {}
        self._run_tools: dict[str, list[str]] = {}

    def record_execution(
        self,
        *,
        actor_id: str,
        run_id: str,
        tool_name: str,
        output_labels: set[DataLabel],
        output_text: str | None,
        source_event_id: str,
    ) -> None:
        sensitive = output_labels & SENSITIVE
        with self._lock:
            self._run_tools.setdefault(run_id, []).append(tool_name)
            if not sensitive:
                return
            run = self._run_taint.setdefault(run_id, _Taint())
            actor = self._actor_taint.setdefault(actor_id, _Taint())
            actor.expires_at = time.time() + self._ttl
            for label in sensitive:
                run.labels.setdefault(label, source_event_id)
                actor.labels.setdefault(label, source_event_id)
            if output_text:
                for sh in _shingles(output_text):
                    self._fingerprints.setdefault(sh, (frozenset(sensitive), source_event_id))

    def prior_tools(self, run_id: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._run_tools.get(run_id, ()))

    def labels_for(
        self, *, actor_id: str, run_id: str, outbound_text: str | None
    ) -> list[Provenance]:
        out: list[Provenance] = []
        now = time.time()
        with self._lock:
            run = self._run_taint.get(run_id)
            if run:
                out += [Provenance(lbl, "run_taint", ev) for lbl, ev in run.labels.items()]
            actor = self._actor_taint.get(actor_id)
            if actor and actor.expires_at > now:
                out += [Provenance(lbl, "actor_taint", ev) for lbl, ev in actor.labels.items()]
            if outbound_text:
                seen: set[tuple[DataLabel, str]] = set()
                for sh in _shingles(outbound_text):
                    hit = self._fingerprints.get(sh)
                    if hit:
                        for lbl in hit[0]:
                            if (lbl, hit[1]) not in seen:
                                seen.add((lbl, hit[1]))
                                out.append(Provenance(lbl, "fingerprint", hit[1]))
        return out
