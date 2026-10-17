"""Deterministic policy engine (CLAUDE.md §5.2).

- Policy bundles are YAML, validated strictly on load; an invalid bundle is rejected as a whole.
- Precedence: DENY > REQUIRE_APPROVAL > ALLOW. No matching ALLOW rule → DENY (default deny).
- The engine never executes actions and never invents a rule.
- The policy version is `<label>@<sha256 prefix>` so every decision is tied to exact policy bytes.
"""

from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinel.contracts import DataLabel, Decision, DecisionRequest, Mode, PolicyDecision


class PolicyError(Exception):
    """The policy bundle could not be loaded or validated."""


class PolicyUnavailable(Exception):
    """A decision cannot be made; callers must fail closed."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolPolicy(_Model):
    protected: bool = True
    safe_in_restricted: bool = False
    description: str = ""


class Match(_Model):
    tools: tuple[str, ...] = ()
    actors: tuple[str, ...] = ()
    roles_any: tuple[str, ...] = ()
    data_labels_any: tuple[DataLabel, ...] = ()
    destination_domain_in: tuple[str, ...] = ()
    destination_domain_not_in: tuple[str, ...] = ()
    after_tools_any: tuple[str, ...] = ()
    arg_gt: dict[str, float] = Field(default_factory=dict)


class Rule(_Model):
    id: str = Field(pattern=r"^R-[A-Z0-9-]+$")
    effect: Decision
    match: Match
    reason: str = Field(pattern=r"^[A-Z0-9_]+$")
    description: str = ""


class PolicyBundle(_Model):
    version_label: str = Field(min_length=1)
    approvers: tuple[str, ...] = Field(min_length=1)
    approval_ttl_seconds: int = Field(gt=0, le=86400)
    tools: dict[str, ToolPolicy]
    rules: tuple[Rule, ...]


def destination_domain(destination: str | None) -> str | None:
    if not destination:
        return None
    if "@" in destination and "://" not in destination:
        return destination.rsplit("@", 1)[1].lower().strip()
    host = urlparse(destination).hostname
    return host.lower() if host else None


def _domain_matches(domain: str, allowed: tuple[str, ...]) -> bool:
    return any(domain == a or domain.endswith("." + a) for a in allowed)


def _match(m: Match, req: DecisionRequest) -> bool:
    """All specified conditions must hold. Unspecified conditions are ignored."""
    if m.tools and req.tool_name not in m.tools:
        return False
    if m.actors and req.actor_id not in m.actors:
        return False
    if m.roles_any and not set(m.roles_any) & set(req.actor_roles):
        return False
    if m.data_labels_any and not set(m.data_labels_any) & set(req.data_labels):
        return False
    domain = destination_domain(req.destination)
    if m.destination_domain_in and (domain is None or not _domain_matches(domain, m.destination_domain_in)):
        return False
    # Unknown destination counts as "not in" the approved list (conservative for DENY rules).
    if (m.destination_domain_not_in and domain is not None
            and _domain_matches(domain, m.destination_domain_not_in)):
        return False
    if m.after_tools_any and not set(m.after_tools_any) & set(req.prior_tools_in_run):
        return False
    for arg, threshold in m.arg_gt.items():
        value = req.arguments.get(arg)
        if not isinstance(value, int | float) or isinstance(value, bool) or not value > threshold:
            return False
    return True


class PolicyEngine:
    def __init__(self, path: Path):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._bundle: PolicyBundle | None = None
        self._digest: str | None = None
        self.loaded_at: float | None = None
        # Fault-injection switch for control-validation tests/demos (Scenario D).
        self.available = True
        self.reload()

    # ---- loading -------------------------------------------------------------------------
    @staticmethod
    def _read(path: Path) -> tuple[PolicyBundle, str]:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
        try:
            data = yaml.safe_load(raw)
            bundle = PolicyBundle.model_validate(data)
        except (yaml.YAMLError, ValidationError) as exc:
            raise PolicyError(f"invalid policy bundle {path}: {exc}") from exc
        ids = [r.id for r in bundle.rules]
        if len(ids) != len(set(ids)):
            raise PolicyError("duplicate rule ids in policy bundle")
        for rule in bundle.rules:
            unknown = set(rule.match.tools) - set(bundle.tools)
            if unknown:
                raise PolicyError(f"rule {rule.id} references unknown tools {sorted(unknown)}")
        return bundle, hashlib.sha256(raw).hexdigest()

    def reload(self) -> None:
        bundle, digest = self._read(self._path)
        with self._lock:
            self._bundle, self._digest, self.loaded_at = bundle, digest, time.time()

    # ---- introspection (used by the watchdog) --------------------------------------------
    @property
    def bundle(self) -> PolicyBundle:
        if self._bundle is None:
            raise PolicyUnavailable("no policy loaded")
        return self._bundle

    @property
    def version(self) -> str:
        if self._bundle is None or self._digest is None:
            raise PolicyUnavailable("no policy loaded")
        return f"{self._bundle.version_label}@{self._digest[:12]}"

    @property
    def digest(self) -> str | None:
        return self._digest

    @property
    def path(self) -> Path:
        return self._path

    def disk_digest(self) -> str | None:
        try:
            return hashlib.sha256(self._path.read_bytes()).hexdigest()
        except OSError:
            return None

    def tool_policy(self, tool_name: str) -> ToolPolicy | None:
        return self.bundle.tools.get(tool_name)

    # ---- evaluation ------------------------------------------------------------------------
    def evaluate(self, req: DecisionRequest) -> PolicyDecision:
        if not self.available:
            raise PolicyUnavailable("policy engine unavailable")
        with self._lock:
            bundle, version = self.bundle, self.version

        def decide(decision: Decision, rules: list[str], reasons: list[str]) -> PolicyDecision:
            return PolicyDecision(
                decision=decision,
                request_id=req.request_id,
                policy_version=version,
                matched_rules=tuple(rules),
                reason_codes=tuple(reasons),
                requires_human_approval=decision is Decision.REQUIRE_APPROVAL,
            )

        tool = bundle.tools.get(req.tool_name)
        if tool is None:
            return decide(Decision.DENY, [], ["UNKNOWN_TOOL"])
        if req.mode is Mode.RESTRICTED and not tool.safe_in_restricted:
            return decide(Decision.DENY, [], ["SAFE_MODE_RESTRICTED"])

        matched: dict[Decision, list[Rule]] = {d: [] for d in Decision}
        for rule in bundle.rules:
            if _match(rule.match, req):
                matched[rule.effect].append(rule)

        for effect in (Decision.DENY, Decision.REQUIRE_APPROVAL, Decision.ALLOW):
            if matched[effect]:
                rules = matched[effect]
                return decide(effect, [r.id for r in rules], [r.reason for r in rules])
        return decide(Decision.DENY, [], ["DEFAULT_DENY_NO_MATCHING_ALLOW"])


def describe(bundle: PolicyBundle) -> dict[str, Any]:
    return {
        "version_label": bundle.version_label,
        "tools": sorted(bundle.tools),
        "rules": [r.id for r in bundle.rules],
    }
