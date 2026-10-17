"""Shared data contracts (CLAUDE.md §6).

All boundary objects are strict Pydantic models: unknown fields and invalid enum values are
rejected, so malformed requests fail at the edge instead of deep inside enforcement.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    NOT_EVALUATED = "NOT_EVALUATED"


class ExecutionStatus(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class OutcomeStatus(StrEnum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"
    INCONCLUSIVE = "INCONCLUSIVE"


class Mode(StrEnum):
    NORMAL = "NORMAL"
    RESTRICTED = "RESTRICTED"


class HealthStatus(StrEnum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"


class EventType(StrEnum):
    TOOL_CALL_REQUESTED = "tool_call_requested"
    POLICY_DECISION = "policy_decision"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    TOOL_EXECUTED = "tool_executed"
    OUTCOME_VERIFIED = "outcome_verified"
    FINDING = "finding"
    HEALTH_CHECK = "health_check"
    MODE_CHANGED = "mode_changed"
    HEARTBEAT = "heartbeat"
    AUDIT_PROBE = "audit_probe"
    AGENT_TASK = "agent_task"


class DataLabel(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"


class ToolCallRequest(Strict):
    """What an agent asks for. Note: no actor_id — identity comes from the credential."""

    tool_name: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_.]*$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    run_id: str = Field(min_length=1, max_length=100)
    session_id: str | None = Field(default=None, max_length=100)
    purpose: str | None = Field(default=None, max_length=500)


class DecisionRequest(Strict):
    """Normalized input to the policy engine; built by the gateway from validated data only."""

    request_id: str
    actor_id: str
    actor_roles: tuple[str, ...]
    tool_name: str
    arguments: dict[str, Any]
    resource: str | None
    destination: str | None
    data_labels: tuple[DataLabel, ...]
    prior_tools_in_run: tuple[str, ...]
    mode: Mode


class PolicyDecision(Strict):
    decision: Decision
    request_id: str
    policy_version: str
    matched_rules: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    requires_human_approval: bool = False
    expires_at: datetime | None = None
    decided_at: datetime = Field(default_factory=utcnow)


class SecurityEvent(Strict):
    event_id: str = Field(default_factory=new_id)
    timestamp: datetime = Field(default_factory=utcnow)
    trace_id: str
    run_id: str | None = None
    session_id: str | None = None
    actor_id: str
    parent_actor_id: str | None = None
    event_type: EventType
    tool_name: str | None = None
    resource: str | None = None
    destination: str | None = None
    data_labels: tuple[DataLabel, ...] = ()
    policy_decision: Decision = Decision.NOT_EVALUATED
    policy_version: str | None = None
    reason_codes: tuple[str, ...] = ()
    execution_status: ExecutionStatus = ExecutionStatus.NOT_STARTED
    evidence_refs: tuple[str, ...] = ()
    synthetic: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(Strict):
    finding_id: str = Field(default_factory=new_id)
    component: str = Field(pattern=r"^(monitoring|sequence_dataflow|risk|outcome|audit|watchdog)$")
    severity: Severity
    summary: str
    evidence_event_ids: tuple[str, ...] = ()
    confidence: float = Field(ge=0.0, le=1.0)
    status: FindingStatus = FindingStatus.OPEN
    recommended_action: str
    created_at: datetime = Field(default_factory=utcnow)


class OutcomeResult(Strict):
    status: OutcomeStatus
    trace_id: str
    tool_name: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    discrepancies: tuple[str, ...] = ()


class ProbeResult(Strict):
    probe: str
    status: HealthStatus
    detail: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class CallOutcome(StrEnum):
    EXECUTED = "EXECUTED"
    DENIED = "DENIED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ERROR = "ERROR"


class GatewayResponse(Strict):
    """What the agent gets back from the gateway."""

    trace_id: str
    outcome: CallOutcome
    decision: Decision
    reason_codes: tuple[str, ...] = ()
    approval_id: str | None = None
    result: dict[str, Any] | None = None
    verification: OutcomeStatus | None = None
