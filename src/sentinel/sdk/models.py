"""Data model for the SDK: monitoring points, analysis results and their lifecycle."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Category(StrEnum):
    SENSITIVE_DATA = "sensitive_data_access"
    TOOL_CALL = "tool_call"
    EXTERNAL_API = "external_api"
    MESSAGING = "messaging"
    INTER_AGENT = "inter_agent"
    CODE_EXECUTION = "code_execution"
    FILE_SYSTEM = "file_system"
    DATABASE = "database"
    SECRET_ACCESS = "secret_access"  # noqa: S105 — a category label, not a credential
    LLM_CALL = "llm_call"


class Risk(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


RISK_ORDER = [Risk.LOW, Risk.MEDIUM, Risk.HIGH, Risk.CRITICAL]


def bump(risk: Risk, steps: int = 1) -> Risk:
    return RISK_ORDER[max(0, min(len(RISK_ORDER) - 1, RISK_ORDER.index(risk) + steps))]


class PointState(StrEnum):
    """Lifecycle. Each state is derived from evidence, never asserted.

    IDENTIFIED   found by analysis
    SELECTED     the developer chose to monitor it (selection recorded in state.json)
    IMPLEMENTED  a guard for this point id exists in the project's source code
    ACTIVE       the guard has been observed evaluating policy at runtime (audit-store evidence)
    """

    IDENTIFIED = "IDENTIFIED"
    SELECTED = "SELECTED"
    IMPLEMENTED = "IMPLEMENTED"
    ACTIVE = "ACTIVE"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Location(Strict):
    file: str
    line: int = Field(ge=1)
    symbol: str = "<module>"
    snippet: str = ""
    arg_names: list[str] = Field(default_factory=list)


class MonitoringPoint(Strict):
    point_id: str = Field(pattern=r"^MP-[0-9A-F]{8}$")
    title: str
    category: Category
    risk: Risk
    static_risk: Risk
    description: str
    reason: str
    locations: list[Location] = Field(min_length=1)
    source: str = Field(default="static", pattern=r"^(static|ai)$")
    verified: bool = True            # location confirmed by static analysis of the real file
    exposed_via_tool: str | None = None
    guideline_refs: list[str] = Field(default_factory=list)
    risk_notes: list[str] = Field(default_factory=list)
    ai_notes: list[str] = Field(default_factory=list)

    @property
    def tool_name(self) -> str:
        return "mp." + self.point_id[3:].lower()


def make_point_id(category: str, kind: str, file: str, symbol: str) -> str:
    """Stable across line shifts: derived from what and where (file + enclosing symbol)."""
    digest = hashlib.sha256(f"{category}|{kind}|{file}|{symbol}".encode()).hexdigest()
    return "MP-" + digest[:8].upper()


def tool_name_for(point_id: str) -> str:
    return "mp." + point_id[3:].lower()


class Requirement(Strict):
    req_id: str
    text: str
    strength: str = Field(pattern=r"^(MUST|SHOULD)$")
    topics: list[Category] = Field(default_factory=list)
    source: str = ""


class GuidelineDoc(Strict):
    source: str
    sha256: str
    chars: int
    requirements: list[Requirement] = Field(default_factory=list)


class ProjectProfile(Strict):
    root_name: str
    files_scanned: int
    files_skipped_sensitive: list[str] = Field(default_factory=list)
    files_skipped_other: int = 0
    languages: dict[str, int] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    readme_excerpt: str = ""


class AgentRecord(Strict):
    name: str
    status: str
    detail: str = ""


class AnalysisResult(Strict):
    analysis_id: str
    created_at: str
    provider: str
    project: ProjectProfile
    guidelines: list[GuidelineDoc] = Field(default_factory=list)
    understanding: dict[str, Any] = Field(default_factory=dict)
    points: list[MonitoringPoint] = Field(default_factory=list)
    agents: list[AgentRecord] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def point(self, point_id: str) -> MonitoringPoint | None:
        return next((p for p in self.points if p.point_id == point_id.upper()), None)
