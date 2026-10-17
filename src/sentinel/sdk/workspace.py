"""The `.sentinel/` workspace inside a business project.

    .sentinel/config.yaml    developer-edited settings (mode, allowed domains, per-point actions)
    .sentinel/analysis.json  latest analysis (points, guideline requirements, understanding)
    .sentinel/state.json     which points the developer selected
    .sentinel/policy.yaml    DERIVED from config + selection; regenerate, don't hand-edit
    .sentinel/audit.db       append-only audit trail (analysis activity + runtime guard events)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinel.sdk.models import AnalysisResult

DIRNAME = ".sentinel"


class WorkspaceError(Exception):
    pass


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    app_name: str = "business-app"
    mode: str = Field(default="observe", pattern=r"^(observe|enforce)$")
    default_action: str = Field(default="ALLOW", pattern=r"^(ALLOW|DENY|REQUIRE_APPROVAL)$")
    allowed_destination_domains: list[str] = Field(default_factory=list)
    approvers: list[str] = Field(default_factory=lambda: ["human.owner"], min_length=1)
    point_actions: dict[str, str] = Field(default_factory=dict)
    activity_window_hours: float = Field(default=24.0, gt=0)

    def validate_actions(self) -> None:
        bad = {k: v for k, v in self.point_actions.items()
               if v not in {"ALLOW", "DENY", "REQUIRE_APPROVAL"}}
        if bad:
            raise WorkspaceError(f"invalid point_actions in config.yaml: {bad}")


@dataclass(frozen=True)
class Workspace:
    project_root: Path

    @property
    def dir(self) -> Path:
        return self.project_root / DIRNAME

    @property
    def config_path(self) -> Path:
        return self.dir / "config.yaml"

    @property
    def analysis_path(self) -> Path:
        return self.dir / "analysis.json"

    @property
    def state_path(self) -> Path:
        return self.dir / "state.json"

    @property
    def policy_path(self) -> Path:
        return self.dir / "policy.yaml"

    @property
    def audit_path(self) -> Path:
        return self.dir / "audit.db"

    def exists(self) -> bool:
        return self.config_path.exists()

    # ---- init ------------------------------------------------------------------------------
    def init(self) -> bool:
        """Create the workspace. Returns False if it already existed (nothing is overwritten)."""
        if self.exists():
            return False
        self.dir.mkdir(parents=True, exist_ok=True)
        cfg = Config(app_name=self.project_root.name)
        self.config_path.write_text(
            "# Sentinel SDK configuration — edit freely.\n"
            "# mode: observe = log and report would-be blocks; enforce = raise on DENY.\n"
            + yaml.safe_dump(cfg.model_dump(), sort_keys=False))
        (self.dir / ".gitignore").write_text(
            "audit.db\naudit.db-wal\naudit.db-shm\npolicy.yaml\n")  # runtime/derived artefacts
        return True

    # ---- config ----------------------------------------------------------------------------
    def load_config(self) -> Config:
        if not self.config_path.exists():
            raise WorkspaceError(f"no {DIRNAME}/config.yaml in {self.project_root} — run "
                                 "`sentinel sdk init`")
        try:
            cfg = Config.model_validate(yaml.safe_load(self.config_path.read_text()) or {})
        except (yaml.YAMLError, ValidationError) as exc:
            raise WorkspaceError(f"invalid {self.config_path}: {exc}") from exc
        cfg.validate_actions()
        return cfg

    # ---- analysis / selection --------------------------------------------------------------
    def save_analysis(self, result: AnalysisResult) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.analysis_path.write_text(result.model_dump_json(indent=2))

    def load_analysis(self) -> AnalysisResult:
        if not self.analysis_path.exists():
            raise WorkspaceError("no analysis yet — run `sentinel sdk analyze`")
        try:
            return AnalysisResult.model_validate_json(self.analysis_path.read_text())
        except ValidationError as exc:
            raise WorkspaceError(f"corrupt {self.analysis_path}: {exc}") from exc

    def load_selected(self) -> dict[str, dict[str, Any]]:
        if not self.state_path.exists():
            return {}
        try:
            data = json.loads(self.state_path.read_text())
            sel = data.get("selected", {})
            if not isinstance(sel, dict):
                raise ValueError("selected must be an object")
            return sel
        except (ValueError, OSError) as exc:
            raise WorkspaceError(f"corrupt {self.state_path}: {exc}") from exc

    def save_selected(self, selected: dict[str, dict[str, Any]]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps({"selected": selected}, indent=2, sort_keys=True))

    def select(self, point_ids: list[str], by: str = "cli") -> list[str]:
        sel = self.load_selected()
        now = datetime.now(UTC).isoformat()
        added = [p for p in point_ids if p not in sel]
        for p in point_ids:
            sel.setdefault(p, {"at": now, "by": by})
        self.save_selected(sel)
        return added

    def deselect(self, point_ids: list[str]) -> list[str]:
        sel = self.load_selected()
        removed = [p for p in point_ids if sel.pop(p, None) is not None]
        self.save_selected(sel)
        return removed


def find_workspace(start: Path | str | None = None) -> Workspace:
    """Walk upward from `start` (default: $SENTINEL_PROJECT or cwd) looking for `.sentinel/`."""
    here = Path(start or os.environ.get("SENTINEL_PROJECT") or Path.cwd()).resolve()
    for d in [here, *here.parents]:
        if (d / DIRNAME / "config.yaml").exists():
            return Workspace(d)
    raise WorkspaceError(f"no {DIRNAME}/ workspace found at or above {here} — run "
                         "`sentinel sdk init`")
