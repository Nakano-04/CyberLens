from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from models.team import Team


class Phase(str, Enum):
    # --- red team ---
    RECON = "recon"
    ENUMERATION = "enumeration"
    MODELING = "modeling"
    HYPOTHESIS = "hypothesis"
    VALIDATION = "validation"
    IMPACT = "impact"
    EVIDENCE = "evidence"
    REPORT = "report"
    # --- blue team ---
    DETECT = "detect"
    TRIAGE = "triage"
    INVESTIGATE = "investigate"
    # --- purple team ---
    PLAN = "plan"
    EMULATE = "emulate"
    COVERAGE = "coverage"
    IMPROVE = "improve"


class AttackStage(str, Enum):
    INITIAL_ACCESS = "initial_access"
    FOOTHOLD = "foothold"
    DISCOVERY = "discovery"
    PRIVILEGE_BOUNDARY = "privilege_boundary"
    LATERAL_OPPORTUNITY = "lateral_opportunity"
    OBJECTIVE = "objective"


class Session(BaseModel):
    id: str
    target_id: str
    team: Team = Team.RED
    agent: str = "build"
    phase: Phase = Phase.RECON
    attack_stage: AttackStage = AttackStage.INITIAL_ACCESS
    objective: str = ""
    current_position: str = ""
    known: list[str] = Field(default_factory=list)
    unknown: list[str] = Field(default_factory=list)
    next_areas: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    summaries: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    llm_compact: bool = True
    steps_used: int = 0
    max_steps: Optional[int] = None
    purple_links: dict[str, list[str]] = Field(
        default_factory=lambda: {"red": [], "blue": []}
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)

    def add_note(self, note: str) -> None:
        self.notes.append(note)
        self.touch()


class SessionCreate(BaseModel):
    target_id: str
    team: Team = Team.RED
    agent: str = "build"
    objective: str = ""
    tags: list[str] = Field(default_factory=list)
    llm_compact: bool = True
    max_steps: Optional[int] = None
