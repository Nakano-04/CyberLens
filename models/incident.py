from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, Field

from models.alert import Severity


class IncidentStage(StrEnum):
    DETECT = "detect"
    TRIAGE = "triage"
    INVESTIGATE = "investigate"
    REPORT = "report"


class Incident(BaseModel):
    id: str
    session_id: str
    title: str
    detail: str = ""
    severity: Severity = Severity.MEDIUM
    stage: IncidentStage = IncidentStage.DETECT
    status: str = "open"
    alert_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    evidence_result_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)

    def to_context_block(self) -> str:
        lines = [
            f"[incidente] {self.title} | {self.stage.value} | {self.status} | "
            f"{self.severity.value}",
            f"  alertas: {', '.join(self.alert_ids) or '-'}",
        ]
        if self.technique_ids:
            lines.append(f"  tecnicas MITRE: {', '.join(self.technique_ids)}")
        if self.recommendations:
            lines.append(f"  recomendaciones: {'; '.join(self.recommendations)}")
        if self.detail:
            lines.append(f"  detalle: {self.detail}")
        return "\n".join(lines)


class IncidentCreate(BaseModel):
    title: str
    detail: str = ""
    severity: Severity = Severity.MEDIUM
    alert_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
