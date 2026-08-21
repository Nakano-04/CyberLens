from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class Alert(BaseModel):
    id: str
    session_id: str
    rule_id: str
    rule_name: str
    title: str
    detail: str = ""
    severity: Severity = Severity.MEDIUM
    status: AlertStatus = AlertStatus.OPEN
    technique_ids: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    source: str = "manual"
    host: Optional[str] = None
    evidence_result_id: Optional[str] = None
    occurrences: int = 1
    event_time: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    triaged_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    notes: list[str] = Field(default_factory=list)

    def touch_triage(self) -> None:
        if self.triaged_at is None:
            self.triaged_at = datetime.now(timezone.utc)

    def touch_close(self) -> None:
        if self.closed_at is None:
            self.closed_at = datetime.now(timezone.utc)

    def to_context_block(self) -> str:
        lines = [
            f"[alerta] {self.title} | {self.status.value} | "
            f"{self.severity.value} | regla={self.rule_id}",
            f"  fuente={self.source} host={self.host or '-'} ocurrencias={self.occurrences}",
        ]
        if self.technique_ids:
            lines.append(f"  tecnicas MITRE: {', '.join(self.technique_ids)}")
        if self.detail:
            lines.append(f"  detalle: {self.detail}")
        return "\n".join(lines)


class AlertCreate(BaseModel):
    rule_id: str
    rule_name: str = ""
    title: str = ""
    detail: str = ""
    severity: Severity = Severity.MEDIUM
    technique_ids: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    source: str = "manual"
    host: Optional[str] = None
    evidence_result_id: Optional[str] = None
    event_time: Optional[datetime] = None
