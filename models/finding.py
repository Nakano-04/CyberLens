from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class FindingStatus(str, Enum):
    UNVERIFIED = "unverified"
    VALIDATED = "validated"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class Finding(BaseModel):
    id: str
    session_id: str
    title: str
    detail: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    against: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.UNVERIFIED
    technique_id: Optional[str] = None
    verified: bool = False
    verification_notes: list[str] = Field(default_factory=list)
    related_alerts: list[str] = Field(default_factory=list)
    related_rules: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_context_block(self) -> str:
        lines = [f"[hipotesis] {self.title} | {self.status.value} | conf={self.confidence:.2f}"]
        if self.technique_id:
            lines.append(f"  tecnica MITRE: {self.technique_id}")
        if self.evidence_ids:
            lines.append(f"  evidencia: {', '.join(self.evidence_ids)}")
        if self.related_alerts:
            lines.append(f"  alertas relacionadas: {', '.join(self.related_alerts)}")
        if self.related_rules:
            lines.append(f"  reglas relacionadas: {', '.join(self.related_rules)}")
        if self.against:
            lines.append(f"  contra: {', '.join(self.against)}")
        if self.detail:
            lines.append(f"  detalle: {self.detail}")
        return "\n".join(lines)


class FindingCreate(BaseModel):
    title: str
    detail: str = ""
    confidence: float = 0.5
    evidence_ids: list[str] = Field(default_factory=list)
    against: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.UNVERIFIED
    technique_id: Optional[str] = None
