from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class InvestigationStatus(str, Enum):
    NOT_PERFORMED = "not_performed"
    PERFORMED = "performed"
    INCONCLUSIVE = "inconclusive"


class Investigation(BaseModel):
    id: str
    session_id: str
    name: str
    status: InvestigationStatus = InvestigationStatus.NOT_PERFORMED
    result: str = ""
    evidence_result_id: Optional[str] = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_context_line(self) -> str:
        evidence = f"evidencia={self.evidence_result_id}" if self.evidence_result_id else "sin evidencia"
        line = f"[investigacion] {self.name} | {self.status.value} | conf={self.confidence:.2f} | {evidence}"
        return line + (f" | {self.result}" if self.result else "")


class InvestigationCreate(BaseModel):
    name: str
    status: InvestigationStatus = InvestigationStatus.NOT_PERFORMED
    result: str = ""
    evidence_result_id: Optional[str] = None
    confidence: float = 0.5
