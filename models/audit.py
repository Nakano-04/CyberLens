from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


class AuditEntry(BaseModel):
    id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: Optional[str] = None
    actor: str
    action: str
    detail: str = ""
    verdict: Verdict = Verdict.ALLOWED

    def to_log_line(self) -> str:
        return (
            f"[{self.timestamp.isoformat()}] actor={self.actor} "
            f"verdict={self.verdict.value} action={self.action} "
            f"detail={self.detail}"
        )
