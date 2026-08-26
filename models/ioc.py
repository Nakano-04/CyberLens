from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    HASH = "hash"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE = "file"
    OTHER = "other"


class IOC(BaseModel):
    id: str
    session_id: str
    value: str
    type: IOCType = IOCType.OTHER
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str = "manual"
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_context_line(self) -> str:
        tags = ", ".join(self.tags) if self.tags else "-"
        return (
            f"[ioc] {self.type.value}:{self.value} | conf={self.confidence:.2f} "
            f"| fuente={self.source} | tags={tags}"
        )


class IOCCreate(BaseModel):
    value: str
    type: IOCType = IOCType.OTHER
    confidence: float = 0.5
    source: str = "manual"
    description: str = ""
    tags: list[str] = Field(default_factory=list)
