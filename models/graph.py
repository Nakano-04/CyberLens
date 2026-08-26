from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class KnowledgeState(str, Enum):
    KNOWN = "KNOWN"
    INFERRED = "INFERRED"
    UNVERIFIED = "UNVERIFIED"


class Node(BaseModel):
    id: str
    session_id: str
    kind: str
    name: str
    state: KnowledgeState = KnowledgeState.UNVERIFIED
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "manual"
    related_findings: list[str] = Field(default_factory=list)
    related_tests: list[str] = Field(default_factory=list)
    properties: dict = Field(default_factory=dict)

    def to_context_line(self) -> str:
        return (
            f"[{self.kind}] {self.name} | {self.state.value} "
            f"| conf={self.confidence:.2f} | fuente={self.source} "
            f"| visto={self.last_seen.strftime('%Y-%m-%d %H:%M')}"
        )


class NodeUpsert(BaseModel):
    kind: str
    name: str
    state: KnowledgeState = KnowledgeState.UNVERIFIED
    confidence: float = 0.5
    source: str = "manual"
    properties: dict = Field(default_factory=dict)


class LinkCreate(BaseModel):
    source: str
    target: str
    kind: str = "contains"


class Relationship(BaseModel):
    session_id: str
    source: str
    target: str
    kind: str
