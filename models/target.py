from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class Service(BaseModel):
    port: int
    protocol: str = "tcp"
    name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


class Target(BaseModel):
    id: str
    host: str
    authorized: bool = True
    assessment: str = "web"
    description: str = ""
    os_hint: Optional[str] = None
    services: list[Service] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def add_service(self, service: Service) -> None:
        for existing in self.services:
            if existing.port == service.port and existing.protocol == service.protocol:
                self.services.remove(existing)
        self.services.append(service)

    def summary(self) -> str:
        parts = [f"host={self.host}"]
        if self.os_hint:
            parts.append(f"os={self.os_hint}")
        if self.services:
            svc = ", ".join(
                f"{s.port}/{s.protocol}({s.name or 'unknown'})" for s in self.services
            )
            parts.append(f"services=[{svc}]")
        if self.mitigations:
            parts.append(f"mitigations={','.join(self.mitigations)}")
        return " | ".join(parts)


class TargetCreate(BaseModel):
    host: str
    description: str = ""
    authorized: bool = True
    assessment: str = "web"
    os_hint: Optional[str] = None
