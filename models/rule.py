from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from models.alert import Severity


class DetectionRule(BaseModel):
    """Regla de deteccion (estilo Sigma simplificado).

    `patterns` matchean contra la telemetria ingerida:
      - "command": regex contra el comando/origen del evento
      - "stdout": regex contra el payload/linea del evento
      - "fields": {clave_parsed: [regex...]} contra el dict parseado
    """

    id: str
    session_id: str
    name: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    technique_ids: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    patterns: dict = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_context_line(self) -> str:
        techs = ", ".join(self.technique_ids) or "-"
        return (
            f"[regla] {self.name} | {self.severity.value} | tecnicas={techs} "
            f"| {self.description or 'sin descripcion'}"
        )


class RuleCreate(BaseModel):
    name: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    technique_ids: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    patterns: dict = Field(default_factory=dict)
    enabled: bool = True
