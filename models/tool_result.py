from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    id: str
    session_id: str
    tool: str
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    timed_out: bool = False
    duration_ms: int = 0
    parsed: dict = Field(default_factory=dict)
    approved: bool = True
    team: str = "red"
    event_time: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_context_block(self) -> str:
        body = [f"[{self.tool}] {self.command}", "stdout:"]
        body.extend(self.stdout.splitlines()[:50])
        if self.stderr:
            body.append("stderr:")
            body.extend(self.stderr.splitlines()[:20])
        body.append(f"exit={self.exit_code} {self.duration_ms}ms")
        if self.parsed:
            body.append(f"parsed={self.parsed}")
        return "\n".join(body)
