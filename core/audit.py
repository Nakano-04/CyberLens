from __future__ import annotations

from typing import Optional

from models.audit import AuditEntry, Verdict


class AuditLog:
    def __init__(self, max_entries: int = 5000) -> None:
        self._entries: list[AuditEntry] = []
        self._max_entries = max_entries

    def record(
        self,
        actor: str,
        action: str,
        detail: str = "",
        session_id: Optional[str] = None,
        verdict: Verdict = Verdict.ALLOWED,
    ) -> AuditEntry:
        entry = AuditEntry(
            id=f"aud-{len(self._entries) + 1}",
            actor=actor,
            action=action,
            detail=detail,
            session_id=session_id,
            verdict=verdict,
        )
        self._entries.append(entry)
        if len(self._entries) > self._max_entries:
            self._entries = self._entries[-self._max_entries:]
        return entry

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def export(self) -> list[str]:
        return [e.to_log_line() for e in self._entries]

    def restore(self, entries: list[dict]) -> None:
        self._entries = [AuditEntry(**e) for e in entries]
