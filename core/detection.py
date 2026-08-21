from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from models.alert import Alert, AlertCreate, AlertStatus
from models.rule import DetectionRule
from models.tool_result import ToolResult

# Tecnicas modernas: compilacion cacheada de regex (una sola vez por patron)
@lru_cache(maxsize=512)
def _compiled(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


class DetectionEngine:
    """Motor de deteccion sobre telemetria ingerida.

    Evaluar reglas es barato y determinista: regex precompiladas con cache
    contra command/stdout y campos parseados del evento. Nunca ejecuta nada;
    las alertas nacen de eventos ya ingeridos (ToolResult con team='blue').
    Incluye deteccion de anomalias por volumen (rapfagas) por host/fuente.
    """

    def __init__(
        self,
        dedup_window_seconds: int = 300,
        burst_window_seconds: int = 60,
        burst_threshold: int = 10,
    ) -> None:
        self._dedup_window = timedelta(seconds=dedup_window_seconds)
        self._burst_window = timedelta(seconds=burst_window_seconds)
        self._burst_threshold = burst_threshold

    # ------------------------------------------------------------------
    # matching (regex cache + structural pattern matching)
    # ------------------------------------------------------------------
    def evaluate(self, result: ToolResult, rules: list[DetectionRule]) -> list[dict]:
        """Devuelve los matches [{rule, reason}] para un evento ingerido."""
        matches: list[dict] = []
        for rule in rules:
            if not rule.enabled:
                continue
            reason = self._match(rule, result)
            if reason:
                matches.append({"rule": rule, "reason": reason})
        return matches

    def _match(self, rule: DetectionRule, result: ToolResult) -> str | None:
        patterns = rule.patterns or {}
        command = result.command or ""
        stdout = result.stdout or ""
        parsed = result.parsed or {}

        for pattern in patterns.get("command", []):
            if _compiled(pattern).search(command):
                return f"command: {pattern}"
        for pattern in patterns.get("stdout", []):
            if _compiled(pattern).search(stdout):
                return f"stdout: {pattern}"
        for field, field_patterns in patterns.get("fields", {}).items():
            value = parsed.get(field)
            if value is None:
                continue
            match value:
                case str():
                    text = value
                case list():
                    text = " ".join(str(v) for v in value)
                case _:
                    text = str(value)
            for pattern in field_patterns:
                if _compiled(pattern).search(text):
                    return f"fields.{field}: {pattern}"
        return None

    # ------------------------------------------------------------------
    # deduplicacion de alertas
    # ------------------------------------------------------------------
    def dedupe(
        self,
        existing: list[Alert],
        rule_id: str,
        host: str | None,
        event_time: datetime | None,
    ) -> Alert | None:
        """Si ya existe una alerta abierta/trigeada de la misma regla y host
        dentro de la ventana de deduplicacion, la devuelve para incrementar
        ocurrencias (no se crea otra)."""
        if host is None:
            return None
        now = event_time or datetime.now(timezone.utc)
        for alert in existing:
            if alert.status in (AlertStatus.OPEN, AlertStatus.TRIAGED):
                if alert.rule_id == rule_id and alert.host == host:
                    if now - alert.created_at <= self._dedup_window:
                        return alert
        return None

    # ------------------------------------------------------------------
    # anomalia por volumen (deteccion de rafagas)
    # ------------------------------------------------------------------
    def detect_burst(
        self,
        events: list[ToolResult],
        source: str,
        host: str | None,
        event_time: datetime | None,
    ) -> bool:
        """True si el mismo host/fuente supero `burst_threshold` eventos en
        `burst_window` segundos. Deteccion clasica de beaconing/escaneo."""
        if self._burst_threshold <= 0:
            return False
        now = event_time or datetime.now(timezone.utc)
        window_start = now - self._burst_window
        count = sum(
            1
            for r in events
            if r.tool == f"telemetry:{source}"
            and r.created_at >= window_start
            and (
                host is None
                or host in str(r.parsed.get("hosts", []))
                or host in str(r.parsed.get("ips", []))
            )
        )
        return count >= self._burst_threshold

    def create_alert(
        self,
        session_id: str,
        data: AlertCreate,
        alert_id: str,
        occurrences: int = 1,
    ) -> Alert:
        return Alert(
            id=alert_id,
            session_id=session_id,
            rule_id=data.rule_id,
            rule_name=data.rule_name,
            title=data.title or data.rule_name or data.rule_id,
            detail=data.detail,
            severity=data.severity,
            technique_ids=data.technique_ids,
            data_sources=data.data_sources,
            source=data.source,
            host=data.host,
            evidence_result_id=data.evidence_result_id,
            occurrences=occurrences,
            event_time=data.event_time,
        )
