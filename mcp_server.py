from __future__ import annotations

import json
import os

from fastmcp import FastMCP

from models.finding import FindingCreate
from models.graph import NodeUpsert
from models.incident import IncidentCreate
from models.investigation import InvestigationCreate
from models.ioc import IOCCreate
from models.rule import RuleCreate
from models.session import Phase, SessionCreate
from models.target import TargetCreate
from models.team import Team

mcp = FastMCP("offensive-context-engine")

_mediator = None


def _m():
    """Mediador con la config real (config.yaml junto a este archivo, igual que
    main.py). Si no hay config o falla, usa defaults."""
    global _mediator
    if _mediator is None:
        try:
            from main import build_mediator, load_config

            _mediator = build_mediator(
                load_config(os.path.join(os.path.dirname(__file__), "config.yaml"))
            )
        except Exception:
            from core.mediator import Mediator

            _mediator = Mediator()
    return _mediator


def _dump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


@mcp.tool()
def create_target(host: str, description: str = "", assessment: str = "web") -> str:
    target = _m().create_target(TargetCreate(host=host, description=description, assessment=assessment))
    return _dump(target.model_dump(mode="json"))


@mcp.tool()
def list_targets() -> str:
    return _dump([t.model_dump(mode="json") for t in _m().state.list_targets()])


@mcp.tool()
def create_session(
    target_id: str, agent: str = "build", objective: str = "", team: str = "red"
) -> str:
    session = _m().create_session(
        SessionCreate(
            target_id=target_id, agent=agent, objective=objective, team=Team(team)
        )
    )
    return _dump(session.model_dump(mode="json"))


@mcp.tool()
def update_objective(
    session_id: str,
    objective: str = "",
    current_position: str = "",
    next_areas: str = "",
) -> str:
    session = _m().update_objective(
        session_id,
        objective=objective or None,
        current_position=current_position or None,
        next_areas=[a.strip() for a in next_areas.split(";")] if next_areas else None,
    )
    return _dump(session.model_dump(mode="json"))


@mcp.tool()
def set_phase(session_id: str, phase: str) -> str:
    session = _m().set_phase(session_id, Phase(phase))
    return _dump(session.model_dump(mode="json"))


@mcp.tool()
def execute_command(session_id: str, command: str, parser: str = "") -> str:
    result = _m().execute(session_id, "shell", command, parser=parser or None)
    return _dump(result.model_dump(mode="json"))


@mcp.tool()
def add_node(session_id: str, kind: str, name: str, state: str = "UNVERIFIED", confidence: float = 0.5) -> str:
    from models.graph import KnowledgeState

    node = _m().upsert_node(
        session_id,
        NodeUpsert(kind=kind, name=name, state=KnowledgeState(state), confidence=confidence),
    )
    return _dump(node.model_dump(mode="json"))


@mcp.tool()
def add_finding(
    session_id: str,
    title: str,
    confidence: float = 0.5,
    evidence_ids: str = "",
    technique_id: str = "",
    detail: str = "",
) -> str:
    finding = _m().add_finding(
        session_id,
        FindingCreate(
            title=title,
            confidence=confidence,
            evidence_ids=[e.strip() for e in evidence_ids.split(",")] if evidence_ids else [],
            technique_id=technique_id or None,
            detail=detail,
        ),
    )
    return _dump(finding.model_dump(mode="json"))


@mcp.tool()
def add_investigation(session_id: str, name: str, status: str = "not_performed") -> str:
    investigation = _m().add_investigation(
        session_id, InvestigationCreate(name=name, status=status)
    )
    return _dump(investigation.model_dump(mode="json"))


@mcp.tool()
def get_plan(session_id: str) -> str:
    return _dump(_m().plan(session_id))


@mcp.tool()
def get_context(session_id: str) -> str:
    return _m().get_context(session_id)


@mcp.tool()
def get_metrics(session_id: str) -> str:
    return _dump(_m().get_metrics(session_id))


@mcp.tool()
def get_evidence_chains(session_id: str) -> str:
    return _dump(_m().evidence_chains(session_id))


@mcp.tool()
def suggested_techniques(session_id: str) -> str:
    return _dump(_m().suggested_techniques(session_id))


# ---------------------------------------------------------------------------
# Blue team
# ---------------------------------------------------------------------------
@mcp.tool()
def ingest_telemetry(session_id: str, source: str, stdout: str, command: str = "") -> str:
    """Blue: ingiere un evento de telemetria; dispara la deteccion (alertas)."""
    raw = stdout or command
    result = _m().ingest_event(session_id, source, raw, None)
    return _dump(result.model_dump(mode="json"))


@mcp.tool()
def list_alerts(session_id: str) -> str:
    return _dump([a.model_dump(mode="json") for a in _m().alerts(session_id)])


@mcp.tool()
def update_alert_status(session_id: str, alert_id: str, status: str, note: str = "") -> str:
    alert = _m().update_alert_status(session_id, alert_id, status, note or None)
    return _dump(alert.model_dump(mode="json"))


@mcp.tool()
def add_detection_rule(
    session_id: str,
    name: str,
    pattern_stdout: str,
    severity: str = "medium",
    technique_id: str = "",
) -> str:
    rule = _m().add_rule(
        session_id,
        RuleCreate(
            name=name,
            severity=severity,
            technique_ids=[technique_id] if technique_id else [],
            patterns={"stdout": [pattern_stdout]},
        ),
    )
    return _dump(rule.model_dump(mode="json"))


@mcp.tool()
def list_rules(session_id: str) -> str:
    return _dump([r.model_dump(mode="json") for r in _m().rules(session_id)])


@mcp.tool()
def create_incident(session_id: str, title: str, alert_ids: str = "", severity: str = "medium") -> str:
    incident = _m().create_incident(
        session_id,
        IncidentCreate(
            title=title,
            alert_ids=[a.strip() for a in alert_ids.split(",")] if alert_ids else [],
            severity=severity,
        ),
    )
    return _dump(incident.model_dump(mode="json"))


@mcp.tool()
def list_incidents(session_id: str) -> str:
    return _dump([i.model_dump(mode="json") for i in _m().incidents(session_id)])


@mcp.tool()
def update_incident_stage(session_id: str, incident_id: str, stage: str) -> str:
    incident = _m().update_incident_stage(session_id, incident_id, stage)
    return _dump(incident.model_dump(mode="json"))


@mcp.tool()
def add_recommendation(session_id: str, text: str) -> str:
    """Blue: documenta una recomendacion de respuesta. Nunca ejecuta acciones."""
    session = _m().add_recommendation(session_id, text)
    return _dump({"session": session.id, "recommendations": len(session.notes)})


@mcp.tool()
def add_ioc(session_id: str, value: str, type: str = "other", confidence: float = 0.5) -> str:
    ioc = _m().add_ioc(
        session_id, IOCCreate(value=value, type=type, confidence=confidence)
    )
    return _dump(ioc.model_dump(mode="json"))


@mcp.tool()
def list_iocs(session_id: str) -> str:
    return _dump([i.model_dump(mode="json") for i in _m().iocs(session_id)])


# ---------------------------------------------------------------------------
# Purple team
# ---------------------------------------------------------------------------
@mcp.tool()
def link_session(session_id: str, linked_session_id: str, team: str) -> str:
    """Purple: enlaza una sesion red o blue a la orquestacion."""
    return _dump(_m().link_session(session_id, linked_session_id, Team(team)))


@mcp.tool()
def get_coverage(session_id: str) -> str:
    return _dump(_m().coverage(session_id))


if __name__ == "__main__":
    mcp.run()
