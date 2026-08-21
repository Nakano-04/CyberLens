from __future__ import annotations

from models.alert import AlertStatus
from models.incident import IncidentStage
from models.session import Phase

# Maquina de estado del equipo BLUE (deteccion, triage e investigacion).
# Sin acciones de containment: las recomendaciones se documentan, no se ejecutan.
# Transiciones: detect -> triage -> investigate -> report

TRANSITIONS: dict[Phase, list[Phase]] = {
    Phase.DETECT: [Phase.TRIAGE],
    Phase.TRIAGE: [Phase.INVESTIGATE],
    Phase.INVESTIGATE: [Phase.REPORT],
}

REQUIREMENTS: dict[Phase, str] = {
    Phase.TRIAGE: "se necesita al menos 1 alerta antes de pasar a triage",
    Phase.INVESTIGATE: "se necesita al menos 1 alerta CONFIRMED antes de investigar",
    Phase.REPORT: "se necesita al menos 1 incidente con evidencia antes del cierre",
}


def blockers(state, session, target_phase: Phase) -> list[str]:
    missing: list[str] = []
    alerts = state.get_alerts(session.id)
    incidents = state.get_incidents(session.id)
    if target_phase == Phase.TRIAGE and not alerts:
        missing.append(REQUIREMENTS[Phase.TRIAGE])
    if target_phase == Phase.INVESTIGATE and not any(
        a.status == AlertStatus.CONFIRMED for a in alerts
    ):
        missing.append(REQUIREMENTS[Phase.INVESTIGATE])
    if target_phase == Phase.REPORT and not any(
        i.evidence_result_ids for i in incidents
    ):
        missing.append(REQUIREMENTS[Phase.REPORT])
    return missing


def incident_transition_blockers(
    state, incident, target_stage: IncidentStage
) -> list[str]:
    """Transiciones del ciclo de vida de un incidente (espejo de la maquina blue).

    - triage: el incidente debe tener al menos 1 alerta.
    - investigate: al menos 1 alerta del incidente CONFIRMED.
    - report (cierre): al menos 1 evidencia (result id) registrada.
    """
    missing: list[str] = []
    alerts = [
        a for a in state.get_alerts(incident.session_id) if a.id in incident.alert_ids
    ]
    if target_stage == IncidentStage.TRIAGE and not incident.alert_ids:
        missing.append("el incidente necesita al menos 1 alerta asociada")
    if target_stage == IncidentStage.INVESTIGATE and not any(
        a.status == AlertStatus.CONFIRMED for a in alerts
    ):
        missing.append("el incidente necesita al menos 1 alerta CONFIRMED")
    if target_stage == IncidentStage.REPORT and not incident.evidence_result_ids:
        missing.append("el incidente necesita al menos 1 evidencia antes del cierre")
    return missing
