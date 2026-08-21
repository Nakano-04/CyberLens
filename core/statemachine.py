from __future__ import annotations

from core.machines import machine_for
from core.machines.red import TRANSITIONS, REQUIREMENTS
from core.state import MediatorState
from models.session import Phase, Session
from models.team import Team

PHASE_ORDER: dict[Phase, int] = {phase: i for i, phase in enumerate(Phase)}


def allowed_transitions(current: Phase, team: Team = Team.RED) -> list[Phase]:
    """Fases permitidas desde `current` para el equipo (default red)."""
    return machine_for(team).TRANSITIONS.get(current, [])


def can_skip(current: Phase, target: Phase) -> bool:
    """¿El target es una fase posterior (adelantar sin pasar por las intermedias)?"""
    return PHASE_ORDER[target] > PHASE_ORDER[current]


def blockers(
    state: MediatorState,
    session: Session,
    target_phase: Phase,
    allow_skip: bool = False,
) -> list[str]:
    missing: list[str] = []
    if target_phase == session.phase:
        return []
    if allow_skip:
        if not can_skip(session.phase, target_phase):
            return [
                f"no se puede retroceder: {session.phase.value} -> {target_phase.value}"
            ]
        return []
    if target_phase not in allowed_transitions(session.phase, session.team):
        return [f"transicion no permitida: {session.phase.value} -> {target_phase.value}"]
    return machine_for(session.team).blockers(state, session, target_phase)


def critical_evidence_exists(state: MediatorState, session_id: str) -> list[str]:
    """Evidencia critica (equipo red) que justifica adelantar fases:
    - nodos de kind critico (beacon, session, data_asset, vulnerability, pivot)
      con confianza >= 0.9 (ej: RCE confirmado en recon),
    - findings verified con confianza >= 0.9.
    Devuelve los nombres/ids que lo justifican."""
    justificaciones: list[str] = []
    for node in state.graph.critical_nodes(session_id):
        justificaciones.append(f"nodo {node.kind}:{node.name} conf={node.confidence:.2f}")
    for finding in state.get_findings(session_id):
        if finding.verified and finding.confidence >= 0.9:
            justificaciones.append(
                f"finding '{finding.title}' verified conf={finding.confidence:.2f}"
            )
    return justificaciones
