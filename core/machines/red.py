from __future__ import annotations

from models.session import Phase
from models.team import Team

# Maquina de estado del equipo RED (pentest ofensivo).
# Transiciones: recon -> enumeration -> modeling -> hypothesis -> validation
#              (validation <-> hypothesis) -> impact -> evidence -> report

TRANSITIONS: dict[Phase, list[Phase]] = {
    Phase.RECON: [Phase.ENUMERATION],
    Phase.ENUMERATION: [Phase.MODELING],
    Phase.MODELING: [Phase.HYPOTHESIS],
    Phase.HYPOTHESIS: [Phase.VALIDATION],
    Phase.VALIDATION: [Phase.IMPACT, Phase.HYPOTHESIS],
    Phase.IMPACT: [Phase.EVIDENCE],
    Phase.EVIDENCE: [Phase.REPORT],
}

REQUIREMENTS: dict[Phase, str] = {
    Phase.VALIDATION: "se necesita al menos 1 hipotesis (finding) antes de validar",
    Phase.EVIDENCE: "se necesita al menos 1 hipotesis VALIDATED antes de pasar a evidencia",
    Phase.REPORT: "se necesita al menos 1 hallazgo validado con evidencia antes del reporte",
}


def blockers(state, session, target_phase: Phase) -> list[str]:
    from core.state import MediatorState

    missing: list[str] = []
    findings = state.get_findings(session.id)
    if target_phase == Phase.VALIDATION and not findings:
        missing.append(REQUIREMENTS[Phase.VALIDATION])
    if target_phase == Phase.EVIDENCE and not any(f.status.value == "validated" for f in findings):
        missing.append(REQUIREMENTS[Phase.EVIDENCE])
    if target_phase == Phase.REPORT and not any(
        f.verified and f.status.value == "validated" for f in findings
    ):
        missing.append(REQUIREMENTS[Phase.REPORT])
    return missing
