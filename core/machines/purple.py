from __future__ import annotations

from models.session import Phase

# Maquina de estado del equipo PURPLE (orquestacion red + blue).
# Ciclo: plan -> emulate -> detect -> coverage -> improve -> (emulate | report)
# - emulate: ejecutar emulacion de ataque (requiere sesiones red enlazadas).
# - detect: correlacionar con deteccion (requiere sesiones blue enlazadas).
# - coverage: medir cobertura ATT&CK (findings vs reglas).
# - improve: cerrar gaps de cobertura (nuevas reglas) y volver a emular.

TRANSITIONS: dict[Phase, list[Phase]] = {
    Phase.PLAN: [Phase.EMULATE],
    Phase.EMULATE: [Phase.DETECT],
    Phase.DETECT: [Phase.COVERAGE],
    Phase.COVERAGE: [Phase.IMPROVE, Phase.EMULATE],
    Phase.IMPROVE: [Phase.EMULATE, Phase.REPORT],
}

REQUIREMENTS: dict[Phase, str] = {
    Phase.EMULATE: "se necesita al menos 1 sesion red enlazada antes de emular",
    Phase.DETECT: "se necesita al menos 1 sesion blue enlazada antes de evaluar deteccion",
    Phase.COVERAGE: "se necesitan findings (red) y alertas (blue) para calcular cobertura",
    Phase.IMPROVE: "se necesita la matriz de cobertura calculada antes de mejorar",
    Phase.REPORT: "se necesita al menos 1 gap evaluado o cerrado antes del reporte",
}


def blockers(state, session, target_phase: Phase) -> list[str]:
    missing: list[str] = []
    red_ids = session.purple_links.get("red", [])
    blue_ids = session.purple_links.get("blue", [])
    findings = [
        f for rid in red_ids for f in state.get_findings(rid) if state.get_session(rid)
    ]
    alerts = [
        a for bid in blue_ids for a in state.get_alerts(bid) if state.get_session(bid)
    ]
    rules = [
        r for bid in blue_ids for r in state.get_rules(bid) if state.get_session(bid)
    ]

    if target_phase == Phase.EMULATE and not red_ids:
        missing.append(REQUIREMENTS[Phase.EMULATE])
    if target_phase == Phase.DETECT and not blue_ids:
        missing.append(REQUIREMENTS[Phase.DETECT])
    if target_phase == Phase.COVERAGE and (not findings or not alerts):
        missing.append(REQUIREMENTS[Phase.COVERAGE])
    if target_phase == Phase.IMPROVE and not rules:
        missing.append(REQUIREMENTS[Phase.IMPROVE])
    if target_phase == Phase.REPORT and not rules:
        missing.append(REQUIREMENTS[Phase.REPORT])
    return missing
