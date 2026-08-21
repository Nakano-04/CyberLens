from __future__ import annotations

from core.state import MediatorState
from models.alert import AlertStatus
from models.graph import KnowledgeState
from models.team import Team

_CRITICALITY_VALUE = {"alta": 3, "media": 2, "baja": 1}

# Bonificaciones por tipo de rama (peso base antes de contexto)
_BASE_TYPE_VALUE = {
    "hipotesis": 2.0,
    "lateralidad": 1.5,
    "c2": 1.5,
    "activo_de_datos": 1.0,
    "area": 0.5,
    "superficie": 0.5,
}

_SEVERITY_VALUE = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}


def build_plan(
    state: MediatorState,
    session_id: str,
    priorities: list[str],
    techniques: list[dict] | None = None,
) -> dict:
    """Plan contextual por equipo: red (ramas ofensivas), blue (alerta/incidente/
    ioc/gaps), purple (emulacion + deteccion + gaps de cobertura)."""
    session = state.get_session(session_id)
    if not session:
        raise KeyError(f"session {session_id} not found")
    if session.team == Team.BLUE:
        return build_blue_plan(state, session, priorities)
    if session.team == Team.PURPLE:
        return build_purple_plan(state, session, priorities, techniques or [])
    return build_red_plan(state, session, priorities)


# ---------------------------------------------------------------------------
# RED: plan ofensivo con scoring por conexion del grafo
# ---------------------------------------------------------------------------
def build_red_plan(state: MediatorState, session: object, priorities: list[str]) -> dict:
    session_id = session.id
    nodes = state.graph.nodes(session_id)
    findings = state.get_findings(session_id)
    investigations = state.get_investigations(session_id)
    links = state.graph.links(session_id)

    unverified_nodes = [n for n in nodes if n.state == KnowledgeState.UNVERIFIED]
    data_assets = [n for n in nodes if n.kind == "data_asset"]
    pivots = [n for n in nodes if n.kind in ("pivot", "listener", "beacon")]

    linked_ids = {l.source for l in links} | {l.target for l in links}
    performed = {i.name.lower() for i in investigations if i.status.value == "performed"}
    inconclusive = {i.name.lower() for i in investigations if i.status.value == "inconclusive"}
    pending = {i.name.lower() for i in investigations if i.status.value == "not_performed"}

    branches: list[dict] = []
    seen: set[str] = set()

    # 1. hipotesis activas (la base del plan)
    for finding in findings:
        if finding.status.value in {"unverified", "inconclusive"}:
            branches.append(
                {
                    "type": "hipotesis",
                    "name": finding.title,
                    "confidence": finding.confidence,
                    "technique": finding.technique_id,
                    "finding_id": finding.id,
                    "evidence_gap": bool(finding.evidence_ids) and not finding.verified,
                }
            )
            seen.add(finding.id)

    # 2. activos de datos: rutas hacia ellos, no solo keywords
    for asset in data_assets:
        label = f"data_asset: {asset.name}"
        if label not in seen:
            criticality = str(asset.properties.get("criticality", "media")).lower()
            branches.append(
                {
                    "type": "activo_de_datos",
                    "name": label,
                    "confidence": asset.confidence,
                    "criticality": criticality,
                }
            )
            seen.add(label)

    # 3. pivots / listeners / beacons (lateralidad viva)
    for pivot in pivots:
        label = f"{pivot.kind}: {pivot.name}"
        if label not in seen:
            branches.append(
                {
                    "type": "lateralidad" if pivot.kind in ("pivot", "listener") else "c2",
                    "name": label,
                    "confidence": pivot.confidence,
                    "orphan": pivot.id not in linked_ids,
                }
            )
            seen.add(label)

    # 4. areas del agente (filtra las ya investigadas en firme)
    for area in session.next_areas:
        if area not in seen and area.lower() not in performed:
            branches.append(
                {
                    "type": "area",
                    "name": area,
                    "confidence": 0.5,
                    "already_inconclusive": area.lower() in inconclusive,
                }
            )
            seen.add(area)

    # 5. superficie sin verificar (nodes aislados primero)
    for node in unverified_nodes:
        label = f"{node.kind}: {node.name}"
        if label not in seen:
            branches.append(
                {
                    "type": "superficie",
                    "name": label,
                    "confidence": node.confidence,
                    "orphan": node.id not in linked_ids,
                }
            )

    for branch in branches:
        expected = _score_branch(branch, priorities, performed, inconclusive, pending)
        branch["expected_value"] = expected

    # descarta ramas con valor negativo neto (ya investigadas y desmentidas)
    branches = [b for b in branches if b["expected_value"] > 0]

    return {
        "team": "red",
        "objective": session.objective,
        "current_position": session.current_position,
        "knowledge": {
            "known": [n.name for n in nodes if n.state == KnowledgeState.KNOWN],
            "inferred": [n.name for n in nodes if n.state == KnowledgeState.INFERRED],
            "unverified": [n.name for n in unverified_nodes],
            "data_assets": [
                {"name": a.name, "criticality": a.properties.get("criticality", "media")}
                for a in data_assets
            ],
            "pivots": [
                {"kind": p.kind, "name": p.name, "confidence": p.confidence} for p in pivots
            ],
        },
        "unknown": session.unknown,
        "investigations": [{"name": i.name, "status": i.status.value} for i in investigations],
        "branches": sorted(branches, key=lambda b: b["expected_value"], reverse=True),
    }


def _score_branch(
    branch: dict,
    priorities: list[str],
    performed: set[str],
    inconclusive: set[str],
    pending: set[str],
) -> float:
    name = branch["name"].lower()
    score = _BASE_TYPE_VALUE.get(branch["type"], 0.5)

    # keywords de assessment_priorities
    score += sum(1.0 for p in priorities if p.lower() in name)

    # context-driven
    if branch["type"] == "hipotesis":
        if branch.get("evidence_gap"):
            score += 1.0
        if branch.get("confidence", 0) >= 0.75 and branch.get("evidence_gap"):
            score += 1.0  # confianza alta SIN evidencia = riesgo / pendiente

    if branch.get("orphan"):
        score += 1.5  # nodo sin ninguna relacion: superficie sin explorar

    if branch.get("already_inconclusive"):
        score -= 1.0

    # memoria de investigaciones (dedupe real entre agentes)
    if name in performed:
        score -= 3.0
    elif name in inconclusive:
        score -= 2.0
    elif name in pending:
        score += 1.0

    return round(score, 2)


# ---------------------------------------------------------------------------
# BLUE: plan defensivo (triage, incidentes, iocs, gaps de reglas)
# ---------------------------------------------------------------------------
def build_blue_plan(state: MediatorState, session: object, priorities: list[str]) -> dict:
    session_id = session.id
    alerts = state.get_alerts(session_id)
    incidents = state.get_incidents(session_id)
    iocs = state.get_iocs(session_id)
    investigations = state.get_investigations(session_id)
    rules = state.get_rules(session_id)
    nodes = state.graph.nodes(session_id)

    branches: list[dict] = []
    seen: set[str] = set()

    # 1. alertas abiertas/triageadas, por severidad
    open_alerts = sorted(
        [a for a in alerts if a.status in (AlertStatus.OPEN, AlertStatus.TRIAGED)],
        key=lambda a: _SEVERITY_VALUE.get(a.severity.value, 1.0),
        reverse=True,
    )
    for alert in open_alerts:
        branches.append(
            {
                "type": "alerta",
                "name": f"{alert.rule_name} ({alert.host or '-'})",
                "alert_id": alert.id,
                "severity": alert.severity.value,
                "occurrences": alert.occurrences,
                "expected_value": round(
                    3.0 + _SEVERITY_VALUE.get(alert.severity.value, 1.0) * 0.8
                    + min(alert.occurrences, 10) * 0.1,
                    2,
                ),
            }
        )
        seen.add(alert.id)

    # 2. incidentes activos
    for incident in incidents:
        if incident.status == "open":
            branches.append(
                {
                    "type": "incidente",
                    "name": incident.title,
                    "incident_id": incident.id,
                    "stage": incident.stage.value,
                    "expected_value": round(
                        2.5 + _SEVERITY_VALUE.get(incident.severity.value, 1.0) * 0.6, 2
                    ),
                }
            )
            seen.add(incident.id)

    # 3. iocs sin incidente asociado
    incident_iocs: set[str] = set()
    for incident in incidents:
        for aid in incident.alert_ids:
            incident_iocs.add(aid)
    for ioc in iocs:
        if ioc.id not in seen:
            branches.append(
                {
                    "type": "ioc",
                    "name": f"{ioc.type.value}:{ioc.value}",
                    "confidence": ioc.confidence,
                    "expected_value": round(1.5 + ioc.confidence * 1.5, 2),
                }
            )
            seen.add(ioc.id)

    # 4. gaps de cobertura: tecnicas observadas sin regla
    observed_techs = sorted(
        {t for a in alerts for t in a.technique_ids}
    )
    covered_techs = {t for r in rules for t in r.technique_ids}
    for tid in observed_techs:
        if tid not in covered_techs:
            branches.append(
                {
                    "type": "gap_regla",
                    "name": f"regla faltante para {tid}",
                    "technique": tid,
                    "expected_value": 2.0,
                }
            )

    # 5. areas
    performed = {i.name.lower() for i in investigations if i.status.value == "performed"}
    for area in session.next_areas:
        if area.lower() not in performed:
            branches.append(
                {
                    "type": "area",
                    "name": area,
                    "confidence": 0.5,
                    "expected_value": 1.0,
                }
            )

    return {
        "team": "blue",
        "objective": session.objective,
        "current_position": session.current_position,
        "posture": {
            "alerts_open": len([a for a in alerts if a.status in (AlertStatus.OPEN, AlertStatus.TRIAGED)]),
            "incidents_open": len([i for i in incidents if i.status == "open"]),
            "iocs": len(iocs),
            "rules": len(rules),
            "graph_nodes": len(nodes),
        },
        "unknown": session.unknown,
        "investigations": [{"name": i.name, "status": i.status.value} for i in investigations],
        "branches": sorted(branches, key=lambda b: b["expected_value"], reverse=True),
    }


# ---------------------------------------------------------------------------
# PURPLE: plan de orquestacion (emulacion + deteccion + gaps de cobertura)
# ---------------------------------------------------------------------------
def build_purple_plan(
    state: MediatorState, session: object, priorities: list[str], techniques: list[dict]
) -> dict:
    session_id = session.id
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

    techniques_map = {t["id"]: t.get("name", t["id"]) for t in techniques}
    covered_techs = {t for r in rules for t in r.technique_ids}
    findings_by_tech: dict[str, list] = {}
    for f in findings:
        if f.technique_id:
            findings_by_tech.setdefault(f.technique_id, []).append(f.title)

    branches: list[dict] = []
    seen: set[str] = set()

    # 1. emulacion: findings activos de las sesiones red enlazadas
    for finding in findings:
        if finding.status.value in {"unverified", "inconclusive"}:
            branches.append(
                {
                    "type": "emulacion",
                    "name": f"{finding.title} ({finding.technique_id or '?'})",
                    "finding_id": finding.id,
                    "red_session": finding.session_id,
                    "expected_value": round(2.5 + finding.confidence, 2),
                }
            )
            seen.add(finding.id)

    # 2. deteccion: alertas abiertas de las sesiones blue enlazadas
    for alert in alerts:
        if alert.status in (AlertStatus.OPEN, AlertStatus.TRIAGED):
            branches.append(
                {
                    "type": "deteccion",
                    "name": f"{alert.rule_name} ({alert.host or '-'})",
                    "alert_id": alert.id,
                    "blue_session": alert.session_id,
                    "severity": alert.severity.value,
                    "expected_value": round(
                        2.0 + _SEVERITY_VALUE.get(alert.severity.value, 1.0) * 0.7, 2
                    ),
                }
            )
            seen.add(alert.id)

    # 3. gaps de cobertura: tecnicas probadas por red sin regla en blue
    for tid, titles in findings_by_tech.items():
        if tid not in covered_techs:
            branches.append(
                {
                    "type": "gap",
                    "name": f"{tid} {techniques_map.get(tid, '')}".strip(),
                    "technique": tid,
                    "findings": titles[:5],
                    "expected_value": 3.0,
                }
            )
            seen.add(tid)

    # 4. areas
    for area in session.next_areas:
        if area not in seen:
            branches.append(
                {
                    "type": "area",
                    "name": area,
                    "confidence": 0.5,
                    "expected_value": 1.0,
                }
            )

    return {
        "team": "purple",
        "objective": session.objective,
        "linked": {"red": red_ids, "blue": blue_ids},
        "emulation": {
            "red_sessions": red_ids,
            "active_findings": len([f for f in findings if f.status.value in {"unverified", "inconclusive"}]),
        },
        "detection": {
            "blue_sessions": blue_ids,
            "alerts_open": len([a for a in alerts if a.status in (AlertStatus.OPEN, AlertStatus.TRIAGED)]),
            "rules": len(rules),
        },
        "coverage_gaps": [
            {
                "technique": tid,
                "name": techniques_map.get(tid, ""),
                "findings": titles[:5],
            }
            for tid, titles in findings_by_tech.items()
            if tid not in covered_techs
        ],
        "branches": sorted(branches, key=lambda b: b["expected_value"], reverse=True),
    }
