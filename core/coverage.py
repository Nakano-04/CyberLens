from __future__ import annotations

from core.state import MediatorState
from models.session import Session
from models.team import Team


def coverage_from(
    state: MediatorState,
    session: Session,
    techniques: list[dict],
    default_rules: list | None = None,
) -> dict:
    """Matriz de cobertura ATT&CK (logica pura, sin dependencia del mediator).

    - Conocimiento: catalogo MITRE.
    - Red: findings de las sesiones red enlazadas (que se probo).
    - Blue: reglas y alertas de las sesiones blue enlazadas (que se detecta).
    - coverage: % de tecnicas del catalogo con al menos 1 regla.
    - detection_rate: % de tecnicas probadas por red que blue detecta.
    - gaps: tecnicas con findings (probadas) pero sin regla.
    - default_rules: catalogo base de deteccion (SIGMA) desplegado por defecto
      en toda sesion blue; se suma a las reglas custom de la sesion.
    """
    if session.team == Team.PURPLE:
        red_ids = session.purple_links.get("red", [])
        blue_ids = session.purple_links.get("blue", [])
    else:
        red_ids = []
        blue_ids = [session.id]

    findings = [
        f for rid in red_ids for f in state.get_findings(rid) if state.get_session(rid)
    ]
    alerts = [
        a for bid in blue_ids for a in state.get_alerts(bid) if state.get_session(bid)
    ]
    rules = [
        r for bid in blue_ids for r in state.get_rules(bid) if state.get_session(bid)
    ]
    if default_rules:
        rules = list(rules) + list(default_rules)

    techniques_map: dict[str, dict] = {
        t["id"]: {"name": t.get("name", ""), "tactic": t.get("tactic", "unknown")}
        for t in techniques
    }

    findings_by_tech: dict[str, list] = {}
    for f in findings:
        if f.technique_id:
            findings_by_tech.setdefault(f.technique_id, []).append(f.title)

    rules_by_tech: dict[str, list] = {}
    for r in rules:
        for tid in r.technique_ids:
            rules_by_tech.setdefault(tid, []).append(r.id)

    alerts_by_tech: dict[str, int] = {}
    for a in alerts:
        for tid in a.technique_ids:
            alerts_by_tech[tid] = alerts_by_tech.get(tid, 0) + 1

    by_tactic: dict[str, dict] = {}
    rows: list[dict] = []
    for tid, meta in sorted(techniques_map.items()):
        row = {
            "id": tid,
            "name": meta["name"],
            "tactic": meta["tactic"],
            "findings": findings_by_tech.get(tid, []),
            "finding_count": len(findings_by_tech.get(tid, [])),
            "rules": rules_by_tech.get(tid, []),
            "rule_count": len(rules_by_tech.get(tid, [])),
            "alerts": alerts_by_tech.get(tid, 0),
            "covered": bool(rules_by_tech.get(tid)),
        }
        rows.append(row)
        tactic = by_tactic.setdefault(
            meta["tactic"], {"total": 0, "covered": 0, "techniques": []}
        )
        tactic["total"] += 1
        if row["covered"]:
            tactic["covered"] += 1
        tactic["techniques"].append(row)

    total = len(rows) or 1
    covered = sum(1 for r in rows if r["covered"])
    gaps = [r for r in rows if r["finding_count"] > 0 and not r["covered"]]

    detected = sum(1 for r in rows if r["finding_count"] > 0 and r["covered"])
    probed = sum(1 for r in rows if r["finding_count"] > 0) or 1

    return {
        "team": session.team.value,
        "session_id": session.id,
        "linked_red": red_ids,
        "linked_blue": blue_ids,
        "total_techniques": len(rows),
        "covered_techniques": covered,
        "coverage": round(covered / total, 3),
        "probed_techniques": sum(1 for r in rows if r["finding_count"] > 0),
        "detected_techniques": sum(1 for r in rows if r["finding_count"] > 0 and r["covered"]),
        "detection_rate": round(detected / probed, 3),
        "open_gaps": len(gaps),
        "gaps": [
            {
                "technique": g["id"],
                "name": g["name"],
                "tactic": g["tactic"],
                "findings": g["findings"][:10],
                "finding_count": g["finding_count"],
            }
            for g in sorted(gaps, key=lambda r: -r["finding_count"])
        ],
        "by_tactic": [
            {
                "tactic": name,
                "total": stats["total"],
                "covered": stats["covered"],
                "coverage": round(stats["covered"] / stats["total"], 3) if stats["total"] else 0,
            }
            for name, stats in sorted(by_tactic.items())
        ],
    }


def compute_coverage(mediator, session_id: str) -> dict:
    """Cobertura desde el mediador (usa el catalogo MITRE real y las reglas
    de deteccion desplegadas)."""
    session = mediator.state.get_session(session_id)
    if not session:
        raise KeyError(f"session {session_id} not found")
    return coverage_from(
        mediator.state,
        session,
        mediator._techniques.all(),
        default_rules=getattr(mediator, "_default_rules", None),
    )
