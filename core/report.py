from __future__ import annotations

import html as html_lib
from datetime import datetime, timezone

from core.mediator import Mediator
from models.session import Session
from models.team import Team


def generate_report(mediator: Mediator, session_id: str, fmt: str = "markdown") -> str:
    """Reporte de la evaluacion desde el estado real, con dispatch por equipo.
    Nunca inventa datos."""
    session = mediator.state.get_session(session_id)
    if not session:
        raise KeyError(f"session {session_id} not found")
    team = session.team or Team.RED
    if team is Team.BLUE:
        sections = _blue_sections(mediator, session)
    elif team is Team.PURPLE:
        sections = _purple_sections(mediator, session)
    else:
        sections = _red_sections(mediator, session)
    return render_markdown(sections) if fmt == "markdown" else render_html(sections)


def _header(target_host: str | None, session: Session) -> dict:
    return {
        "title": "Resumen",
        "lines": [
            f"Equipo: {session.team.value.upper()} | Objetivo: {target_host or session.target_id} "
            f"({session.attack_stage.value})",
            f"Fase actual: {session.phase.value}",
            f"Posicion: {session.current_position or 'sin definir'}",
            f"Objective: {session.objective or 'sin definir'}",
            f"Generado: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        ],
    }


def _red_sections(mediator: Mediator, session: Session) -> list[dict]:
    target = mediator.state.get_target(session.target_id)
    findings = mediator.state.get_findings(session.id)
    chains = mediator.evidence_chains(session.id)
    metrics = mediator.get_metrics(session.id)
    investigations = mediator.investigations(session.id)
    surface = mediator.get_surface(session.id)
    audit = mediator.audit.entries()
    risk = metrics.get("evidence_hygiene") or {"score": 0, "level": "low"}

    sections: list[dict] = [_header(target.host if target else None, session)]

    if findings:
        sections.append(
            {
                "title": "Hallazgos",
                "rows": [
                    {
                        "Estado": f.status.value,
                        "Titulo": f.title,
                        "Confianza": f"{f.confidence:.2f}",
                        "Verificado": "si" if f.verified else "no",
                        "Tecnica": f.technique_id or "-",
                        "Evidencia": ", ".join(f.evidence_ids) or "-",
                    }
                    for f in findings
                ],
            }
        )
    else:
        sections.append({"title": "Hallazgos", "lines": ["Sin hipotesis registradas."]})

    if chains:
        sections.append(
            {
                "title": "Cadenas de evidencia",
                "rows": [
                    {
                        "Hallazgo": c.get("finding", "?"),
                        "Evidencia": "; ".join(
                            e.get("command", str(e)) if isinstance(e, dict) else str(e)
                            for e in c.get("evidence", [])
                        )
                        or "-",
                        "Tecnica": c.get("technique") or "-",
                        "Verificada": "si" if c.get("verified") else "no",
                    }
                    for c in chains
                ],
            }
        )
    else:
        sections.append({"title": "Cadenas de evidencia", "lines": ["Sin cadenas."]})

    sections.append(
        {
            "title": "Metricas",
            "lines": [
                f"Ejecuciones: {metrics.get('executions', {}).get('total', 0)} "
                f"(aprobadas {metrics.get('executions', {}).get('approved', 0)} / "
                f"bloqueadas {metrics.get('executions', {}).get('blocked', 0)} / "
                f"fallidas {metrics.get('executions', {}).get('failed', 0)})",
                f"Tasa de exito: {metrics.get('success_rate', 0):.2f} | "
                f"Duracion media: {metrics.get('avg_duration_ms', 0)}ms",
                f"Grafo: {metrics.get('graph', {}).get('total', 0)} nodos "
                f"(KNOWN {metrics.get('graph', {}).get('known', 0)} / "
                f"INFERRED {metrics.get('graph', {}).get('inferred', 0)} / "
                f"UNVERIFIED {metrics.get('graph', {}).get('unverified', 0)})",
                f"Investigaciones: {metrics.get('investigations', {}).get('total', 0)}",
                f"Higiene de evidencia: {risk['score']:.1f} ({risk['level']})",
            ],
        }
    )

    surface_rows = []
    for kind, items in surface.items():
        for item in items:
            name = item.get("name", "?")
            state = item.get("state", "?")
            surface_rows.append({"Tipo": kind, "Elemento": name, "Estado": state})
    if surface_rows:
        sections.append({"title": "Superficie de ataque", "rows": surface_rows})

    if investigations:
        sections.append(
            {
                "title": "Memoria de investigaciones",
                "rows": [
                    {"Nombre": i.name, "Estado": i.status.value, "Resultado": i.result or "-"}
                    for i in investigations
                ],
            }
        )

    tail = audit[-20:]
    if tail:
        sections.append(
            {
                "title": "Auditoria (ultimas 20)",
                "rows": [
                    {
                        "Hora": e.timestamp.isoformat(timespec="seconds"),
                        "Actor": e.actor,
                        "Accion": e.action,
                        "Veredicto": e.verdict.value,
                        "Detalle": e.detail[:120],
                    }
                    for e in tail
                ],
            }
        )
    return sections


def _blue_sections(mediator: Mediator, session: Session) -> list[dict]:
    alerts = mediator.state.get_alerts(session.id)
    incidents = mediator.state.get_incidents(session.id)
    rules = mediator.effective_rules(session.id)
    iocs = mediator.state.get_iocs(session.id)
    metrics = mediator.get_metrics(session.id)

    sections: list[dict] = [_header(None, session)]

    sections.append(
        {
            "title": "Alertas",
            "lines": [
                f"Total: {len(alerts)} | "
                f"Abiertas: {sum(a.status.value == 'open' for a in alerts)} | "
                f"Confirmadas: {sum(a.status.value == 'confirmed' for a in alerts)} | "
                f"Falsos positivos: {sum(a.status.value == 'false_positive' for a in alerts)}"
            ],
            "rows": [
                {
                    "Id": a.id,
                    "Regla": a.rule_name or a.rule_id,
                    "Severidad": a.severity.value,
                    "Estado": a.status.value,
                    "Host": a.host or "-",
                    "Ocurrencias": a.occurrences,
                    "Tecnica": ", ".join(a.technique_ids) or "-",
                    "Evento": (a.event_time or a.created_at).isoformat(timespec="seconds"),
                }
                for a in sorted(
                    alerts,
                    key=lambda a: (a.severity.value, a.created_at),
                    reverse=True,
                )
            ],
        }
    )

    if incidents:
        sections.append(
            {
                "title": "Incidentes",
                "rows": [
                    {
                        "Id": i.id,
                        "Titulo": i.title,
                        "Etapa": i.stage.value,
                        "Severidad": i.severity.value,
                        "Alertas": len(i.alert_ids),
                        "Evidencia": len(i.evidence_result_ids),
                        "Recomendaciones": len(i.recommendations),
                    }
                    for i in incidents
                ],
            }
        )
    else:
        sections.append(
            {"title": "Incidentes", "lines": ["Sin incidentes registrados."]}
        )

    alerts_metrics = metrics.get("alerts", {})
    rules_metrics = metrics.get("rules", {})
    sections.append(
        {
            "title": "Metricas de defensa",
            "lines": [
                f"MTTA (proxy): {alerts_metrics.get('mean_time_to_triage_min', 0)} min | "
                f"Tasa falsos positivos: {alerts_metrics.get('false_positive_rate', 0):.2%}",
                f"Cobertura de deteccion: {rules_metrics.get('techniques_covered', 0)} tecnicas con regla "
                f"({len([r for r in rules if r.enabled])} reglas activas / "
                f"{rules_metrics.get('techniques_observed', 0)} tecnicas observadas en alertas)",
            ],
        }
    )

    if iocs:
        sections.append(
            {
                "title": "Indicadores de compromiso",
                "rows": [
                    {
                        "Tipo": i.type.value,
                        "Valor": i.value,
                        "Confianza": f"{i.confidence:.2f}",
                        "Fuente": i.source,
                        "Tags": ", ".join(i.tags) or "-",
                    }
                    for i in iocs
                ],
            }
        )
    else:
        sections.append(
            {"title": "Indicadores de compromiso", "lines": ["Sin IOCs."]}
        )
    return sections


def _purple_sections(mediator: Mediator, session: Session) -> list[dict]:
    metrics = mediator.get_metrics(session.id)
    coverage = mediator.coverage(session.id)
    links = session.purple_links or {"red": [], "blue": []}
    red_ids = links.get("red", [])
    blue_ids = links.get("blue", [])
    red_alerts = sum(len(mediator.state.get_alerts(b)) for b in blue_ids)
    red_findings = sum(len(mediator.state.get_findings(r)) for r in red_ids)

    sections: list[dict] = [_header(None, session)]
    sections.append(
        {
            "title": "Orquestacion",
            "lines": [
                f"Sesiones red enlazadas: {len(red_ids)} ({', '.join(red_ids) or 'ninguna'})",
                f"Sesiones blue enlazadas: {len(blue_ids)} ({', '.join(blue_ids) or 'ninguna'})",
                f"Hallazgos red acumulados: {red_findings} | "
                f"Alertas blue acumuladas: {red_alerts}",
                f"Fase: {session.phase.value} | Objective: {session.objective or 'sin definir'}",
            ],
        }
    )

    matrix = coverage.get("by_tactic", [])
    rows = []
    for tactic in matrix:
        for row in tactic.get("techniques", []):
            rows.append(
                {
                    "Tecnica": row["id"],
                    "Nombre": row.get("name", "-"),
                    "Tactica": row.get("tactic", "-"),
                    "Cubierta": "si" if row.get("covered") else "no",
                    "Hallazgos": row.get("finding_count", 0),
                    "Alertas": row.get("alerts", 0),
                }
            )
    sections.append(
        {
            "title": "Matriz de cobertura",
            "lines": [
                f"Cobertura: {coverage.get('coverage', 0):.1%} | "
                f"Tecnicas: {coverage.get('total_techniques', 0)} | "
                f"Cubiertas: {coverage.get('covered_techniques', 0)} | "
                f"Brechas abiertas: {coverage.get('open_gaps', 0)}",
            ],
            "rows": rows,
        }
    )

    if coverage.get("gaps"):
        sections.append(
            {
                "title": "Brechas de cobertura",
                "lines": [
                    f"- {g['technique']} ({g.get('name', '-')}): {g['finding_count']} hallazgo(s) sin regla"
                    for g in coverage["gaps"]
                ],
            }
        )

    purple_cov = metrics.get("coverage", {})
    purple_det = metrics.get("detection", {})
    purple_emu = metrics.get("emulation", {})
    sections.append(
        {
            "title": "Metricas de mejora",
            "lines": [
                f"Tasa de deteccion: {purple_cov.get('detection_rate', 0):.1%} "
                f"(detectadas {purple_cov.get('detected_techniques', 0)} / "
                f"probadas {purple_cov.get('probed_techniques', 0)})",
                f"Cobertura: {purple_cov.get('coverage', 0):.1%} "
                f"({purple_cov.get('covered_techniques', 0)} / {purple_cov.get('total_techniques', 0)} tecnicas)",
                f"Alertas en blue enlazado: {purple_det.get('alerts_total', 0)} "
                f"({purple_det.get('alerts_open', 0)} abiertas)",
                f"Hallazgos validados: {purple_emu.get('findings_validated', 0)} | "
                f"Brechas abiertas: {purple_cov.get('open_gaps', 0)}",
            ],
        }
    )
    return sections


def _escape(text: str) -> str:
    return html_lib.escape(text, quote=True)


def render_markdown(sections: list[dict]) -> str:
    out = ["# Reporte de evaluacion", "", "> Generado por Offensive Context Engine"]
    for section in sections:
        out += ["", f"## {section['title']}"]
        if "lines" in section:
            for line in section["lines"]:
                out.append(f"- {line}")
        if "rows" in section and section["rows"]:
            headers = list(section["rows"][0].keys())
            out.append("| " + " | ".join(headers) + " |")
            out.append("|" + "|".join(["---"] * len(headers)) + "|")
            for row in section["rows"]:
                out.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
    out.append("")
    return "\n".join(out)


def render_html(sections: list[dict]) -> str:
    parts = [
        "<!DOCTYPE html>",
        '<html><head><meta charset="utf-8"><title>Reporte Offensive Context Engine</title>',
        "<style>",
        "body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:900px;color:#222}",
        "h1{border-bottom:3px solid #333;padding-bottom:.4rem}",
        "h2{margin-top:2rem;color:#0b5394}",
        "table{border-collapse:collapse;width:100%;font-size:.9rem}",
        "th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}",
        "th{background:#f0f0f0}",
        "code{background:#f6f6f6;padding:.1rem .3rem;border-radius:3px}",
        "</style></head><body>",
    ]
    parts.append("<h1>Reporte de evaluacion</h1>")
    parts.append("<p><em>Generado por Offensive Context Engine</em></p>")
    for section in sections:
        parts.append(f"<h2>{_escape(section['title'])}</h2>")
        if "lines" in section:
            parts.append("<ul>")
            parts.extend(f"<li>{_escape(line)}</li>" for line in section["lines"])
            parts.append("</ul>")
        if "rows" in section and section["rows"]:
            headers = list(section["rows"][0].keys())
            parts.append("<table><thead><tr>")
            parts.extend(f"<th>{_escape(h)}</th>" for h in headers)
            parts.append("</tr></thead><tbody>")
            for row in section["rows"]:
                parts.append("<tr>")
                parts.extend(
                    f"<td>{_escape(str(row.get(h, '')))}</td>" for h in headers
                )
                parts.append("</tr>")
            parts.append("</tbody></table>")
    parts.append("</body></html>")
    return "\n".join(parts)
