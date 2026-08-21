from __future__ import annotations

import hashlib
from collections import Counter

from core.coverage import coverage_from
from core.state import MediatorState
from models.alert import AlertStatus
from models.graph import KnowledgeState
from models.team import Team
from models.tool_result import ToolResult


def _stdout_hash(result: ToolResult) -> str:
    return hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()


def compute_metrics(state: MediatorState, session_id: str, techniques: list[dict] | None = None) -> dict:
    session = state.get_session(session_id)
    if not session:
        raise KeyError(f"session {session_id} not found")
    if session.team == Team.BLUE:
        return compute_blue_metrics(state, session)
    if session.team == Team.PURPLE:
        return compute_purple_metrics(state, session, techniques or [])
    return compute_red_metrics(state, session_id)


# ---------------------------------------------------------------------------
# metricas compartidas (grafo / investigaciones / ejecuciones)
# ---------------------------------------------------------------------------
def _shared_counts(state: MediatorState, session_id: str) -> dict:
    session = state.get_session(session_id)
    results = state.get_results(session_id)
    investigations = state.get_investigations(session_id)
    nodes = state.graph.nodes(session_id)

    total = len(results)
    approved = [r for r in results if r.approved]
    blocked = [r for r in results if not r.approved]
    succeeded = [r for r in approved if r.exit_code == 0 and not r.timed_out]
    failed = [r for r in approved if r.exit_code != 0]
    timed_out = [r for r in approved if r.timed_out]

    repeatability: dict[str, dict] = {}
    by_command: dict[str, list[ToolResult]] = {}
    for r in approved:
        by_command.setdefault(r.command, []).append(r)
    for command, runs in by_command.items():
        if len(runs) >= 2:
            hashes = {_stdout_hash(r) for r in runs}
            codes = {r.exit_code for r in runs}
            repeatability[command] = {
                "runs": len(runs),
                "stable": len(hashes) == 1 and len(codes) == 1,
                "distinct_outputs": len(hashes),
            }

    phase_coverage = sorted(
        {r.parsed.get("phase") for r in results if r.parsed.get("phase")}
    )

    inv_performed = [i for i in investigations if i.status.value == "performed"]
    inv_inconclusive = [i for i in investigations if i.status.value == "inconclusive"]
    inv_not_performed = [i for i in investigations if i.status.value == "not_performed"]

    return {
        "session_id": session_id,
        "team": session.team.value,
        "phase": session.phase.value,
        "executions": {
            "total": total,
            "approved": len(approved),
            "blocked": len(blocked),
            "succeeded": len(succeeded),
            "failed": len(failed),
            "timed_out": len(timed_out),
        },
        "success_rate": round(len(succeeded) / len(approved), 3) if approved else 0.0,
        "avg_duration_ms": round(sum(r.duration_ms for r in approved) / len(approved)) if approved else 0,
        "tools": dict(Counter(r.tool for r in approved)),
        "phase_coverage": phase_coverage,
        "repeatability": repeatability,
        "graph": {
            "total": len(nodes),
            "known": sum(1 for n in nodes if n.state == KnowledgeState.KNOWN),
            "inferred": sum(1 for n in nodes if n.state == KnowledgeState.INFERRED),
            "unverified": sum(1 for n in nodes if n.state == KnowledgeState.UNVERIFIED),
        },
        "investigations": {
            "total": len(investigations),
            "performed": len(inv_performed),
            "inconclusive": len(inv_inconclusive),
            "not_performed": len(inv_not_performed),
        },
    }


# ---------------------------------------------------------------------------
# RED
# ---------------------------------------------------------------------------
def compute_red_metrics(state: MediatorState, session_id: str) -> dict:
    session = state.get_session(session_id)
    results = state.get_results(session_id)
    findings = state.get_findings(session_id)
    nodes = state.graph.nodes(session_id)

    approved = [r for r in results if r.approved]
    failed = [r for r in approved if r.exit_code != 0]
    timed_out = [r for r in approved if r.timed_out]
    unapproved = [r for r in results if not r.approved]

    verified = [f for f in findings if f.verified]
    unverified_findings = [f for f in findings if not f.verified]
    unverified_nodes = [n for n in nodes if n.state == KnowledgeState.UNVERIFIED]

    blocked_n = len(unapproved)
    failed_n = len(failed)
    timeout_n = len(timed_out)
    unverified_findings_n = len(unverified_findings)
    unverified_nodes_n = len(unverified_nodes)
    # Formula documentada en el README:
    #   bloqueados x20 + fallidos x20 + timeouts x15 +
    #   findings sin evidencia x25 + nodos sin verificar x20   (tope 100)
    # Contador operativo de higiene de evidencia: senala que tan limpio es el
    # proceso de recolecta (senales concretas: bloqueos, fallos, evidencia
    # ausente). NO mide si el contenido es verdadero: un score bajo no
    # garantiza ausencia de alucinaciones, solo que el proceso no viene
    # ensuciado por estas senales.
    hygiene = min(
        100.0,
        blocked_n * 20
        + failed_n * 20
        + timeout_n * 15
        + unverified_findings_n * 25
        + unverified_nodes_n * 20,
    )
    hygiene_level = (
        "low" if hygiene < 30 else "medium" if hygiene < 60 else "high"
    )

    metrics = _shared_counts(state, session_id)
    hygiene_block = {
        "score": round(hygiene, 1),
        "level": hygiene_level,
    }
    metrics.update(
        {
            "attack_stage": session.attack_stage.value,
            "findings": {
                "total": len(findings),
                "verified": len(verified),
                "unverified": len(unverified_findings),
                "evidence_coverage": round(len(verified) / len(findings), 3) if findings else 0.0,
                "avg_confidence": round(sum(f.confidence for f in findings) / len(findings), 3) if findings else 0.0,
            },
            "evidence_hygiene": hygiene_block,
            "hallucination_risk": {**hygiene_block, "deprecated": True},
        }
    )
    return metrics


# ---------------------------------------------------------------------------
# BLUE: deteccion y triage (sin ejecucion)
# ---------------------------------------------------------------------------
def compute_blue_metrics(state: MediatorState, session: object) -> dict:
    session_id = session.id
    alerts = state.get_alerts(session_id)
    incidents = state.get_incidents(session_id)
    rules = state.get_rules(session_id)
    iocs = state.get_iocs(session_id)

    by_status = Counter(a.status.value for a in alerts)
    by_severity = Counter(a.severity.value for a in alerts)

    # tiempo medio a triage (proxy MTTA en minutos)
    triaged = [
        a
        for a in alerts
        if a.triaged_at is not None and a.status in (AlertStatus.TRIAGED, AlertStatus.CONFIRMED, AlertStatus.CLOSED)
    ]
    if triaged:
        mean_ttt = round(
            sum((a.triaged_at - a.created_at).total_seconds() for a in triaged) / len(triaged) / 60,
            1,
        )
    else:
        mean_ttt = None

    confirmed = by_status.get("confirmed", 0)
    fp = by_status.get("false_positive", 0)
    fp_rate = round(fp / (fp + confirmed), 3) if (fp + confirmed) else 0.0

    open_alerts = by_status.get("open", 0) + by_status.get("triaged", 0)

    techniques_in_alerts = {t for a in alerts for t in a.technique_ids}
    covered_techniques = {t for r in rules for t in r.technique_ids}

    metrics = _shared_counts(state, session_id)
    metrics.update(
        {
            "alerts": {
                "total": len(alerts),
                "open": open_alerts,
                "triaged": by_status.get("triaged", 0),
                "confirmed": confirmed,
                "false_positive": fp,
                "closed": by_status.get("closed", 0),
                "by_severity": dict(by_severity),
                "false_positive_rate": fp_rate,
                "mean_time_to_triage_min": mean_ttt,
            },
            "incidents": {
                "total": len(incidents),
                "open": sum(1 for i in incidents if i.status == "open"),
                "closed": sum(1 for i in incidents if i.status == "closed"),
                "with_recommendations": sum(1 for i in incidents if i.recommendations),
            },
            "rules": {
                "total": len(rules),
                "enabled": sum(1 for r in rules if r.enabled),
                "by_severity": dict(Counter(r.severity.value for r in rules)),
                "techniques_covered": len(covered_techniques),
                "techniques_observed": len(techniques_in_alerts),
            },
            "iocs": {"total": len(iocs)},
        }
    )
    return metrics


# ---------------------------------------------------------------------------
# PURPLE: orquestacion (cobertura ATT&CK)
# ---------------------------------------------------------------------------
def compute_purple_metrics(state: MediatorState, session: object, techniques: list[dict]) -> dict:
    session_id = session.id
    findings = [
        f
        for rid in session.purple_links.get("red", [])
        for f in state.get_findings(rid)
        if state.get_session(rid)
    ]
    alerts = [
        a
        for bid in session.purple_links.get("blue", [])
        for a in state.get_alerts(bid)
        if state.get_session(bid)
    ]
    coverage = coverage_from(state, session, techniques)

    metrics = _shared_counts(state, session_id)
    metrics.update(
        {
            "linked": {"red": session.purple_links.get("red", []), "blue": session.purple_links.get("blue", [])},
            "emulation": {
                "findings_total": len(findings),
                "findings_validated": sum(1 for f in findings if f.status.value == "validated"),
                "findings_active": sum(1 for f in findings if f.status.value in {"unverified", "inconclusive"}),
            },
            "detection": {
                "alerts_total": len(alerts),
                "alerts_open": sum(
                    1
                    for a in alerts
                    if a.status in (AlertStatus.OPEN, AlertStatus.TRIAGED)
                ),
            },
            "coverage": {
                "coverage": coverage["coverage"],
                "detection_rate": coverage["detection_rate"],
                "open_gaps": coverage["open_gaps"],
                "total_techniques": coverage["total_techniques"],
                "covered_techniques": coverage["covered_techniques"],
                "by_tactic": coverage["by_tactic"],
            },
        }
    )
    return metrics
