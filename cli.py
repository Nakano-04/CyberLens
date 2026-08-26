from __future__ import annotations

import argparse
import json
import os
import sys

from client import MediatorClient, MediatorError


def _client() -> MediatorClient:
    return MediatorClient(os.environ.get("MEDIADOR_URL", "http://127.0.0.1:8000"))


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _handle(fn, *args, **kwargs) -> None:
    try:
        result = fn(*args, **kwargs)
    except MediatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
    _print_json(result)


def _split_list(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [item.strip() for item in value.split(";") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mediador-cli", description="Cliente CLI del Offensive Context Engine"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health", help="verifica que el mediador responda")

    p = sub.add_parser("target-create", help="registra un target")
    p.add_argument("host")
    p.add_argument("--desc", default="")
    p.add_argument("--assessment", default="web", choices=["web", "internal", "cloud"])
    p.add_argument("--unauthorized", action="store_true")
    p.add_argument("--os", dest="os_hint", default=None)

    sub.add_parser("target-list", help="lista targets")
    p = sub.add_parser("target-show", help="muestra un target")
    p.add_argument("target_id")

    p = sub.add_parser("session-create", help="abre una sesion sobre un target")
    p.add_argument("target_id")
    p.add_argument("--agent", default="build")
    p.add_argument("--objective", default="")
    p.add_argument("--tag", action="append", default=[])
    p.add_argument("--team", default="red", choices=["red", "blue", "purple"], help="equipo: red (ofensivo), blue (deteccion/triage), purple (orquestador)")
    p.add_argument("--no-llm-compact", dest="llm_compact", action="store_false", default=True)
    p.add_argument("--max-steps", type=int, default=None)

    sub.add_parser("session-list", help="lista sesiones")
    p = sub.add_parser("session-show", help="muestra una sesion")
    p.add_argument("session_id")

    p = sub.add_parser("objective", help="actualiza objetivo/posicion/areas de la sesion")
    p.add_argument("session_id")
    p.add_argument("--objective", default=None)
    p.add_argument("--position", dest="current_position", default=None)
    p.add_argument("--stage", dest="attack_stage", default=None)
    p.add_argument("--known", default=None)
    p.add_argument("--unknown", default=None)
    p.add_argument("--areas", dest="next_areas", default=None)

    p = sub.add_parser("phase", help="cambia la fase (validada por el state machine)")
    p.add_argument("session_id")
    p.add_argument(
        "phase",
        choices=["recon", "enumeration", "modeling", "hypothesis", "validation", "impact", "evidence", "report"],
    )
    p.add_argument("--override", action="store_true", help="salta las validaciones (auditado)")
    p.add_argument("--reason", default="", help="razon obligatoria si usas --override")

    p = sub.add_parser("transitions", help="fases permitidas desde la actual")
    p.add_argument("session_id")

    p = sub.add_parser("note", help="agrega una nota a la sesion")
    p.add_argument("session_id")
    p.add_argument("note")

    p = sub.add_parser("exec", help="ejecuta un comando validado por el mediador")
    p.add_argument("session_id")
    p.add_argument("cmd")
    p.add_argument("--tool", default="shell")
    p.add_argument("--timeout", type=int, default=None)
    p.add_argument("--parser", default=None)
    p.add_argument("--human-approved", action="store_true", help="aprueba comandos del approval gate")

    p = sub.add_parser("results", help="resultados de una sesion")
    p.add_argument("session_id")

    p = sub.add_parser("yara-scan", help="escanea una muestra con el motor YARA del mediador")
    p.add_argument("session_id")
    p.add_argument("rules")
    p.add_argument("target_path")

    p = sub.add_parser("prompt", help="muestra el system prompt construido")
    p.add_argument("session_id")

    p = sub.add_parser("context", help="muestra el contexto acumulado")
    p.add_argument("session_id")

    p = sub.add_parser("summary", help="resumen compacto de la sesion")
    p.add_argument("session_id")

    p = sub.add_parser("compact", help="compacta el contexto (fallback inmediato)")
    p.add_argument("session_id")
    p.add_argument("--async", dest="async_llm", action="store_true", help="resumen LLM en background")

    p = sub.add_parser("compress", help="contexto ofensivo comprimido (pipeline)")
    p.add_argument("session_id")

    p = sub.add_parser("node-add", help="registra un nodo en el grafo de conocimiento")
    p.add_argument("session_id")
    p.add_argument("kind")
    p.add_argument("name")
    p.add_argument("--state", default="UNVERIFIED", choices=["KNOWN", "INFERRED", "UNVERIFIED"])
    p.add_argument("--confidence", type=float, default=0.5)
    p.add_argument("--source", default="manual")

    p = sub.add_parser("nodes", help="nodos del grafo de la sesion")
    p.add_argument("session_id")

    p = sub.add_parser("link", help="relaciona dos nodos")
    p.add_argument("session_id")
    p.add_argument("source")
    p.add_argument("target")
    p.add_argument("--kind", default="contains")

    p = sub.add_parser("surface", help="superficie de ataque viva")
    p.add_argument("session_id")

    p = sub.add_parser("prune", help="poda TTL del grafo (nodos obsoletos)")
    p.add_argument("session_id")

    p = sub.add_parser("investigation-add", help="registra una investigacion (memoria)")
    p.add_argument("session_id")
    p.add_argument("name")
    p.add_argument("--status", default="not_performed", choices=["not_performed", "performed", "inconclusive"])
    p.add_argument("--result", default="")
    p.add_argument("--evidence", dest="evidence_result_id", default=None)
    p.add_argument("--confidence", type=float, default=0.5)

    p = sub.add_parser("investigations", help="memoria de investigaciones")
    p.add_argument("session_id")

    p = sub.add_parser("finding-add", help="registra una hipotesis con evidencia")
    p.add_argument("session_id")
    p.add_argument("title")
    p.add_argument("--detail", default="")
    p.add_argument("--confidence", type=float, default=0.5)
    p.add_argument("--evidence", dest="evidence_ids", action="append", default=[])
    p.add_argument("--against", action="append", default=[])
    p.add_argument("--status", default="unverified", choices=["unverified", "validated", "rejected", "inconclusive"])
    p.add_argument("--technique", dest="technique_id", default=None)

    p = sub.add_parser("findings", help="hipotesis de la sesion")
    p.add_argument("session_id")

    p = sub.add_parser("finding-status", help="cambia el estado de una hipotesis")
    p.add_argument("session_id")
    p.add_argument("finding_id")
    p.add_argument("status", choices=["unverified", "validated", "rejected", "inconclusive"])

    p = sub.add_parser("metrics", help="metricas estables de la sesion")
    p.add_argument("session_id")

    p = sub.add_parser("plan", help="plan contextual (ramas y valor esperado)")
    p.add_argument("session_id")

    p = sub.add_parser("chains", help="cadenas de evidencia de las hipotesis")
    p.add_argument("session_id")

    p = sub.add_parser("report", help="reporte de la evaluacion (markdown o html)")
    p.add_argument("session_id")
    p.add_argument("--format", default="markdown", choices=["markdown", "html"])

    p = sub.add_parser("debrief", help="debriefing: correlacion alertas por paso del kill-chain")
    p.add_argument("session_id")

    p = sub.add_parser("debrief-report", help="debriefing: reporte automatico (markdown o html)")
    p.add_argument("session_id")
    p.add_argument("--format", default="markdown", choices=["markdown", "html"])

    p = sub.add_parser("debrief-suggestions", help="debriefing: auto-sugerencias conexables para la proxima campana")
    p.add_argument("session_id")

    p = sub.add_parser("debrief-seed", help="debriefing: seed de config inicial (c2-dect/CyberLens) para la proxima campana")
    p.add_argument("session_id")
    p.add_argument("--output", default=None, help="archivo JSON de salida (default: stdout)")

    sub.add_parser("techniques", help="referencia MITRE ATT&CK")
    p = sub.add_parser("technique-show", help="detalle de una tecnica")
    p.add_argument("technique_id")

    p = sub.add_parser("techniques-suggested", help="tecnicas MITRE candidatas para la fase")
    p.add_argument("session_id")

    sub.add_parser("audit", help="muestra la auditoria completa")

    # ------------------------------------------------------------------
    # Blue team: telemetria, alertas, incidentes, reglas, IOCs
    # ------------------------------------------------------------------
    p = sub.add_parser("blue-ingest", help="blue: ingiere un evento de telemetria (dispara deteccion)")
    p.add_argument("session_id")
    p.add_argument("source", help="origen del evento: process, network, mail, cloud_audit, auth...")
    p.add_argument("stdout", help="contenido del evento (log line o salida)")
    p.add_argument("--command", default="")
    p.add_argument("--json", dest="parsed_json", default=None, help="campos parseados como JSON")

    sub.add_parser("alerts", help="blue: alertas de la sesion")
    p = sub.add_parser("alert-status", help="blue: cambia el estado de una alerta")
    p.add_argument("session_id")
    p.add_argument("alert_id")
    p.add_argument("status", choices=["open", "triaged", "confirmed", "false_positive", "closed"])
    p.add_argument("--note", default=None)

    p = sub.add_parser("rule-add", help="blue: agrega una regla de deteccion")
    p.add_argument("session_id")
    p.add_argument("name")
    p.add_argument("--id", dest="rule_id", default=None)
    p.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])
    p.add_argument("--technique", dest="technique_ids", action="append", default=[])
    p.add_argument("--pattern", dest="pattern_stdout", action="append", default=[], help="patron regex contra stdout (repetible)")
    p.add_argument("--pattern-command", action="append", default=[], help="patron regex contra command (repetible)")
    p.add_argument("--description", default="")

    sub.add_parser("rules", help="blue: reglas activas de la sesion")

    p = sub.add_parser("rule-load-yaml", help="blue: carga reglas SIGMA desde YAML")
    p.add_argument("session_id")
    p.add_argument("path", help="ruta al archivo YAML con reglas SIGMA")

    p = sub.add_parser("incident-create", help="blue: crea un incidente desde alertas")
    p.add_argument("session_id")
    p.add_argument("title")
    p.add_argument("--alert", dest="alert_ids", action="append", default=[])
    p.add_argument("--evidence", dest="evidence_ids", action="append", default=[])
    p.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])

    sub.add_parser("incidents", help="blue: incidentes de la sesion")
    p = sub.add_parser("incident-stage", help="blue: avanza la etapa de un incidente")
    p.add_argument("session_id")
    p.add_argument("incident_id")
    p.add_argument("stage", choices=["detect", "triage", "investigate", "report"])

    p = sub.add_parser("recommendation-add", help="blue: documenta una recomendacion de respuesta (sin ejecutarla)")
    p.add_argument("session_id")
    p.add_argument("text")

    p = sub.add_parser("ioc-add", help="blue: registra un indicador de compromiso")
    p.add_argument("session_id")
    p.add_argument("value")
    p.add_argument("--type", default="other", choices=["hash", "ip", "domain", "url", "file", "other"])
    p.add_argument("--confidence", type=float, default=0.5)
    p.add_argument("--source", default="manual")
    p.add_argument("--description", default="")
    p.add_argument("--tag", dest="tags", action="append", default=[])

    sub.add_parser("iocs", help="blue: indicadores de compromiso")

    # ------------------------------------------------------------------
    # Purple team: orquestacion red+blue y cobertura
    # ------------------------------------------------------------------
    p = sub.add_parser("purple-link", help="purple: enlaza una sesion red o blue")
    p.add_argument("session_id")
    p.add_argument("team", choices=["red", "blue"])
    p.add_argument("linked_session_id")

    p = sub.add_parser("coverage", help="purple: matriz de cobertura ATT&CK/ATLAS")
    p.add_argument("session_id")
    return parser


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args()
    client = _client()
    command = args.command

    if command == "health":
        _handle(client.health)
    elif command == "target-create":
        _handle(client.create_target, args.host, args.desc, not args.unauthorized, args.assessment, args.os_hint)
    elif command == "target-list":
        _handle(client.list_targets)
    elif command == "target-show":
        _handle(client.get_target, args.target_id)
    elif command == "session-create":
        _handle(client.create_session, args.target_id, args.agent, args.objective, args.tag, args.llm_compact, args.max_steps, args.team)
    elif command == "session-list":
        _handle(client.list_sessions)
    elif command == "session-show":
        _handle(client.get_session, args.session_id)
    elif command == "objective":
        _handle(
            client.update_objective,
            args.session_id,
            args.objective,
            args.current_position,
            args.attack_stage,
            _split_list(args.known),
            _split_list(args.unknown),
            _split_list(args.next_areas),
        )
    elif command == "phase":
        _handle(client.set_phase, args.session_id, args.phase, args.override, args.reason)
    elif command == "transitions":
        _handle(client.phase_transitions, args.session_id)
    elif command == "note":
        _handle(client.add_note, args.session_id, args.note)
    elif command == "exec":
        _handle(client.execute, args.session_id, args.cmd, args.tool, args.timeout, args.parser, args.human_approved)
    elif command == "results":
        _handle(client.results, args.session_id)
    elif command == "yara-scan":
        _handle(client.yara_scan, args.session_id, args.rules, args.target_path)
    elif command == "prompt":
        _handle(client.system_prompt, args.session_id)
    elif command == "context":
        _handle(client.context, args.session_id)
    elif command == "summary":
        _handle(client.compact_summary, args.session_id)
    elif command == "compact":
        _handle(client.compact, args.session_id, args.async_llm)
    elif command == "compress":
        _handle(client.compress, args.session_id)
    elif command == "node-add":
        _handle(client.upsert_node, args.session_id, args.kind, args.name, args.state, args.confidence, args.source)
    elif command == "nodes":
        _handle(client.nodes, args.session_id)
    elif command == "link":
        _handle(client.link_nodes, args.session_id, args.source, args.target, args.kind)
    elif command == "surface":
        _handle(client.surface, args.session_id)
    elif command == "prune":
        _handle(client.prune_graph, args.session_id)
    elif command == "investigation-add":
        _handle(
            client.add_investigation,
            args.session_id,
            args.name,
            args.status,
            args.result,
            args.evidence_result_id,
            args.confidence,
        )
    elif command == "investigations":
        _handle(client.investigations, args.session_id)
    elif command == "finding-add":
        _handle(
            client.add_finding,
            args.session_id,
            args.title,
            args.detail,
            args.confidence,
            args.evidence_ids,
            args.against,
            args.status,
            args.technique_id,
        )
    elif command == "findings":
        _handle(client.findings, args.session_id)
    elif command == "finding-status":
        _handle(client.update_finding_status, args.session_id, args.finding_id, args.status)
    elif command == "metrics":
        _handle(client.metrics, args.session_id)
    elif command == "plan":
        _handle(client.plan, args.session_id)
    elif command == "chains":
        _handle(client.evidence_chains, args.session_id)
    elif command == "report":
        _handle(client.report, args.session_id, args.format)
    elif command == "debrief":
        _handle(client.debrief, args.session_id)
    elif command == "debrief-report":
        _handle(client.debrief_report, args.session_id, args.format)
    elif command == "debrief-suggestions":
        _handle(client.debrief_suggestions, args.session_id)
    elif command == "debrief-seed":
        seed = client.debrief_seed(args.session_id)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(seed, fh, indent=2, ensure_ascii=False, default=str)
            print(f"seed guardado en {args.output}")
        else:
            _print_json(seed)
    elif command == "techniques":
        _handle(client.techniques)
    elif command == "technique-show":
        _handle(client.technique, args.technique_id)
    elif command == "techniques-suggested":
        _handle(client.session_techniques, args.session_id)
    elif command == "audit":
        _handle(client.audit)

    # blue team
    elif command == "blue-ingest":
        parsed = json.loads(args.parsed_json) if args.parsed_json else None
        _handle(client.ingest_event, args.session_id, args.source, args.command, args.stdout, parsed)
    elif command == "alerts":
        _handle(client.alerts, args.session_id)
    elif command == "alert-status":
        _handle(client.update_alert_status, args.session_id, args.alert_id, args.status, args.note)
    elif command == "rule-add":
        _handle(
            client.add_rule,
            args.session_id,
            args.name,
            args.rule_id,
            args.severity,
            args.technique_ids,
            args.pattern_stdout,
            args.pattern_command,
            args.description,
        )
    elif command == "rules":
        _handle(client.rules, args.session_id)
    elif command == "rule-load-yaml":
        _handle(lambda sid, p: client._request("POST", f"/sessions/{sid}/rules/yaml", {"path": p}), args.session_id, args.path)
    elif command == "incident-create":
        _handle(
            client.create_incident,
            args.session_id,
            args.title,
            args.alert_ids,
            args.evidence_ids,
            args.severity,
        )
    elif command == "incidents":
        _handle(client.incidents, args.session_id)
    elif command == "incident-stage":
        _handle(client.update_incident_stage, args.session_id, args.incident_id, args.stage)
    elif command == "recommendation-add":
        _handle(client.add_recommendation, args.session_id, args.text)
    elif command == "ioc-add":
        _handle(
            client.add_ioc,
            args.session_id,
            args.value,
            args.type,
            args.confidence,
            args.source,
            args.description,
            args.tags,
        )
    elif command == "iocs":
        _handle(client.iocs, args.session_id)

    # purple team
    elif command == "purple-link":
        _handle(client.link_session, args.session_id, args.linked_session_id, args.team)
    elif command == "coverage":
        _handle(client.coverage, args.session_id)


if __name__ == "__main__":
    main()
