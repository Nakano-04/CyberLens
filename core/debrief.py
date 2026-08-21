from __future__ import annotations

import html as html_lib
import re
import secrets
from datetime import datetime, timezone

from client import MediatorClient
from knowledge.detection import RULES as DETECTION_RULES
from knowledge.mitre import TECHNIQUES
from knowledge.sentryguard import SentryGuardIndex

# El oficio: cierre del ciclo operativo.
# Consume alertas y resultados (via API o estado local), correlaciona cada
# deteccion por paso del kill-chain (acceso -> LPE -> credenciales -> lateral...),
# emite el reporte "te detectaron en el paso X, por el evento Y, a los Z
# segundos", genera auto-sugerencias conexables (jitter, rotacion de nombre de
# proceso, cambio de canal HTTPS->DNS, evasion) y produce el seed de config
# inicial de la proxima campana (c2-dect + CyberLens).

KILL_CHAIN: list[dict] = [
    {"id": "recon", "label": "Reconocimiento", "tactics": ["reconnaissance"]},
    {"id": "acceso", "label": "Acceso inicial", "tactics": ["initial_access"]},
    {"id": "ejecucion", "label": "Ejecucion", "tactics": ["execution", "ai_attack_staging"]},
    {"id": "lpe", "label": "Escalada de privilegios", "tactics": ["privilege_escalation"]},
    {"id": "credenciales", "label": "Robo de credenciales", "tactics": ["credential_access"]},
    {"id": "persistencia", "label": "Persistencia", "tactics": ["persistence"]},
    {"id": "defensa", "label": "Evasion de defensas", "tactics": ["defense_evasion"]},
    {"id": "descubrimiento", "label": "Descubrimiento", "tactics": ["discovery"]},
    {"id": "lateral", "label": "Movimiento lateral", "tactics": ["lateral_movement"]},
    {"id": "c2", "label": "Comando y control", "tactics": ["command_and_control"]},
    {"id": "coleccion", "label": "Recoleccion", "tactics": ["collection"]},
    {"id": "exfiltracion", "label": "Exfiltracion", "tactics": ["exfiltration"]},
    {"id": "impacto", "label": "Impacto", "tactics": ["impact"]},
    {"id": "otro", "label": "Sin clasificar", "tactics": []},
]

TECHNIQUE_STEP_OVERRIDES: dict[str, str] = {
    "T1071": "c2",
    "T1505.003": "acceso",
    "T1190": "acceso",
    "T1203": "acceso",
    "T1055": "lpe",
    "T1036": "defensa",
    "T1070": "defensa",
    "T1136": "persistencia",
    "T1588.002": "recon",
}

TACTIC_TO_STEP: dict[str, str] = {
    tactic: step["id"] for step in KILL_CHAIN for tactic in step["tactics"]
}

STEP_BY_TECHNIQUE: dict[str, str] = {}
for _tid, _meta in TECHNIQUES.items():
    STEP_BY_TECHNIQUE[_tid] = TACTIC_TO_STEP.get(_meta["tactic"], "otro")
STEP_BY_TECHNIQUE.update(TECHNIQUE_STEP_OVERRIDES)

STEP_KEYWORDS: dict[str, list[str]] = {
    "acceso": [r"webshell", r"web shell", r"phish", r"initial access", r"public-facing", r"proxy"],
    "ejecucion": [r"reverse shell", r"macro", r"scripting", r"execution", r"interpreter"],
    "lpe": [r"privilege", r"\buac\b", r"elevat", r"\beop\b"],
    "credenciales": [r"credential", r"lsass", r"kerber", r"brute", r"password", r"ticket", r"dump"],
    "persistencia": [r"persistence", r"scheduled task", r"registry", r"autorun", r"boot persist"],
    "defensa": [r"obfusc", r"encoding", r"bypass", r"evasion", r"defense"],
    "descubrimiento": [r"scan", r"recon", r"discovery", r"enumerat"],
    "lateral": [r"lateral", r"psexec", r"winrm", r"remote service", r"\bwmic\b", r"remote desktop"],
    "c2": [r"beacon", r"\bc2\b", r"command.?(and|&).?control", r"checkin"],
    "exfiltracion": [r"exfil"],
    "impacto": [r"ransom", r"encrypt", r"destruction", r"hijack", r"resource hijack"],
    "coleccion": [r"collect", r"data from", r"staging"],
    "recon": [r"reconnaissance", r"active scanning", r"gather victim"],
}

STEP_ORDER: dict[str, int] = {step["id"]: i for i, step in enumerate(KILL_CHAIN)}

PROFILE_BASE: dict = {
    "method": "POST",
    "uris": ["/api/update", "/login", "/dashboard/data", "/api/v2/events"],
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ],
    "headers": {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Referer": "https://app.example.com/dashboard",
        "Origin": "https://app.example.com",
    },
    "post_data": '{"data":"{{payload}}","timestamp":{{timestamp}},"nonce":"{{nonce}}"}',
    "content_type": "application/json",
    "encode_mode": "json",
    "jitter": 30,
    "default_sleep": 10,
}

SUGGESTIONS: list[dict] = [
    {
        "id": "SUG-0001",
        "type": "jitter",
        "title": "Jitter de timing del beacon",
        "action": "Aumenta el jitter y varia el intervalo de beacon para romper la ventana de deteccion de rafagas.",
        "trigger_techniques": ["T1071"],
        "trigger_rule_patterns": [r"beacon", r"c2"],
        "parameters": {"jitter": 45, "default_sleep": 45},
    },
    {
        "id": "SUG-0002",
        "type": "channel",
        "title": "Cambio de canal HTTPS -> DNS",
        "action": "Cambia el canal de comunicacion a DNS (o alterna HTTPS/DNS) para salir del balanceo de trafico web monitorizado.",
        "trigger_techniques": ["T1071", "T1059"],
        "trigger_rule_patterns": [r"beacon", r"reverse shell", r"c2"],
        "parameters": {"channel": "dns", "encode_mode": "base64"},
    },
    {
        "id": "SUG-0003",
        "type": "process_name",
        "title": "Rotacion de nombre de proceso",
        "action": "Rota el nombre de proceso y evita las herramientas de nombre conocido que dispararon la regla; renombra binario y dropper.",
        "trigger_techniques": ["T1003", "T1505.003", "T1558", "T1027"],
        "trigger_rule_patterns": [r"credential dump", r"webshell", r"kerberoast", r"dump"],
        "parameters": {"process_name_pool": ["svchost.exe", "conhost.exe", "dns.exe"], "process_rotation": True},
    },
    {
        "id": "SUG-0004",
        "type": "timing",
        "title": "Ritmo de la actividad",
        "action": "Reduce el ritmo: espacia intentos y agrega espera exponencial para evadir el umbral de rafaga por host.",
        "trigger_techniques": ["T1046", "T1110"],
        "trigger_rule_patterns": [r"scan", r"brute", r"spray"],
        "parameters": {"scan_delay_s": 180, "exponential_backoff": True},
    },
    {
        "id": "SUG-0005",
        "type": "evasion",
        "title": "Ajuste de cadena de evasion",
        "action": "Ajusta la evasion: alterna el encoding (base64/hex/xor) y cambia el mecanismo de carga para no repetir la firma detectada.",
        "trigger_techniques": ["T1027", "T1548", "T1558"],
        "trigger_rule_patterns": [r"obfusc", r"encoding", r"uac", r"elevat"],
        "parameters": {"encode_mode": "xor", "evasion_chain": ["certutil", "mshta", "rundll32"]},
    },
    {
        "id": "SUG-0006",
        "type": "persistence",
        "title": "Mecanismo de persistencia alternativo",
        "action": "Usa un mecanismo de persistencia alternativo (Run key, WMI event subscription, servicio) fuera del que te detectaron.",
        "trigger_techniques": ["T1053", "T1546", "T1574", "T1136"],
        "trigger_rule_patterns": [r"persistence", r"scheduled task", r"event triggered"],
        "parameters": {"persistence_mechanism": "registry_run_key"},
    },
    {
        "id": "SUG-0007",
        "type": "payload",
        "title": "Fragmentacion de payload de IA",
        "action": "Divide el payload y evita las frases firmadas (prompt injection, jailbreak): tokeniza y ofusca las instrucciones.",
        "trigger_techniques": [
            "AML.T0051", "AML.T0054", "AML.T0043", "AML.T0070",
            "AML.T0034", "AML.T0020", "AML.T0048", "T1496",
        ],
        "trigger_rule_patterns": [r"prompt injection", r"llmjacking", r"jailbreak"],
        "parameters": {"payload_chunking": True, "prompt_obfuscation": "rot13+base64"},
    },
    {
        "id": "SUG-0008",
        "type": "lateral",
        "title": "Rotacion de tecnica de movimiento lateral",
        "action": "Cambia la tecnica de movimiento lateral (SMB/psExec -> WinRM/WMI) y rota cuentas y credenciales usadas.",
        "trigger_techniques": ["T1021", "T1550", "T1570"],
        "trigger_rule_patterns": [r"lateral", r"remote service", r"psexec", r"winrm"],
        "parameters": {"lateral_channel": "winrm", "credential_rotation": True},
    },
    {
        "id": "SUG-0009",
        "type": "review",
        "title": "Revision de la cadena completa",
        "action": "Toda deteccion indica firma o comportamiento conocido: revisa la cadena completa y ajusta la evasion antes de la re-emulacion.",
        "trigger_techniques": [],
        "trigger_rule_patterns": [],
        "parameters": {},
    },
]

PROFILE_PARAM_KEYS: set[str] = {"jitter", "default_sleep", "encode_mode"}
CHANNEL_PARAM_KEYS: set[str] = {"channel"}


class DebriefSource:
    kind: str = "api"

    def fetch(self, session_id: str) -> tuple[dict, list[dict], list[dict]]:
        raise NotImplementedError


class ApiDebriefSource(DebriefSource):
    kind = "api"

    def __init__(self, client: MediatorClient) -> None:
        self._client = client

    def fetch(self, session_id: str) -> tuple[dict, list[dict], list[dict]]:
        return (
            self._client.get_session(session_id),
            self._client.alerts(session_id),
            self._client.results(session_id),
        )


class LocalDebriefSource(DebriefSource):
    kind = "local"

    def __init__(self, mediator) -> None:
        self._mediator = mediator

    def fetch(self, session_id: str) -> tuple[dict, list[dict], list[dict]]:
        session = self._mediator.state.get_session(session_id)
        if not session:
            raise KeyError(f"session {session_id} not found")
        alerts = [
            a.model_dump(mode="json") for a in self._mediator.state.get_alerts(session_id)
        ]
        results = [
            r.model_dump(mode="json") for r in self._mediator.state.get_results(session_id)
        ]
        return session.model_dump(mode="json"), alerts, results


def _dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _classify(alert: dict) -> str:
    for tid in alert.get("technique_ids") or []:
        step = STEP_BY_TECHNIQUE.get(tid)
        if step:
            return step
    text = " ".join(
        str(alert.get(k) or "")
        for k in ("rule_name", "title", "detail")
    ).lower()
    for step, patterns in STEP_KEYWORDS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return step
    return "otro"


class DebriefEngine:
    def __init__(self, sentryguard: SentryGuardIndex | None = None) -> None:
        self._sentryguard = sentryguard

    def analyze(
        self,
        session: dict,
        alerts: list[dict],
        results: list[dict],
        source: str = "api",
    ) -> dict:
        session_start = _dt(session.get("created_at")) or datetime.now(timezone.utc)
        results_by_id = {r.get("id"): r for r in results}
        entries: list[dict] = []
        for alert in alerts:
            ts = _dt(alert.get("event_time")) or _dt(alert.get("created_at"))
            seconds = max(0, int((ts - session_start).total_seconds())) if ts else 0
            step_id = _classify(alert)
            evidence = ""
            evidence_id = alert.get("evidence_result_id")
            if evidence_id and evidence_id in results_by_id:
                evidence = results_by_id[evidence_id].get("command") or ""
            entries.append(
                {
                    "alert_id": alert.get("id"),
                    "rule_id": alert.get("rule_id"),
                    "rule_name": alert.get("rule_name") or alert.get("title") or "?",
                    "title": alert.get("title") or "",
                    "detail": alert.get("detail") or "",
                    "severity": alert.get("severity") or "medium",
                    "status": alert.get("status") or "open",
                    "host": alert.get("host"),
                    "techniques": list(alert.get("technique_ids") or []),
                    "sentryguard_rules": (
                        self._sentryguard.rules_for(list(alert.get("technique_ids") or []))
                        if self._sentryguard
                        else []
                    ),
                    "step_id": step_id,
                    "seconds": seconds,
                    "event_time": ts.isoformat(timespec="seconds") if ts else None,
                    "evidence": evidence,
                    "occurrences": alert.get("occurrences") or 1,
                }
            )

        entries.sort(key=lambda e: (e["seconds"], e["event_time"] or ""))

        steps = []
        for step in KILL_CHAIN:
            assigned = [e for e in entries if e["step_id"] == step["id"]]
            first = assigned[0] if assigned else None
            techniques: list[str] = []
            for e in assigned:
                for t in e["techniques"]:
                    if t not in techniques:
                        techniques.append(t)
            sentryguard_rules: list[str] = []
            for e in assigned:
                for r in e["sentryguard_rules"]:
                    if r not in sentryguard_rules:
                        sentryguard_rules.append(r)
            steps.append(
                {
                    "step_id": step["id"],
                    "label": step["label"],
                    "detected": bool(assigned),
                    "alert_count": len(assigned),
                    "first_detection_seconds": first["seconds"] if first else None,
                    "first_rule_id": first["rule_id"] if first else None,
                    "first_rule_name": first["rule_name"] if first else None,
                    "techniques": techniques,
                    "sentryguard_rules": sentryguard_rules,
                    "events": assigned,
                }
            )

        detected_steps = [s for s in steps if s["detected"]]
        first_overall = detected_steps[0] if detected_steps else None

        transitions = []
        previous = None
        for s in detected_steps:
            if previous is not None:
                delta = max(
                    0,
                    (s["first_detection_seconds"] or 0)
                    - (previous["first_detection_seconds"] or 0),
                )
                transitions.append(
                    {
                        "from_step": previous["step_id"],
                        "from_label": previous["label"],
                        "to_step": s["step_id"],
                        "to_label": s["label"],
                        "delta_seconds": delta,
                    }
                )
            previous = s

        if first_overall:
            summary = (
                f"Te detectaron en el paso {first_overall['step_id']} "
                f"({first_overall['label']}), por el evento "
                f"«{first_overall['first_rule_name']}», a los "
                f"{first_overall['first_detection_seconds']} segundos."
            )
        else:
            summary = "Sin detecciones: la operacion no fue detectada por el equipo azul."

        return {
            "session_id": session.get("id"),
            "campaign_start": (
                session_start.isoformat(timespec="seconds") if session_start else None
            ),
            "source": source,
            "total_alerts": len(entries),
            "false_positives": sum(
                1 for e in entries if e["status"] == "false_positive"
            ),
            "conformed": sum(
                1 for e in entries if e["status"] == "confirmed"
            ),
            "detected_steps": len(detected_steps),
            "total_steps": len(KILL_CHAIN),
            "first_detection": (
                {
                    "step_id": first_overall["step_id"],
                    "label": first_overall["label"],
                    "rule_name": first_overall["first_rule_name"],
                    "rule_id": first_overall["first_rule_id"],
                    "seconds": first_overall["first_detection_seconds"],
                    "techniques": first_overall["techniques"],
                    "sentryguard_rules": first_overall["sentryguard_rules"],
                }
                if first_overall
                else None
            ),
            "summary": summary,
            "steps": steps,
            "transitions": transitions,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def suggestions(self, analysis: dict) -> list[dict]:
        alerts = [
            e
            for step in analysis["steps"]
            for e in step["events"]
        ]
        rule_names = [a["rule_name"] for a in alerts]
        techniques = set()
        for a in alerts:
            techniques.update(a["techniques"])
        triggered: list[dict] = []
        for suggestion in SUGGESTIONS:
            by_technique = [
                a["rule_name"]
                for a in alerts
                if any(t in suggestion["trigger_techniques"] for t in a["techniques"])
            ]
            by_rule = [
                name
                for name in rule_names
                if any(
                    re.search(pattern, name, re.IGNORECASE)
                    for pattern in suggestion["trigger_rule_patterns"]
                )
            ]
            matched = list(dict.fromkeys(by_technique + by_rule))
            if not matched:
                if suggestion["id"] != "SUG-0009" or not analysis["first_detection"]:
                    continue
                matched = [analysis["first_detection"]["rule_name"]]
            triggered.append(
                {
                    "suggestion": suggestion["id"],
                    "type": suggestion["type"],
                    "title": suggestion["title"],
                    "action": suggestion["action"],
                    "parameters": dict(suggestion.get("parameters") or {}),
                    "triggered_by": matched,
                    "triggered_techniques": sorted(
                        techniques & set(suggestion["trigger_techniques"])
                    ),
                }
            )
        return triggered

    def build_seed(self, analysis: dict, suggestions: list[dict]) -> dict:
        applied: list[str] = []
        profile = dict(PROFILE_BASE)
        for suggestion in suggestions:
            params = suggestion.get("parameters") or {}
            if suggestion.get("suggestion") == "SUG-0002":
                profile["channel"] = params.get("channel", "dns")
                applied.append("canal de comunicacion -> DNS")
            for key in PROFILE_PARAM_KEYS & params.keys():
                if profile.get(key) != params[key]:
                    applied.append(f"{key} {profile.get(key)} -> {params[key]}")
                    profile[key] = params[key]
            if suggestion.get("suggestion") == "SUG-0003":
                profile["process_name_pool"] = params.get("process_name_pool", [])
                applied.append("rotacion de nombre de proceso habilitada")
            for key in CHANNEL_PARAM_KEYS & params.keys():
                if suggestion.get("suggestion") != "SUG-0002" and profile.get(key) != params[key]:
                    applied.append(f"{key} -> {params[key]}")
                    profile[key] = params[key]

        focus_steps = [
            {"step_id": s["step_id"], "label": s["label"]}
            for s in analysis["steps"]
            if s["detected"]
        ]

        rules: list[dict] = []
        seen_rule_ids = set()
        for step in analysis["steps"]:
            for event in step["events"]:
                rule_id = event["rule_id"]
                if rule_id in seen_rule_ids:
                    continue
                seen_rule_ids.add(rule_id)
                rules.append(self._rule_for_alert(event))

        summary = analysis["summary"]
        return {
            "campaign": f"seed-{secrets.token_hex(3)}",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_session_id": analysis["session_id"],
            "summary": summary,
            "c2_dect": {
                "profile": profile,
                "profile_name": f"campaign-{secrets.token_hex(2)}",
                "notes": [
                    "perfil derivado del debrief de la campana fuente",
                    *[f"ajuste: {a}" for a in applied],
                ],
            },
            "cyberlens": {
                "objective": "re-emular la operacion evitando las detecciones del ejercicio fuente",
                "tags": ["debrief", "campaign-seed", analysis.get("session_id") or "source"],
                "focus_steps": focus_steps,
                "rules": rules,
                "notes": [
                    "registra estas reglas en la sesion blue de la proxima campana "
                    "para re-medir la deteccion desde el arranque",
                ],
            },
            "suggestions": suggestions,
        }

    def _rule_for_alert(self, event: dict) -> dict:
        rule_id = event["rule_id"] or ""
        for rule in DETECTION_RULES:
            if rule["id"] == rule_id:
                return {
                    key: value
                    for key, value in rule.items()
                    if key in ("id", "name", "description", "severity", "technique_ids", "data_sources", "patterns")
                }
        return {
            "id": rule_id or "custom",
            "name": event["rule_name"],
            "description": "regla replicada desde el debrief (patrones no disponibles)",
            "severity": event["severity"] or "medium",
            "technique_ids": event["techniques"],
            "data_sources": [],
            "patterns": {},
        }

    def report(self, analysis: dict, fmt: str = "markdown") -> str:
        sections = self._sections(analysis)
        if fmt == "html":
            return _render_html(sections)
        return _render_markdown(sections)

    def _sections(self, analysis: dict) -> list[dict]:
        steps = [s for s in analysis["steps"] if s["detected"]]
        rows = [
            {
                "Paso": s["step_id"],
                "Etapa": s["label"],
                "Detectado a los": f"{s['first_detection_seconds']}s",
                "Evento": s["first_rule_name"] or "-",
                "Tecnicas MITRE": ", ".join(s["techniques"]) or "-",
                "Alertas": s["alert_count"],
            }
            for s in analysis["steps"]
            if s["detected"]
        ]
        sections: list[dict] = [
            {
                "title": "Resumen",
                "lines": [
                    analysis["summary"],
                    f"Alertas: {analysis['total_alerts']} | Pasos del kill-chain con deteccion: "
                    f"{analysis['detected_steps']} de {analysis['total_steps']} | "
                    f"Falsos positivos: {analysis['false_positives']} | "
                    f"Confirmadas: {analysis['conformed']}",
                    f"Campana iniciada: {analysis.get('campaign_start') or '-'} | "
                    f"Generado: {analysis.get('generated_at') or '-'}",
                ],
            },
            {"title": "Pasos del kill-chain con deteccion", "rows": rows},
        ]
        for step in steps:
            lines = [
                f"Primera deteccion en este paso: {step['first_detection_seconds']}s "
                f"desde el inicio de la campana",
                f"Regla que disparo: {step['first_rule_id'] or '-'} - "
                f"{step['first_rule_name'] or '-'}",
            ]
            if step["sentryguard_rules"]:
                lines.append(
                    "Reglas SentryGuard involucradas: " + ", ".join(step["sentryguard_rules"])
                )
            event_rows = [
                {
                    "Alerta": e["alert_id"],
                    "Regla": e["rule_name"],
                    "Segundos": e["seconds"],
                    "Severidad": e["severity"],
                    "Tecnicas": ", ".join(e["techniques"]) or "-",
                    "Host": e["host"] or "-",
                    "Evidencia": e["evidence"][:120] or "-",
                }
                for e in step["events"]
            ]
            sections.append(
                {
                    "title": f"{step['step_id']} — {step['label']}",
                    "lines": lines,
                    "rows": event_rows,
                }
            )
        if analysis["transitions"]:
            sections.append(
                {
                    "title": "Velocidad de respuesta entre pasos",
                    "rows": [
                        {
                            "Transicion": f"{t['from_step']} -> {t['to_step']}",
                            "Etapas": f"{t['from_label']} -> {t['to_label']}",
                            "Delta (s)": t["delta_seconds"],
                        }
                        for t in analysis["transitions"]
                    ],
                }
            )
        return sections


def run_debrief(
    source: DebriefSource,
    session_id: str,
    engine: DebriefEngine | None = None,
) -> dict:
    session, alerts, results = source.fetch(session_id)
    if engine is None:
        engine = DebriefEngine()
    return engine.analyze(session, alerts, results, source=source.kind)


def _render_markdown(sections: list[dict]) -> str:
    out = ["# Debriefing de campana (kill-chain)", ""]
    for section in sections:
        out += ["", f"## {section['title']}"]
        for line in section.get("lines", []):
            out.append(f"- {line}")
        rows = section.get("rows") or []
        if rows:
            headers = list(rows[0].keys())
            out.append("| " + " | ".join(headers) + " |")
            out.append("|" + "|".join(["---"] * len(headers)) + "|")
            for row in rows:
                out.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
    return "\n".join(out) + "\n"


def _escape(text: str) -> str:
    return html_lib.escape(str(text), quote=True)


def _render_html(sections: list[dict]) -> str:
    parts = [
        "<!DOCTYPE html>",
        '<html><head><meta charset="utf-8"><title>Debriefing de campana</title>',
        "<style>",
        "body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:960px;color:#222}",
        "h1{border-bottom:3px solid #333;padding-bottom:.4rem}",
        "h2{margin-top:2rem;color:#0b5394}",
        "table{border-collapse:collapse;width:100%;font-size:.9rem}",
        "th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}",
        "th{background:#f0f0f0}",
        "code{background:#f6f6f6;padding:.1rem .3rem;border-radius:3px}",
        "</style></head><body>",
        "<h1>Debriefing de campana (kill-chain)</h1>",
    ]
    for section in sections:
        parts.append(f"<h2>{_escape(section['title'])}</h2>")
        for line in section.get("lines", []):
            parts.append(f"<p>{_escape(line)}</p>")
        rows = section.get("rows") or []
        if rows:
            headers = list(rows[0].keys())
            parts.append("<table><thead><tr>")
            parts.extend(f"<th>{_escape(h)}</th>" for h in headers)
            parts.append("</tr></thead><tbody>")
            for row in rows:
                parts.append("<tr>")
                parts.extend(
                    f"<td>{_escape(row.get(h, ''))}</td>" for h in headers
                )
                parts.append("</tr>")
            parts.append("</tbody></table>")
    parts.append("</body></html>")
    return "\n".join(parts)