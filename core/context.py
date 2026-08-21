from __future__ import annotations

from core.state import MediatorState
from models.graph import KnowledgeState
from models.session import Phase
from models.team import Team
from models.tool_result import ToolResult


class ContextBuilder:
    def __init__(self, max_results_in_context: int = 15) -> None:
        self._max_results = max_results_in_context

    def build_system_prompt(self, state: MediatorState, session_id: str) -> str:
        session = state.get_session(session_id)
        if not session:
            raise KeyError(f"session {session_id} not found")
        if session.team == Team.BLUE:
            return self._build_blue_prompt(state, session)
        if session.team == Team.PURPLE:
            return self._build_purple_prompt(state, session)
        return self._build_red_prompt(state, session)

    def _session_lines(self, session, target) -> list[str]:
        lines = [
            f"AGENTE: {session.agent}",
            f"FASE: {session.phase.value}",
            f"OBJETIVO: {session.objective or 'no definido'}",
            f"POSICION: {session.current_position or 'no definida'}",
            f"TARGET: {target.summary()}",
        ]
        if session.known:
            lines.append(f"SABIDO: {'; '.join(session.known)}")
        if session.unknown:
            lines.append(f"DESCONOCIDO: {'; '.join(session.unknown)}")
        if session.next_areas:
            lines.append(f"PROXIMAS AREAS: {'; '.join(session.next_areas)}")
        if session.notes:
            lines.append(f"NOTAS: {'; '.join(session.notes)}")
        return lines

    def _build_red_prompt(self, state: MediatorState, session) -> str:
        target = state.get_target(session.target_id)
        if not target:
            raise KeyError(f"target {session.target_id} not found")
        lines = [
            "Eres un agente de operaciones ofensivas autorizadas (red team).",
            "Solo puedes actuar sobre los targets registrados en la sesion.",
            "NO inventes hechos: toda afirmacion debe basarse en evidencia "
            "(resultado de herramienta) o registrarse como hipotesis "
            "(unverified, confidence < 0.6).",
            "Responde en espanol salvo que se indique lo contrario.",
            "",
        ]
        lines.extend(self._session_lines(session, target))
        lines.append(f"ATAQUE: {session.attack_stage.value}")
        return "\n".join(lines)

    def _build_blue_prompt(self, state: MediatorState, session) -> str:
        target = state.get_target(session.target_id)
        if not target:
            raise KeyError(f"target {session.target_id} not found")
        lines = [
            "Eres un agente defensivo (blue team / SOC).",
            "Trabajas con telemetria INGERIDA: logs, alertas e IOCs. NO ejecutas "
            "comandos en el host; las acciones de respuesta se documentan como "
            "recomendaciones.",
            "NO inventes hechos: cada alerta debe referenciar su evidencia "
            "(result_id) o registrarse como hipotesis.",
            "Responde en espanol salvo que se indique lo contrario.",
            "",
        ]
        lines.extend(self._session_lines(session, target))
        return "\n".join(lines)

    def _build_purple_prompt(self, state: MediatorState, session) -> str:
        target = state.get_target(session.target_id)
        if not target:
            raise KeyError(f"target {session.target_id} not found")
        red = ", ".join(session.purple_links.get("red", [])) or "ninguna"
        blue = ", ".join(session.purple_links.get("blue", [])) or "ninguna"
        lines = [
            "Eres un coordinador purple team: orquestas sesiones red (emulacion) "
            "y blue (deteccion) contra el mismo target.",
            "Tu objetivo es medir y cerrar gaps de cobertura ATT&CK: toda tecnica "
            "probada por red debe tener regla de deteccion en blue.",
            "NO inventes hechos: usa findings (red), alertas y reglas (blue).",
            "Responde en espanol salvo que se indique lo contrario.",
            "",
            f"SESIONES RED ENLAZADAS: {red}",
            f"SESIONES BLUE ENLAZADAS: {blue}",
        ]
        lines.extend(self._session_lines(session, target))
        return "\n".join(lines)

    def build_context(self, state: MediatorState, session_id: str) -> str:
        session = state.get_session(session_id)
        if not session:
            raise KeyError(f"session {session_id} not found")
        if session.team == Team.BLUE:
            return self._build_blue_context(state, session_id)
        if session.team == Team.PURPLE:
            return self._build_purple_context(state, session)
        return self._build_red_context(state, session_id)

    def _shared_blocks(self, state: MediatorState, session_id: str) -> list[str]:
        session = state.get_session(session_id)
        nodes = state.graph.nodes(session_id)
        investigations = state.get_investigations(session_id)
        results = state.get_results(session_id)
        blocks: list[str] = []
        if session and session.summaries:
            blocks.append("## CONTEXTO COMPRIMIDO\n" + "\n".join(f"- {s}" for s in session.summaries))
        if nodes:
            parts = []
            for state_name in (KnowledgeState.KNOWN, KnowledgeState.INFERRED, KnowledgeState.UNVERIFIED):
                selected = [n for n in nodes if n.state == state_name]
                if selected:
                    parts.append(
                        f"--- {state_name.value} ---\n"
                        + "\n".join(n.to_context_line() for n in selected)
                    )
            blocks.append("## CONOCIMIENTO (grafo)\n" + "\n\n".join(parts))
        if investigations:
            blocks.append(
                "## MEMORIA DE INVESTIGACION\n"
                + "\n".join(i.to_context_line() for i in investigations)
            )
        if results:
            blocks.append(
                "## RESULTADOS RECIENTES\n"
                + "\n\n".join(r.to_context_block() for r in results[-self._max_results:])
            )
        return blocks

    def _build_red_context(self, state: MediatorState, session_id: str) -> str:
        blocks = self._shared_blocks(state, session_id)
        findings = state.get_findings(session_id)
        if findings:
            blocks.insert(
                len([b for b in blocks if b.startswith("## ")]),
                "## HIPOTESIS\n" + "\n\n".join(f.to_context_block() for f in findings),
            )
        return "\n\n".join(blocks) if blocks else "Sin contexto aun."

    def _build_blue_context(self, state: MediatorState, session_id: str) -> str:
        session = state.get_session(session_id)
        alerts = state.get_alerts(session_id)
        incidents = state.get_incidents(session_id)
        iocs = state.get_iocs(session_id)
        rules = state.get_rules(session_id)
        blocks: list[str] = []
        if session and session.summaries:
            blocks.append("## CONTEXTO COMPRIMIDO\n" + "\n".join(f"- {s}" for s in session.summaries))
        if alerts:
            blocks.append("## ALERTAS\n" + "\n\n".join(a.to_context_block() for a in alerts[-25:]))
        if incidents:
            blocks.append("## INCIDENTES\n" + "\n\n".join(i.to_context_block() for i in incidents))
        if iocs:
            blocks.append("## IOCS\n" + "\n".join(i.to_context_line() for i in iocs))
        if rules:
            blocks.append("## REGLAS DE DETECCION\n" + "\n".join(r.to_context_line() for r in rules))
        blocks.extend(self._shared_blocks(state, session_id))
        return "\n\n".join(blocks) if blocks else "Sin contexto aun."

    def _build_purple_context(self, state: MediatorState, session) -> str:
        blocks: list[str] = []
        if session.summaries:
            blocks.append("## CONTEXTO COMPRIMIDO\n" + "\n".join(f"- {s}" for s in session.summaries))
        for role in ("red", "blue"):
            linked = []
            for sid in session.purple_links.get(role, []):
                linked_session = state.get_session(sid)
                if not linked_session:
                    continue
                heading = f"## SESION {role.upper()} {sid} ({linked_session.phase.value})"
                parts = [heading]
                if role == "red":
                    findings = state.get_findings(sid)
                    if findings:
                        parts.append("HIPOTESIS:")
                        parts.extend(f.to_context_block() for f in findings[:10])
                else:
                    alerts = state.get_alerts(sid)
                    if alerts:
                        parts.append("ALERTAS:")
                        parts.extend(a.to_context_block() for a in alerts[-10:])
                linked.append("\n".join(parts))
            blocks.extend(linked)
        blocks.extend(self._shared_blocks(state, session.id))
        return "\n\n".join(blocks) if blocks else "Sin contexto aun."

    def compact(self, results: list[ToolResult]) -> str:
        if not results:
            return "sin actividad previa"
        groups: dict[str, list[ToolResult]] = {}
        for r in results:
            phase = r.parsed.get("phase", Phase.RECON.value)
            groups.setdefault(phase, []).append(r)
        summary = []
        for phase_name, phase_results in groups.items():
            tools = {}
            for r in phase_results:
                tools[r.tool] = tools.get(r.tool, 0) + 1
            summary.append(
                f"{phase_name}: {len(phase_results)} ejecuciones "
                f"({', '.join(f'{t}x{c}' for t, c in tools.items())})"
            )
        return " | ".join(summary) if summary else "sin actividad previa"

    def compress_context(self, state: MediatorState, session_id: str, keep_last: int = 8) -> str:
        session = state.get_session(session_id)
        results = state.get_results(session_id)
        nodes = state.graph.nodes(session_id)
        hypotheses = state.get_findings(session_id)
        counts: dict[str, int] = {}
        for r in results:
            counts[r.command] = counts.get(r.command, 0) + 1
        recent = results[-keep_last:]
        active = [h for h in hypotheses if h.status.value in {"unverified", "inconclusive"}]
        validated = [h for h in hypotheses if h.status.value == "validated"]
        unresolved = [h for h in hypotheses if h.status.value not in {"validated", "rejected"}]
        lines = [
            "CONTEXTO OFENSIVO ACTUAL",
            f"Target: {session.target_id} | Fase: {session.phase.value}",
            f"Superficie relevante: {len(nodes)} activos",
            f"Sabido: {sum(1 for n in nodes if n.state == KnowledgeState.KNOWN)} observaciones confirmadas",
            f"Hipotesis activas: {len(active)}",
            f"Validadas: {len(validated)}",
            f"Sin resolver: {len(unresolved)}",
        ]
        if session.next_areas:
            lines.append(f"Investigacion de mayor valor: {session.next_areas[0]}")
        lines.append("Evidencia reciente:")
        for r in recent:
            suffix = f" x{counts[r.command]}" if counts[r.command] > 1 else ""
            lines.append(f"  [{r.tool}] {r.command} exit={r.exit_code}{suffix}")
        return "\n".join(lines)
