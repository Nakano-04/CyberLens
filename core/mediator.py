from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone

from core.audit import AuditLog
from core.compactor import Compactor
from core.context import ContextBuilder
from core.coverage import compute_coverage
from core.detection import DetectionEngine
from core.evidence import adjust_confidence, evaluate
from core.events import EventBus
from core.machines import initial_phase
from core.metrics import compute_metrics
from core.planner import build_plan
from core.scope import ScopeGuard
from core.statemachine import (
    allowed_transitions,
    blockers,
    can_skip,
    critical_evidence_exists,
)
from core.state import MediatorState
from core.storage import Storage
from knowledge.detection import RULES as DEFAULT_DETECTION_RULES
from models.alert import Alert, AlertCreate, AlertStatus, Severity
from models.audit import Verdict
from models.finding import Finding, FindingCreate, FindingStatus
from models.graph import KnowledgeState, LinkCreate, Node, NodeUpsert
from models.incident import Incident, IncidentCreate, IncidentStage
from models.investigation import Investigation, InvestigationCreate
from models.ioc import IOC, IOCCreate
from models.rule import DetectionRule, RuleCreate
from models.session import Phase, Session, SessionCreate
from models.target import Target, TargetCreate
from models.team import Team
from models.tool_result import ToolResult
from providers.scanner import ScannerProvider, YaraScannerProvider
from providers.technique import BuiltinTechniqueProvider, TechniqueProvider
from tools.executor import ExecResult, Executor, SandboxUnavailable
from tools.parsers import (
    parse_burp_log,
    parse_http_requests,
    parse_msf_output,
    parse_nmap_services,
    parse_observations,
)


class Mediator:
    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        denied_prefixes: list[str] | None = None,
        command_timeout: int = 60,
        max_results_in_context: int = 15,
        compactor: Compactor | None = None,
        priorities: list[str] | None = None,
        techniques: TechniqueProvider | None = None,
        scanner: ScannerProvider | None = None,
        storage: Storage | None = None,
        deny_evasions: bool = True,
        require_approval_patterns: list[str] | None = None,
        sandbox: str | None = None,
        sandbox_image: str = "alpine",
        node_ttl_seconds: int | None = None,
        max_nodes_per_kind: int | None = None,
        prune_min_confidence: float = 0.5,
        session_budget_steps: int | None = None,
        dedup_window_seconds: int = 300,
        max_alerts: int | None = None,
        auto_register_nodes: bool = True,
    ) -> None:
        self.state = MediatorState(
            node_ttl_seconds=node_ttl_seconds,
            max_nodes_per_kind=max_nodes_per_kind,
        )
        self.audit = AuditLog()
        self.events = EventBus()
        self.scope = ScopeGuard(
            allowed_hosts,
            denied_prefixes,
            deny_evasions=deny_evasions,
            require_approval_patterns=require_approval_patterns,
        )
        self.executor = Executor(command_timeout, sandbox=sandbox, sandbox_image=sandbox_image)
        self.context_builder = ContextBuilder(max_results_in_context)
        self.compactor = compactor or Compactor()
        self.priorities = priorities or []
        self._techniques = techniques or BuiltinTechniqueProvider()
        self._scanner = scanner or YaraScannerProvider()
        self._storage = storage
        self._prune_min_confidence = prune_min_confidence
        self._session_budget_steps = session_budget_steps
        self._detection = DetectionEngine(dedup_window_seconds=dedup_window_seconds)
        self._max_alerts = max_alerts
        self._auto_register_nodes = auto_register_nodes
        self._default_rules = [
            DetectionRule(id=r["id"], session_id="", **{k: v for k, v in r.items() if k != "id"})
            for r in DEFAULT_DETECTION_RULES
        ]
        if storage:
            storage.migrate_legacy()
            self.state.load_snapshot(
                {
                    "targets": storage.load_all("targets"),
                    "sessions": storage.load_all("sessions"),
                    "results": storage.load_all("results"),
                    "findings": storage.load_all("findings"),
                    "investigations": storage.load_all("investigations"),
                    "alerts": storage.load_all("alerts"),
                    "incidents": storage.load_all("incidents"),
                    "rules": storage.load_all("rules"),
                    "iocs": storage.load_all("iocs"),
                    "nodes": storage.load_all("nodes"),
                    "links": storage.load_all("links"),
                }
            )
            self.audit.restore(storage.load_all("audit"))

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _require_session(self, session_id: str) -> Session:
        session = self.state.get_session(session_id)
        if not session:
            raise KeyError(f"session {session_id} not found")
        return session

    def _persist(self, kind: str, record: dict) -> None:
        if self._storage:
            self._storage.upsert(kind, record)

    def _publish_risk(self, session_id: str) -> None:
        """Alerta WebSocket cuando la higiene de evidencia de la sesion
        cruza a medio/alto (evento metrics.risk). Silencioso si baja.
        No es un medidor de verdad: solo agrega senales operativas."""
        try:
            risk = self.get_metrics(session_id).get("evidence_hygiene") or self.get_metrics(
                session_id
            ).get("hallucination_risk", {})
        except KeyError:
            return
        level = risk.get("level", "low")
        if level != "low":
            self.events.publish(
                session_id,
                {"type": "metrics.risk", "data": {"score": risk.get("score", 0), "level": level}},
            )

    def _audit(self, actor: str, action: str, detail: str, session_id: str | None = None, verdict: Verdict = Verdict.ALLOWED) -> None:
        entry = self.audit.record(actor, action, detail=detail, session_id=session_id, verdict=verdict)
        if self._storage:
            self._storage.upsert("audit", entry.model_dump(mode="json"))

    def _require_team(self, session: Session, *teams: Team) -> None:
        if session.team not in teams:
            raise PermissionError(
                f"sesion {session.team.value} no permite esta operacion (requiere: "
                + "/".join(t.value for t in teams)
                + ")"
            )

    def effective_rules(self, session_id: str) -> list[DetectionRule]:
        """Catalogo curado + reglas propias de la sesion (las propias ganan por id)."""
        merged = {r.id: r for r in self._default_rules}
        for rule in self.state.get_rules(session_id):
            merged[rule.id] = rule
        return list(merged.values())

    # ------------------------------------------------------------------
    # targets / sesiones
    # ------------------------------------------------------------------
    def create_target(self, data: TargetCreate) -> Target:
        target = Target(id=uuid.uuid4().hex[:8], **data.model_dump())
        self.state.add_target(target)
        self._audit("system", "target.create", detail=target.host)
        self._persist("target", target.model_dump(mode="json"))
        return target

    def create_session(self, data: SessionCreate) -> Session:
        target = self.state.get_target(data.target_id)
        if not target:
            raise KeyError(f"target {data.target_id} not found")
        if not self.scope.validate_target(target):
            self._audit(
                "system",
                "session.create",
                detail=f"target {target.host} fuera de scope",
                verdict=Verdict.BLOCKED,
            )
            raise PermissionError(f"target {target.host} fuera de scope autorizado")
        payload = data.model_dump()
        if payload.get("max_steps") is None and self._session_budget_steps:
            payload["max_steps"] = self._session_budget_steps
        payload["phase"] = initial_phase(data.team)
        session = Session(id=uuid.uuid4().hex[:8], **payload)
        self.state.add_session(session)
        self._audit(
            "system",
            "session.create",
            detail=(
                f"session={session.id} target={target.host} "
                f"agent={session.agent} team={session.team.value}"
                + (f" budget={session.max_steps}" if session.max_steps else "")
            ),
            session_id=session.id,
        )
        self._persist("session", session.model_dump(mode="json"))
        return session

    def update_objective(
        self,
        session_id: str,
        objective: str | None = None,
        current_position: str | None = None,
        attack_stage: str | None = None,
        known: list[str] | None = None,
        unknown: list[str] | None = None,
        next_areas: list[str] | None = None,
    ) -> Session:
        session = self._require_session(session_id)
        if objective is not None:
            session.objective = objective
        if current_position is not None:
            session.current_position = current_position
        if attack_stage is not None:
            session.attack_stage = attack_stage
        if known is not None:
            session.known = known
        if unknown is not None:
            session.unknown = unknown
        if next_areas is not None:
            session.next_areas = next_areas
        session.touch()
        self._audit(
            "agent", "session.objective", detail=f"objetivo='{session.objective}'", session_id=session_id
        )
        self._persist("session", session.model_dump(mode="json"))
        return session

    def set_phase(
        self,
        session_id: str,
        phase: Phase,
        override: bool = False,
        reason: str = "",
    ) -> Session:
        session = self._require_session(session_id)
        if phase == session.phase:
            return session

        if override:
            if not reason.strip():
                raise ValueError("override exige una razon (--reason)")
            self._apply_phase(session_id, phase, detail=f"OVERRIDE ({reason})")
            return session

        # Salto de fases solo si hay evidencia critica (break-glass justificado)
        if can_skip(session.phase, phase):
            critical = critical_evidence_exists(self.state, session_id)
            if critical:
                self._apply_phase(
                    session_id,
                    phase,
                    detail=f"SALTO-CRITICO: {'; '.join(critical)}",
                )
                return session

        missing = blockers(self.state, session, phase)
        if missing:
            self._audit(
                "system",
                "session.phase",
                detail=f"BLOQUEADO -> {phase.value}: {'; '.join(missing)}",
                session_id=session_id,
                verdict=Verdict.BLOCKED,
            )
            self.events.publish(
                session_id, {"type": "session.phase", "data": {"blocked": True, "phase": phase.value}}
            )
            raise ValueError("; ".join(missing))
        self._apply_phase(session_id, phase, detail=f"-> {phase.value}")
        return session

    def _apply_phase(self, session_id: str, phase: Phase, detail: str) -> None:
        self.state.set_phase(session_id, phase)
        self._audit("system", "session.phase", detail=detail, session_id=session_id)
        self.events.publish(session_id, {"type": "session.phase", "data": {"blocked": False, "phase": phase.value}})
        session = self._require_session(session_id)
        self._persist("session", session.model_dump(mode="json"))

    def phase_transitions(self, session_id: str) -> dict:
        session = self._require_session(session_id)
        critical = critical_evidence_exists(self.state, session_id)
        return {
            "team": session.team.value,
            "current": session.phase.value,
            "allowed": [p.value for p in allowed_transitions(session.phase, session.team)],
            "critical_evidence": critical,
        }

    def add_note(self, session_id: str, note: str) -> Session:
        session = self._require_session(session_id)
        self.state.add_note(session_id, note)
        self._audit("system", "session.note", detail=note[:200], session_id=session_id)
        self._persist("session", session.model_dump(mode="json"))
        return session

    # ------------------------------------------------------------------
    # ejecucion con scope endurecido
    # ------------------------------------------------------------------
    def execute(
        self,
        session_id: str,
        tool: str,
        command: str,
        timeout: int | None = None,
        parser: str | None = None,
        human_approved: bool = False,
    ) -> ToolResult:
        session = self._require_session(session_id)
        target = self.state.get_target(session.target_id)
        if not target:
            raise KeyError(f"target {session.target_id} not found")

        # equipos blue/purple: solo deteccion/triage/orquestacion, nunca ejecutan
        if session.team in (Team.BLUE, Team.PURPLE):
            approved = False
            block_detail = (
                "equipo blue no ejecuta comandos: solo deteccion y triage"
                if session.team == Team.BLUE
                else "equipo purple no ejecuta comandos: orquesta red y blue"
            )
            self._audit(
                "agent",
                "tool.execute",
                detail=f"BLOQUEADO [{session.team.value}] {command[:200]} | motivo: {block_detail}",
                session_id=session_id,
                verdict=Verdict.BLOCKED,
            )
            tool_result = ToolResult(
                id=uuid.uuid4().hex[:8],
                session_id=session_id,
                tool=tool,
                command=command,
                stdout="",
                stderr=block_detail,
                exit_code=1,
                timed_out=False,
                duration_ms=0,
                parsed={},
                approved=False,
                team=session.team.value,
            )
            self.state.add_result(tool_result)
            self.events.publish(
                session_id,
                {"type": "tool.execute", "data": {"id": tool_result.id, "approved": False, "tool": tool, "reason": block_detail}},
            )
            self._persist("result", tool_result.model_dump(mode="json"))
            return tool_result

        verdict = self.scope.validate_command(command, target)
        approved = verdict.approved
        block_detail = "; ".join(verdict.reasons) if verdict.reasons else ""

        # presupuesto de pasos por sesion
        if session.max_steps and session.steps_used >= session.max_steps:
            approved = False
            block_detail = f"presupuesto de pasos agotado ({session.max_steps})"

        # approval gate humano (ToolAuthZ require_human)
        if approved and verdict.requires_approval and not human_approved:
            approved = False
            block_detail = f"requiere aprobacion humana: {verdict.reasons[0]}"

        # sandbox fail-closed
        if approved and self.executor.sandbox:
            ok, err = self.executor.check_sandbox()
            if not ok:
                approved = False
                block_detail = f"sandbox no disponible (fail-closed): {err}"

        result = ExecResult("", "", 0, False, 0)
        parsed: dict = {}
        if approved:
            try:
                result = self.executor.run(command, timeout)
            except SandboxUnavailable as exc:
                approved = False
                block_detail = f"sandbox no disponible (fail-closed): {exc}"
                result = ExecResult("", block_detail, 1, False, 0)
            else:
                self._parse_and_observe(session, target, result, parser, parsed)
        tool_result = ToolResult(
            id=uuid.uuid4().hex[:8],
            session_id=session_id,
            tool=tool,
            command=command,
            stdout=result.stdout,
            stderr=(block_detail or result.stderr) if not approved else result.stderr,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            duration_ms=result.duration_ms,
            parsed=parsed,
            approved=approved,
        )
        self.state.add_result(tool_result)
        session.steps_used += 1
        session.touch()
        self._audit(
            "agent",
            "tool.execute",
            detail=f"{'OK' if approved else 'BLOQUEADO'} [{tool}] {command[:200]}"
            + (f" | motivo: {block_detail}" if block_detail else ""),
            session_id=session_id,
            verdict=Verdict.ALLOWED if approved else Verdict.BLOCKED,
        )
        self.events.publish(
            session_id,
            {
                "type": "tool.execute",
                "data": {
                    "id": tool_result.id,
                    "approved": approved,
                    "tool": tool,
                    "reason": block_detail or None,
                },
            },
        )
        self._persist("result", tool_result.model_dump(mode="json"))
        self._persist("session", session.model_dump(mode="json"))
        self._publish_risk(session_id)
        return tool_result

    def _parse_and_observe(
        self, session: Session, target: Target, result: ExecResult, parser: str | None, parsed: dict
    ) -> None:
        """Parseo explicito + modo observador: si el parser no extrae nada o no
        hay parser, el observador difuso registra nodos INFERRED (nunca KNOWN),
        de modo que el grafo nunca queda ciego."""
        session_id = session.id
        stdout = result.stdout or ""
        extracted = 0
        if parser == "nmap" and stdout:
            services = parse_nmap_services(stdout)
            for service in services:
                target.add_service(service)
            parsed["services"] = [s.model_dump() for s in services]
            extracted += len(services)
        if parser == "yara" and stdout:
            matches = [line.split(" ", 1)[0] for line in stdout.splitlines() if line.strip()]
            for match in matches:
                self.upsert_node(
                    session_id,
                    NodeUpsert(
                        kind="yara_rule",
                        name=match,
                        state=KnowledgeState.KNOWN,
                        confidence=0.9,
                        source="yara",
                    ),
                )
            parsed["yara_matches"] = matches
            extracted += len(matches)
        if parser == "http" and stdout:
            parsed["http_responses"] = parse_http_requests(stdout)
            extracted += len(parsed["http_responses"])
        if parser == "burp" and stdout:
            requests = parse_burp_log(stdout)
            parsed["requests"] = requests
            extracted += len(requests)
            for req in requests[:20]:
                self.upsert_node(
                    session_id,
                    NodeUpsert(
                        kind="endpoint",
                        name=req["path"],
                        state=KnowledgeState.KNOWN if req["status"] < 400 else KnowledgeState.INFERRED,
                        confidence=0.7,
                        source="burp",
                    ),
                )
        if parser == "msf" and stdout:
            events = parse_msf_output(stdout)
            parsed["msf_events"] = events
            extracted += len(events)
            for ev in events:
                if ev["event"] == "session_opened":
                    self.upsert_node(
                        session_id,
                        NodeUpsert(
                            kind="session",
                            name=ev["detail"],
                            state=KnowledgeState.KNOWN,
                            confidence=0.95,
                            source="msf",
                        ),
                    )
                    self.upsert_node(
                        session_id,
                        NodeUpsert(
                            kind="beacon",
                            name=f"msf-{ev['detail'][:60]}",
                            state=KnowledgeState.KNOWN,
                            confidence=0.9,
                            source="msf",
                            properties={"c2": "meterpreter"},
                        ),
                    )

        # Modo observador: SIEMPRE corre (los datos van a parsed["observations"]),
        # pero solo registra nodos cuando el parseo explicito no extrajo nada.
        explicit_ok = extracted > 0
        observations = parse_observations(stdout, "")
        parsed.setdefault("observations", observations)

        if not explicit_ok and observations:
            for host in observations.get("hosts", []):
                self.upsert_node(
                    session_id,
                    NodeUpsert(
                        kind="host", name=host, state=KnowledgeState.INFERRED,
                        confidence=0.6, source="observer",
                    ),
                )
            for ip in observations.get("ips", []):
                self.upsert_node(
                    session_id,
                    NodeUpsert(
                        kind="host", name=ip, state=KnowledgeState.INFERRED,
                        confidence=0.6, source="observer",
                    ),
                )
            for endpoint in observations.get("endpoints", [])[:25]:
                self.upsert_node(
                    session_id,
                    NodeUpsert(
                        kind="endpoint", name=endpoint, state=KnowledgeState.INFERRED,
                        confidence=0.6, source="observer",
                    ),
                )
            for port in observations.get("ports", []):
                self.upsert_node(
                    session_id,
                    NodeUpsert(
                        kind="service", name=port, state=KnowledgeState.INFERRED,
                        confidence=0.6, source="observer",
                    ),
                )
            for listener in observations.get("listeners", [])[:10]:
                self.upsert_node(
                    session_id,
                    NodeUpsert(
                        kind="listener", name=listener, state=KnowledgeState.INFERRED,
                        confidence=0.7, source="observer",
                    ),
                )
            for pivot in observations.get("pivots", [])[:5]:
                self.upsert_node(
                    session_id,
                    NodeUpsert(
                        kind="pivot", name=pivot[:120], state=KnowledgeState.KNOWN,
                        confidence=0.85, source="observer",
                    ),
                )
            for session_hit in observations.get("sessions", [])[:5]:
                self.upsert_node(
                    session_id,
                    NodeUpsert(
                        kind="beacon", name=f"session-{session_hit[:80]}",
                        state=KnowledgeState.KNOWN, confidence=0.9, source="observer",
                    ),
                )
        parsed.setdefault("phase", session.phase.value)

    def yara_scan(self, session_id: str, rules: str, target_path: str) -> ToolResult:
        session = self._require_session(session_id)
        target = self.state.get_target(session.target_id)
        if not target:
            raise KeyError(f"target {session.target_id} not found")
        command = f"yara {rules} {target_path}"
        verdict = self.scope.validate_command(command, target)
        approved = verdict.approved
        parsed: dict = {}
        if approved:
            scan = self._scanner.scan(rules, target_path)
            result = ExecResult(scan.stdout, scan.stderr, scan.exit_code, False, 0)
            for match in scan.matches:
                self.upsert_node(
                    session_id,
                    NodeUpsert(
                        kind="yara_rule",
                        name=match,
                        state=KnowledgeState.KNOWN,
                        confidence=0.9,
                        source="yara",
                    ),
                )
            parsed["yara_matches"] = scan.matches
            parsed.setdefault("phase", session.phase.value)
        else:
            result = ExecResult("", "bloqueado por scope", 1, False, 0)
        tool_result = ToolResult(
            id=uuid.uuid4().hex[:8],
            session_id=session_id,
            tool="yara",
            command=command,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            duration_ms=result.duration_ms,
            parsed=parsed,
            approved=approved,
        )
        self.state.add_result(tool_result)
        self._audit(
            "agent",
            "yara.scan",
            detail=f"{'OK' if approved else 'BLOQUEADO'} {command[:200]}"
            + (f" | motivo: {'; '.join(verdict.reasons)}" if not approved and verdict.reasons else ""),
            session_id=session_id,
            verdict=Verdict.ALLOWED if approved else Verdict.BLOCKED,
        )
        self.events.publish(
            session_id,
            {"type": "yara.scan", "data": {"id": tool_result.id, "approved": approved, "matches": len(parsed.get("yara_matches", []))}},
        )
        self._persist("result", tool_result.model_dump(mode="json"))
        self._publish_risk(session_id)
        return tool_result

    # ------------------------------------------------------------------
    # blue team: ingesta de telemetria y deteccion
    # ------------------------------------------------------------------
    def ingest_event(
        self,
        session_id: str,
        source: str,
        raw: str,
        parsed: dict | None = None,
        event_time=None,
    ) -> ToolResult:
        """Ingesta de un evento de telemetria (log, EDR, syslog...). NO ejecuta
        nada: parsea, registra nodos y evalua las reglas de deteccion."""
        session = self._require_session(session_id)
        self._require_team(session, Team.BLUE, Team.PURPLE)

        result = ToolResult(
            id=uuid.uuid4().hex[:8],
            session_id=session_id,
            tool=f"telemetry:{source}",
            command=source,
            stdout=raw,
            stderr="",
            exit_code=0,
            timed_out=False,
            duration_ms=0,
            parsed={},
            approved=True,
            team=session.team.value,
            event_time=event_time,
        )
        parsed_input = parse_observations(raw, source)
        if parsed:
            parsed_input.update(parsed)
        parsed_input.setdefault("phase", session.phase.value)
        result.parsed = parsed_input
        self.state.add_result(result)
        self._audit(
            "agent",
            "telemetry.ingest",
            detail=f"[{source}] {len(raw)} chars, fase={session.phase.value}",
            session_id=session_id,
        )
        self.events.publish(
            session_id,
            {"type": "telemetry.ingest", "data": {"id": result.id, "source": source, "tool": result.tool}},
        )
        self._persist("result", result.model_dump(mode="json"))

        if self._auto_register_nodes:
            self._register_telemetry_nodes(session, result)

        self._run_detection(session, result, raw)
        return result

    def _register_telemetry_nodes(self, session: Session, result: ToolResult) -> None:
        obs = result.parsed or {}
        for host in obs.get("hosts", [])[:25]:
            self.upsert_node(
                session.id,
                NodeUpsert(
                    kind="host", name=host, state=KnowledgeState.INFERRED,
                    confidence=0.6, source="telemetry",
                ),
            )
        for ip in obs.get("ips", [])[:25]:
            self.upsert_node(
                session.id,
                NodeUpsert(
                    kind="host", name=ip, state=KnowledgeState.INFERRED,
                    confidence=0.6, source="telemetry",
                ),
            )
        for endpoint in obs.get("endpoints", [])[:25]:
            self.upsert_node(
                session.id,
                NodeUpsert(
                    kind="endpoint", name=endpoint, state=KnowledgeState.INFERRED,
                    confidence=0.6, source="telemetry",
                ),
            )

    def _run_detection(self, session: Session, result: ToolResult, raw: str) -> list[Alert]:
        rules = self.effective_rules(session.id)
        matches = self._detection.evaluate(result, rules)
        created: list[Alert] = []
        obs = result.parsed or {}
        hosts = obs.get("hosts", []) or obs.get("ips", [])
        host = hosts[0] if hosts else None
        now = result.event_time

        for match in matches:
            rule = match["rule"]
            data = AlertCreate(
                rule_id=rule.id,
                rule_name=rule.name,
                title=rule.name,
                detail=f"{match['reason']} | {raw[:400]}",
                severity=rule.severity,
                technique_ids=rule.technique_ids,
                data_sources=rule.data_sources,
                source=result.tool,
                host=host,
                evidence_result_id=result.id,
                event_time=now,
            )
            existing = self._detection.dedupe(
                self.state.get_alerts(session.id), rule.id, host, now
            )
            if existing:
                existing.occurrences += 1
                self._audit(
                    "system",
                    "alert.repeat",
                    detail=f"{rule.id} x{existing.occurrences} host={host or '-'}",
                    session_id=session.id,
                )
                self._persist("alert", existing.model_dump(mode="json"))
                continue
            if self._max_alerts and len(self.state.get_alerts(session.id)) >= self._max_alerts:
                self._audit(
                    "system",
                    "alert.drop",
                    detail=f"tope de alertas alcanzado ({self._max_alerts}): {rule.id}",
                    session_id=session.id,
                    verdict=Verdict.BLOCKED,
                )
                continue
            alert = self._detection.create_alert(session.id, data, uuid.uuid4().hex[:8])
            self.state.add_alert(alert)
            self._audit(
                "agent",
                "alert.new",
                detail=f"{rule.id} {rule.name} [{rule.severity.value}] host={host or '-'}",
                session_id=session.id,
            )
            self.events.publish(
                session.id,
                {
                    "type": "alert.new",
                    "data": {"id": alert.id, "rule_id": rule.id, "severity": rule.severity.value, "host": host},
                },
            )
            self._persist("alert", alert.model_dump(mode="json"))
            created.append(alert)

        # anomalia por volumen: rafaga del mismo host/fuente (beaconing/escaneo)
        if self._detection.detect_burst(
            self.state.get_results(session.id), result.command, host, now
        ):
            burst = next(
                (
                    a
                    for a in self.state.get_alerts(session.id)
                    if a.rule_id == "SIGMA-BURST"
                    and a.host == host
                    and a.status in (AlertStatus.OPEN, AlertStatus.TRIAGED)
                    and (now or datetime.now(timezone.utc)) - a.created_at
                    <= timedelta(seconds=300)
                ),
                None,
            )
            if burst:
                burst.occurrences += 1
                self._persist("alert", burst.model_dump(mode="json"))
            else:
                alert = self._detection.create_alert(
                    session.id,
                    AlertCreate(
                        rule_id="SIGMA-BURST",
                        rule_name="Event Burst / Beaconing",
                        title="Rafaga de eventos del mismo origen",
                        detail=(
                            f"{self._detection._burst_threshold}+ eventos en "
                            f"{int(self._detection._burst_window.total_seconds())}s"
                        ),
                        severity=Severity.MEDIUM,
                        technique_ids=["T1071"],
                        data_sources=["network", "application_log"],
                        source=result.tool,
                        host=host,
                        evidence_result_id=result.id,
                        event_time=now,
                    ),
                    uuid.uuid4().hex[:8],
                )
                self.state.add_alert(alert)
                self._audit(
                    "system",
                    "alert.new",
                    detail=f"SIGMA-BURST rafaga host={host or '-'}",
                    session_id=session.id,
                )
                self.events.publish(
                    session.id,
                    {"type": "alert.new", "data": {"id": alert.id, "rule_id": "SIGMA-BURST", "severity": "medium", "host": host}},
                )
                self._persist("alert", alert.model_dump(mode="json"))
                created.append(alert)
        return created

    def add_rule(self, session_id: str, data: RuleCreate) -> DetectionRule:
        session = self._require_session(session_id)
        self._require_team(session, Team.BLUE, Team.PURPLE)
        rule_id = data.name.lower().replace(" ", "-")[:40]
        rule = DetectionRule(id=rule_id, session_id=session_id, **data.model_dump())
        self.state.add_rule(rule)
        self._audit(
            "agent",
            "rule.add",
            detail=f"{rule.id} tecnicas={','.join(rule.technique_ids) or '-'}",
            session_id=session_id,
        )
        self.events.publish(
            session_id, {"type": "rule.add", "data": {"id": rule.id, "name": rule.name}}
        )
        self._persist("rule", rule.model_dump(mode="json"))
        return rule

    def rules(self, session_id: str) -> list[DetectionRule]:
        self._require_session(session_id)
        return self.effective_rules(session_id)

    def create_alert(self, session_id: str, data: AlertCreate) -> Alert:
        session = self._require_session(session_id)
        self._require_team(session, Team.BLUE, Team.PURPLE)
        alert = self._detection.create_alert(session_id, data, uuid.uuid4().hex[:8])
        self.state.add_alert(alert)
        self._audit(
            "agent",
            "alert.new",
            detail=f"manual {data.rule_id} [{data.severity.value}] host={data.host or '-'}",
            session_id=session_id,
        )
        self.events.publish(
            session_id,
            {"type": "alert.new", "data": {"id": alert.id, "rule_id": data.rule_id, "severity": data.severity.value, "host": data.host}},
        )
        self._persist("alert", alert.model_dump(mode="json"))
        return alert

    def alerts(self, session_id: str) -> list[Alert]:
        return self.state.get_alerts(session_id)

    def update_alert_status(
        self, session_id: str, alert_id: str, status: AlertStatus, note: str | None = None
    ) -> Alert:
        session = self._require_session(session_id)
        self._require_team(session, Team.BLUE, Team.PURPLE)
        alert = self.state.get_alert(session_id, alert_id)
        if not alert:
            raise KeyError(f"alert {alert_id} not found")
        if note:
            alert.notes.append(note)
        alert.status = status
        if status in (AlertStatus.TRIAGED, AlertStatus.CONFIRMED):
            alert.touch_triage()
        if status in (AlertStatus.FALSE_POSITIVE, AlertStatus.CLOSED):
            alert.touch_close()
        self._audit(
            "agent",
            "alert.status",
            detail=f"{alert.rule_id} -> {status.value}",
            session_id=session_id,
        )
        self.events.publish(
            session_id,
            {"type": "alert.status", "data": {"id": alert.id, "status": status.value}},
        )
        self._persist("alert", alert.model_dump(mode="json"))
        return alert

    def create_incident(self, session_id: str, data: IncidentCreate) -> Incident:
        session = self._require_session(session_id)
        self._require_team(session, Team.BLUE, Team.PURPLE)
        alerts = [a for a in self.state.get_alerts(session_id) if a.id in data.alert_ids]
        missing = [aid for aid in data.alert_ids if aid not in {a.id for a in alerts}]
        if missing:
            raise KeyError(f"alertas inexistentes: {', '.join(missing)}")
        technique_ids = list(
            dict.fromkeys(t for a in alerts for t in a.technique_ids + [a.rule_id])
        )
        incident = Incident(
            id=uuid.uuid4().hex[:8],
            session_id=session_id,
            title=data.title,
            detail=data.detail,
            severity=data.severity,
            alert_ids=data.alert_ids,
            technique_ids=technique_ids,
        )
        self.state.add_incident(incident)
        self._audit(
            "agent",
            "incident.create",
            detail=f"{incident.title} alertas={len(incident.alert_ids)}",
            session_id=session_id,
        )
        self.events.publish(
            session_id,
            {"type": "incident.create", "data": {"id": incident.id, "title": incident.title}},
        )
        self._persist("incident", incident.model_dump(mode="json"))
        return incident

    def incidents(self, session_id: str) -> list[Incident]:
        return self.state.get_incidents(session_id)

    def update_incident_stage(
        self, session_id: str, incident_id: str, stage: IncidentStage
    ) -> Incident:
        session = self._require_session(session_id)
        self._require_team(session, Team.BLUE, Team.PURPLE)
        incident = self.state.get_incident(session_id, incident_id)
        if not incident:
            raise KeyError(f"incident {incident_id} not found")
        if stage == incident.stage:
            return incident
        from core.machines.blue import incident_transition_blockers, TRANSITIONS as BLUE_TRANSITIONS

        if stage not in BLUE_TRANSITIONS.get(incident.stage, []):
            raise ValueError(
                f"transicion no permitida: {incident.stage.value} -> {stage.value}"
            )
        missing = incident_transition_blockers(self.state, incident, stage)
        if missing:
            self._audit(
                "system",
                "incident.stage",
                detail=f"BLOQUEADO -> {stage.value}: {'; '.join(missing)}",
                session_id=session_id,
                verdict=Verdict.BLOCKED,
            )
            raise ValueError("; ".join(missing))
        incident.stage = stage
        if stage == IncidentStage.REPORT:
            incident.status = "closed"
        incident.touch()
        self._audit(
            "agent",
            "incident.stage",
            detail=f"{incident.title} -> {stage.value}",
            session_id=session_id,
        )
        self.events.publish(
            session_id,
            {"type": "incident.stage", "data": {"id": incident.id, "stage": stage.value}},
        )
        self._persist("incident", incident.model_dump(mode="json"))
        return incident

    def add_recommendation(
        self, session_id: str, text: str, incident_id: str | None = None
    ) -> Session:
        """Documenta una recomendacion de respuesta del blue team. Nunca
        ejecuta acciones: queda como nota de la sesion (o del incidente)."""
        session = self._require_session(session_id)
        self._require_team(session, Team.BLUE, Team.PURPLE)
        if incident_id:
            incident = self.state.get_incident(session_id, incident_id)
            if not incident:
                raise KeyError(f"incident {incident_id} not found")
            incident.recommendations.append(text)
            incident.touch()
            self._persist("incident", incident.model_dump(mode="json"))
            self._audit(
                "agent",
                "incident.recommend",
                detail=f"{incident.title}: {text[:200]}",
                session_id=session_id,
            )
            return session
        session.notes.append(f"[recomendacion] {text}")
        self._audit(
            "agent",
            "session.recommend",
            detail=text[:200],
            session_id=session_id,
        )
        self._persist("session", session.model_dump(mode="json"))
        return session
        self._persist("incident", incident.model_dump(mode="json"))
        return incident

    def add_ioc(self, session_id: str, data: IOCCreate) -> IOC:
        self._require_session(session_id)
        ioc = IOC(id=uuid.uuid4().hex[:8], session_id=session_id, **data.model_dump())
        self.state.add_ioc(ioc)
        self.upsert_node(
            session_id,
            NodeUpsert(
                kind="ioc", name=f"{ioc.type.value}:{ioc.value}",
                state=KnowledgeState.KNOWN, confidence=ioc.confidence, source=ioc.source,
            ),
        )
        self._audit(
            "agent",
            "ioc.add",
            detail=f"{ioc.type.value}:{ioc.value} conf={ioc.confidence:.2f}",
            session_id=session_id,
        )
        self.events.publish(
            session_id,
            {"type": "ioc.add", "data": {"id": ioc.id, "type": ioc.type.value, "value": ioc.value}},
        )
        self._persist("ioc", ioc.model_dump(mode="json"))
        return ioc

    def iocs(self, session_id: str) -> list[IOC]:
        return self.state.get_iocs(session_id)

    # ------------------------------------------------------------------
    # purple team: orquestacion red + blue
    # ------------------------------------------------------------------
    def link_session(self, purple_id: str, role: str, session_id: str) -> Session:
        session = self._require_session(purple_id)
        self._require_team(session, Team.PURPLE)
        if role not in ("red", "blue"):
            raise ValueError("rol debe ser 'red' o 'blue'")
        linked = self._require_session(session_id)
        if linked.team.value != role:
            raise ValueError(f"la sesion {session_id} es {linked.team.value}, no {role}")
        links = session.purple_links.setdefault(role, [])
        if session_id not in links:
            links.append(session_id)
            session.touch()
            self._audit(
                "system",
                "purple.link",
                detail=f"{role}={session_id} en sesion purple {purple_id}",
                session_id=purple_id,
            )
            self.events.publish(
                purple_id,
                {"type": "purple.link", "data": {"role": role, "session_id": session_id}},
            )
            self._persist("session", session.model_dump(mode="json"))
        return session

    def coverage(self, session_id: str) -> dict:
        session = self._require_session(session_id)
        self._require_team(session, Team.PURPLE, Team.BLUE)
        result = compute_coverage(self, session_id)
        self._audit(
            "agent",
            "coverage.view",
            detail=(
                f"coverage={result['coverage']:.2f} gaps={result['open_gaps']} "
                f"detection_rate={result['detection_rate']:.2f}"
            ),
            session_id=session_id,
        )
        self.events.publish(
            session_id,
            {"type": "coverage.view", "data": {"coverage": result["coverage"], "gaps": result["open_gaps"]}},
        )
        return result

    # ------------------------------------------------------------------
    # grafo
    # ------------------------------------------------------------------
    def upsert_node(self, session_id: str, data: NodeUpsert) -> Node:
        self._require_session(session_id)
        node = self.state.graph.upsert_node(session_id, data)
        self._audit(
            "agent",
            "graph.node",
            detail=f"{node.kind}:{node.name} -> {node.state.value} conf={node.confidence:.2f}",
            session_id=session_id,
        )
        self.events.publish(
            session_id,
            {"type": "graph.node", "data": {"kind": node.kind, "name": node.name, "state": node.state.value}},
        )
        self._persist("node", node.model_dump(mode="json"))
        return node

    def link_nodes(self, session_id: str, data: LinkCreate) -> dict:
        self._require_session(session_id)
        rel = self.state.graph.link(session_id, data)
        self._audit(
            "agent",
            "graph.link",
            detail=f"{rel.source} -{rel.kind}-> {rel.target}",
            session_id=session_id,
        )
        self._persist("link", rel.model_dump(mode="json"))
        return rel.model_dump()

    def get_nodes(self, session_id: str) -> list[Node]:
        return self.state.graph.nodes(session_id)

    def get_surface(self, session_id: str) -> dict:
        self._require_session(session_id)
        return self.state.graph.surface(session_id)

    def prune_graph(self, session_id: str) -> dict:
        """Poda TTL: descarta nodos sin verificar, de baja confianza y antiguos."""
        self._require_session(session_id)
        removed = self.state.graph.prune(session_id, self._prune_min_confidence)
        self._audit(
            "system",
            "graph.prune",
            detail=f"eliminados {len(removed)} nodos obsoletos",
            session_id=session_id,
        )
        if self._storage:
            self._storage.delete_nodes(removed)
        self.events.publish(
            session_id, {"type": "graph.prune", "data": {"removed": len(removed)}}
        )
        return {"removed": removed, "count": len(removed)}

    # ------------------------------------------------------------------
    # investigaciones / findings (con validacion semantica)
    # ------------------------------------------------------------------
    def add_investigation(self, session_id: str, data: InvestigationCreate) -> Investigation:
        self._require_session(session_id)
        investigation = Investigation(
            id=uuid.uuid4().hex[:8], session_id=session_id, **data.model_dump()
        )
        self.state.add_investigation(investigation)
        self._audit(
            "agent",
            "investigation.add",
            detail=f"{investigation.name} status={investigation.status.value}",
            session_id=session_id,
        )
        self.events.publish(
            session_id,
            {"type": "investigation.add", "data": {"name": investigation.name, "status": investigation.status.value}},
        )
        self._persist("investigation", investigation.model_dump(mode="json"))
        self._publish_risk(session_id)
        return investigation

    def investigations(self, session_id: str) -> list[Investigation]:
        return self.state.get_investigations(session_id)

    def add_finding(self, session_id: str, data: FindingCreate) -> Finding:
        self._require_session(session_id)
        evidence = [
            r for r in (self.state.get_result(session_id, rid) for rid in data.evidence_ids) if r
        ]
        all_exist = bool(data.evidence_ids) and len(evidence) == len(data.evidence_ids)
        missing = [rid for rid in data.evidence_ids if rid not in {r.id for r in evidence}]

        against = [
            r for r in (self.state.get_result(session_id, rid) for rid in data.against) if r
        ]
        against_missing = [rid for rid in data.against if rid not in {r.id for r in against}]

        verdicts = [evaluate(r) for r in evidence]
        against_verdicts = [evaluate(r) for r in against]
        notes: list[str] = []
        verified = False
        confidence = data.confidence

        if all_exist and verdicts:
            best = max(verdicts, key=lambda v: v["score"])
            confidence = adjust_confidence(data.confidence, best)
            all_support = all(v["exit_ok"] and v["supported"] for v in verdicts)
            contradiction = [
                v for v in against_verdicts if (not v["exit_ok"]) or v["negatives"]
            ]
            if contradiction:
                confidence = min(confidence, 0.4)
                notes.append(
                    f"evidencia en contra detectada: exit_ok={contradiction[0]['exit_ok']} "
                    f"senales-contra={contradiction[0]['negatives'] or '-'} - verified=False"
                )
            verified = all_support and not contradiction
            if not all_support:
                notes.append(
                    "no toda la evidencia referenciada soporta la hipotesis - verified=False"
                )
            notes.append(
                f"validacion semantica: exit_ok={best['exit_ok']} "
                f"soporte={best['supported']} score={best['score']} "
                f"senales={best['signals'] or '-'} contra={best['negatives'] or '-'}"
            )
        elif data.evidence_ids and not all_exist:
            notes.append(f"evidencia faltante: {', '.join(missing)}")
            confidence = min(confidence, 0.4)
        elif not data.evidence_ids:
            notes.append("sin evidencia referenciada: verified=False")
        if against_missing:
            notes.append(f"evidencia en contra faltante: {', '.join(against_missing)}")

        finding = Finding(
            id=uuid.uuid4().hex[:8],
            session_id=session_id,
            title=data.title,
            detail=data.detail,
            confidence=confidence,
            evidence_ids=data.evidence_ids,
            against=data.against,
            status=data.status,
            technique_id=data.technique_id,
            verified=verified,
            verification_notes=notes,
        )
        self.state.add_finding(finding)
        self._audit(
            "agent",
            "finding.add",
            detail=(
                f"{finding.title} verified={finding.verified} conf={finding.confidence:.2f} "
                f"(base {data.confidence:.2f}) {'; '.join(notes)}"
            ),
            session_id=session_id,
        )
        self.events.publish(
            session_id,
            {"type": "finding.add", "data": {"id": finding.id, "title": finding.title, "verified": finding.verified}},
        )
        self._persist("finding", finding.model_dump(mode="json"))
        self._publish_risk(session_id)
        return finding

    def update_finding_status(
        self, session_id: str, finding_id: str, status: FindingStatus
    ) -> Finding:
        for finding in self.state.get_findings(session_id):
            if finding.id == finding_id:
                finding.status = status
                self._audit(
                    "agent",
                    "finding.status",
                    detail=f"{finding.title} -> {status.value}",
                    session_id=session_id,
                )
                self.events.publish(
                    session_id,
                    {"type": "finding.status", "data": {"id": finding.id, "status": status.value}},
                )
                self._persist("finding", finding.model_dump(mode="json"))
                self._publish_risk(session_id)
                return finding
        raise KeyError(f"finding {finding_id} not found")

    # ------------------------------------------------------------------
    # plan / contexto / compact
    # ------------------------------------------------------------------
    def plan(self, session_id: str) -> dict:
        self._require_session(session_id)
        return build_plan(
            self.state, session_id, self.priorities, techniques=self._techniques.all()
        )

    def compress(self, session_id: str) -> str:
        self._require_session(session_id)
        return self.context_builder.compress_context(self.state, session_id)

    def compact(self, session_id: str, async_llm: bool = False) -> dict:
        """Compactacion de bajo coste: devuelve SIEMPRE primero el fallback
        estadistico rapido; si async_llm, el resumen LLM corre en background y
        llega despues (la latencia nunca bloquea al agente)."""
        session = self._require_session(session_id)
        target = self.state.get_target(session.target_id)
        results = self.state.get_results(session_id)
        if not results:
            return {"summary": "sin actividad que compactar", "pending": False}
        fallback = self.context_builder.compact(results)

        if (
            async_llm
            and session.llm_compact
            and self.compactor.enabled
            and self.compactor.should_compact(results)
        ):
            def _background() -> None:
                try:
                    summary = self.compactor.summarize(results, target, fallback)
                except Exception:  # nunca rompe el flujo
                    return
                current = self.state.get_session(session_id)
                if current:
                    current.summaries.append(summary)
                    current.touch()
                    self._persist("session", current.model_dump(mode="json"))
                    self.events.publish(
                        session_id,
                        {"type": "session.compact_llm", "data": {"summary": summary}},
                    )

            threading.Thread(target=_background, daemon=True).start()
            self._audit(
                "system",
                "session.compact",
                detail=f"fallback inmediato ({len(fallback)} chars) + resumen LLM en background",
                session_id=session_id,
            )
            return {"summary": fallback, "pending": True}

        summary = fallback
        if session.llm_compact:
            summary = self.compactor.summarize(results, target, fallback)
        session.summaries.append(summary)
        session.touch()
        self._audit(
            "system",
            "session.compact",
            detail=f"resumen={len(summary)} chars, resultados={len(results)}, llm={session.llm_compact}",
            session_id=session_id,
        )
        self._persist("session", session.model_dump(mode="json"))
        return {"summary": summary, "pending": False}

    def evidence_chains(self, session_id: str) -> list[dict]:
        session = self._require_session(session_id)
        target = self.state.get_target(session.target_id)
        chains = []
        for finding in self.state.get_findings(session_id):
            evidence = []
            for rid in finding.evidence_ids:
                r = self.state.get_result(session_id, rid)
                if r:
                    evidence.append(
                        {
                            "result_id": rid,
                            "tool": r.tool,
                            "command": r.command,
                            "exit_code": r.exit_code,
                            "timestamp": r.created_at.isoformat(),
                            "target": target.host,
                            "scope": f"authorized={target.authorized} ({target.assessment})",
                        }
                    )
            chains.append(
                {
                    "finding": finding.title,
                    "confidence": finding.confidence,
                    "status": finding.status.value,
                    "technique": finding.technique_id,
                    "verified": finding.verified,
                    "verification_notes": finding.verification_notes,
                    "evidence": evidence,
                    "target": target.host,
                    "authorization": target.authorized,
                }
            )
        return chains

    def techniques(self) -> list[dict]:
        return self._techniques.all()

    def technique(self, technique_id: str) -> dict:
        return self._techniques.get(technique_id)

    def suggested_techniques(self, session_id: str) -> list[dict]:
        session = self._require_session(session_id)
        return self._techniques.suggested(session.phase.value)

    def get_system_prompt(self, session_id: str) -> str:
        return self.context_builder.build_system_prompt(self.state, session_id)

    def get_context(self, session_id: str) -> str:
        return self.context_builder.build_context(self.state, session_id)

    def get_compact_summary(self, session_id: str) -> str:
        results = self.state.get_results(session_id)
        return self.context_builder.compact(results)

    def get_metrics(self, session_id: str) -> dict:
        return compute_metrics(self.state, session_id, techniques=self._techniques.all())

    # ------------------------------------------------------------------
    # Debriefing por kill-chain (cierre del ciclo)
    # ------------------------------------------------------------------
    def _debrief_engine(self, sentryguard_rules_dir: str | None = None):
        from core.debrief import DebriefEngine
        from knowledge.sentryguard import SentryGuardIndex

        sentryguard = None
        if sentryguard_rules_dir:
            sentryguard = SentryGuardIndex().load_dir(sentryguard_rules_dir)
        return DebriefEngine(sentryguard=sentryguard)

    def debrief(
        self, session_id: str, sentryguard_rules_dir: str | None = None
    ) -> dict:
        from core.debrief import LocalDebriefSource, run_debrief

        self._require_session(session_id)
        return run_debrief(
            LocalDebriefSource(self),
            session_id,
            engine=self._debrief_engine(sentryguard_rules_dir),
        )

    def debrief_report(
        self,
        session_id: str,
        fmt: str = "markdown",
        sentryguard_rules_dir: str | None = None,
    ) -> str:
        session = self._require_session(session_id)
        analysis = self.debrief(session.id, sentryguard_rules_dir=sentryguard_rules_dir)
        return self._debrief_engine(sentryguard_rules_dir).report(analysis, fmt=fmt)

    def debrief_suggestions(
        self, session_id: str, sentryguard_rules_dir: str | None = None
    ) -> list[dict]:
        session = self._require_session(session_id)
        analysis = self.debrief(session.id, sentryguard_rules_dir=sentryguard_rules_dir)
        return self._debrief_engine(sentryguard_rules_dir).suggestions(analysis)

    def debrief_seed(
        self, session_id: str, sentryguard_rules_dir: str | None = None
    ) -> dict:
        session = self._require_session(session_id)
        engine = self._debrief_engine(sentryguard_rules_dir)
        analysis = self.debrief(session.id, sentryguard_rules_dir=sentryguard_rules_dir)
        return engine.build_seed(analysis, engine.suggestions(analysis))
