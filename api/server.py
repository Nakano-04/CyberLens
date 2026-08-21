from __future__ import annotations

import secrets
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.mediator import Mediator
from models.alert import Alert, AlertCreate, AlertStatus
from models.finding import Finding, FindingCreate, FindingStatus
from models.graph import LinkCreate, Node, NodeUpsert, Relationship
from models.incident import Incident, IncidentCreate, IncidentStage
from models.investigation import Investigation, InvestigationCreate
from models.ioc import IOC, IOCCreate
from models.rule import DetectionRule, RuleCreate
from models.session import AttackStage, Phase, Session, SessionCreate
from models.target import Target, TargetCreate
from models.tool_result import ToolResult
from models.team import Team


class YaraScanRequest(BaseModel):
    rules: str
    target_path: str


class ExecuteRequest(BaseModel):
    tool: str = "shell"
    command: str
    timeout: Optional[int] = None
    parser: Optional[str] = None
    human_approved: bool = False


class IngestEventRequest(BaseModel):
    source: str
    command: str = ""
    stdout: str = ""
    parsed: Optional[dict] = None
    severity: Optional[str] = None


class AlertStatusRequest(BaseModel):
    status: AlertStatus
    note: Optional[str] = None


class IncidentStageRequest(BaseModel):
    stage: IncidentStage


class RecommendationRequest(BaseModel):
    text: str


class PurpleLinkRequest(BaseModel):
    team: Team
    session_id: str


class NoteRequest(BaseModel):
    note: str


class PhaseRequest(BaseModel):
    phase: Phase
    override: bool = False
    reason: Optional[str] = None


class ObjectiveUpdate(BaseModel):
    objective: Optional[str] = None
    current_position: Optional[str] = None
    attack_stage: Optional[AttackStage] = None
    known: Optional[list[str]] = None
    unknown: Optional[list[str]] = None
    next_areas: Optional[list[str]] = None


class FindingStatusRequest(BaseModel):
    status: FindingStatus


def _token_ok(token: str | None, provided: str | None) -> bool:
    if not token:
        return True  # sin config, acceso abierto (local por defecto)
    if not provided:
        return False
    return secrets.compare_digest(token.encode(), provided.strip().encode())


def create_app(
    mediator: Mediator,
    api_token: str | None = None,
    sentryguard_rules_dir: str | None = None,
) -> FastAPI:
    app = FastAPI(title="Offensive Context Engine", version="0.4.0")

    @app.middleware("http")
    async def require_token(request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        header = request.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            provided = header.split(" ", 1)[1]
        else:
            provided = request.headers.get("X-API-Key")
        if not _token_ok(api_token, provided):
            return JSONResponse({"detail": "token de API requerido o invalido"}, status_code=401)
        return await call_next(request)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/targets", response_model=Target)
    def create_target(data: TargetCreate) -> Target:
        return mediator.create_target(data)

    @app.get("/targets", response_model=list[Target])
    def list_targets() -> list[Target]:
        return mediator.state.list_targets()

    @app.get("/targets/{target_id}", response_model=Target)
    def get_target(target_id: str) -> Target:
        target = mediator.state.get_target(target_id)
        if not target:
            raise HTTPException(404, f"target {target_id} no existe")
        return target

    @app.post("/sessions", response_model=Session)
    def create_session(data: SessionCreate) -> Session:
        try:
            return mediator.create_session(data)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc

    @app.get("/sessions", response_model=list[Session])
    def list_sessions() -> list[Session]:
        return mediator.state.list_sessions()

    @app.get("/sessions/{session_id}", response_model=Session)
    def get_session(session_id: str) -> Session:
        try:
            return mediator._require_session(session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/sessions/{session_id}/phase", response_model=Session)
    def set_phase(session_id: str, data: PhaseRequest) -> Session:
        try:
            return mediator.set_phase(
                session_id, data.phase, override=data.override, reason=data.reason or ""
            )
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/sessions/{session_id}/phase-transitions")
    def phase_transitions(session_id: str) -> dict:
        try:
            return mediator.phase_transitions(session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/sessions/{session_id}/objective", response_model=Session)
    def update_objective(session_id: str, data: ObjectiveUpdate) -> Session:
        try:
            return mediator.update_objective(
                session_id,
                objective=data.objective,
                current_position=data.current_position,
                attack_stage=data.attack_stage,
                known=data.known,
                unknown=data.unknown,
                next_areas=data.next_areas,
            )
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/sessions/{session_id}/notes", response_model=Session)
    def add_note(session_id: str, data: NoteRequest) -> Session:
        try:
            return mediator.add_note(session_id, data.note)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/sessions/{session_id}/execute", response_model=ToolResult)
    def execute(session_id: str, data: ExecuteRequest) -> ToolResult:
        try:
            return mediator.execute(
                session_id,
                data.tool,
                data.command,
                data.timeout,
                data.parser,
                data.human_approved,
            )
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc

    # ------------------------------------------------------------------
    # Blue team: ingesta de telemetria, alertas, incidentes, reglas, IOCs
    # ------------------------------------------------------------------
    @app.post("/sessions/{session_id}/ingest", response_model=ToolResult)
    def ingest(session_id: str, data: IngestEventRequest) -> ToolResult:
        try:
            return mediator.ingest_event(
                session_id, data.source, data.stdout, data.parsed
            )
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc

    @app.get("/sessions/{session_id}/alerts", response_model=list[Alert])
    def alerts(session_id: str) -> list[Alert]:
        return mediator.alerts(session_id)

    @app.patch(
        "/sessions/{session_id}/alerts/{alert_id}",
        response_model=Alert,
    )
    def update_alert_status(session_id: str, alert_id: str, data: AlertStatusRequest) -> Alert:
        try:
            return mediator.update_alert_status(
                session_id, alert_id, data.status, data.note
            )
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/sessions/{session_id}/rules", response_model=DetectionRule)
    def add_rule(session_id: str, data: RuleCreate) -> DetectionRule:
        try:
            return mediator.add_rule(session_id, data)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc

    @app.get("/sessions/{session_id}/rules", response_model=list[DetectionRule])
    def rules(session_id: str) -> list[DetectionRule]:
        return mediator.rules(session_id)

    @app.post("/sessions/{session_id}/incidents", response_model=Incident)
    def create_incident(session_id: str, data: IncidentCreate) -> Incident:
        try:
            return mediator.create_incident(session_id, data)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/sessions/{session_id}/incidents", response_model=list[Incident])
    def incidents(session_id: str) -> list[Incident]:
        return mediator.incidents(session_id)

    @app.patch(
        "/sessions/{session_id}/incidents/{incident_id}",
        response_model=Incident,
    )
    def update_incident_stage(
        session_id: str, incident_id: str, data: IncidentStageRequest
    ) -> Incident:
        try:
            return mediator.update_incident_stage(session_id, incident_id, data.stage)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/sessions/{session_id}/recommendations")
    def add_recommendation(session_id: str, data: RecommendationRequest) -> dict:
        try:
            session = mediator.add_recommendation(session_id, data.text)
            return {"session": session.id, "recommendations": len(session.notes)}
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc

    @app.post("/sessions/{session_id}/iocs", response_model=IOC)
    def add_ioc(session_id: str, data: IOCCreate) -> IOC:
        try:
            return mediator.add_ioc(session_id, data)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc

    @app.get("/sessions/{session_id}/iocs", response_model=list[IOC])
    def iocs(session_id: str) -> list[IOC]:
        return mediator.iocs(session_id)

    # ------------------------------------------------------------------
    # Purple team: orquestacion red+blue y cobertura
    # ------------------------------------------------------------------
    @app.post("/sessions/{session_id}/purple-link", response_model=Session)
    def purple_link(session_id: str, data: PurpleLinkRequest) -> Session:
        try:
            return mediator.link_session(session_id, data.team.value, data.session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/sessions/{session_id}/coverage")
    def coverage(session_id: str) -> dict:
        try:
            return mediator.coverage(session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc

    @app.get("/sessions/{session_id}/results", response_model=list[ToolResult])
    def results(session_id: str) -> list[ToolResult]:
        return mediator.state.get_results(session_id)

    @app.get("/sessions/{session_id}/system-prompt")
    def system_prompt(session_id: str) -> dict:
        try:
            return {"prompt": mediator.get_system_prompt(session_id)}
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/context")
    def context(session_id: str) -> dict:
        try:
            return {"context": mediator.get_context(session_id)}
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/compact-summary")
    def compact_summary(session_id: str) -> dict:
        return {"summary": mediator.get_compact_summary(session_id)}

    @app.post("/sessions/{session_id}/compact")
    def compact(session_id: str, async_llm: bool = False) -> dict:
        try:
            return mediator.compact(session_id, async_llm=async_llm)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/sessions/{session_id}/compress")
    def compress(session_id: str) -> dict:
        try:
            return {"context": mediator.compress(session_id)}
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/sessions/{session_id}/yara-scan", response_model=ToolResult)
    def yara_scan(session_id: str, data: YaraScanRequest) -> ToolResult:
        try:
            return mediator.yara_scan(session_id, data.rules, data.target_path)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/sessions/{session_id}/nodes", response_model=Node)
    def upsert_node(session_id: str, data: NodeUpsert) -> Node:
        try:
            return mediator.upsert_node(session_id, data)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/nodes", response_model=list[Node])
    def nodes(session_id: str) -> list[Node]:
        return mediator.get_nodes(session_id)

    @app.post("/sessions/{session_id}/links", response_model=Relationship)
    def link_nodes(session_id: str, data: LinkCreate) -> Relationship:
        try:
            return mediator.link_nodes(session_id, data)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/surface")
    def surface(session_id: str) -> dict:
        try:
            return mediator.get_surface(session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/sessions/{session_id}/graph/prune")
    def prune_graph(session_id: str) -> dict:
        try:
            return mediator.prune_graph(session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/sessions/{session_id}/investigations", response_model=Investigation)
    def add_investigation(session_id: str, data: InvestigationCreate) -> Investigation:
        try:
            return mediator.add_investigation(session_id, data)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/investigations", response_model=list[Investigation])
    def investigations(session_id: str) -> list[Investigation]:
        return mediator.investigations(session_id)

    @app.post("/sessions/{session_id}/findings", response_model=Finding)
    def add_finding(session_id: str, data: FindingCreate) -> Finding:
        try:
            return mediator.add_finding(session_id, data)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/findings", response_model=list[Finding])
    def findings(session_id: str) -> list[Finding]:
        return mediator.state.get_findings(session_id)

    @app.patch("/sessions/{session_id}/findings/{finding_id}", response_model=Finding)
    def update_finding_status(session_id: str, finding_id: str, data: FindingStatusRequest) -> Finding:
        try:
            return mediator.update_finding_status(session_id, finding_id, data.status)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/metrics")
    def metrics(session_id: str) -> dict:
        try:
            return mediator.get_metrics(session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/plan")
    def plan(session_id: str) -> dict:
        try:
            return mediator.plan(session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/evidence-chains")
    def evidence_chains(session_id: str) -> list[dict]:
        try:
            return mediator.evidence_chains(session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/report")
    def report(session_id: str, format: str = "markdown") -> dict:
        from core.report import generate_report

        try:
            if format not in ("markdown", "html"):
                raise HTTPException(400, "format debe ser markdown o html")
            return {"report": generate_report(mediator, session_id, fmt=format)}
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/debrief")
    def debrief(session_id: str) -> dict:
        try:
            return mediator.debrief(
                session_id, sentryguard_rules_dir=sentryguard_rules_dir
            )
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/debrief/report")
    def debrief_report(session_id: str, format: str = "markdown") -> dict:
        try:
            if format not in ("markdown", "html"):
                raise HTTPException(400, "format debe ser markdown o html")
            return {
                "report": mediator.debrief_report(
                    session_id,
                    fmt=format,
                    sentryguard_rules_dir=sentryguard_rules_dir,
                )
            }
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/debrief/suggestions")
    def debrief_suggestions(session_id: str) -> list[dict]:
        try:
            return mediator.debrief_suggestions(
                session_id, sentryguard_rules_dir=sentryguard_rules_dir
            )
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/debrief/seed")
    def debrief_seed(session_id: str) -> dict:
        try:
            return mediator.debrief_seed(
                session_id, sentryguard_rules_dir=sentryguard_rules_dir
            )
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/sessions/{session_id}/techniques")
    def session_techniques(session_id: str) -> list[dict]:
        try:
            return mediator.suggested_techniques(session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/techniques")
    def techniques() -> list[dict]:
        return mediator.techniques()

    @app.get("/techniques/{technique_id}")
    def technique(technique_id: str) -> dict:
        try:
            return mediator.technique(technique_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/audit")
    def audit() -> list[dict]:
        return [e.model_dump() for e in mediator.audit.entries()]

    @app.websocket("/ws/sessions/{session_id}")
    async def ws_session(websocket: WebSocket, session_id: str) -> None:
        if not _token_ok(api_token, websocket.query_params.get("token")):
            await websocket.accept()
            await websocket.send_json({"type": "error", "detail": "token de API requerido o invalido"})
            await websocket.close()
            return
        await websocket.accept()
        try:
            mediator._require_session(session_id)
        except KeyError as exc:
            await websocket.send_json({"type": "error", "detail": str(exc)})
            await websocket.close()
            return
        await websocket.send_json({"type": "connected", "session_id": session_id})
        queue = await mediator.events.subscribe(session_id)
        try:
            while True:
                event = await queue.get()
                await websocket.send_json(event)
        except WebSocketDisconnect:
            mediator.events.unsubscribe(session_id, queue)

    return app
