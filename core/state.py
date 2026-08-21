from __future__ import annotations

from core.graph import GraphStore
from models.alert import Alert
from models.finding import Finding
from models.graph import Node, Relationship
from models.incident import Incident
from models.investigation import Investigation
from models.ioc import IOC
from models.rule import DetectionRule
from models.session import Phase, Session
from models.target import Target
from models.tool_result import ToolResult


class MediatorState:
    def __init__(
        self,
        node_ttl_seconds: int | None = None,
        max_nodes_per_kind: int | None = None,
    ) -> None:
        self._node_ttl_seconds = node_ttl_seconds
        self._max_nodes_per_kind = max_nodes_per_kind
        self.graph = GraphStore(
            node_ttl_seconds=node_ttl_seconds,
            max_nodes_per_kind=max_nodes_per_kind,
        )
        self._targets: dict[str, Target] = {}
        self._sessions: dict[str, Session] = {}
        self._results: dict[str, list[ToolResult]] = {}
        self._findings: dict[str, list[Finding]] = {}
        self._investigations: dict[str, list[Investigation]] = {}
        self._alerts: dict[str, list[Alert]] = {}
        self._incidents: dict[str, list[Incident]] = {}
        self._rules: dict[str, list[DetectionRule]] = {}
        self._iocs: dict[str, list[IOC]] = {}

    def add_target(self, target: Target) -> None:
        self._targets[target.id] = target

    def get_target(self, target_id: str) -> Target | None:
        return self._targets.get(target_id)

    def list_targets(self) -> list[Target]:
        return list(self._targets.values())

    def add_session(self, session: Session) -> None:
        self._sessions[session.id] = session
        self._results.setdefault(session.id, [])
        self._findings.setdefault(session.id, [])
        self._investigations.setdefault(session.id, [])
        self._alerts.setdefault(session.id, [])
        self._incidents.setdefault(session.id, [])
        self._rules.setdefault(session.id, [])
        self._iocs.setdefault(session.id, [])

    def get_session(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[Session]:
        return list(self._sessions.values())

    def set_phase(self, session_id: str, phase: Phase) -> None:
        session = self.get_session(session_id)
        if session:
            session.phase = phase
            session.touch()

    def add_note(self, session_id: str, note: str) -> None:
        session = self.get_session(session_id)
        if session:
            session.add_note(note)

    def add_result(self, result: ToolResult) -> None:
        self._results.setdefault(result.session_id, []).append(result)

    def get_results(self, session_id: str) -> list[ToolResult]:
        return self._results.get(session_id, [])

    def get_result(self, session_id: str, result_id: str) -> ToolResult | None:
        for result in self.get_results(session_id):
            if result.id == result_id:
                return result
        return None

    def all_results(self) -> list[ToolResult]:
        return [r for results in self._results.values() for r in results]

    def add_finding(self, finding: Finding) -> None:
        self._findings.setdefault(finding.session_id, []).append(finding)

    def get_findings(self, session_id: str) -> list[Finding]:
        return self._findings.get(session_id, [])

    def add_investigation(self, investigation: Investigation) -> None:
        self._investigations.setdefault(investigation.session_id, []).append(investigation)

    def get_investigations(self, session_id: str) -> list[Investigation]:
        return self._investigations.get(session_id, [])

    def add_alert(self, alert: Alert) -> None:
        self._alerts.setdefault(alert.session_id, []).append(alert)

    def get_alerts(self, session_id: str) -> list[Alert]:
        return self._alerts.get(session_id, [])

    def get_alert(self, session_id: str, alert_id: str) -> Alert | None:
        for alert in self.get_alerts(session_id):
            if alert.id == alert_id:
                return alert
        return None

    def add_incident(self, incident: Incident) -> None:
        self._incidents.setdefault(incident.session_id, []).append(incident)

    def get_incidents(self, session_id: str) -> list[Incident]:
        return self._incidents.get(session_id, [])

    def get_incident(self, session_id: str, incident_id: str) -> Incident | None:
        for incident in self.get_incidents(session_id):
            if incident.id == incident_id:
                return incident
        return None

    def add_rule(self, rule: DetectionRule) -> None:
        self._rules.setdefault(rule.session_id, []).append(rule)

    def get_rules(self, session_id: str) -> list[DetectionRule]:
        return self._rules.get(session_id, [])

    def add_ioc(self, ioc: IOC) -> None:
        self._iocs.setdefault(ioc.session_id, []).append(ioc)

    def get_iocs(self, session_id: str) -> list[IOC]:
        return self._iocs.get(session_id, [])

    def to_snapshot(self) -> dict:
        return {
            "targets": [t.model_dump(mode="json") for t in self._targets.values()],
            "sessions": [s.model_dump(mode="json") for s in self._sessions.values()],
            "results": [r.model_dump(mode="json") for r in self.all_results()],
            "findings": [
                f.model_dump(mode="json")
                for entries in self._findings.values()
                for f in entries
            ],
            "investigations": [
                i.model_dump(mode="json")
                for entries in self._investigations.values()
                for i in entries
            ],
            "alerts": [
                a.model_dump(mode="json")
                for entries in self._alerts.values()
                for a in entries
            ],
            "incidents": [
                i.model_dump(mode="json")
                for entries in self._incidents.values()
                for i in entries
            ],
            "rules": [
                r.model_dump(mode="json")
                for entries in self._rules.values()
                for r in entries
            ],
            "iocs": [
                i.model_dump(mode="json")
                for entries in self._iocs.values()
                for i in entries
            ],
            "nodes": [n.model_dump(mode="json") for n in self.graph.all_nodes()],
            "links": [l.model_dump(mode="json") for l in self.graph.all_links()],
        }

    def load_snapshot(self, data: dict) -> None:
        self.graph = GraphStore(
            node_ttl_seconds=self._node_ttl_seconds,
            max_nodes_per_kind=self._max_nodes_per_kind,
        )
        self._targets = {t["id"]: Target(**t) for t in data.get("targets", [])}
        self._sessions = {s["id"]: Session(**s) for s in data.get("sessions", [])}
        self._results = {}
        for r in data.get("results", []):
            self._results.setdefault(r["session_id"], []).append(ToolResult(**r))
        self._findings = {}
        for f in data.get("findings", []):
            self._findings.setdefault(f["session_id"], []).append(Finding(**f))
        self._investigations = {}
        for i in data.get("investigations", []):
            self._investigations.setdefault(i["session_id"], []).append(Investigation(**i))
        self._alerts = {}
        for a in data.get("alerts", []):
            self._alerts.setdefault(a["session_id"], []).append(Alert(**a))
        self._incidents = {}
        for i in data.get("incidents", []):
            self._incidents.setdefault(i["session_id"], []).append(Incident(**i))
        self._rules = {}
        for r in data.get("rules", []):
            self._rules.setdefault(r["session_id"], []).append(DetectionRule(**r))
        self._iocs = {}
        for i in data.get("iocs", []):
            self._iocs.setdefault(i["session_id"], []).append(IOC(**i))
        self.graph.restore(
            [Node(**n) for n in data.get("nodes", [])],
            [Relationship(**l) for l in data.get("links", [])],
        )
