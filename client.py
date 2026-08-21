from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class MediatorError(Exception):
    pass


class MediatorClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = self.base_url + path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise MediatorError(f"HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise MediatorError(
                f"no se pudo conectar con {self.base_url}: {exc.reason}"
            ) from exc

    def health(self) -> dict:
        return self._request("GET", "/health")

    def create_target(
        self,
        host: str,
        description: str = "",
        authorized: bool = True,
        assessment: str = "web",
        os_hint: str | None = None,
    ) -> dict:
        return self._request(
            "POST",
            "/targets",
            {
                "host": host,
                "description": description,
                "authorized": authorized,
                "assessment": assessment,
                "os_hint": os_hint,
            },
        )

    def list_targets(self) -> list[dict]:
        return self._request("GET", "/targets")

    def get_target(self, target_id: str) -> dict:
        return self._request("GET", f"/targets/{target_id}")

    def create_session(
        self,
        target_id: str,
        agent: str = "build",
        objective: str = "",
        tags: list[str] | None = None,
        llm_compact: bool = True,
        max_steps: int | None = None,
        team: str = "red",
    ) -> dict:
        return self._request(
            "POST",
            "/sessions",
            {
                "target_id": target_id,
                "agent": agent,
                "objective": objective,
                "tags": tags or [],
                "llm_compact": llm_compact,
                "max_steps": max_steps,
                "team": team,
            },
        )

    def list_sessions(self) -> list[dict]:
        return self._request("GET", "/sessions")

    def get_session(self, session_id: str) -> dict:
        return self._request("GET", f"/sessions/{session_id}")

    def set_phase(
        self, session_id: str, phase: str, override: bool = False, reason: str = ""
    ) -> dict:
        body: dict = {"phase": phase}
        if override:
            body["override"] = True
            body["reason"] = reason
        return self._request("POST", f"/sessions/{session_id}/phase", body)

    def phase_transitions(self, session_id: str) -> dict:
        return self._request("GET", f"/sessions/{session_id}/phase-transitions")

    def update_objective(
        self,
        session_id: str,
        objective: str | None = None,
        current_position: str | None = None,
        attack_stage: str | None = None,
        known: list[str] | None = None,
        unknown: list[str] | None = None,
        next_areas: list[str] | None = None,
    ) -> dict:
        body = {
            k: v
            for k, v in {
                "objective": objective,
                "current_position": current_position,
                "attack_stage": attack_stage,
                "known": known,
                "unknown": unknown,
                "next_areas": next_areas,
            }.items()
            if v is not None
        }
        return self._request("POST", f"/sessions/{session_id}/objective", body)

    def add_note(self, session_id: str, note: str) -> dict:
        return self._request("POST", f"/sessions/{session_id}/notes", {"note": note})

    def execute(
        self,
        session_id: str,
        command: str,
        tool: str = "shell",
        timeout: int | None = None,
        parser: str | None = None,
        human_approved: bool = False,
    ) -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/execute",
            {
                "command": command,
                "tool": tool,
                "timeout": timeout,
                "parser": parser,
                "human_approved": human_approved,
            },
        )

    def results(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/results")

    def yara_scan(self, session_id: str, rules: str, target_path: str) -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/yara-scan",
            {"rules": rules, "target_path": target_path},
        )

    def system_prompt(self, session_id: str) -> str:
        return self._request("GET", f"/sessions/{session_id}/system-prompt")["prompt"]

    def context(self, session_id: str) -> str:
        return self._request("GET", f"/sessions/{session_id}/context")["context"]

    def compact_summary(self, session_id: str) -> str:
        return self._request("GET", f"/sessions/{session_id}/compact-summary")["summary"]

    def compact(self, session_id: str, async_llm: bool = False) -> dict:
        path = f"/sessions/{session_id}/compact"
        if async_llm:
            path += "?async_llm=true"
        return self._request("POST", path)

    def compress(self, session_id: str) -> str:
        return self._request("POST", f"/sessions/{session_id}/compress")["context"]

    def upsert_node(
        self,
        session_id: str,
        kind: str,
        name: str,
        state: str = "UNVERIFIED",
        confidence: float = 0.5,
        source: str = "manual",
        properties: dict | None = None,
    ) -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/nodes",
            {
                "kind": kind,
                "name": name,
                "state": state,
                "confidence": confidence,
                "source": source,
                "properties": properties or {},
            },
        )

    def nodes(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/nodes")

    def link_nodes(self, session_id: str, source: str, target: str, kind: str = "contains") -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/links",
            {"source": source, "target": target, "kind": kind},
        )

    def surface(self, session_id: str) -> dict:
        return self._request("GET", f"/sessions/{session_id}/surface")

    def prune_graph(self, session_id: str) -> dict:
        return self._request("POST", f"/sessions/{session_id}/graph/prune")

    def add_investigation(
        self,
        session_id: str,
        name: str,
        status: str = "not_performed",
        result: str = "",
        evidence_result_id: str | None = None,
        confidence: float = 0.5,
    ) -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/investigations",
            {
                "name": name,
                "status": status,
                "result": result,
                "evidence_result_id": evidence_result_id,
                "confidence": confidence,
            },
        )

    def investigations(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/investigations")

    def add_finding(
        self,
        session_id: str,
        title: str,
        detail: str = "",
        confidence: float = 0.5,
        evidence_ids: list[str] | None = None,
        against: list[str] | None = None,
        status: str = "unverified",
        technique_id: str | None = None,
    ) -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/findings",
            {
                "title": title,
                "detail": detail,
                "confidence": confidence,
                "evidence_ids": evidence_ids or [],
                "against": against or [],
                "status": status,
                "technique_id": technique_id,
            },
        )

    def findings(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/findings")

    def update_finding_status(self, session_id: str, finding_id: str, status: str) -> dict:
        return self._request(
            "PATCH",
            f"/sessions/{session_id}/findings/{finding_id}",
            {"status": status},
        )

    def metrics(self, session_id: str) -> dict:
        return self._request("GET", f"/sessions/{session_id}/metrics")

    def plan(self, session_id: str) -> dict:
        return self._request("GET", f"/sessions/{session_id}/plan")

    def evidence_chains(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/evidence-chains")

    def report(self, session_id: str, fmt: str = "markdown") -> str:
        return self._request(
            "GET", f"/sessions/{session_id}/report?format={fmt}"
        )["report"]

    def debrief(self, session_id: str) -> dict:
        return self._request("GET", f"/sessions/{session_id}/debrief")

    def debrief_report(self, session_id: str, fmt: str = "markdown") -> str:
        return self._request(
            "GET", f"/sessions/{session_id}/debrief/report?format={fmt}"
        )["report"]

    def debrief_suggestions(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/debrief/suggestions")

    def debrief_seed(self, session_id: str) -> dict:
        return self._request("GET", f"/sessions/{session_id}/debrief/seed")

    def techniques(self) -> list[dict]:
        return self._request("GET", "/techniques")

    def technique(self, technique_id: str) -> dict:
        return self._request("GET", f"/techniques/{technique_id}")

    def session_techniques(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/techniques")

    def audit(self) -> list[dict]:
        return self._request("GET", "/audit")

    # ------------------------------------------------------------------
    # Blue team
    # ------------------------------------------------------------------
    def ingest_event(
        self,
        session_id: str,
        source: str,
        command: str = "",
        stdout: str = "",
        parsed: dict | None = None,
    ) -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/ingest",
            {"source": source, "command": command, "stdout": stdout, "parsed": parsed},
        )

    def alerts(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/alerts")

    def update_alert_status(
        self, session_id: str, alert_id: str, status: str, note: str | None = None
    ) -> dict:
        body: dict = {"status": status}
        if note:
            body["note"] = note
        return self._request(
            "PATCH", f"/sessions/{session_id}/alerts/{alert_id}", body
        )

    def add_rule(
        self,
        session_id: str,
        name: str,
        rule_id: str | None = None,
        severity: str = "medium",
        technique_ids: list[str] | None = None,
        pattern_stdout: list[str] | None = None,
        pattern_command: list[str] | None = None,
        description: str = "",
    ) -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/rules",
            {
                "name": name,
                "rule_id": rule_id,
                "severity": severity,
                "technique_ids": technique_ids or [],
                "patterns": {
                    "command": pattern_command or [],
                    "stdout": pattern_stdout or [],
                },
                "description": description,
            },
        )

    def rules(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/rules")

    def create_incident(
        self,
        session_id: str,
        title: str,
        alert_ids: list[str] | None = None,
        evidence_ids: list[str] | None = None,
        severity: str = "medium",
    ) -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/incidents",
            {
                "title": title,
                "alert_ids": alert_ids or [],
                "evidence_ids": evidence_ids or [],
                "severity": severity,
            },
        )

    def incidents(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/incidents")

    def update_incident_stage(self, session_id: str, incident_id: str, stage: str) -> dict:
        return self._request(
            "PATCH",
            f"/sessions/{session_id}/incidents/{incident_id}",
            {"stage": stage},
        )

    def add_recommendation(self, session_id: str, text: str) -> dict:
        return self._request(
            "POST", f"/sessions/{session_id}/recommendations", {"text": text}
        )

    def add_ioc(
        self,
        session_id: str,
        value: str,
        type: str = "other",
        confidence: float = 0.5,
        source: str = "manual",
        description: str = "",
        tags: list[str] | None = None,
    ) -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/iocs",
            {
                "value": value,
                "type": type,
                "confidence": confidence,
                "source": source,
                "description": description,
                "tags": tags or [],
            },
        )

    def iocs(self, session_id: str) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/iocs")

    # ------------------------------------------------------------------
    # Purple team
    # ------------------------------------------------------------------
    def link_session(self, session_id: str, linked_session_id: str, team: str) -> dict:
        return self._request(
            "POST",
            f"/sessions/{session_id}/purple-link",
            {"team": team, "session_id": linked_session_id},
        )

    def coverage(self, session_id: str) -> dict:
        return self._request("GET", f"/sessions/{session_id}/coverage")
