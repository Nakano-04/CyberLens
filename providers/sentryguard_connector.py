from __future__ import annotations

import glob
import json
import os

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from models.rule import DetectionRule


class SentryGuardConnector:
    """Conector dedicado SentryGuard (EDR) -> CyberLens blue team.

    Polling GET {sentryguard_url}/api/events y mapeo a ingest_telemetry.

    Config (config.yaml):
      sentryguard:
        url: "http://sentryguard.local:9000"
        timeout: 10
        poll_interval: 5
        enabled: false
        rules_dir: "../SentryGuard/src/SentryGuard.Rules/Rules/JSON"
    Usa requests con timeout 10s, dedup por event_id.
    Mapea cada evento a ingest_event(session_id, source, stdout).
    """

    def __init__(self, sentryguard_url: str, timeout: int = 10) -> None:
        self.sentryguard_url = sentryguard_url.rstrip("/")
        self.timeout = timeout
        self._seen: set[str] = set()

    def fetch_events(self) -> list[dict]:
        if requests is None:
            import urllib.request as _req

            with _req.urlopen(f"{self.sentryguard_url}/api/events", timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else []
        resp = requests.get(f"{self.sentryguard_url}/api/events", timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict) and "events" in data:
            return data["events"]
        if isinstance(data, list):
            return data
        return []

    def poll(self, session_id: str, mediator) -> list[dict]:
        events = self.fetch_events()
        ingested: list[dict] = []
        for ev in events:
            eid = str(ev.get("event_id") or ev.get("id") or ev.get("eventId") or id(ev))
            if eid in self._seen:
                continue
            self._seen.add(eid)
            source = ev.get("source") or ev.get("event_source") or "sentryguard"
            stdout = ev.get("stdout") or ev.get("raw") or ev.get("message") or json.dumps(ev, ensure_ascii=False)
            command = ev.get("command") or ""
            parsed = ev.get("parsed") or ev.get("fields") or None
            raw = stdout or command
            try:
                mediator.ingest_event(session_id, source, raw, parsed)
            except Exception:
                pass
            ingested.append({"source": source, "stdout": raw, "command": command, "event_id": eid, "parsed": parsed})
        return ingested


def import_sentryguard_rules(rules_dir: str) -> list[DetectionRule]:
    """Carga reglas JSON desde config.yaml:sentryguard_rules_dir -> list[DetectionRule]."""
    rules: list[DetectionRule] = []
    if not rules_dir or not os.path.isdir(rules_dir):
        return rules
    for path in glob.glob(os.path.join(rules_dir, "*.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            rid = str(item.get("id") or item.get("rule_id") or os.path.splitext(os.path.basename(path))[0])[:40]
            name = str(item.get("name") or item.get("title") or rid)
            severity = str(item.get("severity") or item.get("level") or "medium").lower()
            if severity not in ("low", "medium", "high", "critical"):
                severity = "medium"
            technique_ids = item.get("technique_ids") or item.get("techniques") or []
            if isinstance(technique_ids, str):
                technique_ids = [technique_ids]
            tid_single = item.get("technique_id") or item.get("technique")
            if tid_single and tid_single not in technique_ids:
                technique_ids.append(tid_single)
            patterns = item.get("patterns") or {}
            if not patterns and item.get("pattern"):
                patterns = {"stdout": [str(item["pattern"])]}
            if not patterns and item.get("pattern_stdout"):
                patterns = {"stdout": [str(item["pattern_stdout"])]}
            try:
                rules.append(DetectionRule(id=rid, session_id="", name=name, severity=severity, technique_ids=technique_ids, patterns=patterns, description=str(item.get("description") or "")))
            except Exception:
                continue
    return rules
